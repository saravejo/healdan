import base64
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
from io import StringIO
import os
from pathlib import Path
import plistlib
import sys
from unittest.mock import patch
import venv
import zipfile

from support import VaultTest
import test_source_policy
import test_transactions
import healdan
from healdan import binding, build, compatibility, installation, launchd, maintenance, tasks, transactions
from healdan import integration_journal
from healdan.core import TRANSACTION_V2, Blocked, Vault, atomic, decode, git, read_json, run
from healdan.setup import initialize


def wheel_fixture(directory, variation, *, capabilities=None):
    directory.mkdir(parents=True, exist_ok=True)
    package = Path(healdan.__file__).parent
    files = {"healdan/" + path.name: path.read_bytes() for path in package.iterdir()
             if path.suffix in {".py", ".json"}}
    from healdan.core import canonical
    if capabilities is not None:
        files["healdan/controller_formats.json"] = canonical(capabilities)
    files["healdan/test-build-marker.json"] = canonical({"variant": variation})
    metadata_dir = "healdan-" + healdan.__version__ + ".dist-info/"
    files[metadata_dir + "METADATA"] = f"Metadata-Version: 2.1\nName: healdan\nVersion: {healdan.__version__}\n".encode()
    files[metadata_dir + "WHEEL"] = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    files[metadata_dir + "entry_points.txt"] = b"[console_scripts]\nhealdan = healdan.cli:main\n"
    record = StringIO(newline="")
    writer = csv.writer(record)
    for name, data in sorted(files.items()):
        hashed = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + hashed, len(data)])
    writer.writerow([metadata_dir + "RECORD", "", ""])
    files[metadata_dir + "RECORD"] = record.getvalue().encode()
    path = directory / f"healdan-{healdan.__version__}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return path


class ImmutableInstallation(VaultTest):
    def setUp(self):
        super().setUp()
        self.store = self.base / "controller builds with spaces"

    def stage(self, variant):
        return installation.prepare(wheel_fixture(self.base / variant, variant), self.store)

    def activate(self, installation, vault=None):
        return build.activate(vault or self.vault, installation.identity["sha256"], self.store)

    def identity(self, command, root=None):
        result = run([command, "--vault", root or self.root, "build", "identity"],
                     cwd=self.root, env=installation.isolated_environment())
        return decode(result.stdout)["build"]

    def test_distinct_builds_and_same_entry_point_routes_by_vault(self):
        a, b = (self.stage(variant) for variant in ("wheel A", "wheel B"))
        self.assertEqual(a.identity["version"], b.identity["version"])
        self.assertNotEqual(a.identity["sha256"], b.identity["sha256"])
        sibling = self.base / "sibling vault"
        initialize(sibling, self.base / "sibling state")
        self.activate(a)
        self.activate(b, Vault(sibling))
        self.assertEqual(self.identity(a.entry_point), a.identity)
        self.assertEqual(self.identity(a.entry_point, sibling), b.identity)
        self.assertEqual(self.identity(b.entry_point), a.identity)
        scheduled = next(row["ProgramArguments"] for row in maintenance.schedule_definitions(self.vault)
                         if row["ProgramArguments"][-1] == "lint")
        self.assertEqual(scheduled[0], str(a.entry_point))
        self.assertEqual(scheduled[-3:], ["maintenance", "run-scheduled", "lint"])
        self.assertEqual(maintenance.schedule_definitions(Vault(sibling))[0]["ProgramArguments"][0], str(b.entry_point))
        stale = Vault(self.root)
        stale.controller_selection = build.read_selection(stale.control, stale.identity)
        self.activate(b)
        before = {path: path.read_bytes() for path in stale.control.rglob("*") if path.is_file()}
        for command in (scheduled, [*scheduled[:-3], "lint"], [*scheduled[:-3], "maintenance", "daily"]):
            result = run(command, cwd=self.root, env=installation.isolated_environment(), check=False)
            self.assertEqual(result.returncode, 5)
            self.assertIn("native trials must pass", decode(result.stdout)["error"])
            self.assertEqual({path: path.read_bytes() for path in stale.control.rglob("*") if path.is_file()}, before)
        with patch("healdan.setup.doctor") as doctor:
            with self.assertRaisesRegex(Blocked, "Controller selection changed"):
                maintenance.run_scheduled(stale, "lint", stale.identity)
        doctor.assert_not_called()
        manual = run([a.entry_point, "--vault", self.root, "lint"], cwd=self.root,
                     env=installation.isolated_environment(), check=False)
        self.assertIn(manual.returncode, (0, 5))
        self.assertTrue((stale.control / "lint-state.json").exists())
        manual_daily = run([a.entry_point, "--vault", self.root, "--state", self.state, "maintenance", "daily"],
                           cwd=self.root, env=installation.isolated_environment(), check=False)
        self.assertEqual(manual_daily.returncode, 5)
        self.assertIn("backup generation lifetime", decode(manual_daily.stdout)["error"])
        self.assertTrue(list((stale.control / "deletions").glob("*.json")))
        verifier = Path(__file__).resolve().parent.parent / "scripts/release_check.py"
        release = run([sys.executable, "-I", verifier, "--vault", sibling], cwd=verifier.parent.parent, check=False)
        self.assertEqual(release.returncode, 5)
        result = decode(release.stdout)
        self.assertEqual(result["build"], b.identity)
        self.assertTrue(result["publication_audit"])
        self.assertFalse(result["stable_release_allowed"])

    def test_concurrent_repeat_reuses_verified_environment(self):
        wheel = wheel_fixture(self.base / "same wheel", "same")
        make_venv = venv.EnvBuilder
        with patch("healdan.installation.venv.EnvBuilder",
                   side_effect=lambda **kwargs: make_venv(symlinks=os.name != "nt", **kwargs)):
            with ThreadPoolExecutor(max_workers=2) as pool:
                a, b = list(pool.map(lambda _: installation.prepare(wheel, self.store), range(2)))
        self.assertEqual(a, b)
        if os.name != "nt":
            self.assertTrue(a.python.is_symlink())
        receipt = (a.prefix / build.BUILD_RECEIPT).read_bytes()
        with patch("healdan.installation._install") as install:
            self.assertEqual(a, installation.prepare(wheel, self.store))
        install.assert_not_called()
        self.assertEqual((a.prefix / build.BUILD_RECEIPT).read_bytes(), receipt)
        self.activate(a)
        self.assertEqual(self.identity(a.entry_point), a.identity)

    def test_preparation_and_activation_failures_preserve_the_previous_command(self):
        a = self.stage("previous")
        self.activate(a)
        selected = self.vault.control / build.SELECTION
        original = selected.read_bytes()
        wheel = wheel_fixture(self.base / "interrupted", "interrupted")
        install = installation._install

        def interrupt_after(prefix, package):
            install(prefix, package)
            raise OSError("after pip")

        for target, failure in (("_install", OSError("before pip")), ("_install", interrupt_after),
                                ("_smoke", OSError("smoke test failed"))):
            with patch("healdan.installation." + target, side_effect=failure), self.assertRaises(OSError):
                installation.prepare(wheel, self.store)
            self.assertEqual(selected.read_bytes(), original)
            self.assertEqual(self.identity(a.entry_point), a.identity)
        b = installation.prepare(wheel, self.store)
        with patch("healdan.build.atomic", side_effect=OSError("before activation")), self.assertRaises(OSError):
            self.activate(b)
        self.assertEqual(selected.read_bytes(), original)
        self.assertEqual(self.identity(b.entry_point), a.identity)
        self.activate(b)
        self.assertEqual(self.identity(a.entry_point), b.identity)

    def test_same_wheel_recovers_in_new_store_after_base_python_changes(self):
        original = self.stage("wheel with older Python receipt")
        other = self.stage("independent vault build")
        sibling = self.base / "other vault"
        initialize(sibling, self.base / "other state")
        other_vault = Vault(sibling)
        self.activate(original)
        self.activate(other, other_vault)
        selected = self.vault.control / build.SELECTION
        other_selection = other_vault.control / build.SELECTION
        before = {path: path.read_bytes() for path in (selected, other_selection)}
        wheel = original.prefix / "artifact" / original.manifest["wheel"]
        receipt_path = original.prefix / build.BUILD_RECEIPT
        receipt = read_json(receipt_path)
        receipt["layout"]["python"]["base"]["sha256"] = "0" * 64
        atomic(receipt_path, receipt)
        old_installation = {p.relative_to(original.prefix): p.read_bytes()
                            for p in (receipt_path, original.entry_point, wheel)}
        setup = Path(__file__).resolve().parent.parent / "scripts/setup.py"
        command = [sys.executable, "-I", setup, "--vault", self.root, "--wheel", wheel, "--no-interactive"]
        new_store = self.base / "store for upgraded Python"
        old_command = run([original.entry_point, "--vault", self.root, "build", "identity"], check=False)
        self.assertEqual(old_command.returncode, 5)
        self.assertIn("base Python is unavailable or changed", decode(old_command.stdout)["error"])
        blocked = run([*command, "--store", self.store], check=False)
        self.assertEqual(blocked.returncode, 5)
        self.assertIn("--store NEW_STORE", decode(blocked.stdout)["error"])
        config_before = self.vault.config_path.read_bytes()
        atomic(self.vault.config_path, {**self.vault.config, "schema_version": 100})
        blocked = run([*command, "--store", new_store], check=False)
        self.assertEqual(blocked.returncode, 5)
        self.assertIn(b"cannot read current config format".lower(), blocked.stdout.lower())
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        atomic(self.vault.config_path, config_before)
        recovered = run([*command, "--store", new_store])
        activation = decode(recovered.stdout.splitlines()[-1])
        self.assertEqual(activation["build"], original.identity)
        self.assertEqual(Path(activation["controller"]).parent.parent, new_store / original.identity["sha256"])
        self.assertEqual(self.identity(activation["controller"]), original.identity)
        self.assertEqual(other_selection.read_bytes(), before[other_selection])
        self.assertEqual(self.identity(other.entry_point, sibling), other.identity)
        self.assertEqual({path: (original.prefix / path).read_bytes() for path in old_installation}, old_installation)

    def test_compatible_rollback_and_rejection_preserve_external_state_bytes(self):
        a, b = (self.stage(variant) for variant in ("earlier", "later"))
        self.activate(a)
        self.activate(b)
        self.rows("wiki/control/query-cases.jsonl", [self.case()])
        persisted = list(self.state.rglob("*.json")) + [self.root / "wiki/control/query-cases.jsonl"]
        before = {path: path.read_bytes() for path in persisted}
        self.activate(a)
        self.assertEqual({path: path.read_bytes() for path in persisted}, before)
        self.assertEqual(self.identity(b.entry_point), a.identity)
        selected = self.vault.control / build.SELECTION
        selector = selected.read_bytes()
        config = self.vault.config_path
        journal = self.vault.control / "transaction.json"
        for path, data, reason in ((config, {**self.vault.config, "schema_version": 100}, "config format"),
                                   (journal, {"status": "writing", "format": "future"}, "journal format")):
            atomic(path, data)
            written = path.read_bytes()
            with self.assertRaisesRegex(Blocked, reason):
                self.activate(b, Vault(self.root))
            self.assertEqual(path.read_bytes(), written)
            self.assertEqual(selected.read_bytes(), selector)
            if path in before:
                atomic(path, before[path])
            else:
                path.unlink()
        tampered = b.prefix / b.manifest["layout"]["site_packages"] / "healdan/defaults.json"
        default_bytes = tampered.read_bytes()
        atomic(tampered, b"tampered")
        with self.assertRaisesRegex(Blocked, "differs from the wheel"):
            self.activate(b, Vault(self.root))
        self.assertEqual(selected.read_bytes(), selector)
        atomic(tampered, default_bytes)
        site = b.prefix / b.manifest["layout"]["site_packages"]
        run([b.python, "-I", "-c", "import healdan"], env=installation.isolated_environment())
        self.assertTrue((site / "healdan/__pycache__").is_dir())
        self.assertEqual(build.verify_build(b.prefix).identity, b.identity)
        for startup in (site / "fixture.pth", site / "sitecustomize.py", b.python.with_name("python._pth")):
            atomic(startup, b"# Synthetic startup fixture\n")
            with self.assertRaisesRegex(Blocked, "does not match the verified wheel and environment"):
                self.activate(b, Vault(self.root))
            self.assertEqual(selected.read_bytes(), selector)
            startup.unlink()
        if b.python.is_symlink():
            b.python.unlink()
        b.python.write_bytes(b"synthetic damaged executable")
        if os.name != "nt":
            b.python.chmod(0o700)
        with self.assertRaisesRegex(Blocked, "does not match the verified wheel and environment"):
            build.verify_build(b.prefix)
        with self.assertRaisesRegex(Blocked, "does not match the verified wheel and environment"):
            self.activate(b, Vault(self.root))
        self.assertEqual(selected.read_bytes(), selector)
        self.assertEqual(self.identity(a.entry_point), a.identity)

    def test_activation_and_migration_accept_generated_page_package_without_rewriting(self):
        prepared = self.stage("page package reader")
        _, package = test_transactions.Transactions.prepare_fixture(self)
        identifier = package["id"]
        transactions.inspect_package(self.vault, identifier, {"C-0001": "conform"})
        signed = transactions.approve(self.vault, identifier)
        self.assertTrue(signed["payload"]["page_revisions"])
        transactions.apply(self.vault, identifier)
        journal = self.vault.control / "transaction.json"
        ledger = self.root / transactions.LEDGER
        self.assertEqual(read_json(journal)["format"], integration_journal.FORMAT)
        before = {path: path.read_bytes() for path in (journal, ledger)}
        self.assertEqual(self.activate(prepared)["build"], prepared.identity)
        code, result = self.cli("migration", "preview")
        self.assertEqual(code, 0, result)
        approved, = result["packages"]
        origin = approved["projection"]["origin"]
        self.assertEqual(origin["format"], "healdan-approval-package-v3")
        self.assertEqual(origin["approval"], signed)
        self.assertEqual(base64.b64decode(origin["row_base64"]), before[ledger])
        self.assertEqual({path: path.read_bytes() for path in before}, before)

        current = read_json(journal)
        previous = {key: current[key] for key in ("status", "package_id", "base", "files", "before",
                                                  "before_files", "commit", "completed_at")}
        previous["written"] = list(current["written"])
        atomic(journal, previous)
        unversioned = journal.read_bytes()
        self.assertEqual(self.activate(prepared)["build"], prepared.identity)
        self.assertEqual(journal.read_bytes(), unversioned)
        capabilities = prepared.manifest["capabilities"]
        older = {**capabilities, "journal": [compatibility.LEGACY_JOURNAL]}
        with self.assertRaisesRegex(Blocked, "cannot read current journal format"):
            compatibility.check(self.vault, older)
        older = {**capabilities, "package": capabilities["package"][:-1]}
        with self.assertRaisesRegex(Blocked, "cannot read current package format"):
            compatibility.check(self.vault, older)

    def test_activation_reads_interrupted_and_withdrawn_publication_journals(self):
        prepared = self.stage("withdrawn source reader")
        body = b"Disposable source approval fixture"
        source = test_source_policy.SourcePolicy.proposal(self, body)
        identifier = test_source_policy.SourcePolicy.approved(self)
        destination = self.root / source["path"]

        with patch("healdan.integration_git.publish", side_effect=OSError("Interrupted before CAS")), \
                self.assertRaisesRegex(OSError, "Interrupted"):
            transactions.apply(self.vault, identifier)
        journal = self.vault.control / "transaction.json"
        self.assertEqual(read_json(journal)["status"], "writing")
        before = journal.read_bytes()
        self.assertEqual(self.activate(prepared)["build"], prepared.identity)
        self.assertEqual(journal.read_bytes(), before)
        pending = read_json(journal)
        withdrawn = {key: pending[key] for key in ("package_id", "base", "files", "before", "before_files")}
        withdrawn.update(format=TRANSACTION_V2, status="aborted", written=[], reason="Prior withdrawal fixture",
                         aborted_at=pending["git_identity"]["at"])
        atomic(journal, withdrawn)
        self.assertFalse(destination.exists())
        after = journal.read_bytes()
        self.assertEqual(self.activate(prepared)["build"], prepared.identity)
        self.assertEqual(journal.read_bytes(), after)
        changed = read_json(journal)
        changed["before_files"][transactions.LEDGER] = "%%%"
        atomic(journal, changed)
        with self.assertRaisesRegex(Blocked, "Invalid integration journal bytes"):
            self.activate(prepared)

    def test_migrating_one_vault_preserves_shared_legacy_environment(self):
        legacy_home = self.base / "legacy controller home"
        legacy = legacy_home / ".local/share/healdan/controller-1.0"
        venv_config = legacy / "pyvenv.cfg"
        atomic(venv_config, b"existing shared controller environment")
        loaded = set()
        with patch("healdan.binding.Path.home", return_value=legacy_home), \
                patch("healdan.launchd._service_loaded", side_effect=loaded.__contains__):
            repositories = []
            plists = []
            for name in ("legacy A", "legacy B"):
                root = self.base / name
                root.mkdir()
                git(root, "init", "-b", "main")
                repository = binding.Repository.open(root)
                repositories.append(repository)
                state = repository.default_state
                atomic(state / "config.json", {"git_name": name})
                label = next(label for label in launchd.legacy_labels(str(repository.common)) if label.endswith(".lint"))
                installed = legacy_home / "Library/LaunchAgents" / (label + ".plist")
                atomic(installed, plistlib.dumps({"Label": label, "ProgramArguments": [str(legacy / "bin/healdan"),
                                                  "--vault", str(root), "--state", str(state), "lint"]}))
                plists.append(installed)
                loaded.add(label)
            a, b = repositories
            a_plist, b_plist = plists
            original = {path: path.read_bytes() for path in (venv_config, b_plist, b.default_state / "config.json")}
            preview = binding.adopt(a.root)
            self.assertEqual(preview["legacy_launchagents"], [{"label": a_plist.stem, "loaded": True,
                                                              "installed_plist": str(a_plist)}])
            with self.assertRaisesRegex(Blocked, a_plist.stem):
                binding.adopt(a.root, confirmation=preview["confirmation"])
            self.assertFalse((a.control / binding.PENDING).exists())
            self.assertFalse((a.default_state / binding.MARKER).exists())
            loaded.remove(a_plist.stem)
            with self.assertRaisesRegex(Blocked, a_plist.stem):
                binding.adopt(a.root, confirmation=preview["confirmation"])
            loaded.add(a_plist.stem)
            a_plist.unlink()
            with self.assertRaisesRegex(Blocked, a_plist.stem):
                binding.adopt(a.root, confirmation=preview["confirmation"])
            loaded.remove(a_plist.stem)
            def interrupt(path, data):
                if path == a.default_state / binding.MARKER:
                    raise OSError("interrupt after the adoption intent")
                atomic(path, data)
            with patch("healdan.binding.atomic", side_effect=interrupt), self.assertRaises(OSError):
                binding.adopt(a.root, confirmation=preview["confirmation"])
            self.assertTrue((a.control / binding.PENDING).exists())
            loaded.add(a_plist.stem)
            with self.assertRaisesRegex(Blocked, a_plist.stem):
                binding.adopt(a.root, confirmation=preview["confirmation"])
            self.assertFalse((a.default_state / binding.MARKER).exists())
            loaded.remove(a_plist.stem)
            self.assertEqual(binding.adopt(a.root, confirmation=preview["confirmation"])["status"], "adopted")
            initialize(a.root)
            prepared = self.stage("new wheel")
            loaded.add(a_plist.stem)
            with self.assertRaisesRegex(Blocked, a_plist.stem):
                self.activate(prepared, Vault(a.root))
            loaded.remove(a_plist.stem)
            self.activate(prepared, Vault(a.root))
            for plist in maintenance.schedule_definitions(Vault(a.root)):
                self.assertEqual(plist["ProgramArguments"][0], str(prepared.entry_point))
            self.assertEqual(self.identity(prepared.entry_point, a.root), prepared.identity)
            self.assertEqual({path: path.read_bytes() for path in original}, original)
            self.assertFalse((b.default_state / binding.MARKER).exists())

    def test_launchd_trial_uses_disposable_vault_and_keeps_production_gated(self):
        prepared = self.stage("launchd trial build")
        self.activate(prepared)
        destination = self.base / "disposable fixtures"
        destination.mkdir()
        fake_home = self.base / "launchd trial home"
        partial = {"ready": False, "checks": [{"name": "trial:launchd", "passed": False},
                                              {"name": "trial:offline-recovery", "passed": True}]}
        with patch("healdan.maintenance.platform.system", return_value="Darwin"), \
                patch("healdan.launchd._service_loaded", return_value=False), \
                patch("healdan.maintenance.Path.home", return_value=fake_home), \
                patch("healdan.build.require_active", return_value=prepared), \
                patch("healdan.setup.doctor", return_value=partial), \
                patch("healdan.maintenance.gui_domain", return_value="gui/501"), \
                patch("healdan.maintenance.executable", return_value="/bin/launchctl"), \
                patch("healdan.maintenance.run") as launchctl:
            launchctl.return_value.returncode = 0
            with self.assertRaisesRegex(Blocked, "outside all vault worktrees"):
                maintenance.prepare_launchd_trial(self.vault, self.root)
            report = maintenance.prepare_launchd_trial(self.vault, destination)
            trial = Vault(report["vault"], report["state"])
            self.assertNotEqual(trial.identity, self.vault.identity)
            self.assertEqual(report["build"], prepared.identity)
            for vault, trial_mode, error in ((self.vault, False, "native trials must pass"),
                                             (self.vault, True, "matching production or disposable"),
                                             (trial, False, "matching production or disposable")):
                with self.assertRaisesRegex(Blocked, error):
                    maintenance.schedule(vault, activate=True, trial=trial_mode)
                with self.assertRaisesRegex(Blocked, error):
                    maintenance.run_scheduled(vault, "lint", vault.identity, trial=trial_mode)
            with self.assertRaisesRegex(Blocked, "must name its vault identity"):
                maintenance.run_scheduled(trial, "lint", self.vault.identity, trial=True)
            partial["checks"][1]["passed"] = False
            with self.assertRaisesRegex(Blocked, "native trials must pass"):
                maintenance.schedule(trial, activate=True, trial=True)
            partial["checks"][1]["passed"] = True
            atomic(trial.config_path, {**trial.config, "backup_destinations": [str(self.state)]})
            with self.assertRaisesRegex(Blocked, "destinations must stay"):
                maintenance.run_scheduled(trial, "daily", trial.identity, trial=True)
            workspace = Path(report["workspace"])
            key, signers = workspace / "backup-key", workspace / "backup-signers"
            atomic(key, b"trial configuration fixture")
            atomic(signers, b"trial configuration fixture")
            atomic(trial.config_path, {**trial.config, "backup_destinations": [str(workspace / "backups")],
                                      "backup_generation_days": 2, "backup_signing_key": str(key),
                                      "backup_allowed_signers": str(signers), "backup_signing_identity": "fixture"})
            launchctl.assert_not_called()
            plists = maintenance.schedule(trial, activate=True, trial=True)
            self.assertEqual(len(plists["plists"]), 2)
            for path in plists["plists"]:
                definition = plistlib.loads(Path(path).read_bytes())
                self.assertTrue(definition["Label"].startswith(f"org.healdan.trial.{trial.identity}."))
                self.assertEqual(definition["ProgramArguments"][-4:-1],
                                 ["maintenance", "run-scheduled", definition["Label"].split(".")[-1]])
                self.assertEqual(definition["ProgramArguments"][-1], "--trial")
                self.assertTrue(Path(definition["StandardOutPath"]).is_relative_to(trial.state))
            self.assertEqual(launchctl.call_count, 2)
            self.assertFalse((self.state / "launchd").exists())
            order = []
            with patch("healdan.linting.lint", return_value={"status": "complete"}) as lint, \
                    patch("healdan.retention.execute", side_effect=lambda *_: order.append("retention") or
                          {"status": "complete", "id": "plan"}), \
                    patch("healdan.backups.create", side_effect=lambda *_, **__: order.append("backup") or {"id": "backup"}):
                self.assertEqual(maintenance.run_scheduled(trial, "lint", trial.identity, trial=True), lint.return_value)
                self.assertEqual(maintenance.run_scheduled(trial, "daily", trial.identity, trial=True)["backup"], "backup")
            self.assertEqual(order, ["retention", "backup"])
            self.assertFalse((trial.control / "trials/v2/launchd.json").exists())

    def test_activation_from_an_older_worktree_checks_primary_and_active_tasks(self):
        a, b = (self.stage(variant) for variant in ("compatible old", "compatible new"))
        self.activate(a)
        branch = self.base / "older worktree"
        git(self.root, "worktree", "add", "--detach", str(branch))
        task = tasks.create(self.vault, "Task with a divergent registry")
        selection = (self.vault.control / build.SELECTION).read_bytes()
        nested = branch / "nested build store"
        wheel = b.prefix / "artifact" / b.manifest["wheel"]
        code, result = self.cli("build", "prepare", wheel, "--store", nested)
        self.assertEqual(code, 5)
        self.assertIn("outside all vault worktrees", result["error"])
        script = Path(__file__).resolve().parent.parent / "scripts/setup.py"
        result = run([sys.executable, "-I", script, "--vault", self.root, "--wheel", wheel, "--store", nested,
                      "--prepare-only", "--no-interactive"], check=False)
        self.assertEqual(result.returncode, 5)
        self.assertFalse(nested.exists())
        attempted = installation.prepare(wheel, nested)
        for target in (self.root, branch):
            with self.assertRaisesRegex(Blocked, "outside all vault worktrees"):
                build.activate(Vault(target), attempted.identity["sha256"], nested)
            self.assertEqual((self.vault.control / build.SELECTION).read_bytes(), selection)
        for target in (self.root, Path(task["worktree"])):
            registry = target / "wiki/control/query-cases.jsonl"
            original = registry.read_bytes()
            atomic(registry, b'{"id":"Q-0001","format":"future-case"}\n')
            with self.assertRaisesRegex(Blocked, "cannot read current case format"):
                self.activate(b, Vault(branch))
            self.assertEqual((self.vault.control / build.SELECTION).read_bytes(), selection)
            atomic(registry, original)
        self.activate(b, Vault(branch))
        self.assertEqual(self.identity(a.entry_point), b.identity)
