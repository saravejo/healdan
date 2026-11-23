import base64
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
from io import StringIO
from pathlib import Path
import sys
from unittest.mock import patch
import zipfile

from support import VaultTest
import healdan
from healdan import binding, build, installation, maintenance, tasks
from healdan.core import Blocked, Vault, atomic, decode, git, run
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
        self.assertEqual(maintenance.schedule_definitions(self.vault)[0]["ProgramArguments"][0], str(a.entry_point))
        self.assertEqual(maintenance.schedule_definitions(Vault(sibling))[0]["ProgramArguments"][0], str(b.entry_point))
        verifier = Path(__file__).resolve().parent.parent / "scripts/release_check.py"
        release = run([sys.executable, "-I", verifier, "--vault", sibling], cwd=verifier.parent.parent, check=False)
        self.assertEqual(release.returncode, 5)
        result = decode(release.stdout)
        self.assertEqual(result["build"], b.identity)
        self.assertTrue(result["publication_audit"])
        self.assertFalse(result["stable_release_allowed"])

    def test_concurrent_repeat_reuses_verified_environment(self):
        wheel = wheel_fixture(self.base / "same wheel", "same")
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = list(pool.map(lambda _: installation.prepare(wheel, self.store), range(2)))
        self.assertEqual(a, b)
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
        atomic(tampered, b"tampered")
        with self.assertRaisesRegex(Blocked, "differs from the wheel"):
            self.activate(b, Vault(self.root))
        self.assertEqual(selected.read_bytes(), selector)

    def test_migrating_one_vault_preserves_shared_legacy_environment(self):
        legacy_home = self.base / "legacy controller home"
        legacy = legacy_home / ".local/share/healdan/controller-1.0/pyvenv.cfg"
        atomic(legacy, b"existing shared controller environment")
        other = self.base / "legacy vault"
        other.mkdir()
        git(other, "init", "-b", "main")
        with patch("healdan.binding.Path.home", return_value=legacy_home):
            default = binding.Repository.open(other).default_state
            atomic(default / "config.json", {"git_name": "Second legacy vault"})
            existing_config = (default / "config.json").read_bytes()
            prepared = self.stage("new wheel")
            self.activate(prepared)
            self.assertEqual(self.identity(prepared.entry_point), prepared.identity)
            self.assertEqual(legacy.read_bytes(), b"existing shared controller environment")
            self.assertEqual((default / "config.json").read_bytes(), existing_config)
            self.assertFalse((default / binding.MARKER).exists())

    def test_activation_from_an_older_worktree_checks_primary_and_active_tasks(self):
        a, b = (self.stage(variant) for variant in ("compatible old", "compatible new"))
        self.activate(a)
        branch = self.base / "older worktree"
        git(self.root, "worktree", "add", "--detach", str(branch))
        task = tasks.create(self.vault, "Task with a divergent registry")
        selection = (self.vault.control / build.SELECTION).read_bytes()
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
