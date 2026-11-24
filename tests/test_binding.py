from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import os
from pathlib import Path
import plistlib
import sys
from threading import Barrier
from unittest.mock import patch
from uuid import uuid4

from support import VaultTest
from healdan import backups, binding, custody, ids, retention, tasks
from healdan.core import Blocked, Vault, atomic, decode, git, run, utc
from healdan.setup import initialize


class VaultBinding(VaultTest):
    def test_foreign_and_divergent_state_are_rejected_before_changes(self):
        clone = self.base / "sibling clone"
        git(self.root, "clone", "--no-local", str(self.root), str(clone))
        self.assertEqual(git(clone, "rev-parse", "HEAD"), self.vault.head())
        git(clone, "remote", "set-url", "origin", "https://github.com/saravejo/healdan.git")
        remote_config = (clone / ".git/config").read_bytes()
        config = self.vault.config_path.read_bytes()
        atomic(self.vault.config_path, b"foreign invalid JSON")
        with self.assertRaisesRegex(Blocked, "already bound"):
            initialize(clone, self.state)
        self.assertEqual((clone / ".git/config").read_bytes(), remote_config)
        self.assertFalse((clone / ".git/healdan").exists())
        self.assertEqual(self.vault.config_path.read_bytes(), b"foreign invalid JSON")
        atomic(self.vault.config_path, config)
        task = tasks.create(self.vault, "Control")
        reserved = ids.reserve(self.vault, "S", 1, str(uuid4()))
        other = self.base / "divergent state"
        for exists in (False, True):
            if exists:
                other.mkdir()
            with self.assertRaisesRegex(Blocked, "differs"):
                Vault(self.root, other, operational=False)
            self.assertEqual(other.exists(), exists)
        opened = Vault(self.root)
        self.assertEqual(opened.state, self.state)
        self.assertEqual(tasks.get_task(opened, task["id"]), task)
        self.assertIn(reserved, [r["ids"] for r in decode((opened.control / "reservations.json").read_bytes()).values()])

    def test_primary_and_linked_worktrees_share_identity(self):
        linked = self.base / "branch worktree"
        detached = self.base / "detached worktree"
        git(self.root, "worktree", "add", "-b", "binding-test", str(linked))
        git(self.root, "worktree", "add", "--detach", str(detached))
        task = tasks.create(self.vault, "Task worktree")
        for path in (linked, detached, task["worktree"]):
            vault = Vault(path)
            self.assertEqual((vault.identity, vault.common, vault.state),
                             (self.vault.identity, self.vault.common, self.state))
        sibling = self.base / "another vault"
        git(self.root, "clone", "--no-local", str(self.root), str(sibling))
        sibling_linked = self.base / "unbound linked worktree"
        git(sibling, "worktree", "add", "--detach", str(sibling_linked))
        nested_state = sibling_linked / "versionable state"
        for root in (sibling, sibling_linked):
            with self.assertRaisesRegex(Blocked, "outside every registered vault worktree"):
                initialize(root, nested_state)
            self.assertFalse(nested_state.exists())
        initialize(sibling, self.base / "other vault state")
        sibling_id = Vault(sibling).identity
        self.assertNotEqual(sibling_id, self.vault.identity)
        with patch.dict(os.environ, {"GIT_DIR": str(self.vault.common), "GIT_WORK_TREE": str(sibling),
                                     "GIT_INDEX_FILE": str(self.vault.common / "index")}):
            self.assertEqual(Vault(sibling).identity, sibling_id)
            with self.assertRaisesRegex(Blocked, "differs"):
                Vault(sibling, self.state)
            git(sibling, "config", "--local", "healdan.fixture", "selected")
            self.assertEqual(git(self.root, "config", "--get", "healdan.fixture", check=False), "")
            self.assertEqual(git(sibling, "config", "--get", "healdan.fixture"), "selected")
        empty = self.base / "new zip vault"
        initialize(empty, self.base / "new zip state")
        self.assertIsNone(Vault(empty).head())

    def test_verified_legacy_default_custom_and_unilateral_state(self):
        task = tasks.create(self.vault, "Independent provenance")
        old_receipts = {p.name: p.read_bytes() for p in (self.vault.control / "receipts").glob("*.json")}
        old_state_marker = (self.state / binding.MARKER).read_bytes()
        (self.vault.control / binding.MARKER).unlink()
        with self.assertRaisesRegex(Blocked, "unilateral|foreign"):
            binding.adopt(self.root, self.state)
        (self.state / binding.MARKER).unlink()
        ambiguous = self.base / "ambiguous state"
        atomic(ambiguous / "config.json", self.vault.config)
        with self.assertRaisesRegex(Blocked, "different external state"):
            binding.adopt(self.root, ambiguous)
        preview = binding.adopt(self.root, self.state)
        self.assertTrue(any(x["kind"] == "git-worktree" for x in preview["provenance"]))
        self.assertFalse((self.vault.control / binding.MARKER).exists())
        self.assertEqual(binding.adopt(self.root, self.state, preview["confirmation"])["status"], "adopted")
        self.assertEqual(binding.adopt(self.root, self.state, preview["confirmation"])["status"], "already-bound")
        self.assertNotEqual((self.state / binding.MARKER).read_bytes(), old_state_marker)
        self.assertEqual(tasks.get_task(Vault(self.root), task["id"]), task)
        self.assertEqual({p.name: p.read_bytes() for p in (self.vault.control / "receipts").glob("*.json")}, old_receipts)

        root = self.base / "legacy default vault"
        root.mkdir()
        git(root, "init", "-b", "main")
        with patch("healdan.binding.Path.home", return_value=self.base / "legacy home"):
            default = binding.Repository.open(root).default_state
            atomic(default / "config.json", {"git_name": "Legacy name"})
            preview = binding.adopt(root)
            self.assertEqual(preview["provenance"][0]["kind"], "legacy-default-location")
            binding.adopt(root, confirmation=preview["confirmation"])
            initialize(root)
            self.assertEqual(Vault(root).config["git_name"], "Legacy name")
            atomic(default / binding.MARKER, b"{}\n")
            with self.assertRaisesRegex(Blocked, "Invalid vault binding marker"):
                Vault(root)

    def test_interrupted_setup_requires_both_markers_and_retries(self):
        root = self.base / "interrupted vault"
        state = self.base / "interrupted state"

        def interrupt(path, data):
            if path.name == binding.MARKER and path.parent != state:
                raise OSError("interrupted between markers")
            atomic(path, data)

        with patch("healdan.binding.atomic", side_effect=interrupt), self.assertRaises(OSError):
            initialize(root, state)
        self.assertTrue((state / binding.MARKER).exists())
        self.assertFalse((state / "config.json").exists())
        with self.assertRaisesRegex(Blocked, "interrupted"):
            Vault(root, state, operational=False)
        foreign = self.base / "foreign new vault"
        with self.assertRaisesRegex(Blocked, "already bound"):
            initialize(foreign, state)
        self.assertFalse((foreign / ".git").exists())
        initialize(root)
        self.assertEqual(Vault(root).state, state)

    def test_concurrent_processes_agree_on_one_vault_and_one_state(self):
        def compete(first, second):
            barrier = Barrier(2)

            def setup_pair(pair):
                root, state = pair
                barrier.wait()
                result = run([sys.executable, "-m", "healdan", "--vault", root, "--state", state, "setup"], check=False)
                return result.returncode, pair

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(setup_pair, (first, second)))
            self.assertEqual(sum(code == 0 for code, _ in outcomes), 1, outcomes)
            winner = next(pair for code, pair in outcomes if code == 0)
            loser = next(pair for code, pair in outcomes if code != 0)
            self.assertEqual(Vault(*winner).state, winner[1])
            with self.assertRaises(Blocked):
                Vault(*loser, operational=False)

        shared_vault = self.base / "shared vault"
        shared_vault.mkdir()
        git(shared_vault, "init", "-b", "main")
        compete((shared_vault, self.base / "candidate one"), (shared_vault, self.base / "candidate two"))
        other_vaults = [self.base / "concurrent vault one", self.base / "concurrent vault two"]
        for root in other_vaults:
            root.mkdir()
            git(root, "init", "-b", "main")
        shared_state = self.base / "shared state"
        compete((other_vaults[0], shared_state), (other_vaults[1], shared_state))

    def test_normal_reads_do_not_wait_for_the_maintenance_write_lock(self):
        with self.vault.locked(), ThreadPoolExecutor(max_workers=4) as pool:
            writer = pool.submit(self.cli, "task", "reserve-id", "C", "--operation", str(uuid4()))
            status = pool.submit(self.cli, "status")
            query = pool.submit(self.cli, "query", "--entity", "instrument")
            preview = pool.submit(self.cli, "preview")
            self.assertEqual(status.result(timeout=12)[0], 0)
            self.assertEqual(query.result(timeout=12)[0], 20)
            self.assertEqual(preview.result(timeout=12)[0], 0)
            code, details = writer.result(timeout=30)
            self.assertEqual(code, 5, details)
            self.assertIn("Controller lock is busy", details["error"])

            atomic(self.vault.control / "transaction.json", {"status": "writing"})
            code, status = self.cli("status")
            self.assertEqual(code, 0)
            self.assertEqual(status["transaction"], "writing")
            for command in ("query", "preview"):
                code, result = self.cli(command)
                self.assertEqual(code, 5)
                self.assertIn("integration needs recovery", result["error"])

        self.assertFalse((self.vault.control / "reservations.json").exists())
        with self.assertRaisesRegex(Blocked, "binding is interrupted"), self.vault.reading():
            atomic(self.vault.control / binding.PENDING, {"synthetic": "binding in progress"})

    def test_rebind_accepts_only_confirmed_missing_task_worktree(self):
        task = tasks.create(self.vault, "Recorded removal of a disposable task worktree")
        original = Path(task["worktree"])
        saved_worktree = self.base / "retained synthetic worktree"
        original.rename(saved_worktree)
        admin, linked = next(self.vault.repository.linked_worktrees())
        self.assertEqual(linked.parent, original)
        new_state = self.base / "relocated external state"
        self.state.rename(new_state)
        target = new_state / original.relative_to(self.state)
        with self.assertRaisesRegex(Blocked, "Missing Git worktree has no confirmed removal"):
            binding.rebind(self.root, new_state)
        self.assertEqual(binding.marker(new_state), self.vault.binding)

        task["worktree_removed"] = True
        atomic(tasks.task_path(self.vault, task["id"]), task)
        locked = admin / "locked"
        atomic(locked, b"unavailable portable fixture")
        with self.assertRaisesRegex(Blocked, "Missing Git worktree has no confirmed removal"):
            binding.rebind(self.root, new_state)
        locked.unlink()
        preview = binding.rebind(self.root, new_state)
        self.assertEqual(preview["worktrees"], [{"path": str(target), "git_directory": str(admin),
                                                 "needs_repair": False, "removed": True}])
        self.assertEqual(binding.rebind(self.root, new_state, preview["confirmation"])["status"], "rebound")
        self.assertEqual(tasks.get_task(Vault(self.root), task["id"])["worktree"], str(target))
        self.assertTrue(saved_worktree.is_dir())
        self.assertTrue((admin / "gitdir").is_file())

    def test_rebind_separately_and_together_preserves_worktrees_and_signed_custody(self):
        self.age()
        destination = self.state / "backup location"
        external_destination = self.base / "fixed backup location"
        destination.mkdir()
        external_destination.mkdir()
        self.vault.config["backup_destinations"] = [str(destination), str(external_destination)]
        atomic(self.vault.config_path, self.vault.config)
        backup = backups.create(self.vault, "long", utc() + timedelta(days=2))
        material_file = self.vault.control / "materials.json"
        link = self.base / "independent linked worktree"
        git(self.root, "worktree", "add", "-b", "independent", str(link))
        task = tasks.create(self.vault, "Preserve links")
        session = tasks.new_session(self.vault, task["id"], "read", "reader", "Context")
        plan_of_deletions = retention.plan(self.vault, utc() + timedelta(days=3))
        captured_material = material_file.read_bytes()
        deletion_file = self.vault.control / "deletions" / (plan_of_deletions["id"] + ".json")
        captured_deletion = deletion_file.read_bytes()
        plist = self.state / "launchd/org.healdan.binding-test.lint.plist"
        atomic(plist, plistlib.dumps({"Label": plist.stem, "ProgramArguments": [sys.executable, "--vault",
               str(self.root), "--state", str(self.state), "lint"], "StartCalendarInterval": {"Hour": 4},
               "StandardOutPath": str(self.state / "lint.out"), "StandardErrorPath": str(self.state / "lint.err")}))
        root, state = self.root, self.state
        for move_root, move_state in ((True, False), (False, True), (True, True)):
            next_root = root.with_name(root.name + " moved") if move_root else root
            next_state = state.with_name(state.name + " moved") if move_state else state
            if move_root:
                root.rename(next_root)
            if move_state:
                state.rename(next_state)
            with self.assertRaises(Blocked):
                Vault(next_root, next_state)
            if not move_state:
                offline = external_destination.with_name("disconnected backup")
                external_destination.rename(offline)
                with self.assertRaisesRegex(Blocked, "configuration path is unavailable"):
                    binding.rebind(next_root, next_state)
                offline.rename(external_destination)
                fake_home = self.base / "launchd home"
                installed = fake_home / "Library/LaunchAgents" / plist.name
                atomic(installed, b"synthetic installed plist")
                with patch("healdan.relocation.Path.home", return_value=fake_home):
                    with self.assertRaisesRegex(Blocked, "Unload and remove"):
                        binding.rebind(next_root, next_state)
            if move_state:
                state.mkdir()
                with self.assertRaisesRegex(Blocked, "still occupied"):
                    binding.rebind(next_root, next_state)
                state.rmdir()
                ciphertext = next_state / destination.name / (backup["id"] + ".age")
                original_bytes = ciphertext.read_bytes()
                atomic(ciphertext, b"changed")
                with self.assertRaisesRegex(Blocked, "custody bytes changed"):
                    binding.rebind(next_root, next_state)
                atomic(ciphertext, original_bytes)
            preview = binding.rebind(next_root, next_state)
            self.assertTrue(any(worktree["needs_repair"] for worktree in preview["worktrees"]))
            choose_state = next_state if move_state else None
            if not move_state:
                def interrupt(path, data):
                    if path.name == binding.MARKER and path.parent != next_state:
                        raise OSError("interrupted reassociation after updating the state")
                    atomic(path, data)

                with patch("healdan.binding.atomic", side_effect=interrupt), self.assertRaises(OSError):
                    binding.rebind(next_root, choose_state, preview["confirmation"])
                with self.assertRaisesRegex(Blocked, "interrupted"):
                    Vault(next_root, next_state)
            binding.rebind(next_root, choose_state, preview["confirmation"])
            vault = Vault(next_root)
            self.assertEqual(vault.identity, self.vault.identity)
            self.assertEqual(Vault(link).identity, vault.identity)
            recovered_task = tasks.get_task(vault, task["id"])
            self.assertEqual(Vault(recovered_task["worktree"]).identity, vault.identity)
            self.assertTrue(Path(tasks.get_session(vault, session["operation"])["proposal"]).is_dir())
            self.assertEqual(backups.verify_backup(vault, backup["id"])["copies"][0]["root"],
                             str(next_state / destination.name))
            self.assertEqual((vault.control / material_file.name).read_bytes(), captured_material)
            self.assertEqual((vault.control / "deletions" / deletion_file.name).read_bytes(), captured_deletion)
            schedule = plistlib.loads((next_state / "launchd" / plist.name).read_bytes())
            self.assertEqual(schedule["ProgramArguments"][2:5], [str(next_root), "--state", str(next_state)])
            self.assertEqual(schedule["StandardOutPath"], str(next_state / "lint.out"))
            root, state = next_root, next_state
        restored = self.base / "restored vault"
        backups.restore(vault, backup["id"], restored)
        isolated = self.base / "restored state"
        adoption = binding.adopt(restored, isolated)
        self.assertEqual(adoption["provenance"][0]["kind"], "restored-backup")
        binding.adopt(restored, isolated, adoption["confirmation"])
        self.assertNotEqual(Vault(restored).identity, vault.identity)
