import copy
from datetime import timedelta
import os
from pathlib import Path
import subprocess
import sys
import unittest
from uuid import uuid4

from support import VaultTest
from healdan.core import Blocked, Vault, atomic, digest, git, read_json, stamp, utc
from healdan import backups, custody, ids, inbox, pages, tasks


class Boundaries(VaultTest):
    def test_collision_in_another_published_registry_and_no_id_reuse_after_crash(self):
        operation = str(uuid4())
        first = ids.reserve(self.vault, "M", 1, operation)
        reopened = Vault(self.root, self.state)
        self.assertEqual(ids.reserve(reopened, "M", 1, operation), first)
        self.assertEqual(ids.reserve(reopened, "M", 1, str(uuid4())), ["M-0002"])
        self.rows("wiki/claims.jsonl", [{"id": "C-09999"}, {"id": "C-9999"}])
        with self.assertRaises(Blocked):
            ids.reserve(reopened, "C", 1, str(uuid4()))

    def test_symlink_and_hardlink_paths_rejected(self):
        from healdan.core import safe_path
        target = self.base / "outside"
        target.write_text("protected")
        try:
            os.link(target, self.root / "linked")
        except OSError:
            self.skipTest("Filesystem does not support hard links")
        with self.assertRaises(Blocked):
            safe_path(self.root, "linked", exists=True)

    def test_preview_invalidated_by_concurrent_inputs(self):
        self.knowledge([self.claim()])
        original = self.vault.fingerprint
        calls = 0
        def changing():
            nonlocal calls
            calls += 1
            return original() if calls == 1 else "concurrent change"
        self.vault.fingerprint = changing
        with self.assertRaises(Blocked):
            pages.preview(self.vault)

    def test_sensitive_inbox_capture_drives_retention_and_purpose_required(self):
        atomic(self.root / "inbox/export.json", b'{"synthetic":"personal"}')
        item = inbox.inventory(self.vault)[0]
        with self.assertRaises(Blocked):
            inbox.decide(self.vault, item["sha256"], "archive", owner="human", classification="sensitive", destination="restricted")
        entered = utc() - timedelta(days=8)
        inbox.decide(self.vault, item["sha256"], "defer", owner="human", classification="sensitive",
                     entered_at=stamp(entered), entry_origin="Recorded export capture",
                     defer_until=stamp(utc() + timedelta(days=2)), purpose={"purpose": "Evaluate export", "necessity": "Required for task",
                     "owner": "human", "link": "task-fixture"})
        record = custody.materials(self.vault)["inbox-" + item["sha256"]]
        self.assertEqual(custody.retention_deadline(record), entered + timedelta(days=7))

    def test_empty_cli_exit_codes_and_structured_output(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent / "src"))
        result = subprocess.run([sys.executable, "-m", "healdan", "--vault", str(self.root), "--state", str(self.state), "query"],
                                capture_output=True, env=env)
        self.assertEqual(result.returncode, 20)
        self.assertIn(b'"research":"complete"', result.stdout)
        result = subprocess.run([sys.executable, "-m", "healdan", "--vault", str(self.root), "--state", str(self.state), "doctor"],
                                capture_output=True, env=env)
        self.assertEqual(result.returncode, 5)
        self.assertIn(b'"ready":false', result.stdout)

    def test_configurable_context_is_independent_of_page_caps(self):
        self.vault.config["context_bytes"] = {"reader": 100, "editor": 100, "reviewer": 200, "extractor": 200}
        atomic(self.vault.config_path, self.vault.config)
        vault = Vault(self.root, self.state)
        task = tasks.create(vault, "Context limit fixture")
        tasks.new_session(vault, task["id"], "read", "reader", "x" * 100)
        with self.assertRaises(Blocked):
            tasks.new_session(vault, task["id"], "read", "reader", "x" * 101)
        self.assertEqual(pages.CAPS, (6000, 12000, 20000))

    def test_expired_worktree_preservation_does_not_cancel_human_wait(self):
        self.age()
        task = tasks.create(self.vault, "Expired fixture")
        task["created_at"] = stamp(utc() - timedelta(hours=24))
        task["state"] = "waiting"
        task["presented_at"] = stamp(utc() - timedelta(hours=1))
        atomic(tasks.task_path(self.vault, task["id"]), task)
        result = tasks.reconcile_expired(self.vault, task["id"])
        self.assertTrue(result["worktree_removed"])
        self.assertEqual(result["state"], "waiting")
        self.assertTrue(result["capacity_held"])
        self.assertNotIn("closed_at", result)
        self.assertEqual(result["presented_at"], task["presented_at"])

    def test_backup_refuses_historical_native_conversation_and_generation_hold(self):
        atomic(self.root / "old/S-0001.jsonl", b'{"sessionId":"fixture","type":"assistant"}\n')
        git(self.root, "add", ".")
        git(self.root, "commit", "-m", "Disposable forbidden historical conversation")
        with self.assertRaises(Blocked):
            backups.history_bundle(self.vault)
        generation = {"id": "generation", "kind": "backup", "expires_at": stamp(utc() + timedelta(days=1)), "holds": []}
        custody.save_material(self.vault, generation)
        with self.assertRaises(Blocked):
            custody.hold(self.vault, "generation", "Preserve", "human")


if __name__ == "__main__":
    unittest.main()
