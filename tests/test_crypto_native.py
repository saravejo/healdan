import copy
import os
from pathlib import Path
import platform
import unittest

from support import VaultTest
from healdan import backups, custody, incidents, launcher, tasks
from healdan.core import Blocked, atomic, decode, digest, read_json, stamp, utc
from datetime import timedelta


class RealAge(VaultTest):
    def test_real_age_capture_offline_decrypt_and_restore(self):
        identities = self.age()
        origin = self.state / "tasks" / "fixture" / "native"
        atomic(origin / "session.jsonl", b'{"synthetic":"native-format fixture, not a resume proof"}\n')
        identifier = custody.capture_tree(self.vault, origin, task="fixture", classification="common")
        record = custody.materials(self.vault)[identifier]
        copy = record["copies"][0]
        cipher = (Path(copy["root"]) / copy["path"]).read_bytes()
        self.assertNotIn(b"synthetic", cipher)
        self.assertEqual(digest(custody.decrypt(self.vault, cipher, identities[1])), record["plain_sha256"])
        restored = self.state / "reconstructed"
        (self.root / "wiki/claims.jsonl").unlink()
        code, result = self.cli("session", "restore", identifier, restored)
        self.assertEqual(code, 0, result)
        self.assertEqual((restored / "session.jsonl").read_bytes(), (origin / "session.jsonl").read_bytes())
        self.assertTrue(any(c["root"] == str(restored.resolve()) for c in custody.materials(self.vault)[identifier]["copies"]))
        proof = self.state / "incomplete-recovery.json"
        atomic(proof, {})
        code, result = self.cli("session", "approve-recovery", identifier, proof)
        self.assertEqual(code, 5)
        self.assertIn("Recovery proof does not match the captured archive", result["error"])
        self.assertNotIn("native_recovery", custody.materials(self.vault)[identifier])

    def test_real_backup_roundtrip_and_manifest_only_long_generation(self):
        self.age()
        destination = self.base / "backup destination"
        destination.mkdir()
        self.vault.config["backup_destinations"] = [str(destination)]
        record = backups.create(self.vault, "long", utc() + timedelta(days=2))
        self.assertEqual(record["status"], "complete")
        self.assertEqual(len(backups.verify_backup(self.vault, record["id"])["copies"]), 1)
        restored = self.base / "restored vault"
        (self.root / "wiki/claims.jsonl").unlink()
        code, result = self.cli("backup", "verify", record["id"])
        self.assertEqual(code, 0, result)
        self.assertEqual([copy["verified"] for copy in result["copies"]], [True])
        code, result = self.cli("restore", record["id"], restored)
        self.assertEqual(code, 0, result)
        self.assertEqual((restored / "wiki/claims.jsonl").read_bytes(), b"")
        cipher = (destination / record["copies"][0]["path"]).read_bytes()
        data = decode(custody.decrypt(self.vault, cipher))
        self.assertFalse(any(name.startswith("custody/") for name in data["files"]))

    def test_quarantine_rotation_and_deletion_have_separate_receipts(self):
        self.age()
        atomic(self.root / "inbox/synthetic-secret.txt", b"FAKE test value with no authentication capability")
        result = incidents.quarantine(self.vault, "inbox/synthetic-secret.txt", "human")
        self.assertFalse((self.root / "inbox/synthetic-secret.txt").exists())
        with self.assertRaises(Blocked):
            incidents.incident_decision(self.vault, result["material"], "deletion",
                                       {"owner": "human", "reason": "fixture", "reference": "ticket"})
        rotation = incidents.incident_decision(self.vault, result["material"], "rotation",
                                              {"owner": "human", "reason": "Fixture revocation confirmed", "reference": "ticket"})
        deletion = incidents.incident_decision(self.vault, result["material"], "deletion",
                                              {"owner": "human", "reason": "Preservation reviewed", "reference": "ticket"})
        self.assertNotEqual(rotation["digest"], deletion["digest"])
        self.assertNotEqual(result["quarantine_receipt"], rotation["digest"])

    def test_task_close_requires_real_verified_preservation(self):
        self.age()
        task = tasks.create(self.vault, "Disposable task")
        atomic(self.state / "tasks" / task["id"] / "proposals/editor/draft.txt", b"checkpoint")
        closed = tasks.preserve_and_close(self.vault, task["id"])
        self.assertFalse(closed["capacity_held"])
        self.assertFalse(Path(task["worktree"]).exists())
        self.assertTrue(custody.materials(self.vault)[closed["preservation"]]["decryption_verified"])


class ArchiveSafety(VaultTest):
    def test_traversal_and_changed_member_rejected_before_write(self):
        import base64
        data = b"fixture"
        archive = {"format": "healdan-tree-v1", "files": {"../escape": {
            "sha256": digest(data), "size": len(data), "body": base64.b64encode(data).decode()}}}
        with self.assertRaises(Blocked):
            custody.restore_tree(archive, self.base / "restored")
        self.assertFalse((self.base / "escape").exists())
        archive["files"] = {"safe": {"sha256": "0" * 64, "size": len(data), "body": base64.b64encode(data).decode()}}
        with self.assertRaises(Blocked):
            custody.restore_tree(archive, self.base / "restored")
        self.assertFalse((self.base / "restored").exists())

    def test_signing_socket_removed_from_child_environment(self):
        os.environ["SSH_AUTH_SOCK"] = "test socket"
        os.environ["AGE_SECRET_KEY"] = "fake test key"
        env = launcher.clean_env(self.state)
        self.assertNotIn("SSH_AUTH_SOCK", env)
        self.assertNotIn("AGE_SECRET_KEY", env)


@unittest.skipUnless(platform.system() == "Darwin", "Real macOS sandbox trial is required")
class MacSandbox(VaultTest):
    def test_real_srt_denies_files_children_secret_reads_and_socket(self):
        result = launcher.probe(self.vault)
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(result["srt_version"], "0.0.83")


if __name__ == "__main__":
    unittest.main()
