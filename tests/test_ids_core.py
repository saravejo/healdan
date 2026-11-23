import concurrent.futures
import os
from pathlib import Path
import subprocess
import sys
import unittest
from uuid import uuid4

from support import VaultTest
from healdan.core import Blocked, Vault, atomic, decode, digest, git, jsonl, read_json, safe_path, utc
from healdan.ids import TEXT, aliases, format_id, identity, inventory, reserve


class IDs(VaultTest):
    def test_ascii_full_fields_and_growth(self):
        for value in ("C-0000", "C-9999", "C-10000", "C-100000"):
            self.assertEqual(format_id(*identity(value, new=True)), value)
        for value in ("C-010000", "C-１２３４", "C-9999x", "C-123", " C-9999", "C--1234"):
            with self.subTest(value=value), self.assertRaises(Blocked):
                identity(value, new=True)
        self.assertEqual(TEXT.findall("C-10000 C-9999x café C-100000"), ["C-10000", "C-9999", "C-100000"])

    def test_legacy_collision_and_original_bytes(self):
        rows = [{"id": "C-09999"}, {"id": "C-9999"}]
        self.rows("wiki/claims.jsonl", rows)
        before = (self.root / "wiki/claims.jsonl").read_bytes()
        self.assertEqual(inventory(rows)["collisions"], [["C-09999", "C-9999"]])
        with self.assertRaises(Blocked):
            reserve(self.vault, "C", 1, str(uuid4()))
        self.assertEqual((self.root / "wiki/claims.jsonl").read_bytes(), before)
        self.assertEqual(reserve(self.vault, "S", 1, str(uuid4())), ["S-0001"])

    def test_reservation_idempotency_gaps_and_history(self):
        registry = "wiki/claims.jsonl"
        rows = [{"id": "C-9998", "statement": "First\u2028line"},
                {"id": "C-9999", "statement": "Second\u2029paragraph"}]
        for ending in (b"\n", b"\r\n"):
            atomic(self.root / registry, jsonl(rows).replace(b"\n", ending))
            self.assertEqual(self.vault.rows(registry), rows)
            git(self.root, "add", registry)
            git(self.root, "commit", "-m", "Old published identities")
        self.rows(registry, [])
        operation = str(uuid4())
        self.assertEqual(reserve(self.vault, "C", 2, operation), ["C-10000", "C-10001"])
        self.assertEqual(reserve(self.vault, "C", 2, operation), ["C-10000", "C-10001"])
        self.assertEqual(reserve(self.vault, "C", 1, str(uuid4())), ["C-10002"])
        with self.assertRaises(Blocked):
            reserve(self.vault, "C", 3, operation)

    def test_missing_historical_path_and_missing_historical_blob(self):
        registry = "wiki/claims.jsonl"
        self.rows(registry, [{"id": "C-9999"}])
        git(self.root, "commit", "-am", "Publish historical identity")
        oid = git(self.root, "rev-parse", "HEAD:" + registry)
        (self.root / registry).unlink()
        git(self.root, "commit", "-am", "Remove historical registry")
        self.rows(registry, [])
        self.assertEqual(reserve(self.vault, "C", 1, str(uuid4())), ["C-10000"])

        blob = self.vault.common / "objects" / oid[:2] / oid[2:]
        blob.chmod(0o600)
        blob.unlink()
        journal = self.vault.control / "reservations.json"
        before = journal.read_bytes()
        with self.assertRaises(Blocked) as raised:
            reserve(self.vault, "C", 1, str(uuid4()))
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(journal.read_bytes(), before)

    def assert_invalid_current_and_historical_registry(self, data, message):
        registry = "wiki/claims.jsonl"
        atomic(self.root / registry, data)
        operation = str(uuid4())
        with self.assertRaisesRegex(Blocked, message) as current:
            reserve(self.vault, "C", 1, operation)
        git(self.root, "commit", "-am", "Publish malformed registry")
        self.rows(registry, [])
        with self.assertRaisesRegex(Blocked, message) as historic:
            reserve(self.vault, "C", 1, operation)
        self.assertEqual((current.exception.code, historic.exception.code), (4, 4))
        self.assertFalse((self.vault.control / "reservations.json").exists())

    def test_blank_jsonl_row_fails_in_current_and_historical_registry(self):
        self.assert_invalid_current_and_historical_registry(
            b'{"id":"C-0001"}\n\n{"id":"C-0002"}\n', "Blank JSONL row"
        )

    def test_invalid_jsonl_row_fails_in_current_and_historical_registry(self):
        self.assert_invalid_current_and_historical_registry(
            b'{"id":"C-0001"}\r\n{\r\n', "Invalid JSON"
        )

    def test_real_processes_reserve_across_worktrees(self):
        worktree = self.base / "second worktree"
        git(self.root, "worktree", "add", "--detach", str(worktree), "HEAD")
        source = str(Path(__file__).resolve().parent.parent / "src")
        script = "import sys;sys.path.insert(0,sys.argv[1]);from healdan.core import Vault;from healdan.ids import reserve;print(reserve(Vault(sys.argv[2],sys.argv[3]),'S',1,sys.argv[4])[0])"
        procs = [subprocess.Popen([sys.executable, "-c", script, source, str(self.root if i % 2 else worktree),
                                  str(self.state), str(uuid4())], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for i in range(6)]
        completed = [(proc, *proc.communicate(timeout=60)) for proc in procs]
        results = []
        for proc, out, err in completed:
            self.assertEqual(proc.returncode, 0, err.decode())
            results.append(out.decode().strip())
        self.assertEqual(set(results), {f"S-{n:04d}" for n in range(1, 7)})

    def test_signed_alias_preserves_identity(self):
        payload = {"alias": "C-9999", "target": "C-09999", "reason": "Owner confirms same legacy identity", "decided_at": "2026-01-01T00:00:00Z"}
        self.rows("wiki/control/aliases.jsonl", [dict(payload, approval=self.signed(payload, "alias"))])
        self.assertEqual(aliases(self.vault), {"C-9999": "C-09999"})
        payload["target"] = "C-9998"
        self.rows("wiki/control/aliases.jsonl", [dict(payload, approval=self.signed(payload, "alias"))])
        with self.assertRaises(Blocked):
            aliases(self.vault)

    def test_strict_json_and_safe_paths(self):
        for value in ('{"a":1,"a":2}', '{"a":NaN}'):
            with self.assertRaises(Blocked):
                decode(value)
        for path in ("../escape", "/escape", "C:/escape"):
            with self.assertRaises(Blocked):
                safe_path(self.root, path)
        with self.assertRaises(Blocked):
            utc("2026-01-01T00:00:00")


if __name__ == "__main__":
    unittest.main()
