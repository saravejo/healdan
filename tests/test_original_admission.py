from datetime import timedelta
from pathlib import Path
import shlex
import sys
from unittest.mock import patch
from uuid import uuid4

from support import VaultTest
from healdan import backups, inbox, originals, setup, tasks, transactions
from healdan.core import Blocked, atomic, digest, git, git_bytes, jsonl, read_json, stamp, utc
from healdan.ids import reserve
from healdan.knowledge import query


class OriginalAdmission(VaultTest):
    def ingest(self, path):
        return self.cli("inbox", "ingest", path, "--classification", "common",
                        "--provenance", "Disposable capture", "--captured-at", "2026-04-01T10:00:00Z")

    def triage_empty(self, path):
        atomic(self.root / path, b"")
        inbox.inventory(self.vault)
        key = digest(b"")
        inbox.decide(self.vault, key, "archive", owner="human", classification="common", destination="archive")
        return key

    def archive_receipts(self):
        return [row["payload"] for path in (self.vault.control / "receipts").glob("*.json")
                if (row := read_json(path))["kind"] == "zero-byte-archive"]

    def source_proposal(self, body):
        identifier, = reserve(self.vault, "F", 1, str(uuid4()))
        task = tasks.create(self.vault, "Preserve a source without promoting claims")
        path = f"resources/sources/{identifier}/original.jsonl"
        record = {"id": identifier, "path": path, "sha256": digest(body), "size": len(body),
                  "captured_at": stamp(), "provenance": "Disposable source proposal", "classification": "common"}
        editor = self.state / "tasks" / task["id"] / "proposals/editor"
        atomic(editor / path, body)
        atomic(editor / originals.REGISTRY, jsonl(self.vault.rows(originals.REGISTRY) + [record]))
        package = transactions.prepare(self.vault, task["id"])
        transactions.approve(self.vault, package["id"])
        return record, package

    def test_distinct_zero_byte_and_space_originals(self):
        paths = {"inbox/a/nota.txt": b"", "inbox/b/nota.txt": b" \n"}
        records = []
        for relative, body in paths.items():
            atomic(self.root / relative, body)
            code, row = self.ingest(relative)
            self.assertEqual(code, 0, row)
            self.assertEqual((row["size"], row["sha256"]), (len(body), digest(body)))
            self.assertEqual((self.root / row["path"]).read_bytes(), body)
            records.append(row)
        self.assertNotEqual(records[0]["id"], records[1]["id"])
        inbox.inventory(self.vault)
        inbox.decide(self.vault, records[1]["sha256"], "archive", owner="human", classification="common", destination="archive")
        with self.assertRaisesRegex(Blocked, "Only zero-byte"):
            inbox.archive_empty(self.vault, records[1]["sha256"])
        claim = self.claim(state="hypothesis", sources=[{"id": records[0]["id"], "start": 0, "end": 0,
                                                          "sha256": digest(b"")}])
        atomic(self.root / records[0]["path"], b"")
        self.rows(originals.REGISTRY, records)
        self.rows("wiki/claims.jsonl", [claim])
        self.assertIn("Invalid byte locator", query(self.vault, {})["diagnostics"])

    def test_archive_reuses_identical_destination_and_records_each_move(self):
        a, b = "inbox/a/nota.txt", "inbox/b/nota.txt"
        key = self.triage_empty(a)
        inbox.archive_empty(self.vault, key)
        atomic(self.root / b, b"")
        inbox.inventory(self.vault)
        second = inbox.archive_empty(self.vault, key)
        self.assertEqual(inbox.archive_empty(self.vault, key), second)
        self.assertEqual((self.root / f"archive/{key}/nota.txt").read_bytes(), b"")
        self.assertCountEqual([row["source"] for row in self.archive_receipts()], [a, b])

    def test_archive_preserves_edited_destination_and_prior_receipts(self):
        name = "inbox/nota.txt"
        key = self.triage_empty(name)
        inbox.archive_empty(self.vault, key)
        destination = f"archive/{key}/nota.txt"
        atomic(self.root / destination, b"Keep this annotation")
        atomic(self.root / name, b"")
        before = (self.vault.control / "inbox.json").read_bytes()
        with self.assertRaisesRegex(Blocked, f"{name}.*{destination}"):
            inbox.archive_empty(self.vault, key)
        self.assertEqual((self.root / name).read_bytes(), b"")
        self.assertEqual((self.root / destination).read_bytes(), b"Keep this annotation")
        self.assertEqual((self.vault.control / "inbox.json").read_bytes(), before)
        self.assertEqual(len(self.archive_receipts()), 1)

    def test_archive_competing_creation_and_resume_after_destination(self):
        name = "inbox/nota.txt"
        key = self.triage_empty(name)
        destination = self.root / f"archive/{key}/nota.txt"
        original_open = Path.open

        def compete(path, mode="r", *args, **kwargs):
            if path == destination and mode == "xb":
                with original_open(path, "wb") as run:
                    run.write(b"Concurrent annotation")
            return original_open(path, mode, *args, **kwargs)

        with patch.object(Path, "open", compete), self.assertRaisesRegex(Blocked, "inbox/nota.txt.*archive/"):
            inbox.archive_empty(self.vault, key)
        self.assertEqual(destination.read_bytes(), b"Concurrent annotation")
        self.assertEqual((self.root / name).read_bytes(), b"")
        self.assertEqual(self.archive_receipts(), [])
        destination.unlink()
        original_unlink = Path.unlink

        def interrupt(path, *args, **kwargs):
            if path == self.root / name:
                raise OSError("interrupted before removing the origin")
            return original_unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", interrupt), self.assertRaisesRegex(OSError, "interrupted"):
            inbox.archive_empty(self.vault, key)
        self.assertEqual(destination.read_bytes(), b"")
        self.assertTrue((self.root / name).exists())
        inbox.archive_empty(self.vault, key)
        self.assertFalse((self.root / name).exists())
        self.assertEqual(len(self.archive_receipts()), 1)

    def test_original_bytes_survive_stage_commit_checkout_and_locators(self):
        git(self.root, "config", "core.autocrlf", "true")
        bodies = {"mixed.txt": b"\xef\xbb\xbffirst\r\nsecond\n", "mixed.jsonl": b"\xef\xbb\xbf{}\r\n{}\n",
                  "binary.dat": b"\x00\xff\r\n", "empty.txt": b""}
        records = []
        for filename, body in bodies.items():
            atomic(self.root / "inbox" / filename, body)
            code, row = self.ingest("inbox/" + filename)
            self.assertEqual(code, 0, row)
            originals.verify_body(row, body)
            records.append((row, body))
        git(self.root, "add", "--", "resources/sources")
        for row, body in records:
            self.assertEqual(originals.git_blob(self.root, "", row["path"]), body)
        git(self.root, "commit", "-m", "Preserve captured originals")
        proposed_body = b"\xef\xbb\xbf{\"other\": 1}\r\n{}\n"
        row, package = self.source_proposal(proposed_body)
        result = transactions.apply(self.vault, package["id"])
        records.append((row, proposed_body))
        checkout = self.base / "checkout originals"
        git(self.root, "worktree", "add", "--detach", str(checkout), result["commit"])
        for row, body in records:
            self.assertEqual(originals.git_blob(self.root, result["commit"], row["path"]), body)
            self.assertEqual((checkout / row["path"]).read_bytes(), body)
        first, body = records[0]
        locator = {"id": first["id"], "start": 4, "end": 12, "sha256": digest(body[4:12])}
        claim = self.claim(sources=[locator])
        atomic(self.root / first["path"], body)
        self.rows(originals.REGISTRY, [row for row, _ in records])
        self.knowledge([claim])
        self.assertEqual(query(self.vault, {})["code"], 0)

    def test_original_snapshot_and_real_backup_restore(self):
        self.age()
        self.vault.config["backup_destinations"] = [str(self.base)]
        atomic(self.vault.config_path, self.vault.config)
        body = b"\xef\xbb\xbftext\r\nother\n"
        atomic(self.root / "inbox/evidence.txt", body)
        code, row = self.ingest("inbox/evidence.txt")
        self.assertEqual(code, 0, row)
        claim = self.claim(sources=[{"id": row["id"], "start": 5, "end": 11, "sha256": digest(body[5:11])}])
        atomic(self.root / row["path"], body)
        self.rows(originals.REGISTRY, [row])
        self.knowledge([claim])
        git(self.root, "add", "--", "resources/sources", "wiki", "control/approvals")
        git(self.root, "commit", "-m", "Preserve source and locator")
        task = tasks.create(self.vault, "Freeze original evidence bytes")
        tasks.validate_evidence(self.vault, task)
        self.assertEqual((self.state / "tasks" / task["id"] / "evidence" / row["path"]).read_bytes(), body)
        generation = backups.create(self.vault, "long", utc() + timedelta(days=2))
        restored = self.base / "restored original"
        recovery = backups.restore(self.vault, generation["id"], restored)
        self.assertEqual((restored / row["path"]).read_bytes(), body)
        self.assertEqual(originals.git_blob(restored, recovery["commit"], row["path"]), body)
        start, end = (claim["sources"][0][field] for field in ("start", "end"))
        self.assertEqual(digest((restored / row["path"]).read_bytes()[start:end]), claim["sources"][0]["sha256"])

    def test_effective_git_attributes_block_ingest_and_approved_proposal(self):
        path = "inbox/converted.txt"
        body = b"wrapper\r\n"
        atomic(self.root / path, body)
        row, package = self.source_proposal(body)
        info = Path(git(self.root, "rev-parse", "--path-format=absolute", "--git-path", "info/attributes"))
        converter = self.base / "mutate one byte.py"
        invoked = self.base / "converter invoked"
        atomic(converter, b"import pathlib, sys\n"
                          b"pathlib.Path(sys.argv[1]).touch()\n"
                          b"data = sys.stdin.buffer.read()\n"
                          b"sys.stdout.buffer.write(bytes([data[0] ^ 1]) + data[1:] if data else data)\n")
        command = shlex.join([Path(sys.executable).as_posix(), converter.as_posix(), invoked.as_posix()])
        git(self.root, "config", "filter.mutate.clean", command)
        git(self.root, "config", "filter.mutate.required", "true")
        for rule, attribute in (("text eol=lf", "text"), ("-text filter=mutate", "filter"),
                                ("-text working-tree-encoding=UTF-16LE", "working-tree-encoding")):
            with self.subTest(rule=rule):
                atomic(info, f"resources/sources/** {rule}\nresources/sources/F-9191/** -text !eol !filter !working-tree-encoding\n".encode())
                if attribute == "filter":
                    raw = git_bytes(self.root, "hash-object", "--stdin", "--no-filters", data=body)
                    self.assertNotEqual(git_bytes(self.root, "hash-object", "--stdin", "--path=" + row["path"], data=body), raw)
                    self.assertTrue(invoked.is_file())
                    invoked.unlink()
                checks = setup.doctor(self.vault)["checks"]
                self.assertTrue(any(c["name"] == "source_attributes" and not c["passed"] and
                                    attribute + "=" in c["detail"] for c in checks), checks)
                originals.verify_storage(self.root, "resources/sources/F-9191/original.txt", body)
                code, failure = self.ingest(path)
                self.assertEqual(code, 5, failure)
                with self.assertRaisesRegex(Blocked, "effective Git " + attribute):
                    transactions.apply(self.vault, package["id"])
                self.assertFalse((self.root / row["path"]).exists())
                self.assertEqual(self.vault.rows(originals.REGISTRY), [])
                self.assertFalse(invoked.exists())
        info.unlink()
        self.assertEqual(transactions.apply(self.vault, package["id"])["status"], "complete")

    def test_legacy_attributes_and_blob_require_verified_raw_reconciliation(self):
        path = "resources/sources/F-0001/original.txt"
        attributes = self.root / ".gitattributes"
        custom = b"* text=auto eol=lf\r\n*.jsonl -merge\r\nwiki/** diff=custom\r\n"
        atomic(attributes, custom)
        body = b"legacy\r\n"
        row = {"id": "F-0001", "path": path, "sha256": digest(body), "size": len(body),
               "captured_at": stamp(), "provenance": "Legacy capture", "classification": "common"}
        claim = self.claim(sources=[{"id": row["id"], "start": 0, "end": len(body), "sha256": digest(body)}])
        self.rows(originals.REGISTRY, [row])
        self.knowledge([claim])
        atomic(self.root / path, body)
        git(self.root, "add", "--", ".gitattributes", "resources/sources", "wiki", "control/approvals")
        git(self.root, "commit", "-m", "Historic loss of CRLF")
        bad_head = self.vault.head()
        approval = originals.git_blob(self.root, bad_head, "control/approvals/packages.jsonl")
        setup.initialize(self.root, self.state)
        updated = attributes.read_bytes()
        self.assertTrue(updated.startswith(custom))
        setup.initialize(self.root, self.state)
        self.assertEqual(attributes.read_bytes(), updated)
        self.assertEqual(git(self.root, "check-attr", "diff", "--", "wiki/index.md"), "wiki/index.md: diff: custom")
        failures = [c["detail"] for c in setup.doctor(self.vault)["checks"] if not c["passed"]]
        self.assertTrue(any(all(field in detail for field in (row["id"], bad_head, path)) for detail in failures))
        self.assertEqual(query(self.vault, {})["code"], 4)
        self.assertEqual(self.vault.head(), bad_head)
        self.assertEqual(originals.git_blob(self.root, bad_head, path), b"legacy\n")
        raw = self.base / "verified raw.txt"
        atomic(raw, b"legacy\n")
        with self.assertRaisesRegex(Blocked, "Source hash/size mismatch"):
            originals.reconcile(self.vault, row["id"], raw)
        atomic(raw, body)
        originals.reconcile(self.vault, row["id"], raw)
        git(self.root, "add", "--", ".gitattributes", path)
        git(self.root, "commit", "-m", "Reconcile original from verified evidence")
        self.assertEqual(query(self.vault, {})["code"], 0)
        self.assertEqual(originals.git_blob(self.root, bad_head, path), b"legacy\n")
        self.assertEqual(originals.git_blob(self.root, self.vault.head(), "control/approvals/packages.jsonl"), approval)
