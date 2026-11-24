from contextlib import contextmanager
from datetime import timedelta
import os
from pathlib import Path
import shlex
import stat
import sys
from unittest.mock import patch
from uuid import uuid4

from support import VaultTest
from healdan import admission, backups, custody, inbox, linting, originals, pages, retention, setup, tasks, transactions
from healdan.core import Blocked, Vault, atomic, digest, git, git_bytes, jsonl, read_json, run, stamp, utc
from healdan.ids import reserve
from healdan.knowledge import Knowledge, query


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

    def expiring_export(self, identifier, *copies):
        record = {"id": identifier, "kind": "export", "classification": "common",
                  "captured_at": "2026-04-01T00:00:00Z", "holds": [], "dependencies": [],
                  "copies": [{"root": str(root), "path": relative, "kind": kind, "status": "present",
                              "sha256": digest((root / relative).read_bytes())} for root, relative, kind in copies]}
        custody.save_material(self.vault, record)
        return record

    def track_empty_copy(self, material_id, relative):
        self.assertEqual((self.root / relative).read_bytes(), b"")
        record = custody.materials(self.vault)[material_id]
        record["copies"].append({"root": str(self.root / "inbox"), "path": relative.removeprefix("inbox/"),
                                 "kind": "export", "status": "present", "sha256": digest(b"")})
        custody.save_material(self.vault, record)

    def defer_empty(self, path):
        atomic(self.root / path, b"")
        inbox.inventory(self.vault)
        return inbox.decide(self.vault, digest(b""), "defer", owner="human", classification="common",
                            entered_at="2026-04-01T00:00:00Z", entry_origin="Original fixture evidence",
                            defer_until=utc() + timedelta(hours=1))

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

    def test_archive_skips_confirmed_reuse_and_moves_independent_empty_file(self):
        retired, fresh = "inbox/retired.txt", "inbox/independent.txt"
        sha = self.defer_empty(retired)["sha256"]
        old = inbox.archive_empty(self.vault, sha)["archive_moves"][0]
        old_receipt = self.vault.control / "receipts" / (old["receipt"] + ".json")
        old_bytes = old_receipt.read_bytes()
        atomic(self.root / fresh, b"")
        inbox.inventory(self.vault)
        incoming = b"A different capture using the previous relative path"
        atomic(self.root / retired, incoming)
        code, result = self.cli("inbox", "archive-empty", sha)
        self.assertEqual(code, 5, result)
        self.assertIn("Inbox item changed: " + retired, result["error"])
        self.assertEqual((self.root / fresh).read_bytes(), b"")
        inbox.inventory(self.vault)
        replacement = inbox.decide(self.vault, digest(incoming), "resource", owner="human", classification="common",
                                   destination="fixture")

        code, item = self.cli("inbox", "archive-empty", sha)
        self.assertEqual(code, 0, item)
        self.assertEqual([move["payload"]["source"] for move in item["archive_moves"]], [retired, fresh])
        self.assertEqual((self.root / retired).read_bytes(), incoming)
        self.assertFalse((self.root / fresh).exists())
        for name in (retired, fresh):
            self.assertEqual((self.root / "archive" / sha / Path(name).name).read_bytes(), b"")
        self.assertEqual(old_receipt.read_bytes(), old_bytes)
        self.assertEqual(read_json(self.vault.control / "inbox.json")[digest(incoming)], replacement)
        self.assertTrue(inbox.archive_complete(self.vault, item))

    def test_archive_rejects_confirmed_reuse_of_an_active_move_origin(self):
        interrupted, fresh = "inbox/interrupted.txt", "inbox/independent.txt"
        sha = self.triage_empty(interrupted)
        unlink = Path.unlink

        def stop_before_unlink(path, *args, **kwargs):
            if path == self.root / interrupted:
                raise OSError("Interrupted with a reserved origin")
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", stop_before_unlink), self.assertRaisesRegex(OSError, "Interrupted"):
            inbox.archive_empty(self.vault, sha)
        journal = self.vault.control / inbox.ARCHIVE_JOURNAL
        pending = journal.read_bytes()
        atomic(self.root / fresh, b"")
        incoming = b"A different capture at an active origin"
        atomic(self.root / interrupted, incoming)
        inbox.inventory(self.vault)
        inbox.decide(self.vault, digest(incoming), "resource", owner="human", classification="common", destination="fixture")

        code, result = self.cli("inbox", "archive-empty", sha)
        self.assertEqual(code, 5, result)
        self.assertIn("Inbox item changed: " + interrupted, result["error"])
        self.assertEqual(journal.read_bytes(), pending)
        self.assertEqual((self.root / interrupted).read_bytes(), incoming)
        self.assertEqual((self.root / fresh).read_bytes(), b"")
        self.assertFalse((self.root / "archive" / sha / Path(fresh).name).exists())

        atomic(self.root / interrupted, b"")
        resumed = inbox.archive_empty(self.vault, sha)
        self.assertEqual(len(resumed["archive_moves"]), 2)
        self.assertEqual(read_json(journal), {})

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
        journal_path = self.vault.control / inbox.ARCHIVE_JOURNAL
        pending = read_json(journal_path)
        legacy = pending[name]
        del legacy["payload"]["worktree"]
        del legacy["payload"]["move_id"]
        atomic(journal_path, pending)
        inbox.archive_empty(self.vault, key)
        self.assertFalse((self.root / name).exists())
        self.assertEqual(self.archive_receipts(), [legacy["payload"]])
        legacy_receipt = digest({"kind": "zero-byte-archive", "at": legacy["at"], "payload": legacy["payload"]})
        self.assertTrue((self.vault.control / "receipts" / (legacy_receipt + ".json")).is_file())

    def test_reclassified_empty_copies_keep_signed_decision_and_custody_on_resume(self):
        first, second = "inbox/a/nota.txt", "inbox/b/nota.txt"
        sha = digest(b"")
        material_id = "inbox-" + sha
        atomic(self.root / first, b"")
        inbox.inventory(self.vault)
        decided = inbox.decide(self.vault, sha, "resource", owner="human", classification="sensitive",
            entered_at="2026-04-01T00:00:00Z", entry_origin="Fixture receipt", destination="Fixture custody",
            purpose={"purpose": "Review capture", "necessity": "Verify empty bytes", "owner": "human", "link": material_id})
        hold = custody.hold(self.vault, material_id, "Keep the capture", "human")
        original = custody.materials(self.vault)[material_id]
        now = "2026-04-15T00:00:00Z"
        original_plan = retention.plan(self.vault, now)
        self.vault.config["source_classification_authorities"] = ["human"]
        atomic(self.vault.config_path, self.vault.config)
        signed = admission.sign_reclassification(self.vault, sha,
            {"classification": "common", "reason": "Verified empty synthetic capture"})
        event = admission.reclassify(self.vault, signed)
        decision_path = self.vault.control / admission.DECISIONS
        decisions = decision_path.read_bytes()
        receipt_folder = self.vault.control / "receipts"
        existing_receipts = {path: path.read_bytes() for path in receipt_folder.glob("*.json")}

        code, result = self.cli("inbox", "archive-empty", sha)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["decided_at"], decided["decided_at"])
        self.assertEqual(result["decision"], "resource")
        atomic(self.root / second, b"")
        self.track_empty_copy(material_id, second)
        inbox.inventory(self.vault)
        save = custody.save_material

        def interrupt(vault, record):
            save(vault, record)
            raise OSError("interrupted after custody recorded the move")

        with patch("healdan.custody.save_material", side_effect=interrupt), self.assertRaisesRegex(OSError, "interrupted"):
            inbox.archive_empty(self.vault, sha)
        self.assertFalse((self.root / second).exists())
        completed = inbox.archive_empty(self.vault, sha)
        self.assertEqual(self.cli("inbox", "archive-empty", sha), (0, completed))
        decision_fields = ("classification", "decided_at", "decision", "decision_receipt")
        self.assertEqual({k: completed[k] for k in decision_fields}, {k: decided[k] for k in decision_fields})
        self.assertEqual(admission.Classification(self.vault, {}).current(sha), ("common", event["receipt"]))
        self.assertEqual(decision_path.read_bytes(), decisions)
        self.assertEqual({path: path.read_bytes() for path in existing_receipts}, existing_receipts)
        self.assertCountEqual([motion["payload"]["source"] for motion in completed["archive_moves"]], [first, second])
        self.assertCountEqual([receipt["source"] for receipt in self.archive_receipts()], [first, second])

        recorded = custody.materials(self.vault)[material_id]
        self.assertEqual(recorded["holds"], [hold])
        self.assertEqual(recorded["purpose"], original["purpose"])
        self.assertEqual(custody.retention_deadline(recorded), custody.retention_deadline(original))
        self.assertCountEqual([(copy["path"], copy["status"]) for copy in recorded["copies"]],
                              [("a/nota.txt", "moved"), ("b/nota.txt", "moved"), (f"{sha}/nota.txt", "present")])
        original_plan_path = self.root / first
        atomic(original_plan_path, b"A separate new arrival")
        result = retention.execute(self.vault, original_plan["id"], now)
        self.assertEqual(result["entries"][0]["status"], "moved")
        self.assertEqual(original_plan_path.read_bytes(), b"A separate new arrival")
        archive = self.root / f"archive/{sha}/nota.txt"
        plan = retention.plan(self.vault, now)
        self.assertEqual([entry["copy"]["kind"] for entry in plan["entries"]], ["archive"])
        result = retention.execute(self.vault, plan["id"], now)
        self.assertIn("Active hold", result["entries"][0]["error"])
        self.assertEqual(archive.read_bytes(), b"")

    def test_retention_preserves_paths_of_pending_archive_moves(self):
        source_path = "inbox/a/nota.txt"
        sha = self.triage_empty(source_path)
        source = self.root / source_path
        archive_path = f"{sha}/nota.txt"
        destination = self.root / "archive" / archive_path
        atomic(destination, b"")
        tracked = self.expiring_export("archive-move", (self.root / "inbox", "a/nota.txt", "export"),
                                       (self.root / "archive", archive_path, "archive"))
        other = self.state / "custody" / "independent.age"
        atomic(other, b"")
        self.expiring_export("independent", (other.parent, other.name, "ciphertext"))
        now = "2026-04-15T00:00:00Z"
        plan = retention.plan(self.vault, now)
        self.assertEqual(len(plan["entries"]), 3)
        unlink = Path.unlink

        def interrupt_before_remove(path, *args, **kwargs):
            if path == source:
                raise OSError("interrupted before removing Inbox copy")
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", interrupt_before_remove), self.assertRaisesRegex(OSError, "interrupted"):
            inbox.archive_empty(self.vault, sha)
        fresh = retention.plan(self.vault, now)
        self.assertEqual([entry["material"] for entry in fresh["entries"]], ["independent"])
        results = retention.execute(self.vault, plan["id"], now)["entries"]
        self.assertEqual([entry["status"] for entry in results], ["pending", "pending", "deleted"])
        self.assertTrue(all("Inbox archive move is pending" in entry["error"] for entry in results[:2]))
        self.assertEqual(source.read_bytes(), b"")
        self.assertEqual(destination.read_bytes(), b"")
        self.assertFalse(other.exists())

        linked = self.expiring_export("shared-export", (self.root / "inbox", "a/nota.txt", "export"))
        hold = custody.hold(self.vault, linked["id"], "Preserve shared copy", "human")
        save = custody.save_material

        def interrupt_after_first_custody(vault, material):
            save(vault, material)
            if material["id"] == tracked["id"]:
                raise OSError("interrupted before archive receipt")

        with patch("healdan.custody.save_material", side_effect=interrupt_after_first_custody), self.assertRaisesRegex(OSError, "interrupted"):
            inbox.archive_empty(self.vault, sha)
        self.assertFalse(source.exists())
        self.assertEqual(self.archive_receipts(), [])
        self.assertEqual(custody.materials(self.vault)[linked["id"]]["copies"][0]["status"], "present")
        self.assertEqual(retention.plan(self.vault, now)["entries"], [])
        results = retention.execute(self.vault, plan["id"], now)["entries"]
        self.assertEqual([entry["status"] for entry in results], ["moved", "pending", "deleted"])
        self.assertEqual(destination.read_bytes(), b"")
        inbox.archive_empty(self.vault, sha)
        self.assertEqual(len(self.archive_receipts()), 1)
        saved = custody.materials(self.vault)[tracked["id"]]
        self.assertEqual(custody.retention_deadline(saved), custody.retention_deadline(tracked))
        held_result = retention.execute(self.vault, plan["id"], now)
        self.assertIn("Active hold", held_result["entries"][1]["error"])
        self.assertEqual(destination.read_bytes(), b"")
        custody.release_hold(self.vault, linked["id"], hold["id"], [])
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        self.assertFalse(destination.exists())

    def test_retention_checks_holds_on_shared_origin_and_archive_paths(self):
        source = "inbox/nota.txt"
        sha = self.triage_empty(source)
        archived = f"{sha}/nota.txt"
        atomic(self.root / "archive" / archived, b"")
        free = self.expiring_export("free", (self.root / "inbox", "nota.txt", "export"),
                                    (self.root / "archive", archived, "archive"))
        shared = self.expiring_export("held", (self.root, source, "export"),
                                      (self.root, "archive/" + archived, "export"))
        hold = custody.hold(self.vault, shared["id"], "Preserve shared copies", "human")
        now = "2026-04-15T00:00:00Z"
        plan = retention.plan(self.vault, now)
        result = retention.execute(self.vault, plan["id"], now)
        ours = [entry for entry in result["entries"] if entry["material"] == free["id"]]
        self.assertEqual([entry["status"] for entry in ours], ["pending", "pending"])
        self.assertTrue(all("Active hold" in entry["error"] for entry in ours))
        self.assertEqual((self.root / source).read_bytes(), b"")
        self.assertEqual((self.root / "archive" / archived).read_bytes(), b"")
        self.assertEqual(custody.materials(self.vault)[shared["id"]]["holds"], [hold])

    def test_archive_custody_follows_only_exact_origin_and_recovers_shared_copy(self):
        first, other = "inbox/a/first.txt", "inbox/b/second.txt"
        sha = self.triage_empty(first)
        atomic(self.root / other, b"")
        direct = self.expiring_export("direct", (self.root / "inbox", "a/first.txt", "export"))
        shared = self.expiring_export("shared", (self.root, first, "export"))
        sibling = self.expiring_export("sibling", (self.root / "inbox", "b/second.txt", "export"))
        hold = custody.hold(self.vault, shared["id"], "Keep the shared origin", "human")
        save = custody.save_material

        def stop_after_direct(vault, record):
            save(vault, record)
            if record["id"] == direct["id"]:
                raise OSError("Interrupted before recording the held shared copy")

        with patch("healdan.custody.save_material", side_effect=stop_after_direct), self.assertRaisesRegex(OSError, "Interrupted"):
            inbox.archive_empty(self.vault, sha)
        self.assertEqual(custody.materials(self.vault)[shared["id"]]["copies"][0]["status"], "present")
        inbox.archive_empty(self.vault, sha)
        saved = custody.materials(self.vault)
        self.assertEqual(saved[sibling["id"]], sibling)
        self.assertEqual((self.root / other).read_bytes(), b"")
        for identifier in (direct["id"], shared["id"]):
            self.assertEqual([copy["status"] for copy in saved[identifier]["copies"]], ["moved", "present"])
            self.assertEqual(saved[identifier]["copies"][1]["path"], f"{sha}/first.txt")
        self.assertEqual(saved[shared["id"]]["holds"], [hold])
        self.assertEqual(custody.retention_deadline(saved[shared["id"]]), custody.retention_deadline(shared))
        with self.assertRaisesRegex(Blocked, "Active hold"):
            retention.guard(self.vault, saved[direct["id"]], saved[direct["id"]]["copies"][1], "2026-04-15T00:00:00Z")
        self.assertEqual(len(self.archive_receipts()), 1)

    def test_lint_uses_completed_archive_receipts_until_an_inbox_path_reappears(self):
        first, second = "inbox/a/first.txt", "inbox/b/second.txt"
        deferred = self.defer_empty(first)
        sha = deferred["sha256"]
        receipt = self.vault.control / "receipts" / (deferred["decision_receipt"] + ".json")
        original = receipt.read_bytes()
        now = utc() + timedelta(days=8)

        def findings():
            results, errors = linting.collect(self.vault, now)
            self.assertEqual(errors, [])
            return {item["message"] for item in results.values() if item["category"] == "inbox"}

        expected = {"original_triage_overdue", "deferral_due"}
        self.assertEqual(findings(), expected)
        inbox.archive_empty(self.vault, sha)
        self.assertEqual(findings(), set())
        atomic(self.root / second, b"")
        inbox.inventory(self.vault)
        self.assertEqual(findings(), expected)
        inbox.archive_empty(self.vault, sha)
        self.assertEqual(findings(), set())
        atomic(self.root / first, b"")
        self.assertEqual(findings(), expected)
        stored = read_json(self.vault.control / "inbox.json")[sha]
        for field in ("classification", "decision", "decision_receipt", "decided_at", "defer_until", "entered_at"):
            self.assertEqual(stored[field], deferred[field])
        self.assertEqual(receipt.read_bytes(), original)

    def test_lint_keeps_followup_open_for_pending_linked_inbox_paths(self):
        relative = "inbox/a/linked.txt"
        deferred = self.defer_empty(relative)
        sha = deferred["sha256"]
        linked = self.base / "linked vault"
        git(self.root, "worktree", "add", "--detach", linked, "HEAD")
        linked_vault = Vault(linked, self.state)
        now = utc() + timedelta(days=8)
        expected = {"original_triage_overdue", "deferral_due"}

        def lint(vault, messages, followup):
            record = linting.lint(vault, now)
            self.assertEqual(record["status"], "complete", record["errors"])
            self.assertEqual({f["message"] for f in record["findings"].values() if f["category"] == "inbox"}, messages)
            self.assertEqual(read_json(vault.control / "followups.json")["inbox"]["state"], followup)

        lint(self.vault, expected, "open")
        inbox.archive_empty(self.vault, sha)
        lint(linked_vault, set(), "resolved")
        atomic(linked / relative, b"")
        atomic(linked / "inbox/uninventoried.txt", b"New synthetic material")
        lint(self.vault, expected | {"File has no triage inventory"}, "open")
        (linked / "inbox/uninventoried.txt").unlink()
        inbox.inventory(linked_vault)
        lint(linked_vault, expected, "open")
        lint(self.vault, expected, "open")
        self.assertEqual((linked / relative).read_bytes(), b"")
        inbox.archive_empty(linked_vault, sha)
        lint(self.vault, set(), "resolved")
        self.assertEqual({row["worktree"] for row in self.archive_receipts()}, {str(self.root), str(linked)})

        target = f"archive/{sha}/linked.txt"
        (self.root / target).unlink()
        lint(linked_vault, expected, "open")
        self.assertEqual((linked / target).read_bytes(), b"")
        atomic(self.root / target, b"")
        lint(self.vault, set(), "resolved")

    def test_lint_requires_archive_bytes_or_verified_retention_deletion(self):
        relative = "inbox/first.txt"
        deferred = self.defer_empty(relative)
        sha = deferred["sha256"]
        self.expiring_export("deferred-inbox", (self.root / "inbox", "first.txt", "export"))
        now = utc() + timedelta(days=8)
        expected = {"original_triage_overdue", "deferral_due"}
        target = self.root / f"archive/{sha}/first.txt"

        def findings(messages):
            found, errors = linting.collect(self.vault, now)
            self.assertEqual(errors, [])
            self.assertEqual({row["message"] for row in found.values() if row["category"] == "inbox"}, messages)

        completed = inbox.archive_empty(self.vault, sha)
        receipt = self.vault.control / "receipts" / (completed["archive_moves"][0]["receipt"] + ".json")
        original_receipt = receipt.read_bytes()
        findings(set())
        target.unlink()
        findings(expected)
        atomic(target, b"Changed synthetic destination")
        findings(expected)
        atomic(target, b"")
        findings(set())

        plan = retention.plan(self.vault, now)
        save = retention.save_material

        def stop_before_record(vault, record):
            if not target.exists():
                raise RuntimeError("Interrupted before saving the verified deletion")
            return save(vault, record)

        with patch("healdan.retention.save_material", side_effect=stop_before_record), self.assertRaisesRegex(RuntimeError, "Interrupted"):
            retention.execute(self.vault, plan["id"], now)
        self.assertFalse(target.exists())
        findings(expected)
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        findings(set())
        self.assertEqual(receipt.read_bytes(), original_receipt)

        second = "inbox/second.txt"
        atomic(self.root / second, b"")
        inbox.inventory(self.vault)
        self.track_empty_copy("deferred-inbox", second)
        inbox.archive_empty(self.vault, sha)
        (self.root / f"archive/{sha}/second.txt").unlink()
        plan = retention.plan(self.vault, now)
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        findings(expected)

    def test_linked_inbox_lint_distinguishes_reused_path_by_content(self):
        relative = "inbox/reused.txt"
        deferred = self.defer_empty(relative)
        empty = deferred["sha256"]
        inbox.archive_empty(self.vault, empty)
        linked = self.base / "linked vault"
        git(self.root, "worktree", "add", "--detach", linked, "HEAD")
        linked_vault = Vault(linked, self.state)
        now = utc() + timedelta(days=8)

        def findings():
            run = linting.lint(self.vault, now)
            self.assertEqual(run["status"], "complete", run["errors"])
            state = read_json(self.vault.control / "followups.json")["inbox"]["state"]
            return {key: row["message"] for key, row in run["findings"].items() if row["category"] == "inbox"}, state

        changed = b"A different capture reusing the relative filename"
        atomic(linked / relative, changed)
        self.assertEqual(findings(), ({"inbox:" + relative: "File has no triage inventory"}, "open"))
        inbox.inventory(linked_vault)
        other = digest(changed)
        self.assertEqual(findings(), ({f"inbox:{other}:{message}": message for message in
                                      ("original_triage_overdue", "classification_pending")}, "open"))
        inbox.decide(linked_vault, other, "resource", owner="human", classification="common", destination="fixture")
        self.assertEqual(findings(), ({}, "resolved"))
        self.assertEqual((self.root / f"archive/{empty}/reused.txt").read_bytes(), b"")
        atomic(linked / relative, b"Another uninventoried capture")
        self.assertEqual(findings(), ({"inbox:" + relative: "File has no triage inventory"}, "open"))
        atomic(linked / relative, b"")
        self.assertEqual(findings(), ({f"inbox:{empty}:{message}": message for message in
                                      ("original_triage_overdue", "deferral_due")}, "open"))

    def test_partial_linked_inbox_read_keeps_other_findings_and_followups(self):
        relative = "inbox/old.txt"
        sha = self.defer_empty(relative)["sha256"]
        linked = self.base / "linked vault"
        git(self.root, "worktree", "add", "--detach", linked, "HEAD")
        now = utc() + timedelta(days=8)
        baseline = linting.lint(self.vault, now)
        self.assertEqual(baseline["status"], "complete")
        state = self.vault.control / "lint-state.json"
        prior_state = state.read_bytes()
        followups = self.vault.control / "followups.json"
        prior_id = read_json(followups)["inbox"]["id"]
        inbox.archive_empty(self.vault, sha)

        paths = {"inbox/blocked.txt": b"Blocked fixture", "inbox/unreadable.txt": b"Unreadable fixture",
                 "inbox/other.txt": b"Readable fixture"}
        for name, body in paths.items():
            atomic(linked / name, body)
        held = self.state / "custody" / "held.age"
        atomic(held, b"Fixture custody bytes")
        self.expiring_export("held-export", (held.parent, held.name, "ciphertext"))
        hold = custody.hold(self.vault, "held-export", "Fixture retention hold", "human")
        safe = inbox.safe_path
        read = Path.read_bytes

        def block(root, name, **kwargs):
            if root == linked and name == "inbox/blocked.txt":
                raise Blocked("Fixture path guard rejected this regular entry", 5)
            return safe(root, name, **kwargs)

        def unreadable(path):
            if path == linked / "inbox/unreadable.txt":
                raise OSError("Fixture read interrupted")
            return read(path)

        with patch("healdan.inbox.safe_path", side_effect=block), patch.object(Path, "read_bytes", unreadable):
            partial = linting.lint(self.vault, now)
        self.assertEqual(partial["status"], "partial")
        self.assertCountEqual([(entry["category"], entry["worktree"], entry["path"]) for entry in partial["errors"]],
                              [("inbox", str(linked), "inbox/blocked.txt"), ("inbox", str(linked), "inbox/unreadable.txt")])
        self.assertIn("inbox:inbox/other.txt", partial["findings"])
        self.assertIn(f"inbox:{sha}:original_triage_overdue", partial["findings"])
        self.assertIn(f"inbox:{sha}:deferral_due", partial["findings"])
        self.assertIn("holds:" + hold["id"], partial["findings"])
        self.assertIn("retention:held-export", partial["findings"])
        self.assertIn("backup", partial["categories"])
        self.assertEqual(partial["delta"]["resolved"], [])
        self.assertEqual(state.read_bytes(), prior_state)
        self.assertEqual(read_json(followups)["inbox"]["state"], "open")
        self.assertEqual(read_json(followups)["inbox"]["id"], prior_id)
        for name, body in paths.items():
            self.assertEqual((linked / name).read_bytes(), body)
            (linked / name).unlink()
        complete = linting.lint(self.vault, now)
        self.assertEqual(complete["status"], "complete")
        self.assertEqual(read_json(followups)["inbox"]["state"], "resolved")

    def test_inventory_preserves_siblings_when_listed_entries_disappear(self):
        folder = self.root / "inbox"
        (folder / ".gitkeep").unlink()
        folder.rmdir()
        self.assertEqual(inbox.inventory(self.vault), [])
        self.assertEqual(linting.lint(self.vault)["status"], "complete")

        early = folder / "first.txt"
        late = folder / "later.txt"
        vanishing = folder / "vanishing-folder"
        excluded = folder / "tasks"
        kept = folder / "welcome" / "sibling.txt"
        for path in (early, late, kept, excluded / "task.txt"):
            atomic(path, b"Inventory fixture")
        vanishing.mkdir()
        lstat, read, scandir = Path.lstat, Path.read_bytes, os.scandir
        removed = set()
        scans = []

        def disappear_at_lstat(path, *args, **kwargs):
            if path == early and path not in removed:
                removed.add(path)
                path.unlink()
            return lstat(path, *args, **kwargs)

        def disappear_at_read(path):
            if path == late and path not in removed:
                removed.add(path)
                path.unlink()
            return read(path)

        def disappear_at_scan(path):
            path = Path(path)
            scans.append(path)
            if path == vanishing and path not in removed:
                removed.add(path)
                path.rmdir()
            return scandir(path)

        with (
            patch.object(Path, "lstat", disappear_at_lstat),
            patch.object(Path, "read_bytes", disappear_at_read),
            patch("healdan.inbox.os.scandir", side_effect=disappear_at_scan),
        ):
            rows = inbox.inventory(self.vault)
        self.assertEqual(removed, {early, late, vanishing})
        self.assertNotIn(excluded, scans)
        self.assertEqual([row["paths"] for row in rows], [["inbox/welcome/sibling.txt"]])
        self.assertEqual(read_json(self.vault.control / "inbox.json")[digest(kept.read_bytes())]["paths"],
                         ["inbox/welcome/sibling.txt"])

    def test_inventory_keeps_permission_and_path_guard_failures_explicit(self):
        old = self.root / "inbox" / "old.txt"
        atomic(old, b"Prior fixture capture")
        inbox.inventory(self.vault)
        state = self.vault.control / "inbox.json"
        saved = state.read_bytes()
        denied = self.root / "inbox" / "denied"
        existing = denied / "fixture.txt"
        atomic(existing, b"Unobserved fixture capture")
        scandir = os.scandir

        def deny(path):
            if Path(path) == denied:
                raise PermissionError("Fixture denied directory")
            return scandir(path)

        with patch("healdan.inbox.os.scandir", side_effect=deny), self.assertRaisesRegex(PermissionError, "Fixture denied"):
            inbox.inventory(self.vault)
        self.assertEqual(state.read_bytes(), saved)
        safe = inbox.safe_path

        def block(root, relative, **kwargs):
            if root == self.root and relative == "inbox/denied/fixture.txt":
                raise Blocked("Fixture strict file guard", 5)
            return safe(root, relative, **kwargs)

        with patch("healdan.inbox.safe_path", side_effect=block), self.assertRaisesRegex(Blocked, "Fixture strict"):
            inbox.inventory(self.vault)
        self.assertEqual(state.read_bytes(), saved)
        self.assertEqual(existing.read_bytes(), b"Unobserved fixture capture")

    def test_inbox_special_metadata_is_ignored_without_reading_content(self):
        special = self.root / "inbox" / "special.txt"
        atomic(special, b"A regular fixture with synthetic special-file metadata")
        lstat, read = Path.lstat, Path.read_bytes

        def special_metadata(path, *args, **kwargs):
            info = lstat(path, *args, **kwargs)
            return os.stat_result((stat.S_IFIFO, *info[1:])) if path == special else info

        def read_regular(path):
            self.assertNotEqual(path, special)
            return read(path)

        with patch.object(Path, "lstat", special_metadata), patch.object(Path, "read_bytes", read_regular):
            self.assertEqual(inbox.inventory(self.vault), [])
            run = linting.lint(self.vault)
        self.assertEqual(run["status"], "complete", run["errors"])
        self.assertNotIn("inbox", run["categories"])

    def test_lint_reports_directory_failures_and_keeps_readable_inbox_branches(self):
        retired = "inbox/old.txt"
        sha = self.defer_empty(retired)["sha256"]
        inbox.archive_empty(self.vault, sha)
        linked = self.base / "linked vault"
        git(self.root, "worktree", "add", "--detach", linked, "HEAD")
        denied = linked / "inbox" / "denied"
        disappearing = linked / "inbox" / "disappearing"
        excluded = linked / "inbox" / "tasks"
        hidden = denied / "empty.txt"
        atomic(hidden, b"")
        atomic(excluded / "task.txt", b"Excluded operational fixture")
        now = utc() + timedelta(days=8)
        baseline = linting.lint(self.vault, now)
        self.assertEqual(baseline["status"], "complete")
        self.assertIn(f"inbox:{sha}:deferral_due", baseline["findings"])
        state = self.vault.control / "lint-state.json"
        saved = state.read_bytes()
        followups = self.vault.control / "followups.json"
        prior_id = read_json(followups)["inbox"]["id"]

        disappearing.mkdir()
        late = linked / "inbox" / "lost.txt"
        good = linked / "inbox" / "readable" / "sibling.txt"
        atomic(late, b"Vanishing fixture")
        atomic(good, b"Readable sibling fixture")
        scandir, read = os.scandir, Path.read_bytes
        scans = []

        def trouble(path):
            path = Path(path)
            scans.append(path)
            if path == denied:
                raise PermissionError("Fixture denied directory")
            if path == disappearing:
                path.rmdir()
            return scandir(path)

        def disappear_at_read(path):
            if path == late:
                path.unlink()
            return read(path)

        with patch("healdan.inbox.os.scandir", side_effect=trouble), patch.object(Path, "read_bytes", disappear_at_read):
            partial = linting.lint(self.vault, now)
        self.assertEqual(partial["status"], "partial")
        self.assertCountEqual([(error["category"], error["worktree"], error["path"]) for error in partial["errors"]],
                              [("inbox", str(linked), path) for path in ("inbox/denied", "inbox/disappearing", "inbox/lost.txt")])
        self.assertNotIn(excluded, scans)
        self.assertIn("inbox:inbox/readable/sibling.txt", partial["findings"])
        self.assertIn(f"inbox:{sha}:deferral_due", partial["findings"])
        self.assertIn("backup", partial["categories"])
        self.assertEqual(partial["delta"]["resolved"], [])
        self.assertEqual(state.read_bytes(), saved)
        self.assertEqual(read_json(followups)["inbox"]["id"], prior_id)
        self.assertEqual(read_json(followups)["inbox"]["state"], "open")
        self.assertEqual(hidden.read_bytes(), b"")
        complete = linting.lint(self.vault, now)
        self.assertEqual(complete["status"], "complete")
        self.assertIn("inbox:inbox/denied/empty.txt", complete["findings"])

    def test_lint_keeps_entries_returned_before_directory_iterator_failure(self):
        linked = self.base / "linked vault"
        git(self.root, "worktree", "add", "--detach", linked, "HEAD")
        linked_vault = Vault(linked, self.state)
        partial_dir = "inbox/incomplete"
        visible = [f"{partial_dir}/already-visible.txt", f"{partial_dir}/branch/nested.txt", "inbox/other/readable.txt"]
        unlisted = f"{partial_dir}/not-returned.txt"
        for relative in [*visible, unlisted]:
            atomic(linked / relative, b"Regular Inbox fixture")
        baseline = linting.lint(self.vault)
        self.assertEqual(baseline["status"], "complete")
        state = self.vault.control / "lint-state.json"
        saved = state.read_bytes()
        tasks_path = self.vault.control / "followups.json"
        prior = read_json(tasks_path)["inbox"]["id"]
        scandir = os.scandir

        @contextmanager
        def interrupted_scan(path):
            with scandir(path) as entries:
                by_name = {entry.name: entry for entry in entries}

                def interrupted():
                    yield by_name["already-visible.txt"]
                    yield by_name["branch"]
                    raise PermissionError("Fixture scan interrupted after delivering two entries")

                yield interrupted()

        def partial_scan(path):
            return interrupted_scan(path) if Path(path) == linked / partial_dir else scandir(path)

        with patch("healdan.inbox.os.scandir", side_effect=partial_scan):
            for vault in (self.vault, linked_vault):
                partial = linting.lint(vault)
                self.assertEqual(partial["status"], "partial")
                self.assertEqual([(e["category"], e["worktree"], e["path"]) for e in partial["errors"]],
                                 [("inbox", str(linked), partial_dir)])
                self.assertCountEqual([row["key"] for row in partial["findings"].values() if row["category"] == "inbox"], visible)
                self.assertEqual(partial["delta"]["resolved"], [])
                self.assertEqual(state.read_bytes(), saved)
                followup = read_json(tasks_path)["inbox"]
                self.assertEqual((followup["id"], followup["state"]), (prior, "open"))
            with self.assertRaisesRegex(PermissionError, "Fixture scan interrupted"):
                inbox.inventory(linked_vault)
        self.assertFalse((self.vault.control / "inbox.json").exists())
        self.assertIn("inbox:" + unlisted, linting.lint(self.vault)["findings"])

    def test_shared_archive_deletion_recovers_all_verified_custody_slots(self):
        first, second = "inbox/a/shared.txt", "inbox/b/shared.txt"
        deferred = self.defer_empty(first)
        sha = deferred["sha256"]
        self.expiring_export("archive-a", (self.root / "inbox", "a/shared.txt", "export"))
        inbox.archive_empty(self.vault, sha)
        now = utc() + timedelta(days=8)
        plan = retention.plan(self.vault, now)
        self.assertEqual(len(plan["entries"]), 1)
        atomic(self.root / second, b"")
        self.expiring_export("archive-b", (self.root / "inbox", "b/shared.txt", "export"))
        inbox.inventory(self.vault)
        inbox.archive_empty(self.vault, sha)
        destination = self.root / f"archive/{sha}/shared.txt"
        self.assertTrue(inbox.archive_complete(self.vault, read_json(self.vault.control / "inbox.json")[sha]))

        hold = custody.hold(self.vault, "archive-b", "Keep this shared archive", "human")
        blocked = retention.execute(self.vault, plan["id"], now)
        self.assertIn("Active hold", blocked["entries"][0]["error"])
        self.assertEqual(destination.read_bytes(), b"")
        custody.release_hold(self.vault, "archive-b", hold["id"], [])
        save = retention.save_material

        def interrupt(vault, record):
            if record["id"] == "archive-b":
                raise OSError("Interrupted after updating only the first custody record")
            return save(vault, record)

        with patch("healdan.retention.save_material", side_effect=interrupt):
            partial = retention.execute(self.vault, plan["id"], now)
        entry = partial["entries"][0]
        self.assertEqual(entry["status"], "deleting")
        self.assertCountEqual([(g["material"], g["copy_index"]) for g in entry["verified_archive_generations"]],
                              [("archive-a", 1), ("archive-b", 1)])
        self.assertFalse(destination.exists())
        copies = custody.materials(self.vault)
        self.assertEqual(copies["archive-a"]["copies"][1]["status"], "deleted")
        self.assertEqual(copies["archive-b"]["copies"][1]["status"], "present")
        self.assertFalse(inbox.archive_complete(self.vault, read_json(self.vault.control / "inbox.json")[sha]))
        atomic(self.root / first, b"")
        with self.assertRaisesRegex(Blocked, "Resume retention first"):
            inbox.archive_empty(self.vault, sha)
        self.assertEqual((self.root / first).read_bytes(), b"")
        (self.root / first).unlink()
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        before = (self.vault.control / "materials.json").read_bytes()
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        self.assertEqual((self.vault.control / "materials.json").read_bytes(), before)
        for material in custody.materials(self.vault).values():
            origin, archive = material["copies"]
            self.assertEqual(origin["archive_copy_index"], 1)
            self.assertEqual((archive["status"], archive["verified_archive_sha256"]), ("deleted", sha))
        finished = linting.lint(self.vault, now)
        self.assertEqual(finished["status"], "complete", finished["errors"])
        self.assertFalse(any(row["category"] == "inbox" for row in finished["findings"].values()))

    def test_lost_archive_generation_cannot_reuse_deletion_proof_after_clock_reversal(self):
        relative = "inbox/repeated.txt"
        deferred = self.defer_empty(relative)
        sha = deferred["sha256"]
        self.expiring_export("archive-repeat", (self.root / "inbox", "repeated.txt", "export"))
        now = utc() + timedelta(days=8)
        first = inbox.archive_empty(self.vault, sha)["archive_moves"][-1]
        plan = retention.plan(self.vault, now)
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        self.assertTrue(inbox.archive_complete(self.vault, read_json(self.vault.control / "inbox.json")[sha]))

        atomic(self.root / relative, b"")
        self.track_empty_copy("archive-repeat", relative)
        with patch("healdan.inbox.stamp", return_value=stamp(utc(first["at"]) - timedelta(hours=1))):
            item = inbox.archive_empty(self.vault, sha)
        second = item["archive_moves"][-1]
        self.assertNotEqual(first["receipt"], second["receipt"])
        copies = custody.materials(self.vault)["archive-repeat"]["copies"]
        self.assertEqual([copy["archive_copy_index"] for copy in copies if copy["kind"] == "export"], [1, 3])
        destination = self.root / f"archive/{sha}/repeated.txt"
        destination.unlink()
        self.assertFalse(inbox.archive_complete(self.vault, item))
        plan = retention.plan(self.vault, now)
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        copies = custody.materials(self.vault)["archive-repeat"]["copies"]
        self.assertEqual(copies[1]["verified_archive_sha256"], sha)
        self.assertNotIn("verified_archive_sha256", copies[3])
        self.assertFalse(inbox.archive_complete(self.vault, item))

    def test_legacy_archive_receipt_accepts_unique_verified_destination(self):
        relative = "inbox/legacy.txt"
        deferred = self.defer_empty(relative)
        sha = deferred["sha256"]
        destination = f"archive/{sha}/legacy.txt"
        atomic(self.root / destination, b"")
        identifier = self.vault.receipt("zero-byte-archive", {"source": relative, "destination": destination.replace("/", "\\"),
                                                              "sha256": sha, "size": 0})
        receipt = self.vault.control / "receipts" / (identifier + ".json")
        original_receipt = receipt.read_bytes()
        (self.root / relative).unlink()
        journal = self.vault.control / "inbox.json"
        items = read_json(journal)
        items[sha]["receipts"].append(identifier)
        atomic(journal, items)
        linked = self.base / "linked vault"
        git(self.root, "worktree", "add", "--detach", linked, "HEAD")
        self.assertTrue(inbox.archive_complete(self.vault, items[sha]))
        atomic(linked / destination, b"")
        self.assertFalse(inbox.archive_complete(self.vault, items[sha]))
        (linked / destination).unlink()
        self.assertTrue(inbox.archive_complete(self.vault, items[sha]))
        self.assertEqual(receipt.read_bytes(), original_receipt)

    def test_stale_deleted_copy_plan_preserves_reused_archive_destination(self):
        first = "inbox/a/nota.txt"
        sha = self.triage_empty(first)
        material = self.expiring_export("archive-copy", (self.root / "inbox", "a/nota.txt", "export"))
        inbox.archive_empty(self.vault, sha)
        now = "2026-04-15T00:00:00Z"
        old = retention.plan(self.vault, now)
        deletion = retention.plan(self.vault, now)
        self.assertEqual(retention.execute(self.vault, deletion["id"], now)["status"], "complete")
        destination = self.root / "archive" / sha / "nota.txt"
        self.assertFalse(destination.exists())
        second = "inbox/b/nota.txt"
        atomic(self.root / second, b"")
        self.track_empty_copy(material["id"], second)
        inbox.inventory(self.vault)
        inbox.archive_empty(self.vault, sha)
        new = retention.plan(self.vault, now)
        self.assertNotEqual(old["entries"][0]["copy_index"], new["entries"][0]["copy_index"])
        path = self.vault.control / "materials.json"
        before = path.read_bytes()
        result = retention.execute(self.vault, old["id"], "2026-04-16T00:00:00Z")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["entries"][0]["status"], "deleted")
        old_copy = custody.materials(self.vault)[material["id"]]["copies"][old["entries"][0]["copy_index"]]
        self.assertEqual(result["entries"][0]["at"], old_copy["deleted_at"])
        self.assertEqual(destination.read_bytes(), b"")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(len(self.archive_receipts()), 2)

    def test_archive_waits_for_pending_deletion_and_archives_independent_paths(self):
        first, second, independent = "inbox/a/nota.txt", "inbox/b/nota.txt", "inbox/c/other.txt"
        sha = self.triage_empty(first)
        tracked = self.expiring_export("archive-copy", (self.root / "inbox", "a/nota.txt", "export"))
        inbox.archive_empty(self.vault, sha)
        archive_name = f"archive/{sha}/nota.txt"
        destination = self.root / archive_name
        original_receipts = self.archive_receipts()
        now = "2026-04-15T00:00:00Z"
        plan = retention.plan(self.vault, now)
        with patch("healdan.retention.save_material", side_effect=OSError("Interrupted before custody update")):
            interrupted = retention.execute(self.vault, plan["id"], now)
        self.assertEqual(interrupted["entries"][0]["status"], "deleting")
        self.assertFalse(destination.exists())
        slot = interrupted["entries"][0]["copy_index"]
        self.assertEqual(custody.materials(self.vault)[tracked["id"]]["copies"][slot]["status"], "present")

        for source in (second, independent):
            atomic(self.root / source, b"")
        self.track_empty_copy(tracked["id"], second)
        inbox.inventory(self.vault)
        code, error = self.cli("inbox", "archive-empty", sha)
        self.assertEqual(code, 5, error)
        self.assertIn("Resume retention first", error["error"])
        self.assertIn("maintenance execute " + plan["id"], error["error"])
        self.assertIn(second, error["error"])
        self.assertIn(archive_name, error["error"])
        self.assertNotIn(independent, error["error"])
        self.assertEqual((self.root / second).read_bytes(), b"")
        self.assertFalse(destination.exists())
        self.assertFalse((self.root / independent).exists())
        self.assertEqual((self.root / f"archive/{sha}/other.txt").read_bytes(), b"")
        self.assertEqual(read_json(self.vault.control / inbox.ARCHIVE_JOURNAL), {})
        self.assertIn(original_receipts[0], self.archive_receipts())

        save_material = custody.save_material

        def interrupt_after_reconciliation(vault, material):
            save_material(vault, material)
            raise OSError("Interrupted after custody update")

        with patch("healdan.retention.save_material", side_effect=interrupt_after_reconciliation):
            reconciled = retention.execute(self.vault, plan["id"], now)
        self.assertEqual(reconciled["entries"][0]["status"], "deleting")
        self.assertEqual(custody.materials(self.vault)[tracked["id"]]["copies"][slot]["status"], "deleted")
        self.assertEqual(self.cli("inbox", "archive-empty", sha)[0], 0)
        self.assertEqual(destination.read_bytes(), b"")
        self.assertCountEqual([receipt["source"] for receipt in self.archive_receipts()], [first, second, independent])
        copies = custody.materials(self.vault)[tracked["id"]]["copies"]
        self.assertEqual(copies[slot]["status"], "deleted")
        self.assertTrue(any(c["status"] == "present" and c["path"] == f"{sha}/nota.txt" for c in copies))
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        self.assertEqual(destination.read_bytes(), b"")

    def test_absent_copy_during_deletion_waits_for_custody_reconciliation(self):
        first, second = "inbox/a/nota.txt", "inbox/b/nota.txt"
        sha = self.triage_empty(first)
        self.expiring_export("archive-copy", (self.root / "inbox", "a/nota.txt", "export"))
        inbox.archive_empty(self.vault, sha)
        now = "2026-04-15T00:00:00Z"
        plan = retention.plan(self.vault, now)
        destination = self.root / "archive" / sha / "nota.txt"
        destination.unlink()
        with patch("healdan.retention.save_material", side_effect=OSError("Interrupted absent-copy reconciliation")):
            result = retention.execute(self.vault, plan["id"], now)
        self.assertEqual(result["entries"][0]["status"], "deleting")
        atomic(self.root / second, b"")
        inbox.inventory(self.vault)
        with self.assertRaisesRegex(Blocked, "Resume retention first"):
            inbox.archive_empty(self.vault, sha)
        self.assertTrue((self.root / second).exists())
        self.assertFalse(destination.exists())
        self.assertEqual(retention.execute(self.vault, plan["id"], now)["status"], "complete")
        inbox.archive_empty(self.vault, sha)
        self.assertEqual(destination.read_bytes(), b"")

    def test_retention_guard_recognizes_held_alias_of_canonical_storage(self):
        root = self.state / "custody"
        root.mkdir()
        alias = self.state / "alternate storage"

        def link_directory(link, target):
            if os.name == "nt":
                run(["cmd.exe", "/d", "/c", "mklink", "/J", link, target])
                self.assertTrue(link.is_junction())
            else:
                link.symlink_to(target, target_is_directory=True)

        link_directory(alias, root)
        copy = {"root": str(root), "path": "only-declared.age", "kind": "ciphertext", "status": "present",
                "sha256": digest(b"")}
        free = {"id": "free", "kind": "export", "classification": "common", "holds": [], "dependencies": [],
                "captured_at": "2026-04-01T00:00:00Z", "copies": [copy]}
        held = {**free, "id": "held", "copies": [{**copy, "root": str(alias)}]}
        custody.save_material(self.vault, free)
        custody.save_material(self.vault, held)
        custody.hold(self.vault, held["id"], "Protect the shared storage path", "human")
        with self.assertRaisesRegex(Blocked, "Active hold"):
            retention.guard(self.vault, free, copy, "2026-04-15T00:00:00Z")

        offline = self.state / "offline"
        offline.mkdir()
        unresolved = self.state / "unresolved storage"
        link_directory(unresolved, offline)
        offline.rmdir()
        held = custody.materials(self.vault)[held["id"]]
        held["copies"][0]["root"] = str(unresolved)
        custody.save_material(self.vault, held)
        with self.assertRaisesRegex(Blocked, "Cannot verify storage location"):
            retention.guard(self.vault, free, copy, "2026-04-15T00:00:00Z")
        self.assertEqual(list(root.iterdir()), [])

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

    def test_query_and_preview_only_read_git_blobs_for_used_sources(self):
        claim = self.claim()
        self.knowledge([claim])
        used, = self.vault.rows(originals.REGISTRY)
        rows = [used]
        cutoff = "2026-06-01T00:00:00Z"
        for count in (0, 8, 32, 64):
            with self.subTest(unused_sources=count):
                for offset in range(len(rows), count + 1):
                    identifier = f"F-{offset + 1:04d}"
                    path = f"resources/sources/{identifier}/original.txt"
                    body = f"Unreferenced material {offset}\n".encode()
                    atomic(self.root / path, body)
                    rows.append(dict(used, id=identifier, path=path, size=len(body), sha256=digest(body)))
                self.rows(originals.REGISTRY, rows)
                git(self.root, "add", "--", "wiki", "resources/sources", "control/approvals")
                git(self.root, "commit", "-m", f"Preserve the cited source and {count} unused sources")
                with patch.object(originals, "git_blob", wraps=originals.git_blob) as read:
                    self.assertEqual(query(self.vault, {"entity": "instrument"}, cutoff)["code"], 0)
                self.assertCountEqual([call.args[2] for call in read.call_args_list], [originals.REGISTRY, used["path"]])
                with patch.object(originals, "git_blob", wraps=originals.git_blob) as read:
                    preview = pages.preview(self.vault, cutoff)
                self.assertEqual(preview["pending_evidence"], [])
                self.assertCountEqual([call.args[2] for call in read.call_args_list], [originals.REGISTRY, used["path"]])

        unused = self.root / rows[-1]["path"]
        raw = unused.read_bytes()
        atomic(unused, b"Divergent bytes committed in a source the query does not use")
        git(self.root, "add", "--", rows[-1]["path"])
        git(self.root, "commit", "-m", "Fixture divergent unused blob")
        atomic(unused, raw)
        self.assertEqual(query(self.vault, {}, cutoff)["code"], 0)
        self.assertEqual(pages.preview(self.vault, cutoff)["pending_evidence"], [])
        with self.assertRaisesRegex(Blocked, rows[-1]["id"]):
            Knowledge(self.vault)

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
