import base64
import copy
from pathlib import Path
from unittest.mock import patch
import unittest
from uuid import uuid4

from support import VaultTest
from healdan import ids, review, tasks, transactions
from healdan.core import Blocked, atomic, digest, git, jsonl, read_json
from healdan.knowledge import query


class Transactions(VaultTest):
    def prepare_fixture(self):
        claim = self.claim()
        git(self.root, "add", ".")
        git(self.root, "commit", "-m", "Preserve source fixture")
        ids.reserve(self.vault, "C", 1, str(uuid4()))
        ids.reserve(self.vault, "Q", 1, str(uuid4()))
        task = tasks.create(self.vault, "Controller transaction fixture; no native execution claim")
        base = self.state / "tasks" / task["id"]
        sessions = []
        for role in ("extractor", "reviewer"):
            session = tasks.new_session(self.vault, task["id"], role, role, "fixture context")
            # Inject completed records only to test downstream controller logic. Native trial remains separate.
            session["state"] = "completed"
            session["launches"] = [{"synthetic_controller_fixture": True}]
            atomic(self.vault.control / "sessions" / (session["operation"] + ".json"), session)
            atomic(base / "proposals" / role / "extraction.json", {"units": [claim]})
            sessions.append(session["operation"])
        frozen = review.freeze_review(self.vault, task["id"], *sessions)
        atomic(base / "proposals/reviewer/comparison.json", {
            "extractions": {role: frozen["outputs"][role]["sha256"] for role in ("extractor", "reviewer")},
            "units": {"C-0001": "conform"}, "defects": []})
        proposal = base / "proposals/editor"
        atomic(proposal / "wiki/claims.jsonl", jsonl([claim]))
        atomic(proposal / "wiki/control/query-cases.jsonl", jsonl([self.case()]))
        atomic(proposal / "wiki/control/page-policy.json", {"cap": 6000, "decision": "Fixture human page choice"})
        atomic(proposal / "wiki/control/selectors.jsonl", jsonl([{
            "path": "wiki/topics/instrument.md", "title": "Instrument", "topic": "measurement", "ids": ["C-0001"],
            "purpose": "current_at_cutoff", "cutoff": "2026-06-01T00:00:00Z"}]))
        package = transactions.prepare(self.vault, task["id"], cutoff="2026-06-01T00:00:00Z")
        return task, package

    def test_signed_promotion_real_git_query_and_regression(self):
        task, package = self.prepare_fixture()
        self.assertEqual(query(self.vault, {})["code"], 20)
        with self.assertRaises(Blocked):
            transactions.approve(self.vault, package["id"])
        transactions.inspect_package(self.vault, package["id"], {"C-0001": "conform"})
        transactions.approve(self.vault, package["id"])
        result = transactions.apply(self.vault, package["id"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(query(self.vault, {"entity": "instrument"})["code"], 0)
        self.assertNotEqual(result["commit"], task["base"])
        self.assertIn("C-0001", (self.root / "wiki/topics/instrument.md").read_text())

    def test_changed_base_invalidates_approval(self):
        task, package = self.prepare_fixture()
        transactions.inspect_package(self.vault, package["id"], {"C-0001": "conform"})
        transactions.approve(self.vault, package["id"])
        atomic(self.root / "wiki/index.md", b"# Concurrent editorial change\n")
        with self.assertRaises(Blocked):
            transactions.apply(self.vault, package["id"])
        self.assertEqual((self.root / "wiki/claims.jsonl").read_bytes(), b"")

    def test_tampered_signed_package_is_rejected(self):
        task, package = self.prepare_fixture()
        transactions.inspect_package(self.vault, package["id"], {"C-0001": "conform"})
        transactions.approve(self.vault, package["id"])
        path = transactions.package_path(self.vault, package["id"])
        record = read_json(path)
        record["payload"]["files"]["wiki/index.md"] = base64.b64encode(b"injected").decode()
        atomic(path, record)
        with self.assertRaises(Blocked):
            transactions.apply(self.vault, package["id"])

    def test_crashed_apply_recovers_same_journal(self):
        task, package = self.prepare_fixture()
        transactions.inspect_package(self.vault, package["id"], {"C-0001": "conform"})
        transactions.approve(self.vault, package["id"])
        failed = False
        def fail_once(path, data):
            nonlocal failed
            if Path(path) == self.root / "wiki/control/selectors.jsonl" and not failed:
                failed = True
                raise OSError("Injected disk failure after journal persistence")
            return atomic(path, data)
        with patch("healdan.transactions.atomic", side_effect=fail_once), self.assertRaises(OSError):
            transactions.apply(self.vault, package["id"])
        self.assertEqual(read_json(self.vault.control / "transaction.json")["status"], "writing")
        with self.assertRaises(Blocked):
            ids.reserve(self.vault, "S", 1, str(uuid4()))
        recovered = transactions.apply(self.vault, recover=True)
        self.assertEqual(recovered["status"], "complete")
        self.assertEqual(query(self.vault, {"entity": "instrument"})["code"], 0)

    def test_pending_case_blocks_preparation(self):
        task, package = self.prepare_fixture()
        path = self.state / "tasks" / task["id"] / "proposals/editor/wiki/control/query-cases.jsonl"
        case = self.case()
        del case["approval"]
        atomic(path, jsonl([case]))
        with self.assertRaises(Blocked):
            transactions.prepare(self.vault, task["id"])

    def test_source_and_signed_decision_bytes_must_survive_migration(self):
        claim = self.claim()
        self.rows("wiki/control/decisions.jsonl", [{"id": "D-0001", "signed_payload": "original"}])
        files = {"wiki/control/decisions.jsonl": base64.b64encode(jsonl([{"id": "D-0001", "signed_payload": "changed"}])).decode()}
        with transactions.Candidate(self.vault, files) as candidate, self.assertRaises(Blocked):
            transactions.preserve_contracts(self.vault, candidate)


if __name__ == "__main__":
    unittest.main()
