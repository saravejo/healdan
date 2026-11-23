import base64
import copy
from pathlib import Path
from unittest.mock import patch
import unittest
from uuid import uuid4

from support import VaultTest
from healdan import ids, review, tasks, transactions
from healdan.core import Blocked, REQUIRED_REGISTRIES, atomic, digest, git, jsonl, read_json
from healdan.knowledge import query
from healdan.signing import verify


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
            atomic(Path(session["proposal"]) / "extraction.json", {"units": [claim]})
            sessions.append(session["operation"])
        frozen = review.freeze_review(self.vault, task["id"], *sessions)
        atomic(Path(tasks.get_session(self.vault, sessions[1])["proposal"]) / "comparison.json", {
            "extractions": {role: frozen["outputs"][role]["sha256"] for role in ("extractor", "reviewer")},
            "units": {"C-0001": {"status": "conform", "sha256": digest(claim)}}, "defects": []})
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
        journal_path = self.vault.control / "transaction.json"
        original = journal_path.read_bytes()
        journal = read_json(journal_path)
        self.assertEqual(journal["status"], "writing")
        with self.assertRaises(Blocked):
            ids.reserve(self.vault, "S", 1, str(uuid4()))
        journal["files"]["wiki/claims.jsonl"] = base64.b64encode(jsonl([{"id": "D-0001"}])).decode("ascii")
        atomic(journal_path, journal)
        with self.assertRaisesRegex(Blocked, "Recovery journal files differ from the signed package"):
            transactions.apply(self.vault, recover=True)
        atomic(journal_path, original)
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

    def test_review_cannot_approve_changed_claim_under_same_id(self):
        task, package = self.prepare_fixture()
        claim = self.claim(statement="A changed assertion with the same typed value")
        path = self.state / "tasks" / task["id"] / "proposals/editor/wiki/claims.jsonl"
        atomic(path, jsonl([claim]))
        with self.assertRaises(Blocked):
            transactions.prepare(self.vault, task["id"])

    def test_csp_defect_resets_next_package_inspection_regime(self):
        atomic(self.vault.control / "csp.json", {"streak": 110})
        task, package = self.prepare_fixture()
        transactions.inspect_package(self.vault, package["id"], {"C-0001": "defect"})
        self.assertEqual(read_json(self.vault.control / "csp.json")["streak"], 0)
        with self.assertRaises(Blocked):
            transactions.approve(self.vault, package["id"])

    def test_unknown_inspection_state_blocks_preparation_and_approval(self):
        state_path = self.vault.control / "csp.json"
        legacy_state = {"streak": 111, "package": "1" * 64}
        atomic(state_path, legacy_state)
        legacy_bytes = state_path.read_bytes()
        with patch("healdan.review.secrets.token_hex", return_value="00" * 32):
            task, frozen = self.prepare_fixture()
        self.assertTrue(review.csp_status(frozen["csp"])["complete"])
        self.assertEqual(frozen["csp"]["inspections"], {})
        path = transactions.package_path(self.vault, frozen["id"])
        original = path.read_bytes()
        receipts = self.vault.control / "receipts"
        before_receipts = set(receipts.glob("*.json"))
        cutoff = frozen["payload"]["cutoff"]
        inspection = self.base / "inspection.json"
        atomic(inspection, {})

        for unsupported in (dict(legacy_state, format="healdan-inspection-state-v99"),
                            dict(legacy_state, authority="unknown metadata"),
                            dict(legacy_state, rule="unknown-inspection-regime")):
            with self.subTest(state=unsupported):
                atomic(state_path, unsupported)
                before = state_path.read_bytes()
                for when in (cutoff, "2026-06-02T00:00:00Z"):
                    code, result = self.cli("review", "package", task["id"], "--cutoff", when)
                    self.assertEqual(code, 5, result)
                    self.assertIn("separate human decision and a new sequence", result["error"])
                self.assertEqual(list(path.parent.glob("*.json")), [path])

                old = copy.deepcopy(frozen)
                old["csp"]["state_digest"] = digest(unsupported)
                atomic(path, old)
                code, result = self.cli("review", "inspect", frozen["id"], inspection)
                self.assertEqual(code, 5, result.get("error"))
                code, result = self.cli("approve", frozen["id"])
                self.assertEqual(code, 5, result)
                self.assertIn("separate human decision and a new sequence", result["error"])
                self.assertIsNone(read_json(path)["approval"])
                self.assertEqual(set(receipts.glob("*.json")), before_receipts)
                old["approval"] = self.signed(transactions.approval_payload(old), "package")
                atomic(path, old)
                code, result = self.cli("apply", frozen["id"])
                self.assertEqual(code, 5, result)
                self.assertFalse((self.vault.control / "transaction.json").exists())
                self.assertEqual(self.vault.rows("control/approvals/packages.jsonl"), [])
                code, preview = self.cli("migration", "preview")
                self.assertEqual(code, 5, preview)
                self.assertEqual(preview["inspection_sequence"]["status"], "pending")
                self.assertEqual(state_path.read_bytes(), before)
                atomic(path, original)

        atomic(state_path, legacy_bytes)
        code, approval = self.cli("approve", frozen["id"])
        self.assertEqual(code, 0, approval)
        self.assertEqual(verify(approval, "package", self.signers), transactions.approval_payload(frozen))
        self.assertEqual(approval["payload"]["csp"]["initial_streak"], 111)
        self.assertEqual(approval["payload"]["csp"]["inspections"], {})
        self.assertEqual(state_path.read_bytes(), legacy_bytes)
        code, applied = self.cli("apply", frozen["id"])
        self.assertEqual(code, 0, applied)
        self.assertEqual(self.vault.rows("control/approvals/packages.jsonl"), [approval])

    def test_recovery_accepts_already_recorded_known_inspection_state(self):
        task, _, package = self.prepare_identity_fixture()
        transactions.approve(self.vault, package["id"])
        state_path = self.vault.control / "csp.json"
        journal = self.vault.control / "transaction.json"

        def interrupt_before_completion(path, data):
            if Path(path) == journal and data["status"] == "complete":
                raise OSError("Injected disconnection after the inspection state was written")
            return atomic(path, data)

        with patch("healdan.transactions.atomic", side_effect=interrupt_before_completion), self.assertRaises(OSError):
            transactions.apply(self.vault, package["id"])
        head = self.vault.head()
        self.assertNotEqual(head, task["base"])
        expected = state_path.read_bytes()
        original_journal = journal.read_bytes()
        self.assertEqual(read_json(state_path)["package"], package["id"])
        unsupported = dict(read_json(state_path), format="healdan-inspection-state-v99")
        atomic(state_path, unsupported)
        code, result = self.cli("apply", "--recover")
        self.assertEqual(code, 5, result)
        self.assertEqual(read_json(state_path), unsupported)
        self.assertEqual(journal.read_bytes(), original_journal)
        self.assertEqual(self.vault.head(), head)

        atomic(state_path, expected)
        code, recovered = self.cli("apply", "--recover")
        self.assertEqual(code, 0, recovered)
        self.assertEqual((recovered["status"], recovered["commit"]), ("complete", head))
        self.assertEqual(state_path.read_bytes(), expected)

    def test_source_and_signed_decision_bytes_must_survive_migration(self):
        claim = self.claim()
        self.rows("wiki/control/decisions.jsonl", [{"id": "D-0001", "signed_payload": "original"}])
        files = {"wiki/control/decisions.jsonl": base64.b64encode(jsonl([{"id": "D-0001", "signed_payload": "changed"}])).decode()}
        with transactions.Candidate(self.vault, files) as candidate, self.assertRaises(Blocked):
            transactions.preserve_contracts(self.vault, candidate)

    def prepare_identity_fixture(self):
        decisions, lessons = "wiki/control/decisions.jsonl", "wiki/control/lessons.jsonl"
        decision, = ids.reserve(self.vault, "D", 1, str(uuid4()))
        lesson, = ids.reserve(self.vault, "L", 1, str(uuid4()))
        task = tasks.create(self.vault, "Identity registry fixture")
        proposal = self.state / "tasks" / task["id"] / "proposals/editor"
        atomic(proposal / decisions, jsonl([*self.vault.rows(decisions), {"id": decision}]))
        atomic(proposal / lessons, jsonl([*self.vault.rows(lessons), {"id": lesson}]))
        return task, proposal, transactions.prepare(self.vault, task["id"])

    def legacy_package(self, package, registry, body):
        record = copy.deepcopy(package)
        record["payload"]["files"][registry] = base64.b64encode(body).decode("ascii")
        record["id"] = digest(record["payload"])
        path = transactions.package_path(self.vault, record["id"])
        atomic(path, record)
        return record, path

    def interrupt_apply(self, record, failure_path):
        def interrupted(path, data):
            if Path(path) == failure_path:
                raise OSError("Injected integration interruption")
            return atomic(path, data)

        with patch("healdan.transactions.atomic", side_effect=interrupted), self.assertRaises(OSError):
            transactions.apply(self.vault, record["id"])
        return self.vault.control / "transaction.json"

    def test_all_identity_registries_bind_the_prefix_and_keep_legacy_spelling(self):
        for registry, prefix in (
            ("wiki/claims.jsonl", "C"),
            ("resources/sources/index.jsonl", "F"),
            ("wiki/control/decisions.jsonl", "D"),
            ("wiki/control/lessons.jsonl", "L"),
            ("wiki/control/query-cases.jsonl", "Q"),
        ):
            with self.subTest(registry=registry):
                original = prefix + "-1"
                row = {"id": original}
                self.assertEqual(ids.registry_records(registry, [row]), {original: row})
                invalid = "D-0001" if prefix != "D" else "L-0001"
                with self.assertRaisesRegex(Blocked, f"Expected a {prefix}- identity"):
                    ids.registry_records(registry, [{"id": invalid}])
                with self.assertRaisesRegex(Blocked, "Numeric identity collision"):
                    ids.registry_records(registry, [row, {"id": prefix + "-0001"}])

    def test_candidate_identities_block_prepare_approve_and_apply(self):
        task, proposal, valid = self.prepare_identity_fixture()
        versions = (
            ("wiki/control/lessons.jsonl", [{"id": "D-0001"}], "Expected a L- identity"),
            ("wiki/control/decisions.jsonl", [{"id": "D-1"}, {"id": "D-0001"}], "Numeric identity collision"),
        )
        receipts = set((self.vault.control / "receipts").glob("*.json"))
        for registry, rows, message in versions:
            with self.subTest(registry=registry):
                body = jsonl(rows)
                original = (proposal / registry).read_bytes()
                atomic(proposal / registry, body)
                with self.assertRaisesRegex(Blocked, message):
                    transactions.prepare(self.vault, task["id"])
                atomic(proposal / registry, original)

                record, path = self.legacy_package(valid, registry, body)
                with self.assertRaisesRegex(Blocked, message):
                    transactions.approve(self.vault, record["id"])
                self.assertIsNone(read_json(path)["approval"])
                self.assertEqual(set((self.vault.control / "receipts").glob("*.json")), receipts)

                record["approval"] = self.signed(transactions.approval_payload(record), "package")
                atomic(path, record)
                with self.assertRaisesRegex(Blocked, message):
                    transactions.apply(self.vault, record["id"])
                self.assertEqual(self.vault.head(), task["base"])
                self.assertFalse((self.vault.control / "transaction.json").exists())

        transactions.approve(self.vault, valid["id"])
        transactions.apply(self.vault, valid["id"])
        self.assertEqual(self.vault.rows("wiki/control/decisions.jsonl"), [{"id": "D-0001"}])
        self.assertEqual(self.vault.rows("wiki/control/lessons.jsonl"), [{"id": "L-0001"}])
        self.assertEqual(ids.reserve(self.vault, "D", 1, str(uuid4())), ["D-0002"])
        self.assertEqual(ids.reserve(self.vault, "L", 1, str(uuid4())), ["L-0002"])

    def test_valid_legacy_decision_and_signed_bytes_survive_integration(self):
        registry = "wiki/control/decisions.jsonl"
        payload = {"id": "D-1", "decision": "Preserve original approval"}
        signed_row = dict(payload, approval=self.signed(payload, "decision"))
        self.rows(registry, [signed_row])
        before = (self.root / registry).read_bytes()
        git(self.root, "commit", "-am", "Preserve legacy decision")
        _, _, package = self.prepare_identity_fixture()
        transactions.approve(self.vault, package["id"])
        transactions.apply(self.vault, package["id"])
        self.assertTrue((self.root / registry).read_bytes().startswith(before))
        self.assertEqual(self.vault.rows(registry), [signed_row, {"id": "D-0002"}])

    def test_recovery_revalidates_signed_identities_before_writes(self):
        task, _, package = self.prepare_identity_fixture()
        registry = "wiki/control/decisions.jsonl"
        record, path = self.legacy_package(package, registry, jsonl([{"id": "D-1"}, {"id": "D-0001"}]))
        record["approval"] = self.signed(transactions.approval_payload(record), "package")
        atomic(path, record)
        with patch("healdan.transactions.validate_candidate"):
            journal = self.interrupt_apply(record, self.root / registry)
        before = journal.read_bytes()
        with self.assertRaisesRegex(Blocked, "Numeric identity collision"):
            transactions.apply(self.vault, recover=True)
        self.assertEqual(journal.read_bytes(), before)
        self.assertEqual(self.vault.head(), task["base"])
        self.assertEqual(self.vault.rows(registry), [])

    def test_recovery_revalidates_identities_of_partially_recorded_commit(self):
        task, _, package = self.prepare_identity_fixture()
        transactions.approve(self.vault, package["id"])
        journal = self.interrupt_apply(package, self.vault.control / "csp.json")
        committed = self.vault.head()
        self.assertNotEqual(committed, task["base"])
        before = journal.read_bytes()
        registry = "wiki/control/decisions.jsonl"
        frozen = (self.root / registry).read_bytes()
        self.rows(registry, [{"id": "D-0002"}])
        git(self.root, "commit", "-am", f"Divergent fixture\n\nHealdan-Package: {package['id']}")
        divergent = self.vault.head()

        with self.assertRaisesRegex(Blocked, "Committed identities differ from the signed candidate"):
            transactions.apply(self.vault, recover=True)
        self.assertEqual(journal.read_bytes(), before)
        self.assertEqual(self.vault.head(), divergent)
        self.assertEqual(self.vault.rows(registry), [{"id": "D-0002"}])

        git(self.root, "update-ref", "HEAD", committed, divergent)
        atomic(self.root / registry, frozen)
        git(self.root, "add", "--", registry)
        result = transactions.apply(self.vault, recover=True)
        self.assertEqual((result["status"], result["commit"]), ("complete", committed))

    def test_candidate_copy_requires_every_registry(self):
        inputs = dict(self.vault.input_files())
        for registry in REQUIRED_REGISTRIES:
            with self.subTest(registry=registry):
                incomplete = [(name, body) for name, body in inputs.items() if name != registry]
                with patch.object(self.vault, "input_files", return_value=incomplete):
                    with self.assertRaisesRegex(Blocked, registry) as raised:
                        with transactions.Candidate(self.vault, {}):
                            self.fail("Candidate accepted an absent registry")
                self.assertEqual(raised.exception.code, 4)
        self.assertEqual(list(self.state.glob("candidate-*")), [])

    def test_candidate_copy_rejects_corrupted_unused_registry(self):
        body = base64.b64encode(b'{"broken":\n').decode("ascii")
        with self.assertRaisesRegex(Blocked, "Invalid JSON") as raised:
            with transactions.Candidate(self.vault, {"wiki/control/decisions.jsonl": body}):
                self.fail("Candidate accepted malformed decisions")
        self.assertEqual(raised.exception.code, 4)
        self.assertEqual(list(self.state.glob("candidate-*")), [])


if __name__ == "__main__":
    unittest.main()
