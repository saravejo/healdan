import base64
import copy
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from support import VaultTest
import test_transactions
from healdan import admission, custody, inbox, incidents, originals, pages, tasks, transactions
from healdan.core import Blocked, atomic, digest, git, jsonl, read_json
from healdan.ids import reserve
from healdan.knowledge import query
from healdan.lineage import ORIGIN

CUT = "2026-06-01T00:00:00Z"
CAPTURE = "2026-04-01T00:00:00Z"


class SourcePolicy(VaultTest):
    def capture(self, name, body, parents=()):
        path = "inbox/" + name
        atomic(self.root / path, body)
        derived = {"method": name, "sources": [self.ref(row) for row in parents]} if parents else None
        return admission.ingest(self.vault, path, provenance="Disposable evidence", captured_at=CAPTURE,
                                classification="common", derived=derived)

    def ref(self, row):
        return {"id": row["id"], "revision": digest(row)}

    def claim_for(self, rows, **changes):
        locators = [{**self.ref(row), "start": 0, "end": row["size"], "sha256": row["sha256"]} for row in rows]
        claim = {"id": "C-0001", "statement": "Synthetic instrument has value 42", "entity": "instrument",
                 "property": "value", "environment": "laboratory", "primary_topic": "measurement",
                 "state": "accepted", "value": {"type": "integer", "value": 42, "unit": None},
                 "polarity": "positive", "sources": locators, "valid_from": None, "valid_to": None, "qualifiers": {}}
        return dict(claim, **changes)

    def triage(self, name, body, classification):
        path = "inbox/" + name
        atomic(self.root / path, body)
        inbox.inventory(self.vault)
        sha = digest(body)
        purpose = {"purpose": "Check narrow evidence", "necessity": "Instrument record required",
                   "owner": "human", "link": "inbox-" + sha}
        item = inbox.decide(self.vault, sha, "ingest", owner="human", classification=classification,
                            destination="review", entered_at=CAPTURE, entry_origin="Receipt",
                            purpose=purpose if classification != "common" else None)
        return item, purpose

    def proposal(self, body, classification="common", **fields):
        if not hasattr(self, "source_task"):
            self.source_task = tasks.create(self.vault, "Review a minimal source")
            self.source_identifier, = reserve(self.vault, "F", 1, str(uuid4()))
        identifier = self.source_identifier
        editor = self.state / "tasks" / self.source_task["id"] / "proposals/editor"
        path = f"resources/sources/{identifier}/original.txt"
        row = {"id": identifier, "path": path, "sha256": digest(body), "size": len(body),
               "captured_at": CAPTURE, "provenance": "Disposable proposal", "classification": classification, **fields}
        atomic(editor / path, body)
        atomic(editor / originals.REGISTRY, jsonl([*self.vault.rows(originals.REGISTRY), row]))
        return row

    def approved(self):
        package = transactions.prepare(self.vault, self.source_task["id"], cutoff=CUT)
        transactions.approve(self.vault, package["id"])
        return package["id"]

    def test_renamed_page_copy_remains_dependent_on_rejected_claim(self):
        _, package = test_transactions.Transactions.prepare_fixture(self)
        transactions.inspect_package(self.vault, package["id"], {"C-0001": "conform"})
        transactions.approve(self.vault, package["id"])
        result = transactions.apply(self.vault, package["id"])
        approval = self.vault.rows(transactions.LEDGER)[0]
        self.assertEqual(approval["payload"]["page_revisions"][0]["claims"][0]["id"], "C-0001")
        page = originals.git_blob(self.root, result["commit"], "wiki/topics/instrument.md")
        first_claim = self.vault.rows("wiki/claims.jsonl")[0]
        first_claim["state"] = "rejected"
        self.rows("wiki/claims.jsonl", [first_claim])
        self.rows("wiki/control/selectors.jsonl", [])
        self.rows("wiki/control/query-cases.jsonl", [])
        git(self.root, "add", "--", "wiki")
        git(self.root, "commit", "-m", "Fixture rejection leaves source bytes intact")
        copied = self.capture("other title.md", page)
        self.assertEqual(copied["origin"]["kind"], "wiki")
        self.assertEqual(copied["origin"]["pages"][0]["revision"], digest(page))
        second_id, = reserve(self.vault, "C", 1, str(uuid4()))
        second = self.claim_for([copied], id=second_id)
        proposal = {"wiki/claims.jsonl": base64.b64encode(jsonl([first_claim, second])).decode()}
        with transactions.Candidate(self.vault, proposal) as candidate, self.assertRaisesRegex(Blocked, "C-0002.*C-0001"):
            transactions.validate_candidate(self.vault, candidate, CUT)
        self.rows("wiki/claims.jsonl", [first_claim, second])
        legacy_approval = self.signed({"claim_digests": {second_id: digest(second)}}, "package")
        self.rows(transactions.LEDGER, [approval, legacy_approval])
        answer = query(self.vault, {}, CUT)
        self.assertEqual(answer["code"], 20, answer)
        self.assertIn("C-0001", " ".join(answer["diagnostics"]))
        preview = pages.preview(self.vault, CUT)
        self.assertEqual(preview["pending_evidence"][0]["id"], second_id)
        self.assertIn("C-0001", " ".join(preview["pending_evidence"][0]["reasons"]))
        self.assertEqual(self.vault.rows(transactions.LEDGER), [approval, legacy_approval])

    def test_two_conversions_share_one_observation(self):
        root = self.capture("original.txt", b"This is a unique observation\r\n")
        first = self.capture("normalization.txt", b"This is a unique observation\n", [root])
        second = self.capture("plus metadata.txt", b"This is a unique observation [capture]\n", [root])
        self.assertNotEqual(first["sha256"], second["sha256"])
        self.knowledge([self.claim_for([first, second], minimum_observations=2)])
        answer = query(self.vault, {}, CUT)
        self.assertEqual(answer["code"], 20, answer)
        self.assertEqual(answer["observations"], [root["sha256"]])
        self.assertIn("1 verified observations, 2 required", " ".join(answer["diagnostics"]))

    def test_independent_capture_and_derivative_stay_eligible(self):
        first = self.capture("earlier.txt", b"First apparatus")
        second = self.capture("other.txt", b"Second independent apparatus")
        derived = self.capture("derived.txt", b"Second apparatus observation extracted", [second])
        refused = self.claim_for([first], state="rejected")
        accepted = self.claim_for([derived], id="C-0002", minimum_observations=1)
        self.knowledge([refused, accepted])
        result = query(self.vault, {}, CUT)
        self.assertEqual(result["ids"], [accepted["id"]], result)
        self.assertEqual(result["observations"], [second["sha256"]])

    def test_current_edges_check_revision_missing_cycle_and_legacy_independence(self):
        first = self.capture("root.txt", b"Observation")
        derived = self.capture("derived.txt", b"Converted", [first])
        claim = self.claim_for([derived])
        claim["sources"][0].pop("revision")  # An authentic pre-revision locator still has a byte range.
        self.knowledge([claim])
        original_approval = (self.root / transactions.LEDGER).read_bytes()
        self.assertEqual(query(self.vault, {}, CUT)["code"], 0)
        revision = {**first, "provenance": "Changed capture revision"}
        missing = {**derived, "origin": {**derived["origin"], "sources": [{"id": "F-0999", "revision": "1" * 64}]}}
        cyclic = {**first, "origin": {"kind": "derived", "format": ORIGIN, "method": "cycle", "sources": [self.ref(derived)]}}
        for records, diagnostic in (([revision, derived], "source revision differs"),
                                    ([first, missing], "missing source F-0999"),
                                    ([cyclic, derived], "lineage cycle")):
            with self.subTest(diagnostic=diagnostic):
                self.rows(originals.REGISTRY, records)
                result = query(self.vault, {}, CUT)
                self.assertEqual(result["code"], 20, result)
                self.assertIn(diagnostic, " ".join(result["diagnostics"]))
                self.assertEqual((self.root / transactions.LEDGER).read_bytes(), original_approval)
        legacy = {k: v for k, v in first.items() if k != "origin"}
        self.rows(originals.REGISTRY, [legacy, derived])
        requiring_independence = self.claim_for([legacy], minimum_observations=1)
        self.knowledge([requiring_independence])
        result = query(self.vault, {}, CUT)
        self.assertIn("legacy source independence is pending", " ".join(result["diagnostics"]))

    def test_initial_classification_distinguishes_inventory_pending_and_recorded_common(self):
        captured = self.capture("new.txt", b"Initially unrecorded")
        path = self.vault.control / "inbox.json"
        item = read_json(path)[captured["sha256"]]
        self.assertTrue(item["decision_receipt"])
        self.assertEqual(item["classification"], "common")
        atomic(self.root / "inbox/unknown.txt", b"Merely inventoried")
        unknown = digest(b"Merely inventoried")
        inbox.inventory(self.vault)
        self.assertEqual(read_json(path)[unknown]["classification"], "unknown")
        self.capture("unknown.txt", b"Merely inventoried")
        self.assertEqual(read_json(path)[unknown]["classification"], "common")
        self.triage("pending.txt", b"Pending decision", "unknown")
        with self.assertRaisesRegex(Blocked, "recorded classification is unknown"):
            self.capture("pending-copy.txt", b"Pending decision")
        triaged, _ = self.triage("common.txt", b"Previously approved common", "common")
        self.capture("common-copy.txt", b"Previously approved common")
        self.assertEqual(read_json(path)[triaged["sha256"]]["decision_receipt"], triaged["decision_receipt"])

    def test_restricted_copies_and_derivatives_cannot_be_declared_common(self):
        for classification in ("personal", "sensitive", "mixed"):
            body = classification.encode() + b" restricted fixture"
            item, purpose = self.triage(classification + ".txt", body, classification)
            material = custody.materials(self.vault)[purpose["link"]]
            copy_path = "inbox/copy-" + classification + ".txt"
            atomic(self.root / copy_path, body)
            with self.assertRaisesRegex(Blocked, f"recorded classification is {classification}"):
                admission.ingest(self.vault, copy_path, provenance="Copy", captured_at=CAPTURE, classification="common")
            self.proposal(body)
            with self.assertRaisesRegex(Blocked, f"recorded classification is {classification}"):
                transactions.prepare(self.vault, self.source_task["id"], cutoff=CUT)
            self.assertEqual(custody.materials(self.vault)[purpose["link"]], material)
            self.assertEqual(read_json(self.vault.control / "inbox.json")[item["sha256"]]["entered_at"], CAPTURE)
            self.assertEqual((self.root / copy_path).read_bytes(), body)
        source = self.proposal(b"sensitive restricted fixture", "sensitive",
                               purpose=custody.materials(self.vault)["inbox-" + digest(b"sensitive restricted fixture")]["purpose"])
        transactions.apply(self.vault, self.approved())
        source = admission.source_rows(self.vault)[source["id"]]
        with self.assertRaisesRegex(Blocked, "derivative inherits sensitive"):
            self.capture("converted.txt", b"Converted from the sensitive fixture", [source])
        self.age()
        secret = b"synthetic fixture designated secret"
        atomic(self.root / "inbox/quarantined.txt", secret)
        incidents.quarantine(self.vault, "inbox/quarantined.txt", "human")
        with self.assertRaisesRegex(Blocked, "Known secret must remain in quarantine"):
            self.capture("another-name.txt", secret)

    def test_minimal_source_requires_verified_purpose_and_custody_copies(self):
        body = b"sensitive source to review"
        _, purpose = self.triage("sensitive.txt", body, "sensitive")
        _, unrelated = self.triage("other.txt", b"different bytes", "sensitive")
        initial = custody.materials(self.vault)[purpose["link"]]
        hold = custody.hold(self.vault, initial["id"], "Preserve pending rights", "human")
        for invalid in (None, {**purpose, "purpose": "different"}, {**purpose, "link": "missing"}, unrelated):
            with self.subTest(purpose=invalid):
                row = self.proposal(body, "sensitive", **({"purpose": invalid} if invalid is not None else {}))
                with self.assertRaisesRegex(Blocked, "purpose|custody"):
                    transactions.prepare(self.vault, self.source_task["id"], cutoff=CUT)
                self.assertFalse((self.root / row["path"]).exists())
        atomic(self.root / "inbox/copy-sensitive.txt", body)
        inbox.inventory(self.vault)
        row = self.proposal(body, "sensitive", purpose=purpose)
        transactions.apply(self.vault, self.approved())
        material = custody.materials(self.vault)[initial["id"]]
        self.assertEqual(custody.retention_deadline(material), custody.retention_deadline(initial))
        self.assertEqual(material["holds"], [hold])
        self.assertCountEqual([copy["path"] for copy in material["copies"]], ["sensitive.txt", "copy-sensitive.txt", row["path"]])
        previous = tasks.get_task(self.vault, self.source_task["id"])
        previous["capacity_held"] = False
        atomic(tasks.task_path(self.vault, previous["id"]), previous)
        del self.source_task
        parent = admission.source_rows(self.vault)[row["id"]]
        body = b"Reviewed minimum from the sensitive origin"
        derivative = self.proposal(body, "sensitive", purpose=purpose,
            origin={"format": ORIGIN, "kind": "derived", "method": "Minimum extract", "sources": [self.ref(parent)]})
        transactions.apply(self.vault, self.approved())
        self.assertNotEqual(derivative["sha256"], parent["sha256"])
        self.assertEqual((self.root / derivative["path"]).read_bytes(), body)
        material = custody.materials(self.vault)[initial["id"]]
        self.assertEqual(custody.retention_deadline(material), custody.retention_deadline(initial))
        self.assertIn(derivative["path"], [copy["path"] for copy in material["copies"]])

    def test_legacy_custody_adoption_preserves_claim_and_reports_class_conflicts(self):
        body = b"Legacy record preserved in Git"
        _, purpose = self.triage("legacy.txt", body, "sensitive")
        source = {"id": "F-0001", "path": "resources/sources/F-0001/original.txt", "sha256": digest(body),
                  "size": len(body), "captured_at": CAPTURE, "provenance": "Historic capture", "classification": "sensitive",
                  "purpose": purpose}
        atomic(self.root / source["path"], body)
        self.rows(originals.REGISTRY, [source])
        self.knowledge([self.claim_for([source])])
        git(self.root, "add", "--", "control/approvals", "wiki", "resources/sources")
        git(self.root, "commit", "-m", "Retain legacy source and signature")
        before = self.vault.head()
        signed = (self.root / transactions.LEDGER).read_bytes()
        manifest = (self.root / originals.REGISTRY).read_bytes()
        self.assertEqual(admission.reconcile_sources(self.vault)["status"], "complete")
        material = custody.materials(self.vault)[purpose["link"]]
        self.assertEqual(custody.retention_deadline(material).isoformat(), "2026-04-08T00:00:00+00:00")
        self.assertIn(source["path"], [copy["path"] for copy in material["copies"]])
        self.assertEqual(self.vault.head(), before)
        self.assertEqual((self.root / originals.REGISTRY).read_bytes(), manifest)
        self.assertEqual((self.root / transactions.LEDGER).read_bytes(), signed)
        self.assertEqual(query(self.vault, {}, CUT)["code"], 0)
        item_path = self.vault.control / "inbox.json"
        items = read_json(item_path)
        items[source["sha256"]]["classification"] = "common"
        atomic(item_path, items)
        report = admission.reconcile_sources(self.vault)
        self.assertEqual(report["status"], "pending")
        self.assertIn("Conflicting source classifications", report["sources"][0]["reason"])
        self.assertEqual(custody.materials(self.vault)[purpose["link"]], material)
        self.assertEqual((self.root / transactions.LEDGER).read_bytes(), signed)

    def test_signed_reclassification_binds_authority_revision_policy_and_copies(self):
        body = b"prior sensitive capture"
        item, purpose = self.triage("sensitive.txt", body, "sensitive")
        sha = item["sha256"]
        request = {"classification": "common", "reason": "Consent and policy permit common reuse"}
        with self.assertRaisesRegex(Blocked, "authority"):
            admission.sign_reclassification(self.vault, sha, request)
        self.vault.config["source_classification_authorities"] = ["human"]
        atomic(self.vault.config_path, self.vault.config)
        stale = admission.sign_reclassification(self.vault, sha, request)
        self.triage("sensitive.txt", body, "sensitive")
        with self.assertRaisesRegex(Blocked, "stale material revision"):
            admission.reclassify(self.vault, stale)
        with self.assertRaisesRegex(Blocked, "authorized reclassification"):
            inbox.decide(self.vault, sha, "ingest", owner="human", classification="common", destination="vault")
        signed = admission.sign_reclassification(self.vault, sha, request)
        tampered = copy.deepcopy(signed)
        tampered["payload"]["reason"] = "Different unsigned reason"
        with self.assertRaisesRegex(Blocked, "Signed payload was changed"):
            admission.reclassify(self.vault, tampered)
        event = admission.reclassify(self.vault, signed)
        policy = event["approval"]["payload"]
        self.assertEqual((policy["actor"], policy["from"], policy["to"], policy["reason"]),
                         ("human", ["sensitive"], "common", request["reason"]))
        self.assertTrue(policy["policy"] and policy["revision"] and event["receipt"] and policy["copies"])
        initial = custody.materials(self.vault)[purpose["link"]]
        public = self.capture("now-common.txt", body)
        material = custody.materials(self.vault)[purpose["link"]]
        self.assertEqual(custody.retention_deadline(material), custody.retention_deadline(initial))
        self.assertIn(public["path"], [copy["path"] for copy in material["copies"]])

    def test_apply_rechecks_before_effects_and_withdraws_interrupted_writes(self):
        first = b"first signed common capture"
        row = self.proposal(first)
        approval = self.approved()
        self.triage("first.txt", first, "sensitive")
        with self.assertRaisesRegex(Blocked, "recorded classification is sensitive"):
            transactions.apply(self.vault, approval)
        self.assertFalse((self.root / row["path"]).exists())
        self.assertIsNone(read_json(self.vault.control / "transaction.json"))
        second = b"second signed common capture"
        row = self.proposal(second)
        approval = self.approved()
        original_manifest = (self.root / originals.REGISTRY).read_bytes()
        base = self.vault.head()

        def interrupted(path, body):
            atomic(path, body)
            if Path(path) == self.root / row["path"]:
                raise OSError("interrupted after original and manifest write")

        with patch("healdan.transactions.atomic", side_effect=interrupted), self.assertRaisesRegex(OSError, "interrupted"):
            transactions.apply(self.vault, approval)
        self.assertEqual((self.root / row["path"]).read_bytes(), second)
        _, purpose = self.triage("second.txt", second, "sensitive")
        with self.assertRaisesRegex(Blocked, "recorded classification is sensitive"):
            transactions.apply(self.vault, recover=True)
        self.assertEqual(read_json(self.vault.control / "transaction.json")["status"], "aborted")
        self.assertEqual(self.vault.head(), base)
        self.assertFalse((self.root / row["path"]).exists())
        self.assertEqual((self.root / originals.REGISTRY).read_bytes(), original_manifest)
        self.assertEqual((self.root / "inbox/second.txt").read_bytes(), second)
        self.assertEqual([copy["path"] for copy in custody.materials(self.vault)[purpose["link"]]["copies"]], ["second.txt"])
