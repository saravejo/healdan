import base64
import copy
from datetime import timedelta
import os
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from support import VaultTest
import test_transactions
from healdan import admission, custody, inbox, incidents, originals, pages, tasks, transactions
from healdan.core import INGEST_JOURNAL, Blocked, atomic, digest, git, jsonl, read_json, utc
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

    def test_unmerged_page_ancestry_cannot_supply_claim_revisions(self):
        side_evidence = self.capture("side.txt", b"Synthetic evidence on the side")
        main_evidence = self.capture("main.txt", b"Synthetic evidence on the main history")
        git(self.root, "add", "--", "resources/sources")
        git(self.root, "commit", "-m", "Preserve both observations")
        side = self.base / "side worktree"
        git(self.root, "worktree", "add", "-b", "side-history", side, "HEAD")
        name = "wiki/topics/instrument.md"
        body = b'<!-- healdan:current:start -->\n<a id="C-0001"></a>\n<!-- healdan:current:end -->\n'
        side_claim = self.claim_for([side_evidence])
        atomic(side / name, body)
        atomic(side / "wiki/claims.jsonl", jsonl([side_claim]))
        git(side, "add", "--", "wiki")
        git(side, "commit", "-m", "Publish side-only legacy page ancestry")
        main_head = self.vault.head()
        copied = self.capture("copied-page.md", body)
        self.assertEqual(copied["origin"]["kind"], "wiki")
        self.assertEqual(copied["origin"]["pages"], [])
        claim = self.claim_for([copied], id="C-0002", entity="copied-page", minimum_observations=1)
        self.knowledge([side_claim, claim])
        result = query(self.vault, {"entity": "copied-page"}, CUT)
        self.assertEqual(result["code"], 20, result)
        self.assertIn("lacks verified claim lineage", " ".join(result["diagnostics"]))
        self.assertEqual(self.vault.head(), main_head)

        main_claim = self.claim_for([main_evidence])
        self.knowledge([main_claim, claim])
        atomic(self.root / name, body)
        git(self.root, "add", "--", "wiki", "resources/sources", "control/approvals")
        git(self.root, "commit", "-m", "Publish the same legacy page bytes with main ancestry")
        result = query(self.vault, {"entity": "copied-page"}, CUT)
        self.assertEqual(result["code"], 0, result)
        self.assertEqual(result["observations"], [main_evidence["sha256"]])

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

    def test_identical_conversions_cannot_change_established_parents(self):
        first = self.capture("first.txt", b"First independent capture")
        second = self.capture("second.txt", b"Second independent capture")
        body = b"Identical conversion result"
        original = self.capture("converted.txt", body, [first])
        copy_row = self.capture("copy.txt", body)
        self.assertEqual(copy_row["origin"]["sources"], original["origin"]["sources"])
        self.knowledge([self.claim_for([original, copy_row], minimum_observations=2)])
        result = query(self.vault, {}, CUT)
        self.assertEqual(result["code"], 20, result)
        self.assertEqual(result["observations"], [first["sha256"]])
        manifest = (self.root / originals.REGISTRY).read_bytes()
        with self.assertRaisesRegex(Blocked, "identical source bytes have conflicting conversion parents"):
            self.capture("conflicting.txt", body, [second])
        self.assertEqual((self.root / originals.REGISTRY).read_bytes(), manifest)
        self.assertFalse((self.root / "resources/sources/F-0005").exists())

        # A signed record from an older installation remains intact and ineligible when its origins disagree.
        disputed = {**copy_row, "origin": {**copy_row["origin"], "sources": [self.ref(second)]}}
        self.rows(originals.REGISTRY, [first, second, original, disputed])
        self.knowledge([self.claim_for([original, disputed], minimum_observations=2)])
        approval = (self.root / transactions.LEDGER).read_bytes()
        result = query(self.vault, {}, CUT)
        self.assertEqual(result["code"], 20, result)
        self.assertEqual(result["observations"], [])
        self.assertIn("conflicting conversion parents", " ".join(result["diagnostics"]))
        self.assertEqual((self.root / transactions.LEDGER).read_bytes(), approval)

        # The reviewed proposal route uses the same byte identity rule.
        self.rows(originals.REGISTRY, [first, second, original, copy_row])
        self.rows("wiki/claims.jsonl", [])
        git(self.root, "add", "--", "resources/sources", "wiki", "control/approvals")
        git(self.root, "commit", "-m", "Preserve the expected conversion lineage")
        proposed = self.proposal(body, origin=disputed["origin"])
        with self.assertRaisesRegex(Blocked, "identical source bytes have conflicting conversion parents"):
            transactions.prepare(self.vault, self.source_task["id"], cutoff=CUT)
        self.assertFalse((self.root / proposed["path"]).exists())

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

    def test_unknown_deferral_allows_first_triage_without_resetting_custody(self):
        body = b"Deferral pending the first explicit decision"
        source = "inbox/deferred.txt"
        sha = digest(body)
        material_id = "inbox-" + sha
        atomic(self.root / source, body)
        inbox.inventory(self.vault)
        deferred = inbox.decide(self.vault, sha, "defer", owner="human", classification="unknown",
            entered_at=CAPTURE, entry_origin="Original fixture receipt", defer_until=utc() + timedelta(days=1),
            purpose={"purpose": "Pending decision", "necessity": "Review required", "owner": "human", "link": material_id})
        hold = custody.hold(self.vault, material_id, "Preserve pending material", "human")
        initial = custody.materials(self.vault)[material_id]
        receipt_path = self.vault.control / "receipts" / (deferred["decision_receipt"] + ".json")
        old = receipt_path.read_bytes()
        with self.assertRaisesRegex(Blocked, "recorded classification is unknown"):
            self.capture("deferred.txt", body)
        with self.assertRaisesRegex(Blocked, "cannot reset"):
            inbox.decide(self.vault, sha, "ingest", owner="human", classification="common",
                         entered_at="2026-04-02T00:00:00Z", entry_origin="Later", destination="Reviewed")

        def stop_before_inbox(path, body):
            if Path(path) == self.vault.control / "inbox.json":
                raise OSError("Interrupted after saving first classification in custody")
            return atomic(path, body)

        with patch("healdan.inbox.atomic", side_effect=stop_before_inbox), self.assertRaisesRegex(OSError, "Interrupted"):
            inbox.decide(self.vault, sha, "ingest", owner="human", classification="common", destination="Reviewed")
        with self.assertRaisesRegex(Blocked, "Conflicting source classifications"):
            self.capture("deferred.txt", body)
        classified = inbox.decide(self.vault, sha, "ingest", owner="human", classification="common", destination="Reviewed")
        self.assertEqual(classified["classification"], "common")
        self.assertEqual(classified["entered_at"], deferred["entered_at"])
        self.assertIsNone(classified["defer_until"])
        self.assertIn(deferred["decision_receipt"], classified["receipts"])
        self.assertEqual(receipt_path.read_bytes(), old)
        self.assertEqual(self.capture("deferred.txt", body)["classification"], "common")
        current = custody.materials(self.vault)[material_id]
        self.assertEqual(current["holds"], [hold])
        self.assertEqual(custody.retention_deadline(current), custody.retention_deadline(initial))
        with self.assertRaisesRegex(Blocked, "authorized reclassification"):
            inbox.decide(self.vault, sha, "archive", owner="human", classification="mixed", destination="Reviewed")

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

    def test_reclassification_of_derivative_checks_current_origin_restriction(self):
        parent = self.capture("parent.txt", b"Observation initially common")
        git(self.root, "add", "--", "resources/sources")
        git(self.root, "commit", "-m", "Preserve observation")
        body = b"Reviewed extract registered under restricted terms"
        _, purpose = self.triage("extract.txt", body, "sensitive")
        self.vault.config["source_classification_authorities"] = ["human"]
        atomic(self.vault.config_path, self.vault.config)
        self.proposal(body, "sensitive", purpose=purpose,
                      origin={"format": ORIGIN, "kind": "derived", "method": "extract", "sources": [self.ref(parent)]})
        transactions.apply(self.vault, self.approved())
        downgrade = {"classification": "common", "reason": "Permission would allow common reuse"}
        previous = admission.sign_reclassification(self.vault, digest(body), downgrade)
        parent_decision = admission.sign_reclassification(self.vault, parent["sha256"],
            {"classification": "sensitive", "reason": "Source requires restricted handling"})
        admission.reclassify(self.vault, parent_decision)
        decision_path = self.vault.control / admission.DECISIONS
        decisions = decision_path.read_bytes()
        receipts = set((self.vault.control / "receipts").glob("*.json"))
        with self.assertRaisesRegex(Blocked, "derivative inherits sensitive"):
            admission.sign_reclassification(self.vault, digest(body), downgrade)
        with self.assertRaisesRegex(Blocked, "derivative inherits sensitive"):
            admission.reclassify(self.vault, previous)
        self.assertEqual(decision_path.read_bytes(), decisions)
        self.assertEqual(set((self.vault.control / "receipts").glob("*.json")), receipts)
        self.assertEqual(admission.Classification(self.vault, admission.source_rows(self.vault)).current(digest(body)),
                         ("sensitive", None))

    def test_ingestion_resumes_original_identity_before_manifest_and_receipt(self):
        journal_path = self.vault.control / INGEST_JOURNAL
        for number, phase in enumerate(("link", "manifest", "receipt"), 1):
            with self.subTest(phase=phase):
                body = f"Exact capture {phase}\r\n".encode()
                name = phase + ".txt"
                if phase == "link":
                    original_link = os.link
                    def interrupted(source, destination):
                        original_link(source, destination)
                        raise OSError("Interrupted after original publication")
                    fault = patch("healdan.admission.os.link", side_effect=interrupted)
                elif phase == "manifest":
                    def interrupted(path, data):
                        if Path(path) == self.root / originals.REGISTRY:
                            raise OSError("Interrupted after original publication")
                        return atomic(path, data)
                    fault = patch("healdan.admission.atomic", side_effect=interrupted)
                else:
                    receipt = self.vault.receipt
                    def interrupted(kind, payload, **kwargs):
                        if kind == "source-ingest":
                            raise OSError("Interrupted after original publication")
                        return receipt(kind, payload, **kwargs)
                    fault = patch.object(self.vault, "receipt", side_effect=interrupted)
                with fault, self.assertRaisesRegex(OSError, "Interrupted"):
                    self.capture(name, body)
                intent = read_json(journal_path)
                expected = intent["record"]
                self.assertEqual(intent["status"], "writing")
                self.assertEqual((self.root / expected["path"]).read_bytes(), body)
                resumed = self.capture(name, body)
                self.assertEqual(resumed, expected)
                self.assertEqual(resumed["id"], f"F-{number:04d}")
                self.assertEqual(self.capture(name, body), expected)
                self.assertEqual(read_json(journal_path)["status"], "complete")
                self.assertEqual(len(list((self.root / "resources/sources").glob("*/original.txt"))), number)
                self.assertEqual(len(self.vault.rows(originals.REGISTRY)), number)
                receipts = [read_json(path) for path in (self.vault.control / "receipts").glob("*.json")]
                self.assertEqual(sum(r["kind"] == "source-ingest" for r in receipts), number)

    def test_ingestion_preserves_concurrent_original_and_rechecks_current_classification(self):
        body = b"Capture subject to the current Inbox policy"
        target = self.root / "resources/sources/F-0001/original.txt"
        real_link = os.link

        def competing(stage, destination):
            if Path(destination) == target:
                atomic(target, b"Concurrent distinct bytes")
            return real_link(stage, destination)

        with patch("healdan.admission.os.link", side_effect=competing), self.assertRaisesRegex(Blocked, "Concurrent edit"):
            self.capture("original.txt", body)
        self.assertEqual(target.read_bytes(), b"Concurrent distinct bytes")
        self.assertEqual(self.vault.rows(originals.REGISTRY), [])
        with self.assertRaisesRegex(Blocked, "Concurrent edit"):
            self.capture("original.txt", body)
        self.assertEqual(target.read_bytes(), b"Concurrent distinct bytes")
        target.unlink()

        def interrupt_receipt(kind, payload, **kwargs):
            if kind == "source-admission":
                raise OSError("Interrupted after manifest write")
            return receipt(kind, payload, **kwargs)

        receipt = self.vault.receipt
        with patch.object(self.vault, "receipt", side_effect=interrupt_receipt), self.assertRaisesRegex(OSError, "Interrupted"):
            self.capture("original.txt", body)
        self.assertEqual(target.read_bytes(), body)
        self.assertEqual(len(self.vault.rows(originals.REGISTRY)), 1)
        _, purpose = self.triage("original.txt", body, "sensitive")
        with self.assertRaisesRegex(Blocked, "recorded classification is sensitive"):
            self.capture("original.txt", body)
        self.assertEqual(read_json(self.vault.control / INGEST_JOURNAL)["status"], "aborted")
        self.assertEqual(self.vault.rows(originals.REGISTRY), [])
        self.assertFalse(target.exists())
        self.assertEqual((self.root / "inbox/original.txt").read_bytes(), body)
        self.assertEqual([c["path"] for c in custody.materials(self.vault)[purpose["link"]]["copies"]], ["original.txt"])

    def test_ingestion_withdrawal_after_quarantine_requires_verified_copy_and_ownership(self):
        self.age()
        journal_path = self.vault.control / INGEST_JOURNAL
        link, receipt = os.link, self.vault.receipt
        for mode in ("created", "reused"):
            with self.subTest(mode=mode):
                relative = f"inbox/{mode}.txt"
                origin = self.root / relative
                body = f"Synthetic capture for quarantine ({mode})".encode()
                atomic(origin, body)

                def before_link(stage, destination):
                    if mode == "reused":
                        atomic(destination, body)
                    return link(stage, destination)

                def interrupt(kind, payload, **kwargs):
                    if kind == "source-admission":
                        raise OSError("Interrupted before completing ingestion")
                    return receipt(kind, payload, **kwargs)

                def retry():
                    return admission.ingest(self.vault, relative, provenance="Disposable evidence",
                                            captured_at=CAPTURE, classification="common")

                with patch("healdan.admission.os.link", side_effect=before_link), patch.object(
                        self.vault, "receipt", side_effect=interrupt), self.assertRaisesRegex(OSError, "Interrupted"):
                    retry()
                intent = read_json(journal_path)
                target = self.root / intent["record"]["path"]
                self.assertEqual(intent["file"], mode)
                pending_manifest = (self.root / originals.REGISTRY).read_bytes()
                origin.unlink()
                with self.assertRaisesRegex(Blocked, "no verified quarantine copy"):
                    retry()
                self.assertEqual(target.read_bytes(), body)
                self.assertEqual((self.root / originals.REGISTRY).read_bytes(), pending_manifest)
                self.assertEqual(read_json(journal_path)["status"], "writing")

                atomic(origin, body)
                quarantine = incidents.quarantine(self.vault, relative, "human")
                record = custody.materials(self.vault)[quarantine["material"]]
                ciphertext = record["copies"][0]
                encrypted = Path(ciphertext["root"]) / ciphertext["path"]
                saved = encrypted.read_bytes()
                atomic(encrypted, b"Different ciphertext")
                with self.assertRaisesRegex(Blocked, "no verified quarantine copy"):
                    retry()
                self.assertEqual(target.read_bytes(), body)
                atomic(encrypted, saved)
                with self.assertRaisesRegex(Blocked, "withdrawn after verified quarantine"):
                    retry()
                self.assertEqual(self.vault.rows(originals.REGISTRY), [])
                self.assertEqual(read_json(journal_path)["status"], "aborted")
                self.assertEqual(target.exists(), mode == "reused")
                self.assertEqual(encrypted.read_bytes(), saved)

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
