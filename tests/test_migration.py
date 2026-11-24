import base64
import copy
from uuid import uuid4

from support import VaultTest
from healdan import ids, regression, review
from healdan.core import Blocked, atomic, canonical, decode, digest, git, jsonl, read_json
from healdan.signing import verify


class Migration(VaultTest):
    def sampled_package(self, claims):
        units = {row["id"]: digest(row) for row in claims}
        earlier = {"streak": 111, "package": "1" * 64}
        plan = review.freeze_csp(units, earlier, "02" * 32)
        self.assertEqual(review.csp_status(plan)["pending"], ["C-0001"])
        self.assertTrue(review.inspect(plan, {"C-0001": "conform"})["complete"])
        payload = {"task": str(uuid4()), "base": self.vault.head(), "fingerprint": self.vault.fingerprint(),
                   "files": {"wiki/claims.jsonl": base64.b64encode(jsonl(claims)).decode("ascii")},
                   "claim_digests": units, "cutoff": "2026-06-01T00:00:00Z", "review": None, "regression": {}}
        package_id = digest(payload)
        return self.signed(dict(payload, package_id=package_id, csp=plan), "package")

    def test_legacy_case_and_sampled_package_preview_are_read_only(self):
        claims = [self.claim(f"C-{number:04d}", modality="relato_operacional") for number in range(1, 4)]
        approved = self.sampled_package(claims)
        package_id = approved["payload"]["package_id"]
        self.rows("wiki/claims.jsonl", claims)
        ledger_path = self.root / "control/approvals/packages.jsonl"
        ledger = b" " + canonical(approved) + b"\r\n"
        atomic(ledger_path, ledger)
        sequence = {"streak": 111, "package": package_id}
        sequence_path = self.vault.control / "csp.json"
        atomic(sequence_path, b" " + canonical(sequence) + b"\r\n")
        reported = self.case(id="Q-1", filters={"entity": "instrument", "modality": "relato_operacional"},
                             expected_ids=[row["id"] for row in claims])
        factual = self.case(id="Q-2", filters={"entity": "instrument", "modality": "fato_operacional"},
                            expected_ids=[], expected_value=None, expected_polarity=None, outcome="abstention")
        cases_path = self.root / regression.CASE_REGISTRY
        first_row = b" \t" + canonical(reported) + b" \r\n"
        atomic(cases_path, first_row + canonical(factual))
        git(self.root, "add", "--", "resources/sources/F-0001/original.txt")
        git(self.root, "commit", "-am", "Preserve archived signed cases and sampled approval")
        self.assertEqual(ids.reserve(self.vault, "Q", 1, str(uuid4())), ["Q-0003"])

        tracked = [cases_path, ledger_path, self.root / "wiki/claims.jsonl",
                   sequence_path, self.vault.control / "reservations.json"]
        before = {path: path.read_bytes() for path in tracked}
        receipts = self.vault.control / "receipts"
        before_receipts = {path: path.read_bytes() for path in receipts.glob("*.json")}
        head = self.vault.head()
        code, result = self.cli("migration", "preview")
        self.assertEqual(code, 0, result)
        self.assertEqual(self.cli("migration", "preview"), (code, result))

        case, other = [record["projection"] for record in result["cases"]]
        self.assertEqual(case["case"]["format"], regression.CASE_FORMAT_V2)
        self.assertEqual(case["case"]["id"], "Q-1")
        self.assertEqual(case["case"]["filters"]["modality"], "relato_operacional")
        self.assertEqual(case["case"]["expectation"], {"ids": reported["expected_ids"],
                         "value": reported["expected_value"], "polarity": reported["expected_polarity"],
                         "outcome": "answer", "conflicts": []})
        self.assertEqual(other["case"]["expectation"]["outcome"], "abstention")
        self.assertEqual(other["case"]["filters"]["modality"], "fato_operacional")
        self.assertEqual(base64.b64decode(other["origin"]["row_base64"]), canonical(factual))
        origin = case["origin"]
        self.assertEqual(origin["format"], regression.CASE_FORMAT_V1)
        self.assertEqual(base64.b64decode(origin["row_base64"]), first_row)
        self.assertEqual(origin["row_sha256"], digest(first_row))
        self.assertEqual(origin["payload_sha256"], reported["approval"]["digest"])
        self.assertEqual(origin["approval"], reported["approval"])
        self.assertEqual(regression.verify_case_projection(self.vault, first_row, case), case)

        package, = result["packages"]
        projected = package["projection"]
        self.assertEqual(projected["origin"]["format"], "healdan-approval-package-v1")
        self.assertEqual(base64.b64decode(projected["origin"]["row_base64"]), ledger)
        self.assertEqual(projected["origin"]["approval"], approved)
        self.assertEqual(projected["plan"], approved["payload"]["csp"])
        self.assertEqual((projected["id"], projected["scope"]), (package_id, "sampled"))
        self.assertEqual(projected["inspected"], ["C-0001"])
        self.assertEqual(projected["outside_sample"], ["C-0002", "C-0003"])
        self.assertEqual(projected["final_streak"], 111)
        self.assertEqual(result["inspection_sequence"]["state"], sequence)
        self.assertEqual(result["inspection_sequence"]["sha256"], digest(before[sequence_path]))
        self.assertEqual(result["inspection_sequence"]["new_regime"],
                         {"human_decision_required": True, "new_sequence_required": True})
        for claim, coverage in zip(result["claims"], ("inspected", "outside_sample", "outside_sample"), strict=True):
            self.assertEqual(claim["authority_status"], "undetermined")
            self.assertIn("authority", claim["pending_fields"])
            self.assertEqual(claim["modality"], "relato_operacional")
            self.assertEqual(claim["approvals"], [{"package_id": package_id, "rule": review.CSP_RULE_V1,
                                                    "inspection": coverage}])

        code, suite = self.cli("review", "regression")
        self.assertEqual(code, 0, suite)
        self.assertEqual([(row["id"], row["status"], row["actual"]["code"]) for row in suite["results"]],
                         [("Q-1", "passed", 0), ("Q-2", "passed", 20)])
        self.assertEqual(self.vault.head(), head)
        self.assertEqual({path: path.read_bytes() for path in tracked}, before)
        self.assertEqual({path: path.read_bytes() for path in receipts.glob("*.json")}, before_receipts)

    def test_rejects_changes_to_projection_and_its_signed_origin(self):
        signed_case = self.case(id="Q-1")
        original = b" " + canonical(signed_case) + b"\r\n"
        case_path = self.root / regression.CASE_REGISTRY
        atomic(case_path, original)
        projection = next(regression.case_projections(self.vault))["projection"]
        for field, replacement in (("payload", {}), ("digest", "0" * 64), ("signature", "invalid")):
            with self.subTest(field=field):
                changed = copy.deepcopy(projection)
                changed["origin"]["approval"][field] = replacement
                with self.assertRaisesRegex(Blocked, "differs from its verified origin"):
                    regression.verify_case_projection(self.vault, original, changed)
                row = decode(original)
                row["approval"][field] = replacement
                with self.assertRaises(Blocked):
                    regression.verify_case_projection(self.vault, jsonl([row]), projection)
        changed = copy.deepcopy(projection)
        changed["case"]["expectation"]["value"]["value"] = 43
        self.assertEqual(changed["origin"]["approval"], projection["origin"]["approval"])
        with self.assertRaisesRegex(Blocked, "differs from its verified origin"):
            regression.verify_case_projection(self.vault, original, changed)
        case = decode(original)
        case["expected_value"]["value"] = 43
        with self.assertRaisesRegex(Blocked, "Case signature does not cover expectation"):
            regression.verify_case_projection(self.vault, jsonl([case]), projection)
        with self.assertRaisesRegex(Blocked, "differs from its verified origin"):
            regression.verify_case_projection(self.vault, jsonl([signed_case]), projection)

    def test_current_case_and_pending_future_fields_and_namespaces(self):
        current = {"format": regression.CASE_FORMAT_V2, "id": "Q-0001", "question": "Any evidence?",
                   "filters": {}, "cutoff": "2026-06-01T00:00:00Z", "temporal_policy": None,
                   "expectation": {"ids": [], "value": None, "polarity": None, "outcome": "abstention", "conflicts": []},
                   "reason": "Reviewed the empty fixture", "decision": {"owner": "human", "at": "2026-06-01T00:00:00Z"}}
        input_path, output_path = self.base / "case in.json", self.base / "case signed.json"
        atomic(input_path, current)
        code, result = self.cli("review", "sign-case", input_path, "--output", output_path)
        self.assertEqual(code, 0, result)
        signed_current = read_json(output_path)
        self.assertEqual(verify(signed_current["approval"], "case", self.signers), current)
        future = self.case(id="Q-2", format="healdan-query-case-v99")
        unknown = self.case(id="Q-3", decision={"owner": "human", "at": "2026-06-01T00:00:00Z",
                                               "authority": "new field"})
        wrong_domain = self.case(id="Q-4")
        wrong_domain.pop("approval")
        unrelated = self.signed(wrong_domain.copy(), "package")
        wrong_domain["approval"] = dict(unrelated, namespace="case")
        self.rows(regression.CASE_REGISTRY, [signed_current, future, unknown, wrong_domain])

        code, preview = self.cli("migration", "preview")
        self.assertEqual(code, 5, preview)
        good, future_result, unknown_result, wrong_result = preview["cases"]
        self.assertEqual(good["projection"]["case"], current)
        self.assertEqual(good["projection"]["origin"]["format"], regression.CASE_FORMAT_V2)
        self.assertIn("Unknown case format", future_result["reason"])
        self.assertIn("Case decision fields are incomplete or unknown", unknown_result["reason"])
        self.assertIn("Invalid human SSH signature", wrong_result["reason"])
        code, result = self.cli("review", "regression")
        self.assertEqual((code, result["passed"], result["pending"]), (5, 1, 3))

    def test_unknown_inspection_regime_requires_its_own_sequence(self):
        claims = [self.claim(f"C-{number:04d}") for number in range(1, 4)]
        approved = self.sampled_package(claims)
        payload = approved["payload"]
        plan = dict(payload["csp"], rule="different-review-regime")
        legacy = self.signed(dict(payload, csp=plan), "package")
        content = {key: value for key, value in payload.items() if key not in {"package_id", "csp"}}
        content["input_hashes"] = self.vault.inputs()
        current = self.signed(dict(content, package_id=digest(content), csp=payload["csp"]), "package")
        invalid_plan = dict(payload["csp"], inspections={"C-0001": "conform", "C-0002": "conform"})
        invalid_scope = self.signed(dict(payload, csp=invalid_plan), "package")
        self.rows("control/approvals/packages.jsonl", [legacy, current, invalid_scope])
        state = {"rule": "different-review-regime", "streak": 111}
        sequence = self.vault.control / "csp.json"
        atomic(sequence, state)
        before = sequence.read_bytes()

        with self.assertRaisesRegex(Blocked, "separate human decision and a new sequence"):
            review.freeze_csp(payload["claim_digests"], state)
        code, result = self.cli("migration", "preview")
        self.assertEqual(code, 5, result)
        package, known, incomplete = result["packages"]
        self.assertEqual(package["status"], "pending")
        self.assertIn("Unknown inspection regime", package["reason"])
        self.assertEqual(known["projection"]["origin"]["format"], "healdan-approval-package-v2")
        self.assertEqual(known["projection"]["outside_sample"], ["C-0002", "C-0003"])
        self.assertEqual(incomplete["status"], "pending")
        self.assertIn("Signed inspection proof is incomplete or inconsistent", incomplete["reason"])
        self.assertEqual(result["inspection_sequence"]["status"], "pending")
        self.assertEqual(result["inspection_sequence"]["state"], state)
        self.assertEqual(sequence.read_bytes(), before)

    def test_corrupt_inspection_state_keeps_compatible_cli_projections(self):
        claims = [self.claim(f"C-{number:04d}") for number in range(1, 4)]
        approved = self.sampled_package(claims)
        case = self.case(id="Q-1", expected_ids=[claim["id"] for claim in claims])
        self.rows("wiki/claims.jsonl", claims)
        self.rows("control/approvals/packages.jsonl", [approved])
        self.rows(regression.CASE_REGISTRY, [case])
        sequence_path = self.vault.control / "csp.json"
        known = {"streak": 111, "package": approved["payload"]["package_id"]}
        atomic(sequence_path, b"\xef\xbb\xbf" + canonical(known) + b"\r\n")
        code, baseline = self.cli("migration", "preview")
        self.assertEqual(code, 0, baseline)
        self.assertEqual(baseline["cases"][0]["status"], "compatible")
        self.assertEqual(baseline["packages"][0]["status"], "compatible")
        self.assertEqual(baseline["inspection_sequence"]["state"], known)
        self.assertEqual(review.read_csp_state(self.vault), known)
        before = self.vault.inputs()

        for description, original, diagnostic in (
            ("truncated JSON", b'{"streak":111,\r\n', "Expecting property name"),
            ("invalid UTF-8", b'{"streak":111,"package":"\xff"}', "utf-8"),
            ("UTF-8 surrogate", b'{"streak":111,"package":"\xed\xa0\x80"}', "utf-8"),
            ("unpaired escaped surrogate", b'{"streak":111,"package":"\\ud800"}', "surrogates not allowed"),
        ):
            with self.subTest(state=description):
                atomic(sequence_path, original)
                code, result = self.cli("migration", "preview")
                self.assertEqual(code, 5, result.get("error"))
                state = result["inspection_sequence"]
                self.assertEqual(state["status"], "pending")
                self.assertIsNone(state["state"])
                self.assertEqual(state["sha256"], digest(original))
                self.assertIn("Invalid JSON", state["reason"])
                self.assertIn(diagnostic, state["reason"])
                for key in ("cases", "packages", "claims"):
                    self.assertEqual(result[key], baseline[key])
                with self.assertRaisesRegex(Blocked, "Invalid JSON") as raised:
                    review.read_csp_state(self.vault)
                self.assertEqual(raised.exception.code, 4)
                self.assertEqual(sequence_path.read_bytes(), original)
                self.assertEqual(self.vault.inputs(), before)
