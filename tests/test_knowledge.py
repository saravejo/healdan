import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from support import VaultTest
from healdan.core import Blocked, REQUIRED_REGISTRIES, Vault, atomic, digest
from healdan.knowledge import Knowledge, query, typed
from healdan.pages import preview, render_current, split_preview, validate_pages
from healdan.regression import sign_case, suite, require_suite
from healdan.setup import initialize
from healdan.signing import verify


class Query(VaultTest):
    def test_empty_abstention_and_integrity_failure_are_distinct(self):
        claim = self.claim()
        self.knowledge([claim])
        self.rows("wiki/control/decisions.jsonl", [{"id": "D-0001"}])
        self.assertEqual(self.cli("query", "--entity", "instrument")[0], 0)
        self.rows("wiki/control/decisions.jsonl", [])
        self.assertEqual(self.cli("query", "--entity", "instrument")[0], 0)
        self.rows("wiki/claims.jsonl", [])
        self.assertEqual(self.cli("query", "--entity", "instrument")[0], 20)
        atomic(self.root / "wiki/claims.jsonl", b'{"broken":\n')
        self.assertEqual(self.cli("query", "--entity", "instrument")[0], 4)

    def test_missing_registries_block_new_and_already_open_vaults(self):
        self.assertEqual(len(REQUIRED_REGISTRIES), 9)
        self.knowledge([self.claim()])
        for name in REQUIRED_REGISTRIES:
            path = self.root / name
            before = path.read_bytes()
            with self.subTest(registry=name):
                try:
                    path.unlink()
                    code, result = self.cli("query", "--entity", "instrument")
                    self.assertEqual(code, 4)
                    self.assertIn(name, result["error"])
                    opened = query(self.vault, {"entity": "instrument"})
                    self.assertEqual(opened["code"], 4)
                    self.assertIn(name, opened["diagnostics"][0])
                finally:
                    atomic(path, before)

    def test_unreadable_registry_is_a_technical_failure(self):
        path = self.root / "wiki/control/decisions.jsonl"
        read_bytes = Path.read_bytes

        def unreadable(target):
            if target == path:
                raise PermissionError("Injected read failure")
            return read_bytes(target)

        with patch.object(Path, "read_bytes", unreadable):
            result = query(self.vault, {})
        self.assertEqual(result["code"], 1)
        self.assertIn("Injected read failure", result["diagnostics"][0])

    def test_unborn_vault_and_optional_page_policy(self):
        root, state = self.base / "unborn vault", self.base / "unborn state"
        initialize(root, state)
        vault = Vault(root, state)
        self.assertIsNone(vault.head())
        self.assertFalse((root / "wiki/control/page-policy.json").exists())
        self.assertEqual(vault.rows("wiki/control/selectors.jsonl"), [])
        validate_pages(vault)
        self.assertEqual(query(vault, {})["code"], 20)

    def test_source_capture_timestamp_errors_are_distinct_from_cutoff_arguments(self):
        self.knowledge([self.claim(valid_from="2026-01-01T00:00:00Z")])
        registry = "resources/sources/index.jsonl"
        row, = self.vault.rows(registry)
        row["captured_at"] = "2026-01-01T01:30:00+01:30"
        self.rows(registry, [row])
        code, result = self.cli("query", "--cutoff", "2026-01-01T01:00:00+01:00")
        self.assertEqual((code, result["cutoff"]), (0, "2026-01-01T00:00:00Z"))
        self.assertEqual(self.cli("query")[0], 0)
        self.assertEqual(self.cli("query", "--cutoff", "2026-01-01T00:00:00")[0], 2)
        without_capture = {name: value for name, value in row.items() if name != "captured_at"}
        invalid = [without_capture, *(dict(row, captured_at=value) for value in
                    (None, 123, "2026-02-30T00:00:00Z", "2026-01-01T00:00:00"))]
        for source in invalid:
            with self.subTest(captured_at=source.get("captured_at", "missing")):
                self.rows(registry, [source])
                code, result = self.cli("query")
                self.assertEqual(code, 4)
                self.assertIn("F-0001 captured_at", result["diagnostics"][0])

    def test_real_answer_and_missing_promotion(self):
        claim = self.claim()
        self.rows("wiki/claims.jsonl", [claim])
        self.assertEqual(query(self.vault, {"entity": "instrument"})["code"], 4)
        self.knowledge([claim])
        result = query(self.vault, {"entity": "instrument"})
        self.assertEqual((result["code"], result["value"]["value"], result["research"]), (0, 42, "complete"))

    def test_successor_term_traversal_and_cycle(self):
        old = self.claim(statement="old searchable name", state="superseded", successor="C-10000")
        new = self.claim("C-10000", statement="different wording")
        self.knowledge([old, new])
        result = query(self.vault, {"term": "searchable"})
        self.assertEqual(result["ids"], ["C-10000"])
        new["successor"] = old["id"]
        self.knowledge([old, new])
        self.assertEqual(query(self.vault, {})["code"], 4)

    def test_conflicts_cross_topics_and_negation(self):
        first = self.claim()
        second = self.claim("C-0002", primary_topic="other", polarity="negative")
        self.knowledge([first, second])
        result = query(self.vault, {"topic": "measurement"})
        self.assertEqual(result["code"], 3)
        self.assertEqual(result["conflicts"], ["C-0001", "C-0002"])
        self.assertIsNone(result["value"])

    def test_hypotheses_expiry_and_incomplete_research(self):
        self.knowledge([self.claim(state="hypothesis")])
        self.assertEqual(query(self.vault, {})["code"], 20)
        self.knowledge([self.claim(valid_to="2025-01-01T00:00:00Z")])
        self.assertEqual(query(self.vault, {}, "2026-01-01T00:00:00Z")["code"], 20)
        self.assertEqual(query(self.vault, {}, max_records=0)["code"], 5)
        self.assertEqual(query(self.vault, {"ingested_after": "2026"})["code"], 2)

    def test_boolean_is_not_integer_and_source_mutation(self):
        with self.assertRaises(Blocked):
            typed({"type": "integer", "value": True, "unit": None})
        self.knowledge([self.claim()])
        atomic(self.root / "resources/sources/F-0001/original.txt", b"tampered")
        self.assertEqual(query(self.vault, {})["code"], 4)

    def test_map_union_replacement_and_p5_share_resolution(self):
        self.knowledge([self.claim()])
        before = (self.root / "wiki/claims.jsonl").read_bytes()
        self.rows("wiki/control/topic-map.jsonl", [{"id": "C-0001", "topics": ["navigation"]}])
        self.assertEqual(query(self.vault, {"topic": "navigation"})["code"], 0)
        self.assertEqual(query(self.vault, {"topic": "measurement"})["code"], 0)
        self.rows("wiki/control/topic-map.jsonl", [{"id": "C-0001", "topics": ["navigation"], "replace_primary_topic": True}])
        self.assertEqual(query(self.vault, {"topic": "measurement"})["code"], 20)
        self.assertEqual(Knowledge(self.vault).topics("C-0001"), {"navigation"})
        self.assertEqual((self.root / "wiki/claims.jsonl").read_bytes(), before)

    def test_case_independent_signature_mutation_and_history(self):
        self.knowledge([self.claim()])
        case = self.case()
        self.rows("wiki/control/query-cases.jsonl", [case])
        self.assertEqual(suite(self.vault)["passed"], 1)
        case["expected_value"]["value"] = 43
        self.rows("wiki/control/query-cases.jsonl", [case])
        self.assertEqual(suite(self.vault)["pending"], 1)
        signed = sign_case(self.vault, case)
        self.assertEqual(len(signed["history"]), 1)
        self.rows("wiki/control/query-cases.jsonl", [signed])
        self.assertEqual(suite(self.vault)["failed"], 1)
        with self.assertRaises(Blocked):
            verify(signed["approval"], "package", self.signers)

    def test_first_factual_promotion_requires_applicable_case(self):
        self.knowledge([self.claim()])
        self.assertEqual(suite(self.vault)["coverage"], "not_established")
        with self.assertRaises(Blocked):
            require_suite(self.vault, factual_ids=["C-0001"])
        self.rows("wiki/control/query-cases.jsonl", [self.case()])
        require_suite(self.vault, factual_ids=["C-0001"])


class Pages(VaultTest):
    def test_real_preview_reports_missing_entity_without_factual_answer(self):
        self.knowledge([self.claim(entity=None)])
        result = preview(self.vault)
        self.assertEqual(result["comparisons"][0]["pending"][0]["reason"], "Missing entity")
        self.assertEqual(query(self.vault, {})["code"], 4)

    def test_complete_segment_utf8_preview_is_pure(self):
        claim = self.claim(statement="Medição " + "é" * 100)
        self.knowledge([claim])
        before = self.vault.inputs()
        result = preview(self.vault, "2026-01-01T00:00:00Z")
        self.assertEqual([r["cap"] for r in result["comparisons"]], [6000, 12000, 20000])
        segment = render_current(Knowledge(self.vault), [claim["id"]], "instrument", result["cutoff"])
        self.assertEqual(result["comparisons"][0]["parts"][0]["bytes"], len(segment.encode("utf-8")))
        self.assertGreater(len(segment.encode("utf-8")), len(segment))
        self.assertEqual(before, self.vault.inputs())

    def test_missing_renderer_fields_and_indivisible_units(self):
        rows = [self.claim(entity=None)]
        absent = split_preview(rows, None)
        self.assertIsNone(absent[0]["bytes"])
        self.assertEqual(absent[0]["pending"][0]["reason"], "Missing entity")
        rows = [self.claim(property=None)]
        result = split_preview(rows, lambda title, ids: "x" * 100, caps=[20])
        self.assertEqual(result[0]["pending"][0]["reason"], "Missing subdivision fields")
        result = split_preview([self.claim()], lambda title, ids: "x" * 100, caps=[20])
        self.assertEqual(result[0]["pending"][0]["reason"], "Indivisible unit exceeds cap")

    def test_split_numeric_order_full_titles_and_whole_claims(self):
        rows = [self.claim("C-10000"), self.claim("C-9999"), self.claim("C-10001")]
        calls = []
        def render(title, ids):
            calls.append((title, ids))
            return title + "é" * (25 * len(ids))
        result = split_preview(rows, render, caps=[100])[0]
        self.assertEqual([p["ids"] for p in result["parts"]], [["C-9999"], ["C-10000"], ["C-10001"]])
        self.assertTrue(all("part-" in p["name"] for p in result["parts"]))
        self.assertTrue(all(p["bytes"] <= 100 for p in result["parts"]))

    def test_pending_visible_coverage_and_tamper_detection(self):
        claim = self.claim(state="hypothesis")
        self.knowledge([claim])
        with self.assertRaises(Blocked):
            validate_pages(self.vault)
        self.pages([claim])
        validate_pages(self.vault)
        page = self.root / "wiki/topics/measurement.md"
        self.assertIn("Pending: abstention", page.read_text(encoding="utf-8"))
        atomic(page, page.read_bytes().replace(b"hypothesis", b"accepted"))
        with self.assertRaises(Blocked):
            validate_pages(self.vault)


if __name__ == "__main__":
    unittest.main()
