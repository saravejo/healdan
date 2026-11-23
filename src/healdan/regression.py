"""Versioned signed expectations evaluated against the actual resolver."""
from copy import deepcopy

from .core import Blocked, canonical, parse_jsonl, require, stamp
from .ids import identity
from .knowledge import QUERY_FILTERS, query, typed
from .signing import human_sign, trusted_signers, verify_origin

CASE_REGISTRY = "wiki/control/query-cases.jsonl"
CASE_FORMAT_V1 = "healdan-query-case-v1"
CASE_FORMAT_V2 = "healdan-query-case-v2"
CASE_FIELDS = {"id", "question", "filters", "cutoff", "temporal_policy", "reason", "decision"}
LEGACY_EXPECTATION = {"ids": "expected_ids", "value": "expected_value", "polarity": "expected_polarity",
                      "outcome": "outcome", "conflicts": "expected_conflicts"}


def _project_v1(record):
    require(set(record) == CASE_FIELDS | set(LEGACY_EXPECTATION.values()),
            "Legacy case fields are incomplete or unknown")
    return {**{field: record[field] for field in CASE_FIELDS}, "format": CASE_FORMAT_V2,
            "expectation": {field: record[old] for field, old in LEGACY_EXPECTATION.items()}}


def _read_v2(record):
    require(set(record) == CASE_FIELDS | {"format", "expectation"}, "Case fields are incomplete or unknown")
    return record


CASE_READERS = {None: _project_v1, CASE_FORMAT_V2: _read_v2}


def _compatible_case(record):
    version = record.get("format")
    require(version is None or isinstance(version, str), "Unknown case format")
    reader = CASE_READERS.get(version)
    require(reader is not None, "Unknown case format")
    case = reader(record)
    require(identity(case["id"])[0] == "Q", "Regression case requires a Q- identity")
    filters, decision, expected = case["filters"], case["decision"], case["expectation"]
    require(isinstance(filters, dict) and set(filters) <= QUERY_FILTERS and
            all(isinstance(value, str) for value in filters.values()), "Unknown or invalid case query filters")
    require(isinstance(decision, dict) and set(decision) == {"owner", "at"},
            "Case decision fields are incomplete or unknown")
    require(all(isinstance(value, str) and value.strip()
                for value in (case["question"], case["reason"], decision["owner"], decision["at"])),
            "Case requires a specific human decision")
    stamp(decision["at"])
    cutoff, temporal_policy = case["cutoff"], case["temporal_policy"]
    require(cutoff is None or isinstance(cutoff, str), "Case cutoff must be textual")
    require(bool(cutoff) != bool(temporal_policy), "Specify cutoff or temporal policy")
    require(temporal_policy in (None, "at_execution"), "Unknown temporal policy")
    if cutoff:
        stamp(cutoff)
    require(isinstance(expected, dict) and set(expected) == set(LEGACY_EXPECTATION),
            "Case expectation fields are incomplete or unknown")
    for name in ("ids", "conflicts"):
        require(isinstance(expected[name], list), "Expected identities must be C-")
        keys = [identity(identifier) for identifier in expected[name]]
        require(all(prefix == "C" for prefix, _ in keys), "Expected identities must be C-")
        require(len(set(keys)) == len(keys), "Duplicate expected identity")
    require(expected["outcome"] in ("answer", "conflict", "abstention"), "Invalid expected outcome")
    require(expected["polarity"] in (None, "positive", "negative"), "Invalid expected polarity")
    if expected["value"] is not None:
        typed(expected["value"])
    return case


def _unsigned_fields(case):
    require(isinstance(case, dict), "Regression case requires an object")
    require(isinstance(case.get("history", []), list), "Case signature history requires an array")
    return {key: value for key, value in case.items() if key not in {"approval", "history"}}


def payload(case):
    result = _unsigned_fields(case)
    _compatible_case(result)
    return result


def _case_projection(vault, row, original):
    signed, origin = verify_origin(original, row.get("approval"), "case", trusted_signers(vault))
    require(canonical(signed) == canonical(_unsigned_fields(row)), "Case signature does not cover expectation")
    case = deepcopy(_compatible_case(signed))
    return {"case": case, "origin": dict(origin, format=signed.get("format", CASE_FORMAT_V1))}


def verify_case_projection(vault, original, projection):
    """Recompute a projection from the trusted original JSONL row."""
    rows = parse_jsonl(original, CASE_REGISTRY)
    require(len(rows) == 1, "Expected one original case record")
    verified = _case_projection(vault, rows[0], original)
    require(canonical(projection) == canonical(verified), "Case projection differs from its verified origin")
    return verified


def case_projections(vault):
    for row, original in vault.rows(CASE_REGISTRY, include_bytes=True):
        try:
            projection = _case_projection(vault, row, original)
        except (Blocked, KeyError, OverflowError, TypeError, ValueError) as exc:
            yield {"id": row.get("id"), "status": "pending", "reason": str(exc)}
        else:
            yield {"id": row["id"], "status": "compatible", "projection": projection}


def sign_case(vault, case):
    signed_payload = payload(case)
    old = case.get("approval")
    new = dict(case)
    new["history"] = list(case.get("history", [])) + ([old] if old else [])
    new["approval"] = human_sign(vault, signed_payload, "case")
    return new


def suite(vault, *, proposed=(), cutoff=None):
    results = []
    for row in case_projections(vault):
        if row["status"] == "pending":
            results.append(row)
            continue
        case = row["projection"]["case"]
        expected = case["expectation"]
        actual = query(vault, case["filters"], case["cutoff"] or cutoff or stamp(), proposed=proposed)
        code = {"answer": 0, "conflict": 3, "abstention": 20}[expected["outcome"]]
        passed = (actual["code"] == code and actual["research"] == "complete" and
                  actual["outcome"] == expected["outcome"] and
                  set(actual["ids"]) == set(expected["ids"]) and
                  actual["value"] == expected["value"] and
                  actual["polarity"] == expected["polarity"] and
                  set(actual["conflicts"]) == set(expected["conflicts"]))
        results.append({"id": case["id"], "status": "passed" if passed else "failed", "actual": actual})
    return {"coverage": "established" if results else "not_established", "total": len(results),
            "passed": sum(r["status"] == "passed" for r in results),
            "pending": sum(r["status"] == "pending" for r in results),
            "failed": sum(r["status"] == "failed" for r in results), "results": results}


def require_suite(vault, *, proposed=(), cutoff=None, factual_ids=()):
    result = suite(vault, proposed=proposed, cutoff=cutoff)
    require(not result["pending"] and not result["failed"], "Signed query regression blocks closure", 5)
    if factual_ids:
        covered = set()
        for row in result["results"]:
            if row["status"] == "passed" and row["actual"]["code"] == 0:
                covered.update(row["actual"]["ids"])
        require(set(factual_ids) <= covered, "Factual promotion needs applicable signed regression cases", 5)
    return result
