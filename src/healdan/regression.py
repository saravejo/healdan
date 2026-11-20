"""Individually signed expectations evaluated against the actual resolver."""
from .core import Blocked, digest, require, stamp
from .knowledge import query, typed
from .ids import identity
from .signing import human_sign, trusted_signers, verify

FIELDS = {"id", "question", "filters", "cutoff", "temporal_policy", "expected_ids", "expected_value",
          "expected_polarity", "outcome", "expected_conflicts", "reason", "decision"}


def payload(case):
    require(set(case) - {"approval", "history"} == FIELDS, "Case fields are incomplete or unknown")
    result = {k: case[k] for k in FIELDS}
    require(identity(case["id"])[0] == "Q", "Regression case requires a Q- identity")
    for name in ("expected_ids", "expected_conflicts"):
        require(isinstance(case[name], list) and all(identity(i)[0] == "C" for i in case[name]), "Expected identities must be C-")
        require(len({identity(i) for i in case[name]}) == len(case[name]), "Duplicate expected identity")
    require(case["question"] and case["reason"] and case["decision"].get("owner") and
            case["decision"].get("at"), "Case requires a specific human decision")
    stamp(case["decision"]["at"])
    require(bool(case["cutoff"]) != bool(case["temporal_policy"]), "Specify cutoff or temporal policy")
    require(case["temporal_policy"] in {None, "at_execution"}, "Unknown temporal policy")
    if case["cutoff"]:
        stamp(case["cutoff"])
    require(case["outcome"] in {"answer", "conflict", "abstention"}, "Invalid expected outcome")
    if case["expected_value"] is not None:
        typed(case["expected_value"])
    return result


def sign_case(vault, case):
    old = case.get("approval")
    new = dict(case)
    new["history"] = list(case.get("history", [])) + ([old] if old else [])
    new["approval"] = human_sign(vault, payload(case), "case")
    return new


def suite(vault, *, proposed=(), cutoff=None):
    cases = vault.rows("wiki/control/query-cases.jsonl")
    results = []
    for case in cases:
        try:
            expected = payload(case)
            require(verify(case.get("approval"), "case", trusted_signers(vault)) == expected,
                    "Case signature does not cover expectation")
        except (Blocked, KeyError, TypeError, ValueError) as exc:
            results.append({"id": case.get("id"), "status": "pending", "reason": str(exc)})
            continue
        actual = query(vault, case["filters"], case["cutoff"] or cutoff or stamp(), proposed=proposed)
        code = {"answer": 0, "conflict": 3, "abstention": 20}[case["outcome"]]
        passed = (actual["code"] == code and actual["research"] == "complete" and
                  actual["outcome"] == case["outcome"] and
                  set(actual["ids"]) == set(case["expected_ids"]) and
                  actual["value"] == case["expected_value"] and
                  actual["polarity"] == case["expected_polarity"] and
                  set(actual["conflicts"]) == set(case["expected_conflicts"]))
        results.append({"id": case["id"], "status": "passed" if passed else "failed", "actual": actual})
    return {"coverage": "established" if cases else "not_established", "total": len(cases),
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
