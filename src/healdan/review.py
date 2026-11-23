"""Blind-review receipts and reproducible sequential CSP-1 inspection."""
import hmac
import secrets
from pathlib import Path

from .core import atomic, digest, read_json, require, safe_path, stamp
from .ids import identity
from .tasks import get_session, get_task, require_active, validate_evidence

CSP_RULE_V1 = "CSP-1/i111/f0.1/numeric-v1"


def freeze_review(vault, task_id, extractor, reviewer):
    with vault.locked():
        task = get_task(vault, task_id)
        require_active(task)
        validate_evidence(vault, task)
        a, b = get_session(vault, extractor), get_session(vault, reviewer)
        require(a["task"] == b["task"] == task_id and a["role"] == "extractor" and b["role"] == "reviewer",
                "Review roles/task do not match")
        require(a["uuid"] != b["uuid"] and a["state"] == b["state"] == "completed",
                "Independent completed native sessions are required", 5)
        path = vault.control / "reviews" / (task_id + ".json")
        existing = read_json(path)
        if existing:
            old = existing["outputs"]
            if old["extractor"]["operation"] == extractor and old["reviewer"]["operation"] == reviewer:
                return existing
            require(old["extractor"]["uuid"] != a["uuid"] and old["reviewer"]["uuid"] != b["uuid"],
                    "Rework requires two new independent sessions", 5)
        base = vault.state / "tasks" / task_id
        outputs = {}
        for role, session in (("extractor", a), ("reviewer", b)):
            output = safe_path(session["proposal"], "extraction.json", exists=True).read_bytes()
            frozen_name = session["operation"] + ".json"
            outputs[role] = {"operation": session["operation"], "uuid": session["uuid"],
                             "sha256": digest(output), "launches": session["launches"], "frozen": frozen_name,
                             "proposal": session["proposal"]}
            atomic(base / "frozen" / frozen_name, output)
        record = {"task": task_id, "frozen_at": stamp(), "outputs": outputs, "source_digest": digest(task["source_manifest"])}
        atomic(path, record)
        vault.receipt("blind-review", record)
        # Only now may the reviewer read the extractor's independent result.
        atomic(Path(b["proposal"]) / "comparison-input.json", (base / "frozen" / outputs["extractor"]["frozen"]).read_bytes())
        return record


def validate_review(vault, task_id, units):
    task = get_task(vault, task_id)
    validate_evidence(vault, task)
    record = read_json(vault.control / "reviews" / (task_id + ".json"))
    require(record, "Blind review has not been frozen", 5)
    require(record["source_digest"] == digest(task["source_manifest"]), "Blind review source snapshot mismatch")
    base = vault.state / "tasks" / task_id
    for role in ("extractor", "reviewer"):
        require(digest(safe_path(base / "frozen", record["outputs"][role]["frozen"], exists=True).read_bytes()) == record["outputs"][role]["sha256"],
                "Independent extraction changed after freezing")
    comparison = read_json(Path(record["outputs"]["reviewer"]["proposal"]) / "comparison.json")
    require(comparison and comparison.get("extractions") ==
            {r: record["outputs"][r]["sha256"] for r in ("extractor", "reviewer")},
            "Comparison is not bound to both frozen extractions", 5)
    require(set(comparison.get("units", {})) == set(units), "Review must cover every promotion unit", 5)
    require(all(comparison["units"][i] == {"status": "conform", "sha256": sha} for i, sha in units.items())
            and not comparison.get("defects"),
            "Independent review has unresolved defects", 5)
    return {"independent": record, "comparison": comparison}


def freeze_csp(units, state, seed=None):
    require(state.get("rule", CSP_RULE_V1) == CSP_RULE_V1,
            "A different inspection regime requires a separate human decision and a new sequence", 5)
    streak = state.get("streak", 0)
    require(type(streak) is int and 0 <= streak <= 111, "Invalid inspection sequence")
    ordered = sorted(units, key=identity)
    require(len({identity(i) for i in ordered}) == len(ordered), "CSP identity collision")
    return {"rule": CSP_RULE_V1, "units": ordered, "units_digest": digest(units),
            "seed": seed or secrets.token_hex(32), "initial_streak": streak,
            "state_digest": digest(state), "inspections": {}}


def csp_status(plan):
    require(plan.get("rule") == CSP_RULE_V1, "Unknown inspection regime")
    streak, selected, pending, defect = plan["initial_streak"], [], [], False
    require(type(streak) is int and 0 <= streak <= 111, "Invalid inspection sequence")
    for index, unit in enumerate(plan["units"]):
        counter = 0
        while True:
            draw = hmac.digest(bytes.fromhex(plan["seed"]), f"{index}:{unit}:{counter}".encode("ascii"), "sha256")[0]
            if draw < 250:
                break
            counter += 1
        inspect = streak < 111 or draw % 10 == 0
        if inspect:
            selected.append(unit)
            result = plan["inspections"].get(unit)
            if result is None:
                pending.append(unit)
                # Future selection depends on this result. Do not guess compliance.
                break
            require(result in {"conform", "defect"}, "Unknown CSP inspection result", 2)
            if result == "defect":
                streak, defect = 0, True
            else:
                streak = min(111, streak + 1)
    return {"selected": selected, "pending": pending, "streak": streak, "defect": defect,
            "complete": not pending}


def inspect(plan, results):
    for identifier, outcome in results.items():
        status = csp_status(plan)
        require(status["pending"] == [identifier], "Inspect the next selected frozen unit", 2)
        require(outcome in {"conform", "defect"}, "Invalid inspection outcome", 2)
        plan["inspections"][identifier] = outcome
    return csp_status(plan)
