"""Blind-review receipts and reproducible sequential CSP-1 inspection."""
import hmac
import secrets
from pathlib import Path

from .core import atomic, digest, read_json, require, safe_path, stamp
from .ids import identity
from .tasks import get_session, get_task, require_active


def freeze_review(vault, task_id, extractor, reviewer):
    with vault.locked():
        task = get_task(vault, task_id)
        require_active(task)
        a, b = get_session(vault, extractor), get_session(vault, reviewer)
        require(a["task"] == b["task"] == task_id and a["role"] == "extractor" and b["role"] == "reviewer",
                "Review roles/task do not match")
        require(a["uuid"] != b["uuid"] and a["state"] == b["state"] == "completed",
                "Independent completed native sessions are required", 5)
        path = vault.control / "reviews" / (task_id + ".json")
        existing = read_json(path)
        if existing:
            return existing
        base = vault.state / "tasks" / task_id
        outputs = {}
        for role, session in (("extractor", a), ("reviewer", b)):
            output = safe_path(base / "proposals" / role, "extraction.json", exists=True).read_bytes()
            outputs[role] = {"operation": session["operation"], "uuid": session["uuid"],
                             "sha256": digest(output), "launches": session["launches"]}
            atomic(base / "frozen" / (role + ".json"), output)
        record = {"task": task_id, "frozen_at": stamp(), "outputs": outputs}
        atomic(path, record)
        # Only now may the reviewer read the extractor's independent result.
        atomic(base / "proposals/reviewer/comparison-input.json", (base / "frozen/extractor.json").read_bytes())
        return record


def validate_review(vault, task_id, units):
    record = read_json(vault.control / "reviews" / (task_id + ".json"))
    require(record, "Blind review has not been frozen", 5)
    base = vault.state / "tasks" / task_id
    for role in ("extractor", "reviewer"):
        require(digest((base / "frozen" / (role + ".json")).read_bytes()) == record["outputs"][role]["sha256"],
                "Independent extraction changed after freezing")
    comparison = read_json(base / "proposals/reviewer/comparison.json")
    require(comparison and comparison.get("extractions") ==
            {r: record["outputs"][r]["sha256"] for r in ("extractor", "reviewer")},
            "Comparison is not bound to both frozen extractions", 5)
    require(set(comparison.get("units", {})) == set(units), "Review must cover every promotion unit", 5)
    require(all(v == "conform" for v in comparison["units"].values()) and not comparison.get("defects"),
            "Independent review has unresolved defects", 5)
    return {"independent": record, "comparison": comparison}


def freeze_csp(units, state, seed=None):
    ordered = sorted(units, key=identity)
    require(len({identity(i) for i in ordered}) == len(ordered), "CSP identity collision")
    return {"rule": "CSP-1/i111/f0.1/numeric-v1", "units": ordered, "units_digest": digest(units),
            "seed": seed or secrets.token_hex(32), "initial_streak": state.get("streak", 0),
            "state_digest": digest(state), "inspections": {}}


def csp_status(plan):
    streak, selected, pending, defect = plan["initial_streak"], [], [], False
    for index, unit in enumerate(plan["units"]):
        draw = int.from_bytes(hmac.digest(bytes.fromhex(plan["seed"]),
                              f"{index}:{unit}".encode("ascii"), "sha256")[:8], "big")
        inspect = streak < 111 or draw < (1 << 64) // 10
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
