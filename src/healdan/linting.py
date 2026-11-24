"""Observational checks, durable runs and one follow-up task per category."""
from datetime import timedelta
from uuid import uuid4
import re

from .core import Blocked, atomic, digest, read_json, require, stamp, utc
from .custody import INACTIVE_COPIES, materials, retention_deadline, validate_purpose
from .ids import inventory as id_inventory
from .inbox import findings as inbox_findings, worktree_inbox_digests
from .knowledge import Knowledge
from .pages import validate_pages
from .regression import suite
from .tasks import age_status, all_tasks


def stale(last_complete, now=None):
    return last_complete is None or utc(now) - utc(last_complete) > timedelta(days=8)


def collect(vault, now=None):
    findings, errors = {}, []
    def add(category, key, message):
        findings[category + ":" + key] = {"category": category, "key": key, "message": message}
    for category, checker in (("integrity", lambda: Knowledge(vault)), ("pages", lambda: validate_pages(vault))):
        try:
            checker()
        except Blocked as exc:
            add(category, digest(str(exc))[:16], str(exc))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append({"category": category, "error": str(exc)})
    for page in (vault.root / "wiki").rglob("*.md"):
        if re.search(r"(?m)^#+\s+F-[0-9]+(?:\s|$)", page.read_text(encoding="utf-8")):
            add("pages", page.relative_to(vault.root).as_posix(), "Current organization explicitly indexes a source; editorial migration required")
    try:
        regression = suite(vault, cutoff=stamp(now))
        if regression["coverage"] == "not_established":
            add("query", "coverage", "Regression coverage not established; historical questions unavailable")
        for row in regression["results"]:
            if row["status"] != "passed":
                add("query", str(row["id"]), row["status"])
    except (Blocked, OSError, ValueError, KeyError, TypeError) as exc:
        errors.append({"category": "query", "error": str(exc)})
    items = read_json(vault.control / "inbox.json", {})
    observed = worktree_inbox_digests(vault)
    for item in items.values():
        for message in inbox_findings(item, now, vault=vault, observed=observed):
            add("inbox", item["sha256"] + ":" + message, message)
    known = {(path, item["sha256"]) for item in items.values() for path in item["paths"]}
    for relative, _ in sorted(observed - known):
        add("inbox", relative, "File has no triage inventory")
    for task in all_tasks(vault):
        if task.get("capacity_held") and age_status(task, now) != "active":
            add("worktrees", task["id"], age_status(task, now))
        if task.get("closure_pending"):
            add("tasks", task["id"], "Closure awaits preservation/reconciliation")
        if task.get("presented_at") and not task.get("answered_at") and utc(now) - utc(task["presented_at"]) >= timedelta(days=7):
            add("tasks", task["id"] + ":human", "Human waiting deadline reached")
    records = materials(vault)
    for material in records.values():
        if material["kind"] != "backup":
            try:
                validate_purpose(material)
            except Blocked as exc:
                add("retention", material["id"] + ":purpose", str(exc))
        deadline = retention_deadline(material)
        if not deadline or utc(now) >= deadline:
            if any(c.get("status") not in INACTIVE_COPIES for c in material.get("copies", [])):
                add("retention", material["id"], "No proven deadline" if not deadline else "Deletion overdue or held")
        for h in material.get("holds", []):
            if not h.get("ended_at"):
                add("holds", h["id"], h["reason"])
        if material.get("dependencies"):
            add("dependencies", material["id"], "Preserved evidence dependencies")
        if material.get("classification") == "secret" and not material.get("rotation_receipt"):
            add("security", material["id"], "Rotation/revocation confirmation missing")
    interval = vault.config.get("backup_interval_hours")
    complete = [r["verified_at"] for r in records.values() if r["kind"] == "backup" and r.get("status") == "complete"]
    if not interval:
        add("backup", "policy", "Backup interval not configured")
    elif not complete or (utc(now) - utc(max(complete))).total_seconds() > interval * 3600:
        add("backup", "freshness", "No recent complete verified backup")
    for path in (vault.control / "deletions").glob("*.json"):
        if read_json(path)["status"] != "complete":
            add("retention", path.stem, "Incomplete deletion plan")
    return findings, errors


def lint(vault, now=None, *, checks=None):
    with vault.locked():
        identifier = str(uuid4())
        receipt_path = vault.control / "lint" / (identifier + ".json")
        record = {"id": identifier, "started_at": stamp(now), "commit": vault.head(),
                  "fingerprint": vault.fingerprint(), "status": "running"}
        atomic(receipt_path, record)
        state_path = vault.control / "lint-state.json"
        previous = read_json(state_path, {"last_complete_lint_at": None, "findings": {}})
        try:
            found, errors = (checks or collect)(vault, now)
        except (Blocked, OSError, ValueError, KeyError, TypeError) as exc:
            found, errors = {}, [{"category": "execution", "error": str(exc)}]
        if vault.fingerprint() != record["fingerprint"]:
            errors.append({"category": "execution", "error": "Inputs changed during lint"})
        old = set(previous["findings"])
        current = set(found)
        delta = {"new": sorted(current - old), "persistent": sorted(current & old),
                 "resolved": sorted(old - current) if not errors else []}
        tasks_path = vault.control / "followups.json"
        tasks = read_json(tasks_path, {})
        categories = {r["category"] for r in found.values()} | {e["category"] for e in errors}
        for category in categories:
            task = tasks.setdefault(category, {"id": str(uuid4()), "category": category, "owner": None, "history": []})
            task.update(state="open", last_run=identifier)
            task["history"].append({"run": identifier, "at": stamp(now)})
        if not errors:
            for category, task in tasks.items():
                if category not in categories:
                    task["state"] = "resolved"
        atomic(tasks_path, tasks)
        record.update(status="partial" if errors else "complete", completed_at=stamp(now), findings=found,
                      errors=errors, delta=delta, categories=sorted(categories))
        atomic(receipt_path, record)
        if not errors:
            atomic(state_path, {"last_complete_lint_at": stamp(now), "findings": found, "run": identifier})
        return record
