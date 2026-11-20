"""Local task/worktree lifecycle, session identity and human waiting clocks."""
from datetime import timedelta
from pathlib import Path
import os
import shutil
from uuid import uuid4

from .core import atomic, digest, git, jsonl, read_json, require, safe_path, stamp, utc
from .ids import reserve


def task_path(vault, identifier):
    return safe_path(vault.control / "tasks", identifier + ".json")


def get_task(vault, identifier):
    task = read_json(task_path(vault, identifier))
    require(task, "Unknown task", 2)
    return task


def age_status(task, now=None):
    age = (utc(now) - utc(task["created_at"])).total_seconds()
    return "expired" if age >= 86400 else "warning" if age >= 43200 else "active"


def require_active(task, now=None):
    require(task["state"] in {"active", "waiting"} and age_status(task, now) != "expired",
            "Task/worktree cannot perform new actions or integrations", 5)


def all_tasks(vault):
    return [read_json(p) for p in (vault.control / "tasks").glob("*.json")]


def create(vault, title, now=None):
    with vault.locked():
        vault.no_transaction()
        require(sum(t.get("capacity_held", True) for t in all_tasks(vault)) < vault.policy["active_writers"],
                "Writing capacity is occupied", 5)
        require(vault.head(), "Create an initial local Git commit before opening a task", 5)
        vault.clean_inputs()
        identifier = str(uuid4())
        base = vault.state / "tasks" / identifier
        worktree = base / "worktree"
        base.mkdir(parents=True, exist_ok=False)
        record = {"id": identifier, "title": title, "created_at": stamp(now), "base": vault.head(),
                  "base_fingerprint": vault.fingerprint(),
                  "worktree": str(worktree), "state": "creating", "capacity_held": True,
                  "sessions": [], "reminders": [], "processes": []}
        atomic(task_path(vault, identifier), record)
        git(vault.root, "worktree", "add", "--detach", str(worktree), vault.head())
        for role in vault.policy["context_bytes"]:
            (base / "proposals" / role).mkdir(parents=True)
            (base / "temporary" / role).mkdir(parents=True)
        evidence = base / "evidence"
        evidence.mkdir()
        sources = vault.rows("resources/sources/index.jsonl")
        for source in sources:
            original = safe_path(vault.root, source["path"], exists=True)
            require(digest(original.read_bytes()) == source["sha256"], "Source changed before task snapshot")
            target = safe_path(evidence, source["path"])
            atomic(target, original.read_bytes())
        atomic(evidence / "resources/sources/index.jsonl", jsonl(sources))
        record["source_manifest"] = sources
        record["state"] = "active"
        atomic(task_path(vault, identifier), record)
        vault.receipt("task-created", record)
        return record


def validate_evidence(vault, task):
    require(vault.rows("resources/sources/index.jsonl") == task["source_manifest"], "Task source inventory changed", 5)
    evidence = vault.state / "tasks" / task["id"] / "evidence"
    require((evidence / "resources/sources/index.jsonl").read_bytes() == jsonl(task["source_manifest"]),
            "Task source snapshot manifest changed")
    for source in task["source_manifest"]:
        require(digest(safe_path(evidence, source["path"], exists=True).read_bytes()) == source["sha256"] and
                digest(safe_path(vault.root, source["path"], exists=True).read_bytes()) == source["sha256"],
                "Task source snapshot no longer matches preserved evidence", 5)


def new_session(vault, task_id, action, role, context, *, operation=None):
    require(role in vault.policy["context_bytes"], "Unknown role", 2)
    body = context.encode("utf-8")
    require(len(body) <= vault.policy["context_bytes"][role], "Own context exceeds role byte budget", 5)
    operation = operation or str(uuid4())
    with vault.locked():
        vault.no_transaction()
        task = get_task(vault, task_id)
        require_active(task)
        path = vault.control / "sessions" / (operation + ".json")
        existing = read_json(path)
        if existing:
            require((existing["task"], existing["action"], existing["role"], existing["context_sha256"]) ==
                    (task_id, action, role, digest(body)), "Session operation arguments changed")
            return existing
        sid = reserve(vault, "S", 1, operation, locked=True)[0]
        session = {"id": sid, "operation": operation, "uuid": str(uuid4()), "task": task_id,
                   "action": action, "role": role, "context_bytes": len(body), "context_sha256": digest(body),
                   "created_at": stamp(), "usage": {"input_tokens": 0, "output_tokens": 0, "evidence_bytes": 0},
                   "launches": [], "state": "prepared"}
        base = vault.state / "tasks" / task_id
        proposal = base / "proposals" / role / session["uuid"]
        proposal.mkdir(parents=True, exist_ok=False)
        session["proposal"] = str(proposal)
        atomic(base / "contexts" / (sid + ".txt"), body)
        atomic(path, session)
        task["sessions"].append(operation)
        atomic(task_path(vault, task_id), task)
        return session


def get_session(vault, operation):
    record = read_json(safe_path(vault.control / "sessions", operation + ".json"))
    require(record, "Unknown session", 2)
    return record


def present(vault, task_id, question, delivery_receipt, now=None):
    require(delivery_receipt and question, "Successful presentation receipt and question are required", 2)
    with vault.locked():
        task = get_task(vault, task_id)
        require(task["state"] not in {"closed", "cancelled"}, "Task is already closed", 5)
        require(not task.get("presented_at"), "Waiting question already presented", 5)
        task.update(state="waiting", question=question, delivery_receipt=delivery_receipt, presented_at=stamp(now))
        atomic(task_path(vault, task_id), task)
        return task


def answer(vault, task_id, decision, now=None):
    from .signing import human_sign
    with vault.locked():
        task = get_task(vault, task_id)
        require(task.get("presented_at") and task["state"] == "waiting" and not task.get("closure_pending") and
                utc(now) < utc(task["presented_at"]) + timedelta(days=7), "Late response requires an explicit reopening decision", 5)
        require(decision.get("answer") and decision.get("owner") and decision.get("reason"), "Incomplete human response", 2)
        signed = human_sign(vault, {"task": task_id, "decision": decision, "at": stamp(now)}, "decision")
        task.update(answered_at=stamp(now), response=signed, state="active")
        atomic(task_path(vault, task_id), task)
        return task


def reopen(vault, task_id, decision):
    from .signing import human_sign
    old = get_task(vault, task_id)
    require(old["state"] in {"closed", "cancelled"} and not old["capacity_held"],
            "Reconcile and preserve the previous task before reopening", 5)
    require(decision.get("owner") and decision.get("reason"), "Reopening needs an explicit human decision", 2)
    signed = human_sign(vault, {"previous_task": task_id, "decision": decision, "at": stamp()}, "decision")
    fresh = create(vault, old["title"])
    with vault.locked():
        inherited = dict(old.get("prior_usage", {}))
        for operation in old["sessions"]:
            for key, amount in get_session(vault, operation)["usage"].items():
                inherited[key] = inherited.get(key, 0) + amount
        fresh.update(predecessor=task_id, reopening_decision=signed, prior_usage=inherited)
        atomic(task_path(vault, fresh["id"]), fresh)
    return fresh


def reconcile_clock(vault, task, now=None):
    now = utc(now)
    updates = []
    if age_status(task, now) == "expired" and task["state"] not in {"closed", "cancelled"}:
        task["worktree_expired"] = True
        updates.append("worktree_expired")
    if task.get("presented_at") and not task.get("answered_at"):
        days = (now - utc(task["presented_at"])).total_seconds() / 86400
        if days >= 7 and task["state"] not in {"closed", "cancelled"}:
            task["closure_reason"] = "human_timeout"
            task["closure_pending"] = True
            updates.append("closure_pending")
        elif days >= 3:
            marker = 5 if days >= 5 else 3
            if marker not in task["reminders"]:
                task["reminders"].append(marker)
                updates.append(f"reminder_day_{marker}")
    atomic(task_path(vault, task["id"]), task)
    return updates


def preserve_and_close(vault, task_id, *, reason="completed"):
    from .custody import capture_tree
    with vault.locked():
        task = get_task(vault, task_id)
        require(not task.get("processes"), "Processes require reconciliation before closure", 5)
        sessions = [get_session(vault, op) for op in task["sessions"]]
        require(all(s.get("state") != "running" for s in sessions), "Session process is still running", 5)
        base = vault.state / "tasks" / task_id
        purpose = {"purpose": "Task reconciliation and recovery", "necessity": "Preserve review and resumption evidence",
                   "owner": vault.config.get("signing_identity") or "controller", "link": task_id}
        from .launcher import profile
        for session in sessions:
            if session["launches"] and not session.get("preservation"):
                session["preservation"] = capture_tree(vault, Path(session.get("active_profile") or profile(vault, session["operation"])), task=task_id,
                    classification="unknown", session=session["operation"], purpose=purpose)
                atomic(vault.control / "sessions" / (session["operation"] + ".json"), session)
        # Includes dirty proposals, original source snapshot, contexts, worktree and native checkpoints.
        capture = capture_tree(vault, base, task=task_id, classification="unknown", purpose=purpose)
        task["preservation"] = capture
        atomic(task_path(vault, task_id), task)
        worktree = Path(task["worktree"])
        if worktree.exists():
            require(worktree.resolve().is_relative_to(base.resolve()), "Unsafe worktree removal")
            git(vault.root, "worktree", "remove", "--force", str(worktree))
        task.update(state="cancelled" if reason == "human_timeout" else "closed",
                    closure_reason=reason, closed_at=stamp(), capacity_held=False)
        atomic(task_path(vault, task_id), task)
        vault.receipt("task-closed", task)
        return task


def reconcile_processes(vault, task):
    """On macOS, stop only the supervised process identity recorded at launch."""
    import platform
    import signal
    import time
    from .core import run
    for process in list(task.get("processes", [])):
        require(platform.system() == "Darwin", "Process reconciliation requires the original macOS host", 5)
        actual = run(["ps", "-p", str(process["pid"]), "-o", "lstart="], check=False).stdout.decode().strip()
        if actual:
            require(actual == process.get("started_identity"), "PID identity changed; manual reconciliation required", 5)
            os.killpg(process["pid"], signal.SIGTERM)
            time.sleep(0.2)
            still = run(["ps", "-p", str(process["pid"]), "-o", "lstart="], check=False).stdout.decode().strip()
            if still == actual:
                os.killpg(process["pid"], signal.SIGKILL)
        session = get_session(vault, process["session"])
        session["state"] = "reconciliation_required"
        atomic(vault.control / "sessions" / (session["operation"] + ".json"), session)
        task["processes"].remove(process)
    atomic(task_path(vault, task["id"]), task)


def reconcile_expired(vault, task_id):
    from .custody import capture_tree
    with vault.locked():
        task = get_task(vault, task_id)
        require(age_status(task) == "expired", "Worktree has not expired", 2)
        if task.get("worktree_removed"):
            return task
        reconcile_processes(vault, task)
        base = vault.state / "tasks" / task_id
        capture = capture_tree(vault, base, task=task_id, classification="unknown", purpose={
            "purpose": "Expired worktree reconciliation", "necessity": "Preserve proposals, sources and checkpoints before removal",
            "owner": vault.config.get("signing_identity") or "controller", "link": task_id})
        task["expiry_preservation"] = capture
        atomic(task_path(vault, task_id), task)
        worktree = Path(task["worktree"])
        require(worktree.resolve().is_relative_to(base.resolve()), "Unsafe worktree removal")
        if worktree.exists():
            git(vault.root, "worktree", "remove", "--force", str(worktree))
        # Worktree expiry does not cancel the task, restart waiting, or release its capacity.
        task.update(worktree_removed=True, worktree_expired=True)
        atomic(task_path(vault, task_id), task)
        return task
