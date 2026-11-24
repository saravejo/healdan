"""Local task/worktree lifecycle, session identity and human waiting clocks."""
from datetime import timedelta
from pathlib import Path
import os
import shutil
from uuid import uuid4

from .binding import project_record
from .core import Blocked, atomic, decode, digest, git, json_paths, jsonl, read_json, require, safe_path, stamp, utc
from .ids import reserve
from . import originals


def task_path(vault, identifier):
    return safe_path(vault.control / "tasks", identifier + ".json")


def get_task(vault, identifier):
    task = read_json(task_path(vault, identifier))
    require(task, "Unknown task", 2)
    return project_record(task, vault.binding, ("worktree",))


def age_status(task, now=None):
    age = (utc(now) - utc(task["created_at"])).total_seconds()
    return "expired" if age >= 86400 else "warning" if age >= 43200 else "active"


def require_active(task, now=None):
    require_reconciled(task)
    require(task["state"] in {"active", "waiting"} and age_status(task, now) != "expired",
            "Task/worktree cannot perform new actions or integrations", 5)


def require_reconciled(task):
    require(task.get("state") != "reconciliation_required",
            "Restored task requires reconciliation. Use task reconcile-restored ID --confirm", 5)


def task_ids(vault):
    return [path.stem for path in json_paths(safe_path(vault.control, "tasks"))]


def all_tasks(vault):
    return [get_task(vault, identifier) for identifier in task_ids(vault)]


def create(vault, title, now=None):
    with vault.locked():
        vault.no_transaction()
        require(sum(t.get("capacity_held", True) for t in all_tasks(vault)) < vault.policy["active_writers"],
                "Writing capacity is occupied", 5)
        require(vault.head(), "Create an initial local Git commit before opening a task", 5)
        vault.clean_inputs()
        revision = vault.head()
        sources = vault.rows(originals.REGISTRY)
        source_bodies = []
        for source in sources:
            originals.verify_attributes(vault.root, source["path"])
            body = originals.git_blob(vault.root, revision, source["path"])
            source_bodies.append(originals.verify_body(source, body, revision=revision))
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
        for source, body in zip(sources, source_bodies, strict=True):
            original = safe_path(worktree, source["path"], exists=True)
            originals.verify_body(source, original.read_bytes(), revision=revision)
            target = safe_path(evidence, source["path"])
            atomic(target, body)
        atomic(evidence / originals.REGISTRY, originals.git_blob(vault.root, revision, originals.REGISTRY))
        record["source_manifest"] = sources
        record["state"] = "active"
        atomic(task_path(vault, identifier), record)
        vault.receipt("task-created", record)
        return record


def validate_evidence(vault, task):
    require(vault.rows(originals.REGISTRY) == task["source_manifest"], "Task source inventory changed", 5)
    evidence = vault.state / "tasks" / task["id"] / "evidence"
    manifest = originals.git_blob(vault.root, task["base"], originals.REGISTRY)
    require((evidence / originals.REGISTRY).read_bytes() in {manifest, jsonl(task["source_manifest"])},
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
            return get_session(vault, operation)
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
    from .relocation import SESSION_PATHS
    record = read_json(safe_path(vault.control / "sessions", operation + ".json"))
    require(record, "Unknown session", 2)
    return project_record(record, vault.binding, SESSION_PATHS)


def present(vault, task_id, question, delivery_receipt, now=None):
    require(delivery_receipt and question, "Successful presentation receipt and question are required", 2)
    with vault.locked():
        task = get_task(vault, task_id)
        require_reconciled(task)
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
    from .custody import capture_tree, materials, verified_capture
    with vault.locked():
        task = get_task(vault, task_id)
        require_reconciled(task)
        if task.get("closed_at") and not task.get("capacity_held"):
            return task
        require(not task.get("processes"), "Processes require reconciliation before closure", 5)
        sessions = [get_session(vault, op) for op in task["sessions"]]
        require(all(s.get("state") != "running" for s in sessions), "Session process is still running", 5)
        base = vault.state / "tasks" / task_id
        worktree = Path(task["worktree"])
        require(worktree.resolve().is_relative_to(base.resolve()), "Unsafe worktree removal", 5)
        purpose = {"purpose": "Task reconciliation and recovery", "necessity": "Preserve review and resumption evidence",
                   "owner": vault.config.get("signing_identity") or "controller", "link": task_id}
        from .launcher import profile
        for session in sessions:
            if session["launches"]:
                if not session.get("preservation"):
                    session["preservation"] = capture_tree(vault, Path(session.get("active_profile") or profile(vault, session["operation"])), task=task_id,
                        classification="unknown", session=session["operation"], purpose=purpose)
                    atomic(vault.control / "sessions" / (session["operation"] + ".json"), session)
                saved = materials(vault)[session["preservation"]]
                require(saved.get("session") == session["operation"] and saved.get("task") == task_id,
                        "Session preservation belongs to a different session or task", 5)
                verified_capture(vault, saved)
        capture = task.get("preservation")
        verified = None
        expiry_capture = None
        if worktree.exists():
            # Includes dirty proposals, original sources, contexts and the current worktree.
            capture = capture_tree(vault, base, task=task_id, classification="unknown", purpose=purpose)
            task["preservation"] = capture
            atomic(task_path(vault, task_id), task)
            verified = remove_preserved_worktree(vault, task, worktree, capture)
        elif task.get("worktree_removed"):
            expiry_capture = task.get("expiry_preservation")
            verify_worktree_preservation(vault, task, worktree, expiry_capture)
            if capture:
                saved = materials(vault)[capture]
                require(saved.get("task") == task_id and not saved.get("session"), "Task preservation belongs to a different task", 5)
                verified_capture(vault, saved)
            else:
                capture = capture_tree(vault, base, task=task_id, classification="unknown", purpose=purpose)
                task["preservation"] = capture
                atomic(task_path(vault, task_id), task)
        else:
            verify_worktree_preservation(vault, task, worktree, capture)
        record_worktree_removal(vault, task, worktree, expiry_capture or capture, verified=verified)
        task.update(state="cancelled" if reason == "human_timeout" else "closed",
                    closure_reason=reason, closed_at=stamp(), capacity_held=False)
        atomic(task_path(vault, task_id), task)
        vault.receipt("task-closed", task)
        return task


def restored_task_origin(vault, task):
    from .backup_recovery import JOURNAL, JOURNAL_FILE, reconcile_task
    from .backup_snapshot import STATE, identifier
    from .lineage import sha256

    origin = task.get("reconciliation")
    require(task["state"] == "reconciliation_required" and isinstance(origin, dict) and identifier(origin.get("backup")),
            "Restored task reconciliation is unavailable for this task", 5)
    journal = read_json(safe_path(vault.state, JOURNAL_FILE), {})
    require(journal.get("format") == JOURNAL and journal.get("phase") == "complete" and
            journal.get("origin", {}).get("vault") == vault.identity and sha256(journal.get("receipt")),
            "Portable backup recovery must complete before task reconciliation", 5)
    receipt = read_json(safe_path(vault.control, f"receipts/{journal['receipt']}.json"), {})
    require(digest(receipt) == journal["receipt"] and receipt.get("kind") == "backup-restored" and
            all(receipt["payload"].get(key) == value for key, value in journal["origin"].items()),
            "Portable backup recovery receipt is unavailable or differs from the journal", 5)
    generation = journal["origin"].get("backup")
    require(identifier(generation), "Portable backup recovery generation is invalid", 5)
    manifest = safe_path(vault.control, f"historical/{generation}.manifest.json", exists=True).read_bytes()
    inventory = journal["inventory"]
    require(digest(manifest) == journal["origin"].get("manifest_sha256") and
            digest(inventory) == decode(manifest)["payload"]["inventory_sha256"],
            "Portable backup recovery inventory differs from the authenticated manifest", 5)

    filename = "tasks/" + task["id"] + ".json"
    primary = "historical/" + filename
    latest = f"historical/generations/{generation}/{filename}" if STATE + primary in inventory else primary
    for name in (primary, f"historical/generations/{origin['backup']}/{filename}"):
        entry = inventory.get(STATE + (filename if name == latest else name), {})
        path = safe_path(vault.control, name)
        if path.is_file():
            raw = path.read_bytes()
            checksum = digest(raw)
            if checksum != entry.get("sha256"):
                continue
            source = decode(raw)
            if (all(source.get(key) == task[key] for key in ("id", "created_at", "sessions")) and
                    reconcile_task(source, origin["backup"]).get("reconciliation") == origin):
                return source, checksum, journal["receipt"]
    require(False, "Restored task origin record is unavailable or differs from reconciliation evidence", 5)


def verified_restored_custody(vault, source, sessions):
    from .custody import materials, verified_capture
    from .retention import require_custody_inventory

    task_id = source["id"]
    records = materials(vault)
    expected = [(source.get(field), None) for field in ("preservation", "expiry_preservation")]
    expected.extend((session.get("preservation"), session["operation"]) for session in sessions)
    for capture, session in expected:
        if capture:
            record = records.get(capture, {})
            require(record.get("id") == capture and record.get("kind") == "conversation" and
                    record.get("task") == task_id and record.get("session") == session,
                    "Recorded preservation does not belong to this task or session", 5)
    verified = {}
    for key, record in sorted(records.items()):
        if record.get("task") != task_id or record.get("kind") != "conversation":
            continue
        require(record.get("id") == key, "Task custody material identity changed", 5)
        # A recovered copy has its own local inventory slot. Origin slots are evidence.
        copies = [copy for copy in record["copies"] if copy["kind"] == "ciphertext" and copy["status"] == "present" and
                  vault.relocated_path(copy["root"]) == vault.state / "custody"]
        try:
            require_custody_inventory(record)
            verified_capture(vault, {**record, "copies": copies})
        except Blocked as exc:
            raise Blocked(f"Task custody material {key} requires verification. {exc}", exc.code) from exc
        verified[key] = record["cipher_sha256"]
    return verified


def reconcile_restored(vault, task_id, *, confirmed=False):
    from .backup_snapshot import identifier
    from .lineage import sha256

    require(confirmed, "Use --confirm to close a restored task and release its capacity", 2)
    require(identifier(task_id), "Invalid restored task ID", 2)
    with vault.locked():
        vault.no_transaction()
        task = get_task(vault, task_id)
        require(task["id"] == task_id, "Task identity does not match its record", 5)
        receipt_kind = "task-restored-reconciled"
        history = task.get("reconciliation_history", [])
        if task["state"] in {"closed", "cancelled"} and not task["capacity_held"] and history:
            receipt_id = history[-1].get("receipt")
            require(sha256(receipt_id), "Restored task closure receipt is invalid", 5)
            receipt = read_json(safe_path(vault.control, f"receipts/{receipt_id}.json"), {})
            require(digest(receipt) == receipt_id and receipt.get("kind") == receipt_kind and
                    receipt["payload"].get("task") == task_id and receipt["payload"].get("closed_at") == task["closed_at"],
                    "Restored task closure receipt does not match its record", 5)
            return task
        source, source_sha, recovery_receipt = restored_task_origin(vault, task)
        require(not task.get("processes"), "Local task processes require reconciliation before closure", 5)
        workspace = vault.state / "tasks" / task_id
        require(not any(path.is_symlink() or path.is_junction() for path in (workspace.parent, workspace)) and
                not workspace.exists(), "Local task workspace requires preservation before closure", 5)
        sessions = [get_session(vault, operation) for operation in task["sessions"]]
        require(all(session["task"] == task_id and session["operation"] == operation and session.get("state") != "running" and
                    not (session.get("active_profile") or session.get("launch_intent"))
                    for operation, session in zip(task["sessions"], sessions, strict=True)),
                "A task session is active locally or belongs to a different task", 5)
        verified = verified_restored_custody(vault, source, sessions)

        pending = task.get("restored_closure_pending")
        at = pending["at"] if pending else stamp()
        closed_at = source.get("closed_at") or at
        require(closed_at == stamp(closed_at), "Restored task closure timestamp is invalid", 5)
        reason = (pending["payload"]["closure_reason"] if pending else
                  source.get("closure_reason") or task.get("closure_reason") or "restored_reconciliation")
        state = "cancelled" if source["state"] == "cancelled" or reason == "human_timeout" else "closed"
        payload = {"task": task_id, "origin_backup": task["reconciliation"]["backup"], "origin_task_sha256": source_sha,
                   "recovery_receipt": recovery_receipt, "verified_captures": verified, "closed_at": closed_at,
                   "closure_reason": reason, "state": state}
        if pending is None:
            task["restored_closure_pending"] = {"at": at, "payload": payload}
            atomic(task_path(vault, task_id), task)
        else:
            require(pending == {"at": at, "payload": payload}, "Restored task closure evidence changed during reconciliation", 5)
        receipt_id = vault.receipt(receipt_kind, payload, at=at)
        origin = task.pop("reconciliation")
        task.pop("restored_closure_pending")
        task.update(state=state, closure_reason=reason, closed_at=closed_at, closure_pending=False, capacity_held=False,
                    reconciliation_history=[*history, {"origin": origin, "receipt": receipt_id}])
        atomic(task_path(vault, task_id), task)
        return task


def reconcile_processes(vault, task):
    """On macOS, stop only the supervised process identity recorded at launch."""
    require_reconciled(task)
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


def verify_worktree_preservation(vault, task, worktree, capture):
    from .custody import materials

    record = materials(vault).get(capture)
    require(record and record.get("task") == task["id"] and not record.get("session"),
            "Missing worktree has no linked verified preservation", 5)
    copies = worktree_checkpoints(vault, record, worktree)
    require(copies, "Preservation does not contain the recorded worktree", 5)
    verify_preserved_checkpoints(vault, record, copies)


def worktree_checkpoints(vault, record, worktree):
    base = vault.state / "tasks" / record["task"]
    copies = []
    for index, copy in enumerate(record["copies"]):
        if copy["kind"] != "checkpoint" or copy.get("restoration"):
            continue
        root = vault.relocated_path(copy["root"])
        if root.is_relative_to(base) and safe_path(root, copy["path"]).is_relative_to(worktree):
            copies.append((index, copy))
    return copies


def verify_preserved_checkpoints(vault, record, copies):
    from .custody import archive_members, verified_capture

    _, plain = verified_capture(vault, record)
    archive = decode(plain)
    files = archive_members(archive, vault.state / "custody")
    hashes = {path: digest(data) for path, data in files.items()}
    require(all(hashes.get(Path(copy["path"])) == copy["sha256"] for _, copy in copies),
            "Capture does not preserve its recorded worktree checkpoints: " + record["id"], 5)
    return hashes


def verified_worktree_checkpoints(vault, task, worktree):
    from .custody import materials

    result = []
    for record in materials(vault).values():
        if record.get("task") != task["id"] or record.get("session") or record.get("kind") != "conversation":
            continue
        copies = [(index, copy) for index, copy in worktree_checkpoints(vault, record, worktree) if copy["status"] == "present"]
        if copies:
            result.append((record, copies, verify_preserved_checkpoints(vault, record, copies)))
    return result


def remove_preserved_worktree(vault, task, worktree, capture):
    from .custody import archive_tree

    verified = verified_worktree_checkpoints(vault, task, worktree)
    hashes = next((hashes for record, _, hashes in verified if record["id"] == capture), None)
    require(hashes is not None, "Current worktree capture is missing", 5)
    prefix = worktree.relative_to(vault.state / "tasks" / task["id"])
    expected = {path.relative_to(prefix).as_posix(): sha for path, sha in hashes.items() if path.is_relative_to(prefix)}
    observed = {name: entry["sha256"] for name, entry in archive_tree(worktree)["files"].items()}
    require(expected == observed, "Worktree changed after its verified capture", 5)
    git(vault.root, "worktree", "remove", "--force", str(worktree))
    return verified


def record_worktree_removal(vault, task, worktree, capture, *, verified=None):
    from .custody import save_material

    base = vault.state / "tasks" / task["id"]
    require(worktree == Path(task["worktree"]) and worktree != base and worktree.is_relative_to(base),
            "Removal does not match the task worktree", 5)
    require(not worktree.exists() and worktree not in vault.repository.worktree_roots(),
            "Worktree removal has not been confirmed by Git", 5)
    if verified is None:
        verified = verified_worktree_checkpoints(vault, task, worktree)
    for record, copies, _ in verified:
        at = record["captured_at"]
        receipt = vault.receipt("worktree-preservation", {"material": record["id"], "task": task["id"],
                                "worktree": str(worktree), "cipher_sha256": record["cipher_sha256"],
                                "removal_capture": capture, "copy_indices": [index for index, _ in copies]}, at=at)
        for _, copy in copies:
            copy.update(status="moved", moved_at=at, move_receipt=receipt)
        save_material(vault, record)


def reconcile_expired(vault, task_id, now=None):
    from .custody import capture_tree
    with vault.locked():
        task = get_task(vault, task_id)
        require_reconciled(task)
        require(age_status(task, now) == "expired", "Worktree has not expired", 2)
        if task.get("worktree_removed"):
            return task
        base = vault.state / "tasks" / task_id
        worktree = Path(task["worktree"])
        require(worktree.resolve().is_relative_to(base.resolve()), "Unsafe worktree removal", 5)
        purpose = {
            "purpose": "Expired worktree reconciliation", "necessity": "Preserve proposals, sources and checkpoints before removal",
            "owner": vault.config.get("signing_identity") or "controller", "link": task_id}
        capture = task.get("expiry_preservation")
        verified = None
        if worktree.exists():
            capture = capture_tree(vault, base, task=task_id, classification="unknown", purpose=purpose)
            if task.get("processes"):
                reconcile_processes(vault, task)
                capture = capture_tree(vault, base, task=task_id, classification="unknown", purpose=purpose)
            task["expiry_preservation"] = capture
            atomic(task_path(vault, task_id), task)
            verified = remove_preserved_worktree(vault, task, worktree, capture)
        else:
            verify_worktree_preservation(vault, task, worktree, capture)
        record_worktree_removal(vault, task, worktree, capture, verified=verified)
        # Worktree expiry does not cancel the task, restart waiting, or release its capacity.
        task.update(worktree_removed=True, worktree_expired=True)
        atomic(task_path(vault, task_id), task)
        return task
