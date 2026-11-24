"""Content-addressed triage with preserved capture provenance and versions."""
from datetime import timedelta
import os
from pathlib import Path
import stat
from uuid import uuid4

from . import admission, custody
from .core import Blocked, atomic, canonical_storage_path, digest, read_json, require, safe_path, stamp, sync_directory, utc

EXCLUDED = {"inbox/agent-activities-today.md", "inbox/manual-activities-today.md", "inbox/agent-dashboard.html"}
ARCHIVE_JOURNAL = "zero-byte-archive.json"


def ordinary(path):
    return path.startswith("inbox/") and path not in EXCLUDED and not path.startswith("inbox/tasks/") and not path.endswith("/.gitkeep")


def ordinary_files(root):
    for path in sorted((root / "inbox").rglob("*")):
        relative = path.relative_to(root).as_posix()
        if ordinary(relative) and (path.is_file() or path.is_symlink()):
            yield relative, safe_path(root, relative, exists=True).read_bytes()


def inventory(vault):
    with vault.locked():
        journal_path = vault.control / "inbox.json"
        items = read_json(journal_path, {})
        for relative, data in ordinary_files(vault.root):
            key = digest(data)
            # Hash identifies copied/renamed bytes. New bytes link to earlier versions at this path.
            if key not in items:
                previous = [k for k, value in items.items() if relative in value["paths"]]
                entries = [items[k]["entered_at"] for k in previous if items[k].get("entered_at")]
                items[key] = {"sha256": key, "size": len(data), "paths": [], "versions_of": previous,
                              "entered_at": min(entries) if entries else None,
                              "entry_origin": "prior_version" if entries else None,
                              "classification": "unknown", "decision": None, "owner": None,
                              "inventoried_at": stamp(), "receipts": []}
            if relative not in items[key]["paths"]:
                items[key]["paths"].append(relative)
        atomic(journal_path, items)
        view = admission.Classification(vault, admission.published_rows(vault))
        result = []
        for item in items.values():
            try:
                classification, _ = view.current(item["sha256"])
                classification = classification or item["classification"]
                result.append(dict(item, classification=classification))
            except Blocked as exc:
                result.append(dict(item, classification="unknown", classification_conflict=str(exc)))
        return result


def decide(vault, sha256, decision, *, owner, classification, entered_at=None, entry_origin=None,
           defer_until=None, destination=None, purpose=None):
    require(decision in {"ingest", "project", "resource", "discard", "archive", "defer"}, "Invalid triage decision", 2)
    require(classification in {"common", "personal", "sensitive", "mixed", "unknown", "secret"}, "Invalid class", 2)
    require(owner, "Triage requires a responsible owner", 2)
    with vault.locked():
        path = vault.control / "inbox.json"
        items = read_json(path, {})
        require(sha256 in items, "Inventory the Inbox item first", 2)
        item = items[sha256]
        if classification == "secret":
            from .incidents import quarantine
            quarantines = []
            for name in item["paths"]:
                origin = safe_path(vault.root, name)
                if origin.is_file() and digest(origin.read_bytes()) == sha256:
                    quarantines.append(quarantine(vault, name, owner))
            return {"classification": "secret", "quarantines": quarantines}
        first_class = admission.require_triage(vault, sha256, classification)
        identifier = "inbox-" + sha256
        existing = custody.materials(vault).get(identifier, {})
        if classification != "common":
            custody.validate_purpose({"classification": classification, "purpose": purpose})
            require(not existing or existing.get("purpose") == purpose or (first_class and existing.get("classification") == "unknown"),
                    "Triage purpose differs from existing custody", 5)
        if entered_at:
            require(entry_origin, "Capture provenance is required", 2)
            if item.get("entered_at"):
                require(utc(entered_at) <= utc(item["entered_at"]), "Capture cannot reset the original deadline", 2)
            item["entered_at"], item["entry_origin"] = stamp(entered_at), entry_origin
        if decision == "defer":
            require(defer_until and utc(defer_until) > utc(), "A future explicit deferral date is required", 2)
        require(decision == "defer" or destination, "A decision needs a destination or disposition reference", 2)
        item.update(classification=classification, decision=decision, owner=owner,
                    decided_at=stamp(), defer_until=stamp(defer_until) if defer_until else None, destination=destination)
        if purpose is not None:
            item["purpose"] = purpose
        receipt = vault.receipt("inbox-decision", item)
        item["decision_receipt"] = receipt
        item["receipts"].append(receipt)
        if classification != "common" or (first_class and existing):
            record = {**existing, "id": identifier, "kind": "export", "classification": classification,
                      "captured_at": min(filter(None, (existing.get("captured_at"), item["entered_at"])), key=utc, default=None),
                      "purpose": purpose if classification != "common" else existing.get("purpose"),
                      "source_sha256": sha256, "holds": existing.get("holds", []),
                      "dependencies": existing.get("dependencies", []), "copies": existing.get("copies", [])}
            if first_class:
                record["decision_receipt"] = receipt
            for name in item["paths"]:
                origin = safe_path(vault.root, name)
                if origin.is_file() and digest(origin.read_bytes()) == sha256:
                    copy = {"root": str(vault.root / "inbox"), "path": name.removeprefix("inbox/"),
                            "sha256": sha256, "kind": "export", "status": "present"}
                    if copy not in record["copies"]:
                        record["copies"].append(copy)
            custody.save_material(vault, record)
        atomic(path, items)
        return item


def worktree_roots(vault):
    return {root for root in vault.repository.worktree_roots() if (root / ".git").exists()}


def worktree_inbox_digests(vault):
    return {(relative, digest(body)) for root in worktree_roots(vault) for relative, body in ordinary_files(root)}


def archive_destination_verified(vault, root, destination, records, sha):
    target = safe_path(root, destination)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return custody.verified_archive_deletion(vault, records, target, sha)
    return stat.S_ISREG(info.st_mode) and info.st_size == 0 and digest(target.read_bytes()) == sha


def archive_complete(vault, item, *, observed=None):
    sha = item["sha256"]
    paths = set(item["paths"])
    if not paths or sha != digest(b""):
        return False
    if paths & read_json(safe_path(vault.control, ARCHIVE_JOURNAL), {}).keys():
        return False
    if observed is None:
        try:
            observed = worktree_inbox_digests(vault)
        except (Blocked, OSError):
            return False
    if any(content == sha for _, content in observed):
        return False
    roots = worktree_roots(vault)
    records = custody.materials(vault).values()
    archived = set()
    for identifier in item.get("receipts", []):
        if not admission.sha256(identifier):
            continue
        value = read_json(safe_path(vault.control / "receipts", identifier + ".json"))
        if not isinstance(value, dict) or value.get("kind") != "zero-byte-archive" or digest(value) != identifier:
            continue
        payload = value.get("payload", {})
        if not isinstance(payload, dict):
            continue
        source, destination = payload.get("source"), payload.get("destination")
        if not (isinstance(source, str) and source in paths and isinstance(destination, str) and
                payload.get("sha256") == sha and payload.get("size") == 0 and
                destination.replace("\\", "/") == f"archive/{sha}/{Path(source).name}"):
            continue
        destination = destination.replace("\\", "/")
        bound_root = payload.get("worktree")
        try:
            candidates = roots if bound_root is None else roots & {vault.relocated_path(bound_root)}
            owned = {root: custody.archived_origin_records(vault, records, safe_path(root, source), sha, identifier)
                     for root in candidates}
            if bound_root is None:
                candidates = {root for root, links in owned.items() if links} or candidates
            proven = [root for root in candidates if archive_destination_verified(
                vault, root, destination, owned[root], sha)]
        except (Blocked, OSError, KeyError, TypeError, ValueError):
            return False
        if len(proven) != 1:
            return False
        archived.add(source)
    return archived == paths


def findings(item, now=None, *, vault=None, observed=None):
    now = utc(now)
    result = []
    if not item.get("entered_at"):
        result.append("unknown_entry_time")
    elif now >= utc(item["entered_at"]) + timedelta(days=7):
        if not item.get("decision") or item["decision"] == "defer":
            result.append("original_triage_overdue")
    if item.get("defer_until") and now >= utc(item["defer_until"]):
        result.append("deferral_due")
    overdue = {"original_triage_overdue", "deferral_due"}
    if vault is not None and overdue.intersection(result) and archive_complete(vault, item, observed=observed):
        result = [finding for finding in result if finding not in overdue]
    if item.get("classification") == "unknown":
        result.append("classification_pending")
    return result


def pending_archive_paths(vault):
    pending = read_json(safe_path(vault.control, ARCHIVE_JOURNAL), {})
    paths = set()
    for move in pending.values():
        roots = (vault.relocated_path(move["worktree"]),) if "worktree" in move else vault.repository.worktree_roots()
        paths.update(canonical_storage_path(root / move["payload"][key])
                     for root in roots for key in ("source", "destination"))
    return paths


def archive_empty(vault, sha256):
    from .retention import pending_deletion_paths

    with vault.locked():
        path = vault.control / "inbox.json"
        items = read_json(path, {})
        require(sha256 in items, "Inventory the Inbox item first", 2)
        item = items[sha256]
        classification = admission.Classification(vault, admission.published_rows(vault))
        current, _ = classification.current(sha256)
        require(sha256 == digest(b"") and item["size"] == 0 and current == "common",
                "Only zero-byte ordinary material may auto-archive", 5)
        journal_path = safe_path(vault.control, ARCHIVE_JOURNAL)
        pending = read_json(journal_path, {})
        deletions = pending_deletion_paths(vault)
        moves, blocked = [], []
        for relative in item["paths"]:
            require(ordinary(relative), "Only ordinary Inbox material may auto-archive", 5)
            source = safe_path(vault.root, relative)
            move = pending.get(relative)
            if move and "worktree" in move:
                require(vault.relocated_path(move["worktree"]) == vault.root,
                        "Retry the pending archive move in its original worktree: " + relative, 5)
            if not source.exists() and not move:
                continue
            target_name = f"archive/{sha256}/{Path(relative).name}"
            plans = deletions.get(canonical_storage_path(source), set()) | deletions.get(
                canonical_storage_path(vault.root / target_name), set())
            if plans:
                commands = ", ".join(f"maintenance execute {identifier}" for identifier in sorted(plans))
                blocked.append(f"{relative} -> {target_name} ({commands})")
                continue
            target = empty_archive_target(vault, relative, target_name)
            if source.exists():
                require(source.is_file() and source.read_bytes() == b"", "Inbox item changed: " + relative, 5)
            else:
                require(target.is_file(), f"Incomplete archive lost both {relative} and {target_name}", 5)
            moves.append((relative, source, target_name))
        for relative, source, target_name in moves:
            payload = {"source": relative, "destination": target_name, "sha256": sha256, "size": 0}
            move = pending.get(relative)
            if move is None:
                move = {"at": stamp(), "payload": {**payload, "worktree": str(vault.root), "move_id": str(uuid4())},
                        "worktree": str(vault.root)}
                pending[relative] = move
                atomic(journal_path, pending)
            # A legacy journal may already have recorded the receipt using this exact payload.
            frozen = move["payload"]
            require(frozen.keys() - payload.keys() <= {"worktree", "move_id"} and
                    all(frozen.get(key) == value for key, value in payload.items()) and
                    ("worktree" not in frozen or vault.relocated_path(frozen["worktree"]) == vault.root),
                    "Archive journal differs from the requested move", 5)
            payload = frozen
            receipt_fields = {"at": move["at"], "payload": payload}
            receipt_id = digest({"kind": "zero-byte-archive", **receipt_fields})
            if receipt_id not in item["receipts"]:
                origins = custody.archive_move_origins(vault, classification.links.get(sha256, []), relative, sha256, receipt_id)
                # An existing destination may have appeared after the preflight.
                create_empty_archive(vault, relative, target_name)
                target = empty_archive_target(vault, relative, target_name)
                require(target.is_file(), f"Archive destination missing for {relative}: {target_name}", 5)
                if source.exists():
                    require(safe_path(vault.root, relative, exists=True).read_bytes() == b"",
                            "Inbox item changed: " + relative, 5)
                    source.unlink()
                    sync_directory(source.parent)
                custody.record_archive_move(vault, origins, move, receipt_id)
                receipt = vault.receipt("zero-byte-archive", payload, at=move["at"])
                item["receipts"].append(receipt)
                item.setdefault("archive_moves", []).append({**receipt_fields, "receipt": receipt})
                atomic(path, items)
            del pending[relative]
            atomic(journal_path, pending)
        require(not blocked, "Resume retention first for the pending deletion: " + ", ".join(blocked), 5)
        return item


def empty_archive_target(vault, source, destination):
    message = f"Archive destination conflicts with {source}: {destination}"
    try:
        target = safe_path(vault.root, destination)
        require(not target.exists() or (target.is_file() and target.read_bytes() == b""), message, 5)
        return target
    except (Blocked, OSError) as exc:
        raise Blocked(message, 5) from exc


def create_empty_archive(vault, source, destination):
    target = empty_archive_target(vault, source, destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as stream:
            os.fsync(stream.fileno())
    except FileExistsError:
        empty_archive_target(vault, source, destination)
    else:
        sync_directory(target.parent)
