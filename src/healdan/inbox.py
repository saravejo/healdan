"""Content-addressed triage with preserved capture provenance and versions."""
from datetime import timedelta
import os
from pathlib import Path

from . import admission, custody
from .core import Blocked, atomic, digest, read_json, require, safe_path, stamp, sync_directory, utc

EXCLUDED = {"inbox/agent-activities-today.md", "inbox/manual-activities-today.md", "inbox/agent-dashboard.html"}
ARCHIVE_JOURNAL = "zero-byte-archive.json"


def ordinary(path):
    return path.startswith("inbox/") and path not in EXCLUDED and not path.startswith("inbox/tasks/") and not path.endswith("/.gitkeep")


def inventory(vault):
    with vault.locked():
        journal_path = vault.control / "inbox.json"
        items = read_json(journal_path, {})
        for path in sorted((vault.root / "inbox").rglob("*")):
            if not path.is_file() and not path.is_symlink():
                continue
            relative = path.relative_to(vault.root).as_posix()
            if not ordinary(relative):
                continue
            data = safe_path(vault.root, relative, exists=True).read_bytes()
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
        admission.require_triage(vault, sha256, classification)
        if classification != "common":
            from .custody import materials, validate_purpose
            validate_purpose({"classification": classification, "purpose": purpose})
            existing = materials(vault).get("inbox-" + sha256, {})
            require(not existing or existing.get("purpose") == purpose,
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
        if classification != "common":
            from .custody import save_material
            identifier = "inbox-" + sha256
            record = {**existing, "id": identifier, "kind": "export", "classification": classification,
                      "captured_at": min(filter(None, (existing.get("captured_at"), item["entered_at"])), key=utc, default=None),
                      "purpose": purpose,
                      "source_sha256": sha256, "holds": existing.get("holds", []),
                      "dependencies": existing.get("dependencies", []), "copies": existing.get("copies", [])}
            for name in item["paths"]:
                origin = safe_path(vault.root, name)
                if origin.is_file() and digest(origin.read_bytes()) == sha256:
                    copy = {"root": str(vault.root / "inbox"), "path": name.removeprefix("inbox/"),
                            "sha256": sha256, "kind": "export", "status": "present"}
                    if copy not in record["copies"]:
                        record["copies"].append(copy)
            save_material(vault, record)
        atomic(path, items)
        return item


def findings(item, now=None):
    now = utc(now)
    result = []
    if not item.get("entered_at"):
        result.append("unknown_entry_time")
    elif now >= utc(item["entered_at"]) + timedelta(days=7):
        if not item.get("decision") or item["decision"] == "defer":
            result.append("original_triage_overdue")
    if item.get("defer_until") and now >= utc(item["defer_until"]):
        result.append("deferral_due")
    if item.get("classification") == "unknown":
        result.append("classification_pending")
    return result


def pending_archive_paths(vault):
    pending = read_json(safe_path(vault.control, ARCHIVE_JOURNAL), {})
    paths = set()
    for move in pending.values():
        roots = (vault.relocated_path(move["worktree"]),) if "worktree" in move else vault.repository.worktree_roots()
        paths.update(root / move["payload"][key] for root in roots for key in ("source", "destination"))
    return paths


def archive_empty(vault, sha256):
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
        moves = []
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
                move = {"at": stamp(), "payload": payload, "worktree": str(vault.root)}
                pending[relative] = move
                atomic(journal_path, pending)
            require(move["payload"] == payload, "Archive journal differs from the requested move", 5)
            receipt_fields = {"at": move["at"], "payload": payload}
            receipt_id = digest({"kind": "zero-byte-archive", **receipt_fields})
            if receipt_id not in item["receipts"]:
                # An existing destination may have appeared after the preflight.
                create_empty_archive(vault, relative, target_name)
                target = empty_archive_target(vault, relative, target_name)
                require(target.is_file(), f"Archive destination missing for {relative}: {target_name}", 5)
                if source.exists():
                    require(safe_path(vault.root, relative, exists=True).read_bytes() == b"",
                            "Inbox item changed: " + relative, 5)
                    source.unlink()
                    sync_directory(source.parent)
                custody.record_archive_move(vault, classification.links.get(sha256, []), move, receipt_id)
                receipt = vault.receipt("zero-byte-archive", payload, at=move["at"])
                item["receipts"].append(receipt)
                item.setdefault("archive_moves", []).append({**receipt_fields, "receipt": receipt})
                atomic(path, items)
            del pending[relative]
            atomic(journal_path, pending)
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
