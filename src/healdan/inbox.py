"""Content-addressed triage with preserved capture provenance and versions."""
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from .core import atomic, digest, read_json, require, safe_path, stamp, utc

EXCLUDED = {"inbox/agent-activities-today.md", "inbox/manual-activities-today.md", "inbox/agent-dashboard.html"}


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
        return list(items.values())


def decide(vault, sha256, decision, *, owner, classification, entered_at=None, entry_origin=None,
           defer_until=None, destination=None, purpose=None):
    require(decision in {"ingest", "project", "resource", "discard", "archive", "defer"}, "Invalid triage decision", 2)
    require(classification in {"common", "personal", "sensitive", "mixed", "unknown", "secret"}, "Invalid class", 2)
    require(owner, "Triage requires a responsible owner", 2)
    if classification == "secret":
        from .incidents import quarantine
        items = read_json(vault.control / "inbox.json", {})
        require(sha256 in items, "Inventory the Inbox item first", 2)
        quarantines = [quarantine(vault, path, owner) for path in items[sha256]["paths"]
                       if safe_path(vault.root, path).is_file()]
        return {"classification": "secret", "quarantines": quarantines}
    if classification != "common":
        from .custody import validate_purpose
        validate_purpose({"classification": classification, "purpose": purpose})
    with vault.locked():
        path = vault.control / "inbox.json"
        items = read_json(path, {})
        require(sha256 in items, "Inventory the Inbox item first", 2)
        item = items[sha256]
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
        receipt = vault.receipt("inbox-decision", item)
        item["receipts"].append(receipt)
        atomic(path, items)
        if classification != "common":
            from .custody import materials, save_material
            identifier = "inbox-" + sha256
            existing = materials(vault).get(identifier, {})
            record = {"id": identifier, "kind": "export", "classification": classification,
                      "captured_at": item["entered_at"], "purpose": purpose, "holds": existing.get("holds", []),
                      "dependencies": existing.get("dependencies", []), "copies": []}
            for name in item["paths"]:
                if safe_path(vault.root, name).is_file():
                    record["copies"].append({"root": str(vault.root / "inbox"), "path": name.removeprefix("inbox/"),
                                             "sha256": sha256, "kind": "export", "status": "present"})
            save_material(vault, record)
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


def archive_empty(vault, sha256):
    with vault.locked():
        path = vault.control / "inbox.json"
        items = read_json(path, {})
        item = items[sha256]
        require(item["size"] == 0 and item["classification"] == "common", "Only zero-byte ordinary material may auto-archive", 5)
        for relative in item["paths"]:
            source = safe_path(vault.root, relative)
            if not source.exists():
                continue
            require(source.stat().st_size == 0 and digest(source.read_bytes()) == sha256, "Inbox item changed")
            target = safe_path(vault.root, "archive/" + sha256 + "/" + Path(relative).name)
            atomic(target, b"")
            receipt = vault.receipt("zero-byte-archive", {"source": relative, "destination": str(target.relative_to(vault.root)),
                                                       "sha256": sha256, "size": 0})
            source.unlink()
            item["receipts"].append(receipt)
        item.update(decision="archive", decided_at=stamp())
        atomic(path, items)
        return item
