"""Durable per-copy deletion plans with rechecks before every effect."""
from os.path import abspath
from pathlib import Path
from uuid import uuid4

from .core import Blocked, atomic, digest, read_json, require, safe_path, stamp, utc
from .custody import INACTIVE_COPIES, materials, native_guard, retention_deadline, save_material
from .inbox import pending_archive_paths
from .tasks import all_tasks


def reconcile_closures(vault):
    tasks = {t["id"]: t for t in all_tasks(vault)}
    for record in materials(vault).values():
        task = tasks.get(record.get("task"))
        if task and task.get("closed_at") and not record.get("closed_at"):
            record["closed_at"] = task["closed_at"]
            save_material(vault, record)


def require_expired(record, now):
    deadline = retention_deadline(record)
    require(deadline and utc(now) >= deadline, "Retention has not expired", 5)
    require(not record.get("dependencies"), "Evidence dependencies prevent deletion", 5)
    require(not any(not h.get("ended_at") for h in record.get("holds", [])), "Active hold prevents deletion", 5)


def copy_path(vault, copy):
    return Path(abspath(vault.relocated_path(copy["root"]) / copy["path"]))


def guard(vault, record, copy, now):
    require_expired(record, now)
    if record.get("classification") == "secret":
        require(record.get("quarantine_receipt") and record.get("rotation_receipt") and
                record.get("deletion_decision"), "Secret incident steps are incomplete", 5)
    if copy["kind"] == "native":
        native_guard(vault, record)
    roots = [Path(p).resolve() for p in vault.config.get("storage_roots", [])]
    roots.append((vault.state / "custody").resolve())
    if record.get("kind") == "export" and copy.get("kind") == "export":
        roots.append((vault.root / "inbox").resolve())
    if record.get("kind") == "export" and copy.get("kind") == "archive":
        require(Path(copy["path"]).parts[:1] == (copy["sha256"],), "Archived custody path does not match its digest", 5)
        roots.append((vault.root / "archive").resolve())
    roots.extend(Path(p).resolve() for p in vault.config.get("backup_destinations", []))
    root = vault.relocated_path(copy["root"])
    controller_copy = root.resolve().is_relative_to(vault.state.resolve()) and root.resolve() != vault.state.resolve()
    require(root.is_absolute() and (root.resolve() in roots or controller_copy), "Copy root is not authorized", 5)
    require(root.is_dir() and not root.is_symlink(), "Copy destination is offline or unsafe", 5)
    target = safe_path(root, copy["path"])
    destination = copy_path(vault, copy)
    require(destination not in pending_archive_paths(vault), "Inbox archive move is pending for " + str(target), 5)
    for other in materials(vault).values():
        if other["id"] != record["id"] and any(c.get("status") not in INACTIVE_COPIES and
                copy_path(vault, c) == destination for c in other.get("copies", [])):
            require_expired(other, now)
    return target


def plan(vault, now=None):
    with vault.locked():
        reconcile_closures(vault)
        now = stamp(now)
        pending = pending_archive_paths(vault)
        entries = []
        for record in materials(vault).values():
            deadline = retention_deadline(record)
            if not deadline or utc(now) < deadline:
                continue
            for index, copy in enumerate(record.get("copies", [])):
                if copy.get("status") not in INACTIVE_COPIES and copy_path(vault, copy) not in pending:
                    entries.append({"material": record["id"], "copy_index": index, "copy": copy,
                                    "status": "planned"})
        result = {"id": str(uuid4()), "created_at": now, "entries": entries, "status": "planned"}
        result["digest"] = digest(result)
        atomic(vault.control / "deletions" / (result["id"] + ".json"), result)
        return result


def execute(vault, identifier, now=None):
    with vault.locked():
        path = safe_path(vault.control / "deletions", identifier + ".json", exists=True)
        record = read_json(path)
        frozen = {"id": record["id"], "created_at": record["created_at"], "status": "planned",
                  "entries": [{"material": e["material"], "copy_index": e["copy_index"], "copy": e["copy"], "status": "planned"}
                              for e in record["entries"]]}
        require(digest(frozen) == record["digest"], "Deletion plan changed after persistence")
        for entry in record["entries"]:
            if entry["status"] in INACTIVE_COPIES:
                continue
            try:
                material = materials(vault)[entry["material"]]
                copy = material["copies"][entry["copy_index"]]
                state = {"status", "deleted_at", "moved_at", "move_receipt"}
                require({k: v for k, v in copy.items() if k not in state} ==
                        {k: v for k, v in entry["copy"].items() if k not in state}, "Copy inventory changed", 5)
                if copy["status"] in INACTIVE_COPIES:
                    status = copy["status"]
                    entry.update(status=status, at=copy.get(f"{status}_at") or stamp(now))
                    entry.pop("error", None)
                    atomic(path, record)
                    continue
                target = guard(vault, material, copy, now)
                if target.exists():
                    require(digest(target.read_bytes()) == copy["sha256"], "Copy hash changed; deletion stopped", 5)
                    # The plan and intent are durable before unlink. Recovery rechecks the same path.
                    entry["status"] = "deleting"
                    atomic(path, record)
                    target.unlink()
                require(not target.exists(), "Copy still exists after deletion", 5)
                copy["status"] = "deleted"
                copy["deleted_at"] = stamp(now)
                save_material(vault, material)
                entry.update(status="deleted", at=stamp(now))
                entry.pop("error", None)
            except (Blocked, OSError, KeyError) as exc:
                entry.update(status="pending", error=str(exc), at=stamp(now))
                if entry["copy"].get("kind") == "native":
                    from .custody import hold
                    current = materials(vault).get(entry["material"], {})
                    if not any(h.get("reason") == "Native recovery unproven" and not h.get("ended_at")
                               for h in current.get("holds", [])):
                        hold(vault, entry["material"], "Native recovery unproven", "controller")
            atomic(path, record)
        record["status"] = "complete" if all(e["status"] in INACTIVE_COPIES for e in record["entries"]) else "pending"
        atomic(path, record)
        vault.receipt("deletion-round", {"plan": identifier, "digest": record["digest"], "status": record["status"]})
        return record
