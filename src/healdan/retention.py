"""Durable per-copy deletion plans with rechecks before every effect."""
import os
from pathlib import Path
from uuid import uuid4

from . import storage_policy
from .core import Blocked, atomic, canonical_storage_path, digest, read_json, require, safe_path, stamp, sync_directory, utc
from .custody import INACTIVE_COPIES, materials, native_guard, save_material, verified_capture
from .inbox import pending_archive_paths
from .tasks import all_tasks

RESOLVED = INACTIVE_COPIES | {"preserved"}
NATIVE_REPLICAS_PENDING = "Verified ciphertext is needed by native copies awaiting deletion"
CHECKPOINT_REPLICAS_PENDING = "Verified ciphertext is needed by checkpoints awaiting deletion"
PRESERVATION_AUTHORIZATION_PENDING = "Expired signed backup awaits individual preservation authorization"


def reconcile_closures(vault):
    tasks = {t["id"]: t for t in all_tasks(vault)}
    for record in materials(vault).values():
        task = tasks.get(record.get("task"))
        if task and task.get("closed_at") and not record.get("closed_at"):
            record["closed_at"] = task["closed_at"]
            save_material(vault, record)


def preserved(vault, record, policy):
    return (policy["retention"]["mode"] == "keep_forever" or
            storage_policy.deadline(record, policy)[0] == "permanent" or
            record.get("kind") == "backup" and storage_policy.preservation_for(vault, record) is not None)


def require_expired(record, now, policy):
    status, deadline = storage_policy.deadline(record, policy)
    require(status != "unknown", "Retention origin or deadline is unknown", 5)
    require(deadline and utc(now) >= deadline, "Retention has not expired", 5)
    require(not record.get("dependencies"), "Evidence dependencies prevent deletion", 5)
    require(not any(not h.get("ended_at") and not recovery_hold(h) for h in record.get("holds", [])),
            "Active hold prevents deletion", 5)


def recovery_hold(hold):
    return (hold.get("origin") == "controller:native-recovery" and hold.get("owner") == "controller" and
            hold.get("reason") == "Native recovery unproven" and hold.get("dependencies") == [])


def copy_path(vault, copy):
    return canonical_storage_path(vault.relocated_path(copy["root"]) / copy["path"])


def shares_path(vault, copy, target):
    try:
        return copy_path(vault, copy) == target
    except (Blocked, OSError, ValueError, KeyError, TypeError) as original:
        try:
            root = vault.relocated_path(copy["root"])
            candidate = safe_path(root, copy["path"])
            if root.is_absolute() and candidate.resolve() == candidate and candidate != target:
                return False
        except (Blocked, OSError, ValueError, KeyError, TypeError, RuntimeError):
            pass
        raise Blocked("Cannot establish whether custody copy shares the deletion path: " + str(original), 5) from original


def copy_identity(copy):
    state = {"status", "deleted_at", "moved_at", "move_receipt", "archive_copy_index", "verified_archive_sha256",
             "deletion_receipt"}
    return {key: value for key, value in copy.items() if key not in state}


def active_slots(vault, inventory, location):
    return [(record, index, copy) for record in inventory.values() for index, copy in enumerate(record.get("copies", []))
            if copy["status"] not in INACTIVE_COPIES and shares_path(vault, copy, location)]


def generation_locator(material, index, copy):
    return {"material": material["id"], "copy_index": index, "identity": digest(copy_identity(copy))}


def shared_generation(material, index, copy):
    locator = generation_locator(material, index, copy)
    if material["kind"] == "backup":
        locator["generation_digest"] = material["approval"]["digest"]
    return locator


def verified_shared_slots(inventory, entry):
    intent = entry["intent"]
    generations = intent["generations"]
    slots = []
    identities = set()
    for generation in generations:
        material = inventory[generation["material"]]
        index = generation["copy_index"]
        require(type(index) is int and 0 <= index < len(material["copies"]), "Shared custody slot is missing", 5)
        copy = material["copies"][index]
        require(copy["sha256"] == entry["copy"]["sha256"] and copy["status"] != "moved" and
                shared_generation(material, index, copy) == generation, "Shared custody slot changed", 5)
        identities.add((material["id"], index, generation["identity"]))
        slots.append((material, index, copy))
    require(slot(entry) in identities and len(identities) == len(slots) and len(slots) > 1,
            "Shared deletion intent does not identify its custody slots", 5)
    return slots


def verified_archive_slots(inventory, entry):
    sha = entry["copy"]["sha256"]
    slots = []
    for generation in entry.get("verified_archive_generations", []):
        record = inventory.get(generation["material"], {})
        copies = record.get("copies", [])
        index = generation["copy_index"]
        require(0 <= index < len(copies), "Verified archive copy is missing from custody", 5)
        copy = copies[index]
        require(copy["kind"] == "archive" and copy["sha256"] == sha and copy["status"] != "moved" and
                digest(copy_identity(copy)) == generation["identity"], "Verified archive copy changed in custody", 5)
        slots.append((record, copy))
    return slots


def archive_verification_complete(inventory, entry):
    try:
        return all(copy["status"] == "deleted" and copy.get("verified_archive_sha256") == copy["sha256"]
                   for _, copy in verified_archive_slots(inventory, entry))
    except (Blocked, KeyError, TypeError):
        return False


def deletion_payload(entry, material, index):
    return {"material": material, "copy_index": index, "sha256": entry["copy"]["sha256"], "intent": entry.get("intent")}


def deletion_receipt(vault, entry, material, index, at):
    return vault.receipt("deletion-copy", deletion_payload(entry, material, index), at=at)


def shared_copy_reconciled(vault, entry, material, index, copy):
    at = entry["intent"]["at"]
    proof = {"kind": "deletion-copy", "at": at, "payload": deletion_payload(entry, material["id"], index)}
    receipt = digest(proof)
    return (copy["status"] == "deleted" and copy.get("deleted_at") == at and copy.get("deletion_receipt") == receipt and
            (copy["kind"] != "archive" or copy.get("verified_archive_sha256") == copy["sha256"]) and
            read_json(safe_path(vault.control, f"receipts/{receipt}.json")) == proof)


def record_shared_deletion(vault, inventory, entry):
    at = entry["intent"]["at"]
    changed = {}
    for material, index, copy in verified_shared_slots(inventory, entry):
        if shared_copy_reconciled(vault, entry, material, index, copy):
            continue
        require(copy["status"] not in INACTIVE_COPIES, "Shared custody slot was disposed by another effect", 5)
        copy.update(status="deleted", deleted_at=at, deletion_receipt=deletion_receipt(vault, entry, material["id"], index, at))
        if copy["kind"] == "archive":
            copy["verified_archive_sha256"] = copy["sha256"]
        changed[material["id"]] = material
    for material in changed.values():
        save_material(vault, material)


def deletion_reconciled(vault, inventory, entry):
    try:
        if (entry.get("intent") or {}).get("generations"):
            return all(shared_copy_reconciled(vault, entry, *row) for row in verified_shared_slots(inventory, entry))
        return archive_verification_complete(inventory, entry)
    except (Blocked, OSError, KeyError, TypeError):
        return False


def record_archive_deletion(vault, inventory, entry, at):
    changed = {}
    for record, copy in verified_archive_slots(inventory, entry):
        sha = copy["sha256"]
        if copy["status"] != "deleted" or copy.get("verified_archive_sha256") != sha:
            copy.update(status="deleted", deleted_at=copy.get("deleted_at") or at, verified_archive_sha256=sha)
            index = next(i for i, candidate in enumerate(record["copies"]) if candidate is copy)
            copy["deletion_receipt"] = deletion_receipt(vault, entry, record["id"], index, copy["deleted_at"])
            changed[record["id"]] = record
    for record in changed.values():
        save_material(vault, record)


def pending_deletion_paths(vault, *, target=None, exclude=None):
    root = safe_path(vault.control, "deletions")
    inventory = materials(vault)
    paths = {}
    for path in root.glob("*.json"):
        plan = read_json(safe_path(root, path.name, exists=True))
        for entry in plan["entries"]:
            if entry["status"] != "deleting" and not entry.get("awaiting_archive_reconciliation"):
                continue
            if exclude is not None and exclude == (plan["id"], slot(entry)):
                continue
            copies = inventory.get(entry["material"], {}).get("copies", [])
            index = entry["copy_index"]
            if 0 <= index < len(copies) and copies[index]["status"] in INACTIVE_COPIES and (
                    copy_identity(copies[index]) == copy_identity(entry["copy"]) and
                    deletion_reconciled(vault, inventory, entry)):
                continue
            if target is None:
                location = copy_path(vault, entry["copy"])
            elif shares_path(vault, entry["copy"], target):
                location = target
            else:
                continue
            paths.setdefault(location, set()).add(plan["id"])
    return paths


def require_secret_decisions(vault, record):
    from .signing import trusted_signers, verify

    receipt_id = record.get("quarantine_receipt")
    require(isinstance(receipt_id, str) and len(receipt_id) == 64, "Secret quarantine receipt is missing", 5)
    receipt = read_json(safe_path(vault.control, "receipts/" + receipt_id + ".json"))
    require(receipt and digest(receipt) == receipt_id and receipt.get("kind") == "quarantine" and
            receipt["payload"].get("id") == record["id"], "Secret quarantine receipt does not match the material", 5)
    for step, field in (("rotation", "rotation_receipt"), ("deletion", "deletion_decision")):
        decision = verify(record.get(field), "decision", trusted_signers(vault))
        require(decision.get("material") == record["id"] and decision.get("step") == step,
                "Secret incident step does not match the material", 5)


def has_active_checkpoints(record):
    return record.get("kind") == "conversation" and any(
        copy["kind"] == "checkpoint" and copy["status"] not in INACTIVE_COPIES for copy in record["copies"])


def material_guard(vault, record, now, policy):
    from .backups import signed_manifest, verify_replica_deletions
    require(not preserved(vault, record, policy), "Retention policy preserves material", 5)
    require_expired(record, now, policy)
    if record.get("classification") == "secret":
        require_secret_decisions(vault, record)
    if record.get("kind") == "backup":
        signed_manifest(vault, record)
        verify_replica_deletions(vault, record)
    if any(c.get("kind") == "native" for c in record.get("copies", [])):
        from .custody import hold

        recovery_holds = [h for h in record.get("holds", []) if recovery_hold(h) and not h.get("ended_at")]
        try:
            native_guard(vault, record)
            verified_capture(vault, record)
        except (Blocked, OSError, KeyError, ValueError, TypeError) as exc:
            if not recovery_holds:
                hold(vault, record["id"], "Native recovery unproven", "controller", origin="controller:native-recovery")
            raise Blocked("Native recovery unproven: " + str(exc), 5) from exc
        if recovery_holds:
            for entry in recovery_holds:
                entry.update(ended_at=stamp(now), resolution=[record["native_recovery"]["digest"]])
            save_material(vault, record)
    elif has_active_checkpoints(record):
        verified_capture(vault, record)


def authorized_target(vault, record, copy):
    roots = [Path(p).resolve() for p in vault.config.get("storage_roots", [])]
    roots.append((vault.state / "custody").resolve())
    if record.get("kind") == "export" and copy.get("kind") == "export":
        roots.append((vault.root / "inbox").resolve())
    if record.get("kind") == "export" and copy.get("kind") == "archive":
        require(Path(copy["path"]).parts[:1] == (copy["sha256"],), "Archived custody path does not match its digest", 5)
        roots.append((vault.root / "archive").resolve())
    roots.extend(Path(p).resolve() for p in vault.config.get("backup_destinations", []))
    root = vault.relocated_path(copy["root"])
    if copy.get("restoration"):
        journal = read_json(safe_path(vault.control, "restorations/" + copy["restoration"] + ".json"), {})
        binding = journal.get("binding", {})
        if (journal.get("status") == "complete" and binding.get("vault") == vault.identity and
                binding.get("material") == record["id"] and binding.get("destination") == copy["root"] and
                journal.get("inventory", {}).get(copy["path"], {}).get("sha256") == copy["sha256"]):
            roots.append(root)
    controller_copy = root.resolve().is_relative_to(vault.state.resolve()) and root.resolve() != vault.state.resolve()
    require(root.is_absolute() and (root.resolve() in roots or controller_copy), "Copy root is not authorized", 5)
    require(root.is_dir() and not root.is_symlink() and not root.is_junction(), "Copy destination is offline or unsafe", 5)
    target = safe_path(root, copy["path"])
    require(canonical_storage_path(target) == root.resolve() / copy["path"], "Copy path is unsafe", 5)
    return root, target


def guard(vault, record, copy, now, policy=None, *, slots=None):
    from .custody import pending_restoration

    policy = policy if policy is not None else storage_policy.effective(vault)
    material_guard(vault, record, now, policy)
    _, target = authorized_target(vault, record, copy)
    destination = copy_path(vault, copy)
    require(destination not in pending_archive_paths(vault), "Inbox archive move is pending for " + str(target), 5)
    require(not pending_restoration(vault, target=destination),
            "Copy path is reserved by a pending restoration", 5)
    slots = active_slots(vault, materials(vault), destination) if slots is None else slots
    checked = {record["id"]}
    for other, _, shared in slots:
        require(shared["sha256"] == copy["sha256"], "Shared copy has conflicting custody hashes", 5)
        if other["id"] not in checked:
            material_guard(vault, other, now, policy)
            checked.add(other["id"])
        if shared["kind"] == "ciphertext":
            guard_ciphertext(vault, other)
        _, shared_target = authorized_target(vault, other, shared)
        require(shared_target == target, "Shared custody paths do not identify the same target", 5)
    return target


def guard_ciphertext(vault, record):
    from .custody import pending_restoration

    require(not pending_restoration(vault, record["id"]), "Ciphertext is needed by a pending restoration", 5)
    require(not any(c["kind"] == "native" and c["status"] not in INACTIVE_COPIES for c in record["copies"]),
            NATIVE_REPLICAS_PENDING, 5)
    require(not has_active_checkpoints(record), CHECKPOINT_REPLICAS_PENDING, 5)


def pending_plans(vault):
    root = safe_path(vault.control, "deletions")
    plans = [read_json(safe_path(root, path.name, exists=True)) for path in sorted(root.glob("*.json"))]
    return sorted((p for p in plans if p["status"] != "complete"),
                  key=lambda p: (not any(e["status"] == "deleting" for e in p["entries"]), p["created_at"], p["id"]))


def slot(entry):
    return entry["material"], entry["copy_index"], digest(copy_identity(entry["copy"]))


def plan_digest(record):
    frozen = {"id": record["id"], "created_at": record["created_at"], "status": "planned",
              "entries": [{"material": e["material"], "copy_index": e["copy_index"], "copy": e["copy"], "status": "planned"}
                          for e in record["entries"]]}
    return digest(frozen)


def reconcile_inbox(vault, now):
    from .inbox import ordinary

    inbox = read_json(vault.control / "inbox.json", {})
    root = vault.root / "inbox"
    archives = pending_archive_paths(vault)
    records = materials(vault)
    owners = {}
    for record in records.values():
        for copy in record.get("copies", []):
            if copy["kind"] == "export" and vault.relocated_path(copy["root"]) == root and copy["status"] not in INACTIVE_COPIES:
                owners.setdefault(copy["sha256"], set()).add(record["id"])
    for record in records.values():
        sha = record.get("source_sha256")
        item = inbox.get(sha, {})
        if (record.get("kind") != "export" or not item or item.get("sha256") != sha or not root.is_dir() or
                owners.get(sha) != {record["id"]}):
            continue
        copies = record["copies"]
        live = {}
        changed = False
        for relative in item.get("paths", []):
            if not ordinary(relative):
                continue
            try:
                target = safe_path(vault.root, relative)
                location = canonical_storage_path(target)
                if (location in archives or pending_deletion_paths(vault, target=location) or
                        not target.is_file() or digest(target.read_bytes()) != sha):
                    continue
            except (Blocked, OSError):
                continue
            index = next((i for i, c in enumerate(copies) if c["kind"] == "export" and c["sha256"] == sha and
                          c["status"] not in INACTIVE_COPIES and c["path"] == relative.removeprefix("inbox/") and
                          vault.relocated_path(c["root"]) == root), len(copies))
            if index == len(copies):
                copies.append({"root": str(root), "path": relative.removeprefix("inbox/"), "sha256": sha,
                               "kind": "export", "status": "present"})
                changed = True
            live[location] = index
        if live:
            for copy in copies:
                if (copy["kind"] != "export" or copy["sha256"] != sha or copy["status"] in INACTIVE_COPIES or
                        vault.relocated_path(copy["root"]) != root):
                    continue
                try:
                    target = safe_path(root, copy["path"])
                    location = canonical_storage_path(target)
                    if location in archives or pending_deletion_paths(vault, target=location) or target.exists():
                        continue
                    receipt = vault.receipt("retention-copy-move", {"material": record["id"], "sha256": sha,
                                            "from": copy["path"], "inventory_copies": sorted(live.values())}, at=now)
                    copy.update(status="moved", moved_at=stamp(now), move_receipt=receipt)
                    changed = True
                except (Blocked, OSError):
                    continue
        if changed:
            save_material(vault, record)


def plan(vault, now=None, *, exclude=(), skip_empty=False):
    with vault.locked():
        reconcile_closures(vault)
        reconcile_inbox(vault, now)
        now = stamp(now)
        pending = pending_archive_paths(vault)
        policy = storage_policy.effective(vault)
        open_tasks = {t["id"] for t in all_tasks(vault) if not t.get("closed_at")}
        excluded = set(exclude)
        entries = []
        for record in materials(vault).values():
            try:
                status, deadline = storage_policy.deadline(record, policy)
                if (deadline and utc(now) < deadline) or (status == "unknown" and record.get("task") in open_tasks):
                    continue
                if preserved(vault, record, policy) and not storage_policy.preservation_authorization_pending(vault, record, policy, now):
                    continue
            except (Blocked, OSError, ValueError, KeyError, TypeError):
                # The execution guard will diagnose unproven deadlines or decisions for this material.
                pass
            for index, copy in enumerate(record.get("copies", [])):
                if copy.get("status") in INACTIVE_COPIES:
                    continue
                try:
                    if copy_path(vault, copy) in pending:
                        continue
                except (Blocked, OSError, ValueError, KeyError, TypeError):
                    # Keep unverified copies in the plan for the execution guard to report.
                    pass
                entry = {"material": record["id"], "copy_index": index, "copy": copy, "status": "planned"}
                if slot(entry) not in excluded:
                    entries.append(entry)
        if skip_empty and not entries:
            return None
        result = {"id": str(uuid4()), "created_at": now, "entries": entries, "status": "planned"}
        result["digest"] = digest(result)
        atomic(vault.control / "deletions" / (result["id"] + ".json"), result)
        return result


def file_identity(path):
    info = path.stat()
    return [info.st_dev, info.st_ino]


def file_revision(path):
    info = path.stat()
    return [info.st_ctime_ns, info.st_size]


def apply_entry(vault, path, plan, entry, now):
    inventory = materials(vault)
    material = inventory[entry["material"]]
    copy = material["copies"][entry["copy_index"]]
    require(copy_identity(copy) == copy_identity(entry["copy"]), "Copy inventory changed", 5)
    at = stamp(now)
    intent = entry.get("intent")
    if intent:
        history = entry.get("intent_history", [])
        require(intent["slot"] == list(slot(entry)) and intent["plan_digest"] == plan["digest"] and
                intent.get("plan_id", plan["id"]) == plan["id"] and
                intent.get("supersedes") == (digest(history[-1]) if history else None),
                "Deletion intent does not match the plan, copy or its history", 5)
    shared = bool(intent and intent.get("generations"))
    if copy["status"] in INACTIVE_COPIES:
        if entry["status"] == "deleting" and shared:
            root, target = authorized_target(vault, material, copy)
            require(intent["path"] == str(target) and intent["root_identity"] == file_identity(root),
                    "Deletion intent no longer matches the storage", 5)
            record_shared_deletion(vault, inventory, entry)
        elif entry["status"] == "deleting" and entry.get("verified_archive_generations"):
            record_archive_deletion(vault, inventory, entry, at)
        status = copy["status"]
        entry.update(status=status, at=copy.get(f"{status}_at") or at)
        if copy.get("deletion_receipt"):
            entry["receipt"] = copy["deletion_receipt"]
        return

    policy = storage_policy.effective(vault)
    if not intent and not entry.get("verified_archive_generations") and preserved(vault, material, policy):
        require(not storage_policy.preservation_authorization_pending(vault, material, policy, now),
                PRESERVATION_AUTHORIZATION_PENDING, 5)
        entry.update(status="preserved", at=at, policy_version=policy["version"])
        return
    root, target = authorized_target(vault, material, copy)
    present = target.exists()
    if intent:
        require(intent["path"] == str(target) and intent["root_identity"] == file_identity(root),
                "Deletion intent no longer matches the storage", 5)
    if present:
        if preserved(vault, material, policy):
            require(not storage_policy.preservation_authorization_pending(vault, material, policy, now),
                    PRESERVATION_AUTHORIZATION_PENDING, 5)
            entry.update(status="preserved", at=at, policy_version=policy["version"])
            return
        location = copy_path(vault, copy)
        slots = active_slots(vault, inventory, location)
        guard(vault, material, copy, now, policy, slots=slots)
        reservation = pending_deletion_paths(vault, target=location, exclude=(plan["id"], slot(entry)))
        require(not reservation, "Another deletion plan is reconciling this copy", 5)
        file_id = file_identity(target)
        revision = file_revision(target)
        mtime_ns = target.stat().st_mtime_ns
        require(not intent or intent["file_identity"] == file_id and intent.get("file_revision", revision) == revision and
                intent.get("file_mtime_ns", mtime_ns) == mtime_ns,
                "Copy identity changed after deletion intent", 5)
        require(digest(safe_path(root, copy["path"], exists=True).read_bytes()) == copy["sha256"],
                "Copy hash changed; deletion stopped", 5)
        archives = [generation_locator(*row) for row in slots if row[2]["kind"] == "archive"]
        previous_archives = entry.get("verified_archive_generations", [])
        if previous_archives:
            verified_archive_slots(inventory, entry)
        generations = [shared_generation(*row) for row in slots]
        if intent:
            if shared:
                verified_shared_slots(inventory, entry)
            previous = intent.get("generations", [shared_generation(material, entry["copy_index"], copy)])
            require(all(generation in generations for generation in previous) and
                    all(generation in archives for generation in previous_archives),
                    "Shared custody changed after verifying deletion", 5)
            if generations != previous or archives != previous_archives:
                # On Windows st_ctime is a creation timestamp, so the old revision alone cannot prove a file was untouched.
                require(len(generations) > 1 and intent.get("file_revision") == revision and
                        (os.name != "nt" or intent.get("file_mtime_ns") == mtime_ns),
                        "Original file revision is unproven for the expanded deletion intent", 5)
                entry.setdefault("intent_history", []).append(intent)
                intent = {**intent, "at": at, "generations": generations, "file_mtime_ns": mtime_ns, "supersedes": digest(intent)}
                shared = True
        elif entry["status"] == "deleting" and previous_archives:
            require(archives == previous_archives and len(generations) == len(archives),
                    "Another custody generation appeared after verifying deletion", 5)
        if archives:
            entry["verified_archive_generations"] = archives
        if intent is None:
            intent = {"path": str(target), "slot": list(slot(entry)), "root_identity": file_identity(root),
                      "file_identity": file_id, "file_revision": revision, "file_mtime_ns": mtime_ns,
                      "plan_digest": plan["digest"], "plan_id": plan["id"], "at": at}
            if material["kind"] == "backup":
                intent["generation_digest"] = material["approval"]["digest"]
            if len(generations) > 1:
                intent["generations"] = generations
                shared = True
        entry["intent"] = intent
        if shared:
            verified_shared_slots(inventory, entry)
        entry["status"] = "deleting"
        atomic(path, plan)
        require(file_identity(target) == file_id and file_revision(target) == revision and target.stat().st_mtime_ns == mtime_ns and
                file_identity(root) == intent["root_identity"] and
                digest(safe_path(root, copy["path"], exists=True).read_bytes()) == copy["sha256"],
                "Copy changed after deletion intent", 5)
        target.unlink()
        sync_directory(target.parent)
    else:
        if copy["kind"] == "archive" and not intent and not entry.get("verified_archive_generations"):
            entry["awaiting_archive_reconciliation"] = True
        require(entry["status"] == "deleting" and (intent and intent["plan_digest"] == plan["digest"] or
                entry.get("verified_archive_generations") or entry.get("verified_archive_sha256") == copy["sha256"]),
                "Copy is absent without verified deletion intent", 5)
    require(not target.exists(), "Copy still exists after deletion", 5)
    at = (entry.get("intent") or {}).get("at", at)
    if shared:
        record_shared_deletion(vault, inventory, entry)
    elif entry.get("verified_archive_generations"):
        record_archive_deletion(vault, inventory, entry, at)
    else:
        copy.update(status="deleted", deleted_at=at,
                    deletion_receipt=deletion_receipt(vault, entry, material["id"], entry["copy_index"], at))
        # A pre-generation journal proved bytes for its own slot only.
        if entry.get("verified_archive_sha256") == copy["sha256"]:
            copy["verified_archive_sha256"] = copy["sha256"]
        save_material(vault, material)
    entry.update(status="deleted", at=at, receipt=copy.get("deletion_receipt"))


def execute(vault, identifier, now=None):
    with vault.locked():
        path = safe_path(vault.control / "deletions", identifier + ".json", exists=True)
        record = read_json(path)
        require(plan_digest(record) == record["digest"], "Deletion plan changed after persistence")
        require(record["id"] == identifier, "Deletion plan identifier changed", 5)
        reconcile_inbox(vault, now)
        for entry in sorted(record["entries"], key=lambda e: (e["status"] != "deleting", e["copy"]["kind"] == "ciphertext")):
            if entry["status"] in RESOLVED:
                if entry["status"] == "preserved":
                    try:
                        material = materials(vault)[entry["material"]]
                        copy = material["copies"][entry["copy_index"]]
                        if (copy["status"] not in INACTIVE_COPIES and
                                storage_policy.preservation_authorization_pending(vault, material, storage_policy.effective(vault), now)):
                            entry.update(status="pending", error=PRESERVATION_AUTHORIZATION_PENDING, at=stamp(now))
                    except (Blocked, OSError, ValueError, KeyError, TypeError) as exc:
                        entry.update(status="pending", error=str(exc), at=stamp(now))
                continue
            try:
                apply_entry(vault, path, record, entry, now)
                entry.pop("error", None)
                entry.pop("awaiting_archive_reconciliation", None)
            except (Blocked, OSError, ValueError, KeyError, IndexError, TypeError) as exc:
                if entry["status"] != "deleting":
                    entry["status"] = "pending"
                entry.update(error=str(exc), at=stamp(now))
            atomic(path, record)
        record["pending"] = [{"material": e["material"], "copy_index": e["copy_index"], "reason": e.get("error")}
                             for e in record["entries"] if e["status"] not in RESOLVED]
        record["status"] = "pending" if record["pending"] else "complete"
        atomic(path, record)
        vault.receipt("deletion-round", {"plan": identifier, "digest": record["digest"], "status": record["status"]},
                      at=record["created_at"])
        return record
