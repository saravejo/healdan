"""Encrypted backup generations with immutable expiry and verified copies."""
from pathlib import Path, PurePosixPath, PureWindowsPath
from uuid import UUID, uuid4
import re
import tempfile

from . import backup_snapshot as snapshot, storage_policy
from .core import Blocked, canonical, decode, digest, file_digest, json_paths, read_json, require, safe_path, stamp, utc, atomic
from .custody import archive_members, decrypt, encrypt, materials, save_material, validate_purpose, verified_capture
from .lineage import sha256
from .signing import envelope, verify


def history_bundle(vault):
    """Bundle history from refs fixed before inspecting their reachable paths."""
    return snapshot.frozen_bundle(vault, snapshot.git_identity(vault.root))


def validate_generation(kind, members, expires_at, now=None, *, policy=None):
    require(kind in {"long", "short"}, "Unknown backup generation kind", 2)
    require(expires_at is not None, "Specify a future UTC expiry or permanent", 2)
    expiry = None if expires_at == "permanent" else utc(expires_at)
    require(expiry is None or expiry > utc(now), "Backup expiry must be in the future", 2)
    if kind == "long":
        require(not members, "Long backups contain conversation manifests only", 5)
    for member in members:
        status, deadline = storage_policy.deadline(member, policy)
        require(status == "permanent" or (status == "finite" and expiry is not None and expiry < deadline),
                "Short backup expiry must precede every finite material deadline; unknown deadlines require resolution", 5)


def generation_members(known, kind, expires_at, member_ids, now, policy):
    require(len(set(member_ids)) == len(member_ids) and all(i in known for i in member_ids),
            "Short backup members must be unique and inventoried", 5)
    members = [known[i] for i in member_ids]
    validate_generation(kind, members, expires_at, now, policy=policy)
    for member_id, member in zip(member_ids, members, strict=True):
        require(snapshot.identifier(member_id) and member.get("id") == member_id and
                member.get("kind") == "conversation" and member.get("classification") != "secret",
                "Only eligible conversation captures can be copied into a short backup", 5)
        validate_purpose(member)
    return members


def verified_member(vault, member, cipher=None):
    if cipher is not None:
        require(digest(cipher) == member.get("cipher_sha256") and len(cipher) == member.get("size"),
                "Short backup member differs from its current custody ciphertext", 5)
    data, plain = verified_capture(vault, member, cipher)
    verify_conversation(member, plain)
    return data


def create(vault, kind, expires_at, member_ids=(), *, now=None, scheduled=False):
    with vault.locked():
        vault.no_transaction()
        now = stamp(now)
        records = snapshot.control_records(vault)
        policy = storage_policy.effective(vault)
        policy_history = decode(records.get("storage-policy.json", b"[]"))
        require(policy_history[-1]["payload"] == policy if policy_history else policy["version"] == 0,
                "Backup policy changed during snapshot capture; retry backup", 5)
        status, detail = storage_policy.backup_status(vault, policy, scheduled=scheduled)
        require(status == "configured", detail, 5)
        require(not scheduled or policy["backup"]["mode"] == "scheduled", "Scheduled backup is disabled by policy", 5)
        known = decode(records.get("materials.json", b"{}"))
        members = generation_members(known, kind, expires_at, member_ids, now, policy)
        member_files = {member["id"]: verified_member(vault, member) for member in members}

        destinations = vault.config["backup_destinations"]
        require(len(destinations) == len(set(map(Path, destinations))) and all(
            Path(p).is_dir() and not Path(p).is_symlink() and not Path(p).is_junction() for p in destinations),
            "A backup destination is offline, duplicated or unsafe", 5)
        key = Path(vault.config.get("backup_signing_key") or "")
        signers = external_file(vault.config.get("backup_allowed_signers"), "Backup allowed signers", vault.root)
        require(key.is_absolute() and key.is_file() and
                not key.resolve().is_relative_to(vault.root) and key.resolve() != Path(vault.config.get("signing_key") or "").resolve(),
                "A separate external backup signing key and policy are required", 5)
        git_state = snapshot.git_identity(vault.root)
        require(snapshot.git_identity(vault.root) == git_state, "Git references changed during snapshot capture; retry backup", 5)
        bundle = snapshot.frozen_bundle(vault, git_state)
        archive = snapshot.assemble(vault, git_state, records, member_files, bundle)
        plain = canonical(archive)
        identifier = str(uuid4())
        copies = [{"root": str(Path(destination).resolve()), "path": identifier + ".age",
                   "manifest": identifier + ".manifest.json"} for destination in destinations]
        manifest = {"format": snapshot.MANIFEST, "id": identifier, "source_vault": vault.identity,
                    "generation": kind, "created_at": now, "expires_at": None if expires_at == "permanent" else stamp(expires_at),
                    "members": list(member_ids), "commit": git_state["head"], "git_sha256": digest(git_state),
                    "inventory_sha256": digest(snapshot.inventory(archive)), "plain_sha256": digest(plain),
                    "origin_binding_sha256": digest(archive[snapshot.SOURCE_BINDING]), "replica_count": len(copies),
                    "replica_slots_sha256": [replica_slot_digest(index, copy) for index, copy in enumerate(copies)]}
        if expires_at == "permanent":
            manifest["expiry"] = "permanent"
        human_signers = vault.config.get("allowed_signers") or ""
        snapshot.check_snapshot(plain, manifest, human_signers, signers, temporary_root=vault.state)
        require(snapshot.control_records(vault) == records,
                "Controller records changed during snapshot capture; retry backup", 5)
        cipher = encrypt(vault, plain)
        manifest["cipher_sha256"] = digest(cipher)
        approval = envelope(manifest, "backup", vault.config["backup_signing_identity"], key)
        verify_portable_manifest(identifier, approval, signers)
        manifest_hash = digest(canonical(approval) + b"\n")
        record = {**manifest, "kind": "backup", "holds": [], "dependencies": [], "copies": copies,
                  "status": "writing", "publication": approval}
        for copy in copies:
            copy.update(sha256=manifest["cipher_sha256"], kind="ciphertext", status="planned", manifest_sha256=manifest_hash)
        save_material(vault, record)
        return publish_generation(vault, record, cipher, plain, now)


def external_file(path, label, *excluded):
    value = Path(path or "")
    require(value.is_absolute() and value.is_file() and
            not any(value.resolve().is_relative_to(Path(root).resolve()) for root in excluded),
            "External " + label + " file is required", 5)
    return safe_path(value.parent, value.name, exists=True)


def verify_conversation(record, plain):
    archive = decode(plain)
    require(isinstance(archive, dict) and archive.get("format") == "healdan-tree-v1" and isinstance(archive.get("files"), dict),
            "Invalid conversation capture archive", 5)
    with tempfile.TemporaryDirectory(prefix="healdan-verify-capture-") as directory:
        files = archive_members(archive, Path(directory))
    require(record.get("artifact_inventory") == {name.as_posix(): {"sha256": digest(body), "size": len(body)}
                                                  for name, body in files.items()},
            "Conversation capture differs from its custody inventory", 5)


def verify_portable_manifest(identifier, approval, signers):
    require(isinstance(approval, dict) and set(approval) == snapshot.SIGNATURE_FIELDS,
            "Invalid portable backup manifest envelope", 5)
    manifest = verify(approval, "backup", signers)
    fields = {"format", "id", "source_vault", "generation", "created_at", "expires_at", "members", "commit",
              "git_sha256", "inventory_sha256", "plain_sha256", "cipher_sha256"}
    require(isinstance(manifest, dict) and manifest.get("format") == snapshot.MANIFEST and
            fields <= manifest.keys() <= fields | {"expiry", "origin_binding_sha256", "replica_count", "replica_slots_sha256"} and
            ("replica_count" not in manifest or type(manifest["replica_count"]) is int and manifest["replica_count"] > 0) and
            ("origin_binding_sha256" not in manifest or sha256(manifest["origin_binding_sha256"])) and manifest["id"] == identifier and
            snapshot.identifier(identifier) and snapshot.identifier(manifest["source_vault"]) and
            manifest["generation"] in {"long", "short"} and isinstance(manifest["members"], list) and
            all(snapshot.identifier(member) for member in manifest["members"]) and
            len(set(manifest["members"])) == len(manifest["members"]) and
            (manifest["generation"] == "short" or not manifest["members"]) and
            isinstance(manifest["commit"], str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", manifest["commit"]) and
            all(sha256(manifest[key]) for key in ("git_sha256", "inventory_sha256", "plain_sha256", "cipher_sha256")),
            "Portable backup manifest does not match the requested generation", 5)
    if "replica_slots_sha256" in manifest:
        slots = manifest["replica_slots_sha256"]
        require(isinstance(slots, list) and len(slots) == manifest.get("replica_count") and
                all(sha256(slot) for slot in slots) and len(set(slots)) == len(slots),
                "Invalid signed backup publication plan", 5)
    require(manifest["created_at"] == stamp(manifest["created_at"]) and
            (manifest["expires_at"] is None and manifest.get("expiry") == "permanent" or
             "expiry" not in manifest and manifest["expires_at"] == stamp(manifest["expires_at"]) and
             utc(manifest["created_at"]) < utc(manifest["expires_at"])), "Invalid original backup expiry", 5)
    return manifest


def publish_file(path, body):
    if path.exists():
        require(safe_path(path.parent, path.name, exists=True).read_bytes() == body,
                "Backup target already contains different bytes: " + str(path), 5)
    else:
        atomic(path, body)


def published_copy(record, index, copy, at):
    return {"id": record["id"], "copy_index": index, "root": copy["root"], "path": copy["path"],
            "cipher_sha256": copy["sha256"], "manifest_sha256": copy["manifest_sha256"],
            "envelope_digest": (record.get("approval") or record["publication"])["digest"], "verified_at": at}


def replica_slot_digest(index, copy):
    return digest({"copy_index": index, "root": copy["root"], "path": copy["path"], "manifest": copy["manifest"]})


def require_distinct_publication_roots(roots):
    require(len(set(roots)) == len(roots), "Backup publication destinations overlap", 5)


def publication_targets(vault, copies):
    roots = [vault.relocated_path(copy["root"]) for copy in copies]
    require_distinct_publication_roots(roots)
    allowed = set(map(Path, vault.config["backup_destinations"]))
    targets, identities = [], set()
    for root, copy in zip(roots, copies, strict=True):
        require(root in allowed and root.is_dir() and not root.is_junction(),
                "Backup replica destination is offline or unauthorized", 5)
        target = safe_path(root, copy["path"])
        manifest_path = safe_path(root, copy["manifest"])
        info = root.stat()
        identity = (info.st_dev, info.st_ino)
        require(identity not in identities, "Backup publication destinations overlap", 5)
        identities.add(identity)
        targets.append((target, manifest_path))
    return targets


def publish_generation(vault, record, cipher, plain, now):
    copies = record["copies"]
    targets = publication_targets(vault, copies)
    manifest_bytes = canonical(record["publication"]) + b"\n"
    for index, (copy, (target, manifest_path)) in enumerate(zip(copies, targets, strict=True)):
        publish_file(target, cipher)
        publish_file(manifest_path, manifest_bytes)
        persisted = safe_path(target.parent, target.name, exists=True).read_bytes()
        require(digest(persisted) == copy["sha256"] and decrypt(vault, persisted) == plain and
                file_digest(safe_path(manifest_path.parent, manifest_path.name, exists=True)) == copy["manifest_sha256"],
                "Persisted backup replica did not match the verified snapshot and manifest", 5)
        if copy["status"] != "present":
            payload = published_copy(record, index, copy, now)
            receipt = vault.receipt("backup-replica-published", payload, at=now)
            copy.update(status="present", published_at=now, publication_receipt=receipt)
            save_material(vault, record)
    record.update(status="complete", verified_at=now, approval=record.pop("publication"))
    save_material(vault, record)
    vault.receipt("backup", {"id": record["id"], "status": "complete", "expires_at": record["expires_at"]}, at=now)
    return record


def reconcile(vault, identifier):
    with vault.locked():
        known = materials(vault)
        record = known[identifier]
        require(record["id"] == identifier, "Backup identity changed", 5)
        if record["status"] == "complete":
            result, _ = _inspect(vault, record, decrypt_replicas=True)
            vault.receipt("backup", {"id": identifier, "status": "complete", "expires_at": record["expires_at"]},
                          at=record["verified_at"])
            return result
        require(record.get("format") == snapshot.MANIFEST and writing_generation(record),
                "Backup is not an interrupted portable publication", 5)
        vault.no_transaction()
        policy = storage_policy.effective(vault)
        require(policy["backup"]["mode"] != "off", "Backup creation disabled by policy", 5)
        manifest = check_writing_generation(vault, record)
        require(record.get("expiry") == "permanent" or utc() < utc(record["expires_at"]),
                "Backup publication has expired", 5)
        require(all(copy["status"] in {"planned", "present"} for copy in record["copies"]),
                "Retired backup publication cannot be resumed", 5)
        signers = vault.config.get("backup_allowed_signers") or ""
        expiry = manifest["expires_at"] or "permanent"
        members = generation_members(known, manifest["generation"], expiry, manifest["members"], utc(), policy)
        for copy in record["copies"]:
            try:
                cipher = replica_path(vault, copy).read_bytes()
                require(digest(cipher) == manifest["cipher_sha256"], "Backup ciphertext mismatch", 5)
                plain = decrypt(vault, cipher)
                require(digest(plain) == manifest["plain_sha256"], "Backup plaintext mismatch", 5)
                _, contents, _ = snapshot.check_snapshot(plain, manifest, vault.config.get("allowed_signers") or "", signers)
            except (Blocked, OSError, ValueError, TypeError, KeyError):
                continue
            for member in members:
                verified_member(vault, member, contents[f"custody/{member['id']}.age"])
            now = utc()
            validate_generation(manifest["generation"], members, expiry, now, policy=policy)
            return publish_generation(vault, record, cipher, plain, stamp(now))
        raise Blocked("Interrupted publication has no verified ciphertext; create a new generation", 5)


def verify_backup(vault, identifier, *, allow_retired=False):
    with vault.locked():
        return _verify_backup(vault, identifier, allow_retired=allow_retired)


def check_portable_generation(record, manifest):
    require(all(key in record and record[key] == value for key, value in manifest.items()) and
            not ({"expiry", "origin_binding_sha256", "replica_count", "replica_slots_sha256"} & (record.keys() - manifest.keys())) and
            type(record.get("replica_count")) is type(manifest.get("replica_count")) and
            record.get("holds") == [] and record.get("dependencies") == [], "Signed backup manifest changed", 5)
    require(isinstance(record.get("copies"), list), "Portable replica inventory changed", 5)


def replica_inventory_problem(record, manifest, count):
    portable = record.get("format") == snapshot.MANIFEST
    if count is None:
        return "Portable backup manifest lacks an authenticated replica count"
    actual = len(record["copies"])
    if actual != count:
        return f"Backup replica count differs from the signed manifest: expected {count}, recorded {actual}"
    if portable and "replica_slots_sha256" not in manifest:
        return "Portable backup manifest lacks an authenticated publication plan"
    return None


def valid_replica_root(value):
    if not isinstance(value, str) or any(ord(char) < 32 for char in value):
        return False
    return any(path.is_absolute() and ".." not in path.parts for path in (PurePosixPath(value), PureWindowsPath(value)))


def check_replica_record(vault, record, manifest, index, copy):
    portable = record.get("format") == snapshot.MANIFEST
    error = "Portable replica inventory changed" if portable else "Signed backup manifest changed"
    require(isinstance(copy, dict) and valid_replica_root(copy.get("root")) and
            copy.get("kind") == "ciphertext" and copy.get("sha256") == manifest["cipher_sha256"], error, 5)
    if portable:
        approval = record.get("approval") or record["publication"]
        states = ("present", "deleted", "unavailable")
        if writing_generation(record):
            states = ("planned", "present", "deleted", "absent")
        require(copy.get("path") == record["id"] + ".age" and copy.get("manifest") == record["id"] + ".manifest.json" and
                copy.get("manifest_sha256") == digest(canonical(approval) + b"\n") and
                copy.get("status") in states, error, 5)
        index = check_replica_publication(vault, record, index, copy, manifest.get("replica_count"))
        slots = manifest.get("replica_slots_sha256")
        require(slots is None or replica_slot_digest(index, copy) == slots[index],
                "Backup replica differs from the signed publication plan", 5)
        return index
    else:
        from .retention import copy_identity

        identity = copy_identity(copy)
        if index is None:
            matches = [slot for slot, original in enumerate(manifest["copies"]) if identity == copy_identity(original)]
            require(len(matches) == 1, "Backup replica has no unique slot in the signed legacy envelope", 5)
            index, = matches
        require(identity == copy_identity(manifest["copies"][index]), error, 5)
        require(copy.get("status") in ("present", "deleted", "unavailable") and
                not ({"absent_at", "absence_receipt"} & copy.keys()), "Invalid backup replica state", 5)
        snapshot.portable_path(copy.get("path"), historical=True)
        if copy.get("manifest"):
            snapshot.portable_path(copy["manifest"], historical=True)
        return index


def check_replica_publication(vault, record, index, copy, replica_count):
    if writing_generation(record):
        if copy["status"] in {"planned", "absent"}:
            return index
        if copy["status"] == "deleted" and not ({"publication_receipt", "published_at"} & copy.keys()):
            return index
    receipt = copy.get("publication_receipt")
    require(sha256(receipt) and isinstance(copy.get("published_at"), str), "Backup replica lacks a publication receipt", 5)
    proof = read_json(safe_path(vault.control, f"receipts/{receipt}.json"), {})
    payload = proof.get("payload") if isinstance(proof, dict) else None
    require(isinstance(payload, dict) and type(payload.get("copy_index")) is int,
            "Backup replica publication receipt changed", 5)
    if index is None:
        index = payload["copy_index"]
        require(0 <= index < replica_count, "Backup replica publication receipt changed", 5)
    expected = published_copy(record, index, copy, copy.get("published_at"))
    require(digest(proof) == receipt and proof.get("kind") == "backup-replica-published" and
            proof.get("at") == copy.get("published_at") and payload == expected,
            "Backup replica publication receipt changed", 5)
    return index


def authenticate_portable_record(vault, record):
    writing = writing_generation(record)
    require(record.get("kind") == "backup" and (writing or record.get("status") == "complete"),
            "Invalid portable backup publication state", 5)
    approval = record.get("publication" if writing else "approval")
    manifest = verify_portable_manifest(record["id"], approval, vault.config.get("backup_allowed_signers") or "")
    check_portable_generation(record, manifest)
    return manifest


def authenticate_generation(vault, record):
    require(record["kind"] == "backup", "Not a backup", 2)
    signers = vault.config.get("backup_allowed_signers") or ""
    if record.get("format") == snapshot.MANIFEST:
        require(record.get("status") == "complete", "Backup publication is incomplete", 5)
        return authenticate_portable_record(vault, record)
    signed = verify(record.get("approval"), "backup", signers)
    require(isinstance(signed, dict) and {k: v for k, v in record.items() if k not in {"approval", "copies"}} ==
            {k: v for k, v in signed.items() if k != "copies"} and
            isinstance(record.get("copies"), list) and isinstance(signed.get("copies"), list) and
            all(isinstance(copy, dict) for copy in signed["copies"]),
            "Signed backup manifest changed", 5)
    return signed


def signed_manifest(vault, record):
    signed = authenticate_generation(vault, record)
    check_replica_inventory(vault, record, signed)
    return signed


def check_replica_inventory(vault, record, signed):
    portable = record.get("format") == snapshot.MANIFEST
    count = signed.get("replica_count") if portable else len(signed["copies"])
    problem = replica_inventory_problem(record, signed, count)
    require(problem is None, problem, 5)
    for index, copy in enumerate(record["copies"]):
        check_replica_record(vault, record, signed, index, copy)
    if portable:
        require_distinct_publication_roots([vault.relocated_path(copy["root"]) for copy in record["copies"]
                                            if copy["status"] in {"planned", "present"}])


def check_portable_replica_inventory(vault, record):
    manifest = authenticate_portable_record(vault, record)
    check_replica_inventory(vault, record, manifest)
    return manifest


def writing_generation(record):
    return record.get("status") == "writing" and "approval" not in record and "verified_at" not in record


def check_writing_generation(vault, record):
    from .lineage import sha256

    identifier = record["id"]
    require(isinstance(identifier, str) and str(UUID(identifier)) == identifier and record.get("generation") in {"long", "short"} and
            sha256(record.get("cipher_sha256")) and isinstance(record.get("created_at"), str) and
            (isinstance(record.get("expires_at"), str) and utc(record["created_at"]) < utc(record["expires_at"]) or
             record.get("format") == snapshot.MANIFEST and record.get("expiry") == "permanent" and record["expires_at"] is None),
            "Interrupted backup generation has an unproven identity or expiry", 5)
    copies = record.get("copies")
    require(isinstance(copies, list) and copies and all(isinstance(copy, dict) and valid_replica_root(copy.get("root")) and
            copy.get("kind") == "ciphertext" and copy.get("path") == identifier + ".age" and
            copy.get("sha256") == record["cipher_sha256"] and copy.get("status") in ("planned", "present", "deleted", "absent")
            for copy in copies), "Interrupted backup copy does not match its generation", 5)
    receipts = safe_path(vault.control, "receipts")
    for path in json_paths(receipts):
        proof = read_json(safe_path(receipts, path.name, exists=True))
        require(isinstance(proof, dict), "Invalid receipt while checking interrupted backups", 5)
        if proof.get("kind") != "backup":
            continue
        payload = proof.get("payload", {})
        require(isinstance(payload, dict), "Invalid backup completion receipt", 5)
        if payload.get("id") == identifier and payload.get("status") == "complete" and digest(proof) == path.stem:
            raise Blocked("Backup generation already has a completion receipt", 5)
    if record.get("format") == snapshot.MANIFEST:
        return check_portable_replica_inventory(vault, record)


def interrupted_absence(plan, record, index, copy, root_identity):
    from .retention import copy_identity

    return {"plan": plan["id"], "plan_digest": plan["digest"], "material": record["id"],
            "copy_index": index, "identity": digest(copy_identity(copy)), "root_identity": root_identity}


def inspect_writing_generation(vault, record):
    from .lineage import sha256
    from .retention import authorized_target, copy_identity, plan_digest

    check_writing_generation(vault, record)
    verify_replica_deletions(vault, record)
    unresolved = False
    for index, copy in enumerate(record["copies"]):
        if copy["status"] == "absent":
            identifier = copy.get("absence_receipt")
            require(sha256(identifier), "Interrupted backup has an unproven absent replica", 5)
            proof = read_json(safe_path(vault.control, f"receipts/{identifier}.json"), {})
            payload = proof.get("payload", {})
            plan_id = payload.get("plan")
            require(isinstance(plan_id, str) and plan_id and Path(plan_id).name == plan_id,
                    "Interrupted backup has an unproven absent replica", 5)
            plan = read_json(safe_path(vault.control, f"deletions/{plan_id}.json"), {})
            root_identity = payload.get("root_identity")
            require(proof.get("kind") == "backup-replica-absent" and proof.get("at") == copy.get("absent_at") and
                    isinstance(proof.get("at"), str) and utc(proof["at"]) >= utc(record["expires_at"]) and
                    digest(proof) == identifier and plan.get("id") == plan_id and plan_digest(plan) == plan["digest"] and
                    isinstance(root_identity, list) and len(root_identity) == 2 and all(type(value) is int for value in root_identity) and
                    payload == interrupted_absence(plan, record, index, copy, root_identity) and any(
                        entry["material"] == record["id"] and entry["copy_index"] == index and
                        copy_identity(entry["copy"]) == copy_identity(copy) for entry in plan["entries"]),
                    "Interrupted backup has an unproven absent replica", 5)
        if copy["status"] in {"deleted", "absent"}:
            root = vault.relocated_path(copy["root"])
            require(not root.is_dir() or not safe_path(root, copy["path"]).exists(),
                    "Bytes reappeared at an inactive interrupted backup replica", 5)
            continue
        _, path = authorized_target(vault, record, copy)
        if path.exists():
            require(file_digest(replica_path(vault, copy)) == copy["sha256"], "Interrupted backup ciphertext mismatch", 5)
        unresolved = True
    require(not unresolved, "Interrupted backup generation has unresolved replicas", 5)


def replica_root(vault, copy):
    root = vault.relocated_path(copy["root"])
    require(root.is_absolute(), "Unsafe backup replica root", 5)
    if root != Path(copy["root"]):
        require(root in map(Path, vault.config.get("backup_destinations", [])),
                "Relocated backup destination is not authorized", 5)
    require(not root.is_junction(), "Unsafe backup replica root", 5)
    return root


def replica_path(vault, copy):
    root = replica_root(vault, copy)
    return safe_path(root, copy["path"], exists=True)


def verified_replica(vault, record, copy):
    cipher = replica_path(vault, copy).read_bytes()
    require(digest(cipher) == copy["sha256"] == record["cipher_sha256"], "Backup ciphertext mismatch")
    require(digest(decrypt(vault, cipher)) == record["plain_sha256"], "Backup plaintext mismatch")
    return cipher


def legacy_replica_receipt(vault, record, copy, index):
    from .retention import copy_identity, plan_digest

    if not (copy.get("deleted_at") and record.get("expires_at") and utc(copy["deleted_at"]) >= utc(record["expires_at"])):
        return None
    root = vault.relocated_path(copy["root"])
    if "origin_status" not in copy and root.is_dir() and safe_path(root, copy["path"]).exists():
        return None
    identity = copy_identity(copy)
    plans = {}
    directory = safe_path(vault.control, "deletions")
    for path in directory.glob("*.json"):
        try:
            plan = read_json(safe_path(directory, path.name, exists=True))
            if (plan["id"] == path.stem and plan["status"] in {"pending", "complete"} and plan_digest(plan) == plan["digest"] and
                    utc(plan["created_at"]) <= utc(copy["deleted_at"]) and any(
                        entry["material"] == record["id"] and entry["copy_index"] == index and
                        entry["status"] == "deleted" and entry.get("at") == copy["deleted_at"] and
                        not ({"intent", "receipt"} & entry.keys()) and entry["copy"].get("status") == "present" and
                        copy_identity(entry["copy"]) == identity for entry in plan["entries"])):
                plans[plan["id"]] = plan["digest"]
        except (Blocked, OSError, ValueError, KeyError, TypeError):
            continue
    if not plans:
        return None
    directory = safe_path(vault.control, "receipts")
    for path in sorted(directory.glob("*.json")):
        try:
            receipt = read_json(safe_path(directory, path.name, exists=True))
            if not isinstance(receipt, dict):
                continue
            payload = receipt.get("payload", {})
            if (receipt.get("kind") == "deletion-round" and isinstance(payload, dict) and
                    set(payload) == {"plan", "digest", "status"} and
                    payload["plan"] in plans and payload["digest"] == plans[payload["plan"]] and
                    payload["status"] in {"pending", "complete"} and utc(receipt["at"]) >= utc(copy["deleted_at"]) and
                    digest(receipt) == path.stem):
                return path.stem
        except (Blocked, OSError, ValueError, KeyError, TypeError):
            continue
    return None


def verify_replica_deletion(vault, record, index, copy):
    from .retention import copy_identity, plan_digest, slot

    writing = writing_generation(record)
    root = str(vault.relocated_path(copy["root"]))
    reason = f"Backup replica {index} lacks a verified deletion receipt"
    if "deletion_receipt" not in copy:
        legacy = None if writing else legacy_replica_receipt(vault, record, copy, index)
        require(legacy, reason, 5)
        return {"copy_index": index, "root": root, "receipt": legacy, "proof": "legacy-round"}
    receipt_id = copy.get("deletion_receipt")
    require(sha256(receipt_id), reason, 5)
    receipt = read_json(safe_path(vault.control, f"receipts/{receipt_id}.json"), {})
    require(isinstance(receipt, dict) and isinstance(receipt.get("payload"), dict), reason, 5)
    payload = receipt["payload"]
    intent = payload.get("intent")
    expected_slot = [record["id"], index, digest(copy_identity(copy))]
    require(isinstance(intent, dict), reason, 5)
    primary = intent.get("slot") == expected_slot
    generation = next((item for item in intent.get("generations", []) if
                       [item["material"], item["copy_index"], item["identity"]] == expected_slot), {})
    require(digest(receipt) == receipt_id and receipt.get("kind") == "deletion-copy" and
            receipt.get("at") == copy.get("deleted_at") and payload.get("material") == record["id"] and
            payload.get("copy_index") == index and payload.get("sha256") == copy["sha256"] and
            intent.get("at") == receipt["at"] and
            (intent if primary else generation).get("generation_digest") == (None if writing else record["approval"]["digest"]) and
            intent.get("path") and deletion_location(vault, intent["path"], copy),
            reason, 5)
    directory = safe_path(vault.control, "deletions")
    plan_id = intent.get("plan_id")
    require(isinstance(plan_id, str) and Path(plan_id).name == plan_id and plan_id, reason, 5)
    plan = read_json(safe_path(directory, plan_id + ".json"), {})
    require(isinstance(plan, dict) and plan.get("id") == plan_id and plan.get("digest") == intent.get("plan_digest") and
            plan_digest(plan) == plan["digest"] and any(list(slot(entry)) == intent.get("slot") and
                entry.get("status") in {"deleting", "deleted"} and entry.get("intent") == intent
                for entry in plan["entries"]), reason, 5)
    return {"copy_index": index, "root": root, "receipt": receipt_id}


def verify_replica_deletions(vault, record):
    return [verify_replica_deletion(vault, record, index, copy) for index, copy in enumerate(record["copies"])
            if copy["status"] == "deleted"]


def deletion_location(vault, path, copy):
    if "origin_status" in copy:
        path_type = PureWindowsPath if PureWindowsPath(copy["root"]).drive else PurePosixPath
        original = path_type(copy["root"]) / copy["path"]
        if path_type(path) == original:
            return True
        return historical_deletion_location(vault, path, copy)
    return vault.relocated_path(path) == vault.relocated_path(copy["root"]) / copy["path"]


def historical_deletion_location(vault, path, copy):
    from .binding import relocated_path

    signers = vault.config.get("backup_allowed_signers") or ""
    for name in snapshot.historical_paths(vault.control, folders=("",)):
        backup_id, logical = snapshot.historical_record(name)
        if logical != "binding.json":
            continue
        origin = read_json(safe_path(vault.control, name, exists=True))
        snapshot.check_origin_binding(origin, vault.identity)
        path_type = snapshot.origin_path_type(origin["location"])
        if not all(path_type(value).is_absolute() for value in (path, copy["root"])):
            continue
        if relocated_path(path, origin, path_type=path_type) != relocated_path(copy["root"], origin, path_type=path_type) / copy["path"]:
            continue
        envelope_path = safe_path(vault.control, f"historical/{backup_id}.manifest.json", exists=True)
        signed = verify_portable_manifest(backup_id, read_json(envelope_path), signers)
        require(signed["source_vault"] == vault.identity and signed.get("origin_binding_sha256") == digest(origin),
                "Historical storage relocation differs from its signed backup", 5)
        return True
    return False


def load_replica(vault, record, copy, *, decrypt_replica):
    path = replica_path(vault, copy)
    cipher = path.read_bytes()
    require(digest(cipher) == copy["sha256"] == record["cipher_sha256"], "Backup ciphertext mismatch", 5)
    if record.get("format") == snapshot.MANIFEST:
        raw_manifest = safe_path(path.parent, copy["manifest"], exists=True).read_bytes()
        require(digest(raw_manifest) == copy["manifest_sha256"] and
                decode(raw_manifest) == record["approval"], "Backup replica manifest mismatch", 5)
    else:
        raw_manifest = None
    if not decrypt_replica:
        return None
    plain = decrypt(vault, cipher)
    require(digest(plain) == record["plain_sha256"], "Backup plaintext mismatch", 5)
    return path, raw_manifest, plain


def replica_availability(vault, copy):
    if copy["status"] != "present":
        return "unavailable"
    root = replica_root(vault, copy)
    if not root.is_dir():
        return "unavailable"
    path = safe_path(root, copy["path"])
    if not path.exists() or copy.get("manifest") and not safe_path(root, copy["manifest"]).exists():
        return "unavailable"
    return "available"


def _inspect(vault, record, *, allow_retired=False, decrypt_replicas=False, allow_partial=False):
    manifest = authenticate_generation(vault, record)
    portable = record.get("format") == snapshot.MANIFEST
    count = manifest.get("replica_count") if portable else len(manifest["copies"])
    inventory_problem = replica_inventory_problem(record, manifest, count)
    require(allow_partial or inventory_problem is None, inventory_problem, 5)
    recover_slot = count is not None and len(record["copies"]) != count
    seen = set()
    checks, replicas, retired, selected = [], [], [], None
    for index, copy in enumerate(record["copies"]):
        entry = {"catalog_index" if recover_slot else "copy_index": index}
        if isinstance(copy, dict):
            entry.update({key: copy[key] for key in ("root", "path") if isinstance(copy.get(key), str)})
        try:
            slot = check_replica_record(vault, record, manifest, None if recover_slot else index, copy)
            require(slot not in seen, "Backup replica duplicates a verified publication slot", 5)
            entry["copy_index"] = slot
            root = str(vault.relocated_path(copy["root"]))
            entry["root"] = root
            if copy["status"] == "deleted":
                retired.append(verify_replica_deletion(vault, record, slot, copy))
                entry["status"] = "deleted"
            elif replica_availability(vault, copy) == "unavailable":
                entry.update(status="unavailable", reason="Required regular file is missing: backup replica is unavailable")
            else:
                candidate = load_replica(vault, record, copy, decrypt_replica=decrypt_replicas)
                if candidate and selected is None:
                    path, raw_manifest, plain = candidate
                    if raw_manifest is not None:
                        verified = snapshot.check_snapshot(plain, manifest, vault.config.get("allowed_signers") or "",
                                                           vault.config.get("backup_allowed_signers") or "")
                    else:
                        verified = decode(plain)
                    selected = (path, raw_manifest, plain, manifest, verified)
                entry["status"] = "verified"
                checks.append({"root": root, "verified": True})
            seen.add(slot)
        except (Blocked, OSError, KeyError, TypeError, ValueError, IndexError, AttributeError, OverflowError) as exc:
            if not allow_partial:
                raise Blocked(str(exc), 5) from exc
            entry.update(status="invalid", reason=str(exc))
        replicas.append(entry)
    pending = [entry for entry in replicas if entry["status"] in {"unavailable", "invalid"}]
    if inventory_problem:
        pending.append({"status": "invalid", "reason": inventory_problem})
    require(allow_partial or not pending, "; ".join(entry["reason"] for entry in pending), 5)
    if portable and not allow_partial:
        require_distinct_publication_roots([Path(check["root"]) for check in checks])
    if not checks and not (allow_retired and retired and not pending):
        raise Blocked("Backup has no verified retained replicas" +
                      (": " + "; ".join(entry["reason"] for entry in pending) if pending else ""), 5)
    report = {"id": record["id"], "status": "complete", "copies": checks, "deleted_copies": retired,
              "replicas": replicas, "pending_replicas": pending}
    if selected:
        report["replica"] = str(selected[0])
    return report, selected


def inspect_backup(vault, record, *, allow_retired=False, decrypt_replicas=False):
    report, _ = _inspect(vault, record, allow_retired=allow_retired, decrypt_replicas=decrypt_replicas)
    return report


def _verify_backup(vault, identifier, *, allow_retired=False):
    record = materials(vault)[identifier]
    require(record["id"] == identifier, "Backup identity changed", 5)
    report, _ = _inspect(vault, record, allow_retired=allow_retired, decrypt_replicas=True, allow_partial=True)
    return report


def _portable_replica(identifier, manifest_path, replica, *, age_identity, backup_signers, allowed_signers=None,
                      excluded=(), expected_vault=None):
    require(manifest_path is not None and replica is not None,
            "Portable backup verification requires both a trusted manifest and an age replica", 5)
    manifest_path = Path(manifest_path).absolute()
    replica = Path(replica).absolute()
    raw_manifest = safe_path(manifest_path.parent, manifest_path.name, exists=True).read_bytes()
    approval = decode(raw_manifest)
    signers = external_file(backup_signers, "backup allowed signers", *excluded)
    signers_human = external_file(allowed_signers, "human allowed signers", *excluded) if allowed_signers else ""
    identity = external_file(age_identity, "age identity", *excluded)
    manifest = verify_portable_manifest(identifier, approval, signers)
    require(expected_vault is None or manifest["source_vault"] == expected_vault, "The backup source vault identity differs", 5)
    cipher = safe_path(replica.parent, replica.name, exists=True).read_bytes()
    require(digest(cipher) == manifest["cipher_sha256"], "Backup ciphertext mismatch", 5)
    try:
        plain = decrypt(None, cipher, identity)
    except Blocked as exc:
        raise Blocked("Cannot decrypt backup replica with the supplied age identity", 5) from exc
    require(digest(plain) == manifest["plain_sha256"], "Backup plaintext mismatch", 5)
    verified = snapshot.check_snapshot(plain, manifest, signers_human, signers)
    entry = {"root": str(replica.parent), "path": replica.name, "manifest": str(manifest_path), "status": "verified"}
    report = {"id": identifier, "status": "complete", "replica": str(replica), "replicas": [entry],
              "copies": [{"root": str(replica.parent), "verified": True}], "deleted_copies": [], "pending_replicas": []}
    return report, (replica, raw_manifest, plain, manifest, verified)


def verify_portable(identifier, manifest_path, replica, **trust):
    report, _ = _portable_replica(identifier, manifest_path, replica, **trust)
    return report


def restore_portable(identifier, destination, manifest_path, replica, *, state, remap=None, expected_vault=None,
                     age_identity, backup_signers, allowed_signers=None):
    from .backup_recovery import recover

    require(state is not None, "Portable restore requires a new external --state directory", 5)
    report, verified = _portable_replica(identifier, manifest_path, replica, age_identity=age_identity,
                                        backup_signers=backup_signers, allowed_signers=allowed_signers,
                                        excluded=(destination, state), expected_vault=expected_vault)
    return recover(verified, destination, state, report, allowed_signers=allowed_signers, backup_signers=backup_signers,
                   age_identity=age_identity, remap=remap)


def restore(vault, identifier, destination, *, state=None, remap=None):
    from .backup_recovery import recover

    with vault.locked():
        record = materials(vault)[identifier]
        require(record["id"] == identifier, "Backup identity changed", 5)
        report, verified = _inspect(vault, record, decrypt_replicas=True, allow_partial=True)
        return recover(verified, destination, state, report, allowed_signers=vault.config.get("allowed_signers"),
                       backup_signers=vault.config.get("backup_allowed_signers"), remap=remap, legacy_source=vault.identity,
                       source_root=vault.root, source_state=vault.state)
