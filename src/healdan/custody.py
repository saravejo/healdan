"""External age custody, verified archives, holds and native-copy guards."""
import base64
import os
from pathlib import Path
import stat
import sys
from uuid import uuid4

from . import storage_policy
from .core import Blocked, atomic, canonical, canonical_storage_path, decode, digest, executable, lock, read_json, require, run, safe_path, stamp, sync_directory
from .signing import trusted_signers, verify

INACTIVE_COPIES = {"deleted", "moved"}


def archive_tree(root):
    root = Path(root).resolve()
    files = {}
    directories = [root]
    while directories:
        directory = directories.pop()
        try:
            if directory != root:
                safe_path(root, directory.relative_to(root))
                require(directory.resolve() == directory, "Cannot preserve an aliased directory")
            with os.scandir(directory) as scan:
                paths = sorted((Path(entry.path) for entry in scan))
        except OSError as exc:
            raise Blocked(f"Cannot enumerate preservation directory {directory}: {exc}", 5) from exc
        for path in paths:
            try:
                metadata = path.lstat()
                require(not stat.S_ISLNK(metadata.st_mode) and not path.is_junction(),
                        "Cannot preserve a symlink tree or junction: " + str(path))
                if stat.S_ISDIR(metadata.st_mode):
                    directories.append(path)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                rel = path.relative_to(root).as_posix()
                data = safe_path(root, rel, exists=True).read_bytes()
            except OSError as exc:
                raise Blocked(f"Cannot read preservation path {path}: {exc}", 5) from exc
            files[rel] = {"sha256": digest(data), "size": len(data),
                          "body": base64.b64encode(data).decode("ascii")}
    return {"format": "healdan-tree-v1", "files": files}


def archive_members(archive, destination):
    require(archive.get("format") == "healdan-tree-v1", "Unknown archive format")
    checked = {}
    for name, entry in archive["files"].items():
        path = safe_path(destination, name)
        data = base64.b64decode(entry["body"], validate=True)
        require(len(data) == entry["size"] and digest(data) == entry["sha256"], "Archive member mismatch")
        relative = path.relative_to(destination)
        require(relative.as_posix() == name and relative not in checked, "Unsafe or duplicate archive member", 5)
        checked[relative] = data
    require(all(not set(path.parents) & checked.keys() for path in checked), "Archive member collides with a directory", 5)
    return checked


def restore_tree(archive, destination):
    destination = Path(destination).absolute()
    require(not destination.exists() or not any(destination.iterdir()), "Restore destination must be empty", 2)
    checked = archive_members(archive, destination)
    destination.mkdir(parents=True, exist_ok=True)
    for relative, data in checked.items():
        atomic(destination / relative, data)
    return {"status": "complete", "archive_sha256": digest(archive), "files": len(checked), "destination": str(destination)}


def encrypt(vault, data):
    recipients = vault.config.get("age_recipients", [])
    recovery = vault.config.get("offline_recipients", [])
    require(recipients and recovery and not set(recipients) & set(recovery),
            "Separate operational and offline age recipients are required", 5)
    args = [executable("age")]
    for recipient in recipients + recovery:
        args.extend(("-r", recipient))
    cipher = run(args, data=data).stdout
    require(cipher.startswith(b"age-encryption.org/v1"), "age returned an invalid envelope")
    require(decrypt(vault, cipher) == data, "Encrypted capture failed decryption verification")
    return cipher


def decrypt(vault, cipher, identity=None):
    key = Path(identity or vault.config.get("age_identity") or "")
    require(key.is_absolute() and key.is_file() and not key.resolve().is_relative_to(vault.root),
            "External age identity is required", 5)
    return run([executable("age"), "--decrypt", "-i", key], data=cipher).stdout


def capture_copy(vault, record):
    errors = []
    for copy in record.get("copies", []):
        if copy["kind"] != "ciphertext" or copy["status"] != "present":
            continue
        try:
            root = vault.relocated_path(copy["root"])
            allowed = root == vault.state / "custody" or root in map(Path, vault.config.get("storage_roots", []))
            require(allowed, "Capture ciphertext root is not authorized", 5)
            cipher = safe_path(root, copy["path"], exists=True).read_bytes()
            require(digest(cipher) == copy["sha256"] == record.get("cipher_sha256"), "Ciphertext changed", 5)
            return cipher
        except (Blocked, OSError) as exc:
            errors.append(str(exc))
    raise Blocked("No verified capture ciphertext is available" + (": " + "; ".join(errors) if errors else ""), 5)


def verified_capture(vault, record, cipher=None):
    require(record.get("kind") == "conversation" and record.get("decryption_verified"),
            "A verified conversation capture is required", 5)
    cipher = capture_copy(vault, record) if cipher is None else cipher
    plain = decrypt(vault, cipher)
    require(digest(plain) == record.get("plain_sha256"), "Plaintext archive digest mismatch", 5)
    return cipher, plain


def materials(vault):
    return read_json(vault.control / "materials.json", {})


def save_material(vault, record):
    with vault.locked():
        rows = materials(vault)
        rows[record["id"]] = record
        atomic(vault.control / "materials.json", rows)


def integrity_findings(vault):
    from .backups import verify_backup

    try:
        records = materials(vault)
    except (Blocked, OSError) as exc:
        return [("inventory", str(exc))]
    findings = []
    for record in records.values():
        live = [copy for copy in record.get("copies", []) if copy.get("status") not in INACTIVE_COPIES]
        if not live and record.get("kind") != "backup":
            continue
        try:
            if record["kind"] == "backup":
                verify_backup(vault, record["id"], allow_retired=True)
            elif record.get("decryption_verified"):
                if any(copy.get("kind") == "ciphertext" for copy in live):
                    verified_capture(vault, record)
                else:
                    require(not any(copy.get("kind") == "native" for copy in live), "Native copies have lost their verified capture", 5)
        except (Blocked, OSError, ValueError, KeyError, TypeError) as exc:
            findings.append((record["id"], str(exc)))
    directory = safe_path(vault.control, "restorations")
    for path in sorted(directory.glob("*.json")):
        try:
            journal = read_json(safe_path(directory, path.name, exists=True))
            if journal["status"] != "complete":
                findings.append((path.stem, journal.get("error") or "Restoration is awaiting reconciliation"))
        except (Blocked, OSError, ValueError, KeyError, TypeError) as exc:
            findings.append((path.stem, str(exc)))
    return findings


def archive_move_origins(vault, records, source, sha, receipt):
    origin_path = canonical_storage_path(safe_path(vault.root, source))
    origins = []
    for record in records:
        tracked = [copy for copy in record["copies"] if copy["kind"] == "export" and copy["sha256"] == sha and
                   (copy["status"] not in INACTIVE_COPIES or copy.get("move_receipt") == receipt) and
                   canonical_storage_path(vault.relocated_path(copy["root"]) / copy["path"]) == origin_path]
        if tracked:
            origins.append((record, tracked))
    return origins


def record_archive_move(vault, origins, move, receipt):
    payload = move["payload"]
    destination, sha = payload["destination"], payload["sha256"]
    archived = safe_path(vault.root, destination, exists=True)
    require(digest(archived.read_bytes()) == sha, "Archived custody copy changed: " + destination, 5)
    location = canonical_storage_path(archived)
    for record, tracked in origins:
        copies = record["copies"]
        index = next((index for index, copy in enumerate(copies) if copy["kind"] == "archive" and
                      copy["sha256"] == sha and copy["status"] == "present" and
                      canonical_storage_path(vault.relocated_path(copy["root"]) / copy["path"]) == location), len(copies))
        if index == len(copies):
            copies.append({"root": str(vault.root / "archive"), "path": destination.removeprefix("archive/"),
                           "sha256": sha, "kind": "archive", "status": "present"})
        for copy in tracked:
            copy.update(status="moved", moved_at=move["at"], move_receipt=receipt, archive_copy_index=index)
        save_material(vault, record)


def archived_origin_records(vault, records, source, sha, receipt):
    location = canonical_storage_path(source)
    origins = []
    for record in records:
        copies = [copy for copy in record["copies"] if copy["kind"] == "export" and copy["sha256"] == sha and
                  copy["status"] == "moved" and copy.get("move_receipt") == receipt and
                  canonical_storage_path(vault.relocated_path(copy["root"]) / copy["path"]) == location]
        if copies:
            origins.append((record, copies))
    return origins


def verified_archive_deletion(vault, origins, target, sha):
    location = canonical_storage_path(target)
    for record, sources in origins:
        generations = {index: copy for index, copy in enumerate(record["copies"]) if copy["kind"] == "archive" and
                       copy["sha256"] == sha and
                       canonical_storage_path(vault.relocated_path(copy["root"]) / copy["path"]) == location}
        for source in sources:
            if "archive_copy_index" in source:
                copy = generations.get(source["archive_copy_index"])
            else:
                # A legacy receipt carries no generation link. Accept only unambiguous history.
                copy = next(iter(generations.values())) if len(generations) == 1 else None
            if not copy or copy["status"] != "deleted" or copy.get("verified_archive_sha256") != sha:
                return False
    return bool(origins)


def capture_tree(vault, root, *, task, classification, session=None, purpose=None):
    with vault.locked():
        return _capture_tree(vault, root, task, classification, session, purpose)


def _capture_tree(vault, root, task, classification, session, purpose):
    root = Path(root).resolve()
    require(not root.is_relative_to(vault.root), "Conversation capture must originate outside Git")
    require(root.is_relative_to(vault.state), "Capture root is not a controller-owned task/profile")
    require(root.is_dir(), "Capture root is missing", 5)
    if classification != "common":
        validate_purpose({"classification": classification, "purpose": purpose})
    archive = archive_tree(root)
    plain = canonical(archive)
    cipher = encrypt(vault, plain)
    identifier = str(uuid4())
    destination = vault.state / "custody" / (identifier + ".age")
    atomic(destination, cipher)
    require(digest(decrypt(vault, destination.read_bytes())) == digest(plain), "Persisted capture is corrupt")
    record = {"id": identifier, "kind": "conversation", "classification": classification,
              "task": task, "session": session, "purpose": purpose, "captured_at": stamp(),
              "plain_sha256": digest(plain), "cipher_sha256": digest(cipher), "size": len(cipher),
              "artifact_inventory": {n: {k: v for k, v in e.items() if k != "body"}
                                     for n, e in archive["files"].items()},
              "decryption_verified": True, "holds": [], "dependencies": [],
              "copies": [{"root": str(destination.parent), "path": destination.name,
                          "sha256": digest(cipher), "kind": "ciphertext", "status": "present"}]}
    for name, entry in archive["files"].items():
        # Native profiles receive their own per-session recovery gate. Task captures cover
        # nonnative checkpoints as well, without inventing proof for a mixed-session archive.
        if session or "/native/" not in "/" + name:
            record["copies"].append({"root": str(root), "path": name, "sha256": entry["sha256"],
                                     "kind": "native" if session else "checkpoint", "status": "present"})
    save_material(vault, record)
    vault.receipt("capture", {k: v for k, v in record.items() if k != "artifact_inventory"})
    return identifier


def retention_deadline(material, policy=None):
    return storage_policy.deadline(material, policy)[1]


def validate_purpose(material):
    if material.get("classification") != "common":
        purpose = material.get("purpose") or {}
        require(all(isinstance(purpose.get(k), str) and purpose[k].strip()
                    for k in ("purpose", "necessity", "owner", "link")), "Personal/unknown material lacks specific purpose")


def hold(vault, identifier, reason, owner, dependencies=(), review_at=None, *, origin="human"):
    with vault.locked():
        record = materials(vault)[identifier]
        require(record.get("kind") != "backup", "Existing backup expiry cannot be suspended; use a separate preservation plan", 5)
        item = {"id": str(uuid4()), "reason": reason, "owner": owner, "started_at": stamp(),
                "review_at": stamp(review_at) if review_at else None, "dependencies": list(dependencies), "origin": origin}
        require(reason and owner, "Hold requires reason and owner", 2)
        record.setdefault("holds", []).append(item)
        save_material(vault, record)
        vault.receipt("hold", {"material": identifier, **item})
        return item


def release_hold(vault, identifier, hold_id, resolved):
    with vault.locked():
        record = materials(vault)[identifier]
        item = next(h for h in record["holds"] if h["id"] == hold_id)
        require(set(item["dependencies"]) <= set(resolved), "Hold dependencies remain unresolved", 5)
        require(not record.get("dependencies"), "Material still has active dependencies", 5)
        item["ended_at"] = stamp()
        item["resolution"] = list(resolved)
        save_material(vault, record)
        return vault.receipt("hold-release", {"material": identifier, "hold": hold_id, "resolved": resolved})


def native_guard(vault, material):
    require(material.get("decryption_verified") and material.get("artifact_inventory"),
            "Native removal requires verified capture and artifact inventory", 5)
    proof = verify(material.get("native_recovery"), "recovery", trusted_signers(vault))
    require(proof.get("material", material["id"]) == material["id"] and
            proof.get("cipher_sha256") == material.get("cipher_sha256") and
            proof.get("plain_sha256") == material.get("plain_sha256") and proof.get("reconstruction_sha256"),
            "Recovery proof does not match the captured archive", 5)
    from .tasks import get_session
    session = get_session(vault, material["session"])
    receipt = next((r for r in session["launches"] if r.get("id") == proof.get("launch_receipt")), None)
    reconstruction = session.get("reconstruction", {})
    require(reconstruction.get("material") == material["id"] and
            reconstruction.get("archive_sha256") == proof.get("reconstruction_sha256") and
            proof.get("reconstruction_sha256") == material.get("plain_sha256"), "Native reconstruction is not proven", 5)
    usage = proof.get("usage")
    require(isinstance(usage, dict) and set(usage) == {"input_tokens", "output_tokens", "evidence_bytes"} and
            all(type(value) is int and value >= 0 for value in usage.values()) and receipt and
            isinstance(receipt.get("cumulative_usage"), dict) and
            all(type(value) is int for value in receipt["cumulative_usage"].values()) and usage == receipt["cumulative_usage"],
            "Native resume requires valid cumulative usage in the decision and receipt", 5)
    require(receipt and receipt.get("resumed") and receipt.get("recovery_material") == material["id"] and receipt.get("success") and
            proof.get("uuid") == session["uuid"] == receipt.get("uuid") and
            proof.get("action") == session["action"] == receipt.get("action"), "Native resume is not proven", 5)


def pending_restoration(vault, identifier=None, *, target=None):
    directory = safe_path(vault.control, "restorations")
    for path in directory.glob("*.json"):
        journal = read_json(safe_path(directory, path.name, exists=True))
        status = journal.get("status")
        if (target is None and journal.get("material") == identifier and
                (status in {"staging", "publishing"} or status == "preparing" and not journal.get("terminal"))):
            return True
        if target is not None and status in {"staging", "publishing"}:
            destination = vault.relocated_path(journal["binding"]["destination"])
            if target.is_relative_to(destination) and target.relative_to(destination).as_posix() in journal["inventory"]:
                return True
    return False


class RestoreDestinationConflict(Blocked):
    pass


def restore_destination(vault, destination):
    prohibited = (*vault.repository.worktree_roots(), vault.common, vault.state / "custody")
    if (destination == destination.parent or ".." in destination.parts or destination == vault.state or
            any(destination.is_relative_to(root) or root.is_relative_to(destination) for root in prohibited)):
        raise RestoreDestinationConflict("Restore destination must be canonical and external to Git and custody storage", 5)
    require(destination.parent.is_dir(), "Restore destination parent is offline", 5)
    if canonical_storage_path(destination) != destination or destination.is_junction():
        raise RestoreDestinationConflict("Restore destination must be canonical and external", 5)
    try:
        safe_path(destination.parent, destination.name)
    except Blocked as exc:
        raise RestoreDestinationConflict(str(exc), 5) from exc


def restored_directory(path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISDIR(metadata.st_mode) and not path.is_junction(), "Restore location is not a safe directory", 5)
    return [metadata.st_dev, metadata.st_ino]


def session_reconstruction(session):
    return {key: session.get(key) for key in ("recovery_profile", "reconstruction")}


def restore_capture(vault, identifier, destination):
    from .tasks import get_session

    destination = Path(destination).absolute()
    identity = digest([vault.identity, identifier, os.path.normcase(str(destination))])
    path = safe_path(vault.control, f"restorations/{identity}.json")
    with lock(safe_path(vault.control, f"restorations/{identity}.lock")):
        with vault.locked():
            record = materials(vault)[identifier]
            binding = {"vault": vault.identity, "material": identifier, "destination": str(destination),
                       "cipher_sha256": record.get("cipher_sha256"), "plain_sha256": record.get("plain_sha256"),
                       "session": record.get("session")}
            journal = read_json(path)
            if journal is None:
                session = get_session(vault, record["session"]) if record.get("session") else None
                journal = {"format": "healdan-restore-v1", "binding": binding, "material": identifier,
                           "started_at": stamp(), "stage": ".healdan-restore-" + uuid4().hex,
                           "status": "preparing", "prior_session": session_reconstruction(session) if session else None}
                atomic(path, journal)
            require(journal.get("format") == "healdan-restore-v1" and journal.get("binding") == binding,
                    "Restore intention no longer matches the capture or destination", 5)
            if journal["status"] != "complete" and journal.pop("error", None) is not None:
                journal.pop("terminal", None)
                atomic(path, journal)
        try:
            restore_destination(vault, destination)
            return reconstruct_capture(vault, record, destination, path, journal)
        except (Blocked, OSError, ValueError, KeyError, TypeError) as exc:
            with vault.locked():
                journal["error"] = str(exc)
                if journal["status"] == "preparing" and isinstance(exc, RestoreDestinationConflict):
                    journal["terminal"] = True
                atomic(path, journal)
            raise


def reconstruction_inventory(archive):
    return {name: {"sha256": entry["sha256"], "size": entry["size"]} for name, entry in archive["files"].items()}


def check_reconstruction(root, journal):
    require(restored_directory(root) == journal["stage_identity"] and
            reconstruction_inventory(archive_tree(root)) == journal["inventory"],
            "Restore destination collides with existing or changed data", 5)


def write_staged_member(target, data):
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(target, flags, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(target.parent)


def reconstruct_capture(vault, record, destination, path, journal):
    stage = safe_path(destination.parent, journal["stage"])
    require(stage.parent == destination.parent and stage.name.startswith(".healdan-restore-") and stage != destination,
            "Invalid reconstruction staging location", 5)
    if journal["status"] == "complete":
        check_reconstruction(destination, journal)
        return journal["result"]

    try:
        destination_id = restored_directory(destination)
    except Blocked as exc:
        raise RestoreDestinationConflict(str(exc), 5) from exc
    if journal.get("stage_identity") and destination_id == journal["stage_identity"]:
        check_reconstruction(destination, journal)
        return finish_reconstruction(vault, destination, path, journal)

    if destination_id is not None and any(destination.iterdir()):
        raise RestoreDestinationConflict("Restore destination must be empty (collision)", 5)
    require(os.name != "nt" or sys.version_info >= (3, 12, 4),
            "Restricted restoration staging on Windows requires Python 3.12.4 or later", 5)
    if not journal.get("stage_identity") and stage.exists():
        # Only a stage created and identified by this attempt can contain plaintext.
        journal["stage"] = ".healdan-restore-" + uuid4().hex
        stage = safe_path(destination.parent, journal["stage"])
        with vault.locked():
            atomic(path, journal)
    with vault.locked():
        cipher = capture_copy(vault, materials(vault)[record["id"]])
    _, plain = verified_capture(vault, record, cipher)
    archive = decode(plain)
    checked = archive_members(archive, stage)
    inventory = reconstruction_inventory(archive)
    require(record.get("artifact_inventory", inventory) == inventory and journal.get("inventory", inventory) == inventory,
            "Restore archive does not match its inventoried members", 5)
    with vault.locked():
        journal.update(status="staging", inventory=inventory)
        if not journal.get("stage_identity"):
            atomic(path, journal)
            stage.mkdir(mode=0o700)
            sync_directory(stage.parent)
            journal["stage_identity"] = restored_directory(stage)
            atomic(path, journal)
    require(restored_directory(stage) == journal["stage_identity"] and
            (os.name == "nt" or stat.S_IMODE(stage.stat().st_mode) == 0o700),
            "Reconstruction staging location changed or is not restricted", 5)
    for relative, data in checked.items():
        target = safe_path(stage, relative)
        if not target.exists() or target.read_bytes() != data:
            write_staged_member(target, data)
    with vault.locked():
        restore_destination(vault, destination)
        check_reconstruction(stage, journal)
        from .retention import pending_deletion_paths
        require(not any(pending_deletion_paths(vault, target=destination / relative) for relative in checked),
                "Restore destination has a pending deletion intent", 5)
        require(restored_directory(destination) in (None, destination_id) and
                (not destination.exists() or not any(destination.iterdir())), "Restore destination collision", 5)
        journal["status"] = "publishing"
        atomic(path, journal)
        if os.name == "nt" and destination.exists():
            destination.rmdir()
        os.rename(stage, destination)
        sync_directory(destination.parent)
        return finish_reconstruction(vault, destination, path, journal)


def finish_reconstruction(vault, destination, path, journal):
    from .tasks import get_session

    with vault.locked():
        check_reconstruction(destination, journal)
        binding = journal["binding"]
        record = materials(vault)[binding["material"]]
        require(all(record.get(key) == binding[key] for key in ("cipher_sha256", "plain_sha256", "session")),
                "Capture identity changed during restoration", 5)
        result = {"status": "complete", "material": record["id"], "archive_sha256": binding["plain_sha256"],
                  "files": len(journal["inventory"]), "destination": str(destination)}
        copies = record["copies"]
        restoration = path.stem
        additions = []
        for name, entry in journal["inventory"].items():
            candidate = {"root": str(destination), "path": name, "sha256": entry["sha256"],
                         "kind": "native" if record.get("session") else "checkpoint", "status": "present",
                         "restoration": restoration}
            if not any(copy["path"] == name and (copy.get("restoration") == restoration or
                       copy["status"] not in INACTIVE_COPIES and copy["kind"] == candidate["kind"] and
                       copy["sha256"] == candidate["sha256"] and vault.relocated_path(copy["root"]) == destination)
                       for copy in copies):
                additions.append(candidate)
        if additions:
            copies.extend(additions)
            save_material(vault, record)
        if record.get("session"):
            session = get_session(vault, record["session"])
            if session_reconstruction(session) == journal["prior_session"]:
                session.update(recovery_profile=str(destination), reconstruction=result)
                atomic(safe_path(vault.control, f"sessions/{session['operation']}.json"), session)
        receipt = vault.receipt("reconstruction", result, at=journal["started_at"])
        journal.update(status="complete", result={**result, "receipt": receipt})
        journal.pop("error", None)
        atomic(path, journal)
        return journal["result"]
