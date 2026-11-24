"""External age custody, verified archives, holds and native-copy guards."""
import base64
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from .core import atomic, canonical, decode, digest, executable, read_json, require, run, safe_path, stamp, utc
from .signing import trusted_signers, verify

INACTIVE_COPIES = {"deleted", "moved"}


def archive_tree(root):
    root = Path(root).resolve()
    files = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "Cannot preserve a symlink tree")
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            data = safe_path(root, rel, exists=True).read_bytes()
            files[rel] = {"sha256": digest(data), "size": len(data),
                          "body": base64.b64encode(data).decode("ascii")}
    return {"format": "healdan-tree-v1", "files": files}


def restore_tree(archive, destination):
    destination = Path(destination).absolute()
    require(not destination.exists() or not any(destination.iterdir()), "Restore destination must be empty", 2)
    require(archive.get("format") == "healdan-tree-v1", "Unknown archive format")
    checked = []
    for name, entry in archive["files"].items():
        path = safe_path(destination, name)
        data = base64.b64decode(entry["body"], validate=True)
        require(len(data) == entry["size"] and digest(data) == entry["sha256"], "Archive member mismatch")
        checked.append((path, data))
    destination.mkdir(parents=True, exist_ok=True)
    for path, data in checked:
        atomic(path, data)
    return {"archive_sha256": digest(archive), "files": len(checked), "destination": str(destination)}


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


def materials(vault):
    return read_json(vault.control / "materials.json", {})


def save_material(vault, record):
    with vault.locked():
        rows = materials(vault)
        rows[record["id"]] = record
        atomic(vault.control / "materials.json", rows)


def record_archive_move(vault, records, move, receipt):
    payload = move["payload"]
    source, destination, sha = payload["source"], payload["destination"], payload["sha256"]
    origin_path = safe_path(vault.root, source)
    archived = safe_path(vault.root, destination, exists=True)
    require(digest(archived.read_bytes()) == sha, "Archived custody copy changed: " + destination, 5)
    for record in records:
        copies = record["copies"]
        origins = [copy for copy in copies if copy["kind"] == "export" and copy["sha256"] == sha and
                   vault.relocated_path(copy["root"]) / copy["path"] == origin_path]
        if not any(copy.get("move_receipt") == receipt for copy in origins):
            active = [copy for copy in origins if copy["status"] not in INACTIVE_COPIES]
            if not active:
                active = [{"root": str(vault.root / "inbox"), "path": source.removeprefix("inbox/"),
                           "sha256": sha, "kind": "export"}]
                copies.extend(active)
            for copy in active:
                copy.update(status="moved", moved_at=move["at"], move_receipt=receipt)
        if not any(copy["kind"] == "archive" and copy["sha256"] == sha and copy["status"] == "present" and
                   vault.relocated_path(copy["root"]) / copy["path"] == archived for copy in copies):
            copies.append({"root": str(vault.root / "archive"), "path": destination.removeprefix("archive/"),
                           "sha256": sha, "kind": "archive", "status": "present"})
        save_material(vault, record)


def capture_tree(vault, root, *, task, classification, session=None, purpose=None):
    with vault.locked():
        return _capture_tree(vault, root, task, classification, session, purpose)


def _capture_tree(vault, root, task, classification, session, purpose):
    root = Path(root).resolve()
    require(not root.is_relative_to(vault.root), "Conversation capture must originate outside Git")
    require(root.is_relative_to(vault.state), "Capture root is not a controller-owned task/profile")
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


def retention_deadline(material):
    if material.get("kind") == "backup":
        return utc(material["expires_at"]) if material.get("expires_at") else None
    origin = material.get("captured_at") if material.get("kind") == "export" else material.get("closed_at")
    if not origin:
        return None
    days = 30 if material.get("classification") == "common" and material.get("kind") != "export" else 7
    return utc(origin) + timedelta(days=days)


def validate_purpose(material):
    if material.get("classification") != "common":
        purpose = material.get("purpose") or {}
        require(all(isinstance(purpose.get(k), str) and purpose[k].strip()
                    for k in ("purpose", "necessity", "owner", "link")), "Personal/unknown material lacks specific purpose")


def hold(vault, identifier, reason, owner, dependencies=(), review_at=None):
    record = materials(vault)[identifier]
    require(record.get("kind") != "backup", "Existing backup expiry cannot be suspended; use a separate preservation plan", 5)
    item = {"id": str(uuid4()), "reason": reason, "owner": owner, "started_at": stamp(),
            "review_at": stamp(review_at) if review_at else None, "dependencies": list(dependencies)}
    require(reason and owner, "Hold requires reason and owner", 2)
    record.setdefault("holds", []).append(item)
    save_material(vault, record)
    vault.receipt("hold", {"material": identifier, **item})
    return item


def release_hold(vault, identifier, hold_id, resolved):
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
    require(proof.get("cipher_sha256") == material.get("cipher_sha256") and
            proof.get("plain_sha256") == material.get("plain_sha256") and proof.get("reconstruction_sha256"),
            "Recovery proof does not match the captured archive", 5)
    from .tasks import get_session
    session = get_session(vault, material["session"])
    receipt = next((r for r in session["launches"] if r.get("id") == proof.get("launch_receipt")), None)
    require(session.get("reconstruction", {}).get("archive_sha256") == proof.get("reconstruction_sha256") and
            proof.get("reconstruction_sha256") == material.get("plain_sha256"), "Native reconstruction is not proven", 5)
    require(receipt and receipt.get("resumed") and receipt.get("recovery_material") == material["id"] and receipt.get("success") and
            proof.get("uuid") == session["uuid"] and proof.get("action") == session["action"] and
            proof.get("usage") == receipt.get("cumulative_usage"), "Native resume is not proven", 5)


def restore_capture(vault, identifier, destination):
    with vault.locked():
        return _restore_capture(vault, identifier, destination)


def _restore_capture(vault, identifier, destination):
    record = materials(vault)[identifier]
    copy = next(c for c in record["copies"] if c["kind"] == "ciphertext" and c["status"] == "present")
    cipher = safe_path(vault.relocated_path(copy["root"]), copy["path"], exists=True).read_bytes()
    require(digest(cipher) == copy["sha256"], "Ciphertext changed")
    plain = decrypt(vault, cipher)
    require(digest(plain) == record["plain_sha256"], "Plaintext archive digest mismatch")
    require(not Path(destination).resolve().is_relative_to(vault.root), "Native restore must be external")
    archive = decode(plain)
    result = restore_tree(archive, destination)
    root = str(Path(destination).resolve())
    for name, entry in archive["files"].items():
        record["copies"].append({"root": root, "path": name, "sha256": entry["sha256"],
                                 "kind": "native" if record.get("session") else "checkpoint", "status": "present"})
    save_material(vault, record)
    if record.get("session"):
        from .tasks import get_session
        session = get_session(vault, record["session"])
        session["recovery_profile"] = str(Path(destination).resolve())
        session["reconstruction"] = dict(result, material=identifier)
        atomic(vault.control / "sessions" / (session["operation"] + ".json"), session)
    vault.receipt("reconstruction", {"material": identifier, **result})
    return result
