"""Encrypted backup generations with immutable expiry and verified copies."""
import base64
from datetime import timedelta
from pathlib import Path
from uuid import uuid4
import re
import tempfile

from .core import Blocked, atomic, canonical, decode, digest, git, git_bytes, read_json, require, safe_path, stamp, utc
from .custody import decrypt, encrypt, materials, retention_deadline, restore_tree, save_material
from .signing import envelope, verify


def history_bundle(vault):
    """Reject known custody/secret paths and native transcript objects before bundling."""
    require(vault.head(), "History backup needs an initial commit", 5)
    for line in git(vault.root, "rev-list", "--objects", "--all").splitlines():
        oid, _, name = line.partition(" ")
        if not name:
            continue
        require(not re.search(r"(^|/)(wiki-1\.4\.md|transcripts|\.env|S-[0-9]+\.jsonl)(/|$)|\.(age|key|pem)$", name),
                "Historical custody/secret paths require a reviewed preservation or purge plan", 5)
        if git(vault.root, "cat-file", "-t", oid) != "blob":
            continue
        body = git_bytes(vault.root, "cat-file", "blob", oid)
        require(not re.search(rb"(?m)^-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----\r?$", body),
                "Private key material detected in history", 5)
        if name.endswith((".json", ".jsonl")) and b'"sessionId"' in body and (b'"assistant"' in body or b'"user"' in body):
            raise Blocked("Native conversation object detected in Git history", 5)
    with tempfile.TemporaryDirectory(prefix="bundle-", dir=vault.state) as directory:
        bundle = Path(directory) / "repository.bundle"
        git(vault.root, "bundle", "create", str(bundle), "--all")
        git(vault.root, "bundle", "verify", str(bundle))
        return bundle.read_bytes()


def validate_generation(kind, members, expires_at, now=None):
    require(kind in {"long", "short"}, "Unknown backup generation kind", 2)
    expiry = utc(expires_at)
    require(expiry > utc(now), "Backup expiry must be in the future", 2)
    if kind == "long":
        require(not members, "Long backups contain conversation manifests only", 5)
    for member in members:
        deadline = retention_deadline(member)
        require(deadline and expiry < deadline, "Short backup expiry must precede every material deadline", 5)


def create(vault, kind, expires_at, member_ids=(), *, now=None):
    with vault.locked():
        vault.no_transaction()
        pending = [read_json(p) for p in (vault.control / "deletions").glob("*.json")]
        require(all(p["status"] == "complete" for p in pending), "Retention round is incomplete", 5)
        records = materials(vault)
        members = [records[i] for i in member_ids]
        validate_generation(kind, members, expires_at, now)
        destinations = vault.config.get("backup_destinations", [])
        require(destinations, "No backup destinations configured", 5)
        require(all(Path(p).is_dir() and not Path(p).is_symlink() for p in destinations),
                "A backup destination is offline", 5)
        files = {}
        names = set(vault.inputs())
        tracked = git_bytes(vault.root, "ls-files", "-z").decode("utf-8")
        names.update(p for p in tracked.split("\0") if p)
        for name in sorted(names):
            data = safe_path(vault.root, name, exists=True).read_bytes()
            files[name] = {"sha256": digest(data), "size": len(data), "body": base64.b64encode(data).decode("ascii")}
        bundle = history_bundle(vault)
        files["control/repository.bundle"] = {"sha256": digest(bundle), "size": len(bundle),
                                                "body": base64.b64encode(bundle).decode("ascii")}
        manifest_data = canonical({i: {k: v for k, v in m.items() if k != "copies"} for i, m in records.items()})
        files["control/custody-manifests.json"] = {"sha256": digest(manifest_data), "size": len(manifest_data),
                                                   "body": base64.b64encode(manifest_data).decode("ascii")}
        checkpoints = {"reservations": read_json(vault.control / "reservations.json", {}),
                       "csp": read_json(vault.control / "csp.json", {"streak": 0}),
                       "sessions": [read_json(p) for p in (vault.control / "sessions").glob("*.json")]}
        checkpoint_data = canonical(checkpoints)
        files["control/controller-checkpoints.json"] = {"sha256": digest(checkpoint_data), "size": len(checkpoint_data),
                                                         "body": base64.b64encode(checkpoint_data).decode("ascii")}
        for member in members:
            copy = next(c for c in member["copies"] if c["kind"] == "ciphertext" and c["status"] == "present")
            data = safe_path(vault.relocated_path(copy["root"]), copy["path"], exists=True).read_bytes()
            require(digest(data) == copy["sha256"], "Member ciphertext changed")
            files["custody/" + member["id"] + ".age"] = {
                "sha256": digest(data), "size": len(data), "body": base64.b64encode(data).decode("ascii")}
        archive = {"format": "healdan-tree-v1", "files": files}
        key = Path(vault.config.get("backup_signing_key") or "")
        signers = Path(vault.config.get("backup_allowed_signers") or "")
        require(key.is_absolute() and key.is_file() and signers.is_file() and
                not key.resolve().is_relative_to(vault.root) and key.resolve() != Path(vault.config.get("signing_key") or "").resolve(),
                "A separate external backup signing key and policy are required", 5)
        identity = vault.config.get("backup_signing_identity")
        require(identity, "Backup signing identity missing", 5)
        cipher = encrypt(vault, canonical(archive))
        identifier = str(uuid4())
        record = {"id": identifier, "kind": "backup", "generation": kind, "created_at": stamp(now),
                  "expires_at": stamp(expires_at), "members": list(member_ids), "commit": vault.head(),
                  "plain_sha256": digest(archive), "cipher_sha256": digest(cipher), "holds": [],
                  "dependencies": [], "copies": [], "status": "writing"}
        # Register every target before the first effect so partial copies remain inventoried.
        for destination in destinations:
            record["copies"].append({"root": str(Path(destination).resolve()), "path": identifier + ".age",
                                     "sha256": digest(cipher), "kind": "ciphertext", "status": "planned"})
        save_material(vault, record)
        for copy in record["copies"]:
            target = safe_path(copy["root"], copy["path"])
            atomic(target, cipher)
            require(digest(decrypt(vault, target.read_bytes())) == record["plain_sha256"], "Backup verification failed")
            copy["status"] = "present"
            save_material(vault, record)
        record["status"] = "complete"
        record["verified_at"] = stamp(now)
        record["approval"] = envelope(record.copy(), "backup", identity, key)
        verify(record["approval"], "backup", signers)
        save_material(vault, record)
        vault.receipt("backup", {"id": identifier, "status": "complete", "expires_at": record["expires_at"]})
        return record


def verify_backup(vault, identifier):
    with vault.locked():
        return _verify_backup(vault, identifier)


def _verify_backup(vault, identifier):
    record = materials(vault)[identifier]
    require(record["kind"] == "backup", "Not a backup", 2)
    signed = verify(record.get("approval"), "backup", vault.config.get("backup_allowed_signers", ""))
    require({k: v for k, v in record.items() if k != "approval"} == signed, "Signed backup manifest changed")
    checks = []
    for copy in record["copies"]:
        root = vault.relocated_path(copy["root"])
        if root != Path(copy["root"]):
            require(root in map(Path, vault.config.get("backup_destinations", [])),
                    "Relocated backup destination is not authorized", 5)
        cipher = safe_path(root, copy["path"], exists=True).read_bytes()
        require(digest(cipher) == copy["sha256"], "Backup ciphertext mismatch")
        require(digest(decrypt(vault, cipher)) == record["plain_sha256"], "Backup plaintext mismatch")
        checks.append({"root": str(root), "verified": True})
    return {"id": identifier, "copies": checks}


def restore(vault, identifier, destination):
    with vault.locked():
        return _restore(vault, identifier, destination)


def _restore(vault, identifier, destination):
    _verify_backup(vault, identifier)
    copy = materials(vault)[identifier]["copies"][0]
    cipher = safe_path(vault.relocated_path(copy["root"]), copy["path"], exists=True).read_bytes()
    result = restore_tree(decode(decrypt(vault, cipher)), destination)
    bundle = Path(destination) / "control/repository.bundle"
    if bundle.exists():
        git(destination, "-c", "init.templateDir=", "init")
        git(destination, "fetch", "--update-head-ok", str(bundle.resolve()), "+refs/*:refs/*")
        git(destination, "symbolic-ref", "HEAD", "refs/heads/healdan-recovered")
        git(destination, "reset", "--mixed", materials(vault)[identifier]["commit"])
        result["commit"] = git(destination, "rev-parse", "HEAD")
        control = Path(destination) / ".git/healdan"
        checkpoints = read_json(Path(destination) / "control/controller-checkpoints.json")
        if checkpoints:
            atomic(control / "reservations.json", checkpoints["reservations"])
            atomic(control / "csp.json", checkpoints["csp"])
            for session in checkpoints["sessions"]:
                atomic(control / "sessions" / (session["operation"] + ".json"), session)
        atomic(control / "restored-from.json", {"format": "healdan-restored-vault-v1", "source_vault": vault.identity,
                                                "backup": identifier, "commit": result["commit"]})
    return result
