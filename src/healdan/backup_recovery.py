"""Recover verified backup bytes through a journaled, staged directory publication."""
from copy import deepcopy
import os
from pathlib import Path
import shutil
from uuid import uuid4

from . import backup_snapshot as snapshot, binding
from .core import (atomic, decode, digest, file_digest, git, git_bytes, lock, read_json,
                   require, safe_path, stamp, sync_directory)
from .custody import INACTIVE_COPIES, archive_members

JOURNAL = snapshot.RESTORE_JOURNAL
JOURNAL_FILE = "backup-restore.json"
LOCK = "backup-restore.lock"


def location(path):
    path = Path(path).absolute()
    checked = safe_path(path.parent, path.name)
    require(not any(part.is_junction() for part in (checked, *checked.parents)),
            "Unsafe backup recovery location: " + str(checked), 5)
    return checked.resolve()


def separate(left, right):
    return not left.is_relative_to(right) and not right.is_relative_to(left)


def directory_identity(path):
    require(path.is_dir() and not path.is_symlink() and not path.is_junction(), "Unsafe recovery directory: " + str(path), 5)
    info = path.stat()
    return [info.st_dev, info.st_ino]


def empty_destination(path):
    require(not path.exists() or path.is_dir() and not any(path.iterdir()),
            "Restore destination must be new or empty", 2)


def proof_receipt(control, kind, payload, at):
    value = {"kind": kind, "payload": payload, "at": at}
    key = digest(value)
    atomic(safe_path(control, f"receipts/{key}.json"), value)
    return key


def reconcile_task(record, identifier):
    if not record.get("processes") and (record["state"] in {"closed", "cancelled"} or
            record["state"] == "reconciliation_required" and isinstance(record.get("reconciliation"), dict)):
        return record
    historical = {"backup": identifier, "status": "required", "state": record["state"],
                  "worktree": record.get("worktree"), "processes": record.get("processes", []),
                  "reason": "Origin worktree and process identities require reconciliation"}
    return {**record, "state": "reconciliation_required", "processes": [], "reconciliation": historical}


def reconcile_session(record, identifier):
    inert = {"active_profile", "recovery_profile", "launch_intent", "reconstruction"}
    if (record.get("state") == "reconciliation_required" and isinstance(record.get("reconciliation"), dict) and
            not (inert & record.keys())):
        return record
    if record.get("state") in {"complete", "completed", "failed", "closed"} and not any(
            record.get(key) for key in ("active_profile", "recovery_profile", "launch_intent", "reconstruction")):
        return record
    origin = {"backup": identifier, "status": "required", "state": record["state"],
              "reason": "Origin session and launch paths require reconciliation"}
    origin.update({key: record[key] for key in inert if key in record})
    return {**{key: value for key, value in record.items() if key not in inert},
            "state": "reconciliation_required", "reconciliation": origin}


def remapped_copies(remap, records, destination, state):
    request = read_json(remap) if isinstance(remap, (str, Path)) else remap
    require(isinstance(request, dict), "Recovery remapping must map material IDs and copy indices to absolute files", 5)
    selected = {}
    for key, indices in request.items():
        record = records.get(key)
        require(record and record["kind"] != "backup" and isinstance(indices, dict),
                "Unknown or ineligible remapped material: " + key, 5)
        for index, filename in indices.items():
            require(isinstance(index, str) and index.isascii() and index.isdecimal() and str(int(index)) == index and
                    int(index) < len(record["copies"]) and isinstance(filename, str) and Path(filename).is_absolute(),
                    "Invalid remapped custody copy: " + key, 5)
            original = record["copies"][int(index)]
            require(original["status"] not in INACTIVE_COPIES and original["kind"] in {"ciphertext", "checkpoint", "export", "archive"},
                    "Remapping cannot revive retired copies or import native profiles", 5)
            snapshot.portable_path(original["path"])
            path = location(filename)
            require(separate(path, state) and separate(path, destination), "Remapped file must be external to recovery", 5)
            data = safe_path(path.parent, path.name, exists=True).read_bytes()
            require(digest(data) == original["sha256"], "Remapped custody copy hash mismatch: " + key, 5)
            if original["kind"] != "ciphertext":
                require(not snapshot.FORBIDDEN_NAMES.search(original["path"]), "Forbidden remapped custody path", 5)
                snapshot.guard_content(original["path"], data)
            selected[key, int(index)] = (path, data)
    return selected


def reconcile_copies(archive, contents, records, state, control, journal, remaps):
    inventory = deepcopy(records)
    sources = {entry["sha256"]: contents[name] for name, entry in archive["files"].items()
               if entry["kind"] == "knowledge" and snapshot.originals.source_path(name)}
    pending = []
    for key, record in inventory.items():
        local = []
        for index, copy in enumerate(record["copies"]):
            copy.setdefault("origin_status", copy["status"])
            if copy["status"] in INACTIVE_COPIES:
                continue
            copy["status"] = "unavailable"
            remap = remaps.get((key, index))
            member = contents.get(f"custody/{key}.age")
            if remap is not None:
                origin, data = remap
            elif member is not None and copy["kind"] == "ciphertext" and digest(member) == copy["sha256"]:
                origin, data = None, member
            elif record.get("classification") != "secret" and copy["kind"] in {"export", "archive"} and copy["sha256"] in sources:
                origin, data = None, sources[copy["sha256"]]
            else:
                pending.append({"material": key, "copy_index": index, "root": copy["root"], "path": copy["path"],
                                "status": "unavailable"})
                continue
            if copy["kind"] == "ciphertext":
                relative = f"custody/{key}.age"
            else:
                relative = f"recovered-copies/{key}/{index}/{copy['path']}"
            target = safe_path(state, relative)
            if target.exists():
                require(file_digest(safe_path(state, relative, exists=True)) == copy["sha256"],
                        "Staged custody copy differs from verified bytes", 5)
            else:
                atomic(target, data)
            if any(entry["root"] == str(target.parent) and entry["path"] == target.name for entry in local):
                continue
            payload = {"backup": journal["origin"]["backup"], "material": key, "origin_copy_index": index,
                       "origin": str(origin) if origin else None, "root": str(target.parent), "path": target.name,
                       "sha256": copy["sha256"]}
            receipt = proof_receipt(control, "backup-copy-recovered", payload, journal["at"])
            local.append({"root": str(target.parent), "path": target.name, "sha256": copy["sha256"], "kind": copy["kind"],
                          "status": "present", "recovery_receipt": receipt})
        record["copies"].extend(local)
    atomic(control / "materials.json", inventory)
    return pending


def build_portable(staging, state, journal, verified, raw_manifest, remaps):
    archive, contents, records = verified
    bundle = safe_path(staging, snapshot.BUNDLE)
    atomic(bundle, contents[snapshot.BUNDLE])
    snapshot.open_bundle(staging, bundle, archive["git"])
    bundle.unlink()
    knowledge = set()
    for name, entry in archive["files"].items():
        if entry["kind"] != "knowledge":
            continue
        target = safe_path(staging, name)
        atomic(target, contents[name])
        if entry["mode"] == "100755" and os.name != "nt":
            target.chmod(0o755)
        knowledge.add(name)
    omitted = {name for name, *_ in snapshot.tree_entries(staging, archive["git"]["head"])} - knowledge
    if omitted:
        git_bytes(staging, "update-index", "--skip-worktree", "-z", "--stdin",
                  data=b"".join(name.encode("utf-8") + b"\0" for name in sorted(omitted)))
    control = staging / ".git/healdan"
    generation = journal["origin"]["backup"]
    raw_records = snapshot.records_from(contents)
    prior = {name: data for name, data in raw_records.items() if snapshot.historical_record(name)}
    for name, data in prior.items():
        atomic(safe_path(control, name), data)
    for name, data in raw_records.items():
        if name in prior:
            continue
        is_task = name.startswith(("tasks/", "sessions/"))
        if name in snapshot.HISTORICAL_STATE | {"materials.json"} or name.startswith("restorations/") or is_task:
            historical = "historical/" + name
            if historical in prior:
                historical = f"historical/generations/{generation}/{name}"
            require(historical not in prior, "Recovery would overwrite historical evidence: " + historical, 5)
            atomic(safe_path(control, historical), data)
        if is_task:
            reconcile = reconcile_task if name.startswith("tasks/") else reconcile_session
            atomic(safe_path(control, name), reconcile(records[name], generation))
        elif name not in snapshot.HISTORICAL_STATE | {"materials.json"} and not name.startswith("restorations/"):
            atomic(safe_path(control, name), data)
    manifest_path = f"historical/{generation}.manifest.json"
    require(manifest_path not in prior, "Recovery would overwrite an earlier generation manifest", 5)
    atomic(safe_path(control, manifest_path), raw_manifest)
    if snapshot.SOURCE_BINDING in archive:
        proof = f"historical/generations/{generation}/binding.json"
        require(proof not in prior, "Recovery would overwrite earlier binding evidence", 5)
        atomic(safe_path(control, proof), archive[snapshot.SOURCE_BINDING])
    pending = reconcile_copies(archive, contents, records["materials.json"], state, control, journal, remaps)
    return len(knowledge), pending


def build_legacy(staging, archive, signed, signers, backup_signers, *, external_state=None):
    from .custody import validate_purpose
    from .lineage import sha256

    require(isinstance(archive, dict) and archive.get("format") == "healdan-tree-v1" and isinstance(archive.get("files"), dict),
            "Unknown legacy backup archive", 5)
    snapshot.paths_compatible(archive["files"])
    members = archive_members(archive, staging)
    prepared = {}
    proven = set()
    selected = signed["members"]
    require(signed["generation"] in {"short", "long"} and isinstance(selected, list) and all(snapshot.identifier(member) for member in selected) and
            len(set(selected)) == len(selected) and (signed["generation"] == "short" or not selected),
            "Invalid legacy backup member selection", 5)
    expected_members = {Path(f"custody/{member}.age"): member for member in selected}
    for relative, body in members.items():
        name = relative.as_posix()
        if name == snapshot.BUNDLE:
            continue
        if name.startswith("custody/"):
            require(relative in expected_members, "Unexpected legacy backup custody member", 5)
            continue
        require(not snapshot.FORBIDDEN_NAMES.search(name), "Forbidden legacy backup path: " + name, 5)
        snapshot.guard_content(name, body)
        if name.endswith(".json"):
            prepared[name] = decode(body)
            snapshot.check_signatures(prepared[name], signers, backup_signers, proven)
        elif name.endswith(".jsonl"):
            from .core import parse_jsonl
            snapshot.check_signatures(parse_jsonl(body, name), signers, backup_signers, proven)
    root = Path(staging)
    custody_records = prepared.get(snapshot.MATERIALS, {})
    require(isinstance(custody_records, dict), "Invalid legacy custody manifests", 5)
    for relative, identifier in expected_members.items():
        record, cipher = custody_records.get(identifier), members.get(relative)
        require(isinstance(record, dict) and record.get("id") == identifier and record.get("kind") == "conversation" and
                record.get("classification") != "secret" and record.get("decryption_verified") is True and
                sha256(record.get("plain_sha256")) and cipher is not None and cipher.startswith(b"age-encryption.org/v1") and
                len(cipher) == record.get("size") and digest(cipher) == record.get("cipher_sha256"),
                "Legacy conversation body does not match its custody manifest", 5)
        validate_purpose(record)
    bundle = safe_path(root, snapshot.BUNDLE)
    require(Path(snapshot.BUNDLE) in members, "Legacy backup lacks a verified Git bundle", 5)
    atomic(bundle, members[Path(snapshot.BUNDLE)])
    listed = dict(line.split(" ", 1)[::-1] for line in git(root, "bundle", "list-heads", str(bundle)).splitlines())
    head = listed.pop("HEAD", signed["commit"])
    require(head == signed["commit"], "Legacy bundle HEAD differs from signed backup", 5)
    branches = [name for name, oid in listed.items() if name.startswith("refs/heads/") and oid == head]
    identity = {"head": head, "refs": listed, "symbolic_refs": {}, "symbolic_head": branches[0] if len(branches) == 1 else None,
                "object_format": "sha1" if len(head) == 40 else "sha256"}
    snapshot.validate_git_identity(identity)
    snapshot.initialize_git(root, identity)
    git(root, "bundle", "verify", str(bundle))
    git(root, "bundle", "unbundle", str(bundle))
    snapshot.install_refs(root, identity)
    git(root, "read-tree", head)
    for relative, body in members.items():
        if relative != Path(snapshot.BUNDLE) and relative.parts[0] != "custody":
            atomic(safe_path(root, relative), body)
    for relative in expected_members:
        target = safe_path(external_state if external_state is not None else root, relative)
        if target.exists():
            require(safe_path(target.parent, target.name, exists=True).read_bytes() == members[relative],
                    "Staged legacy custody copy differs from verified bytes", 5)
        else:
            atomic(target, members[relative])
    if expected_members and external_state is None:
        atomic(root / ".git/info/exclude", b"/custody/\n")
    control = root / ".git/healdan"
    checkpoints = prepared.get("control/controller-checkpoints.json", {})
    for name in ("reservations", "csp"):
        if name in checkpoints:
            require(isinstance(checkpoints[name], dict), "Invalid legacy controller checkpoint", 5)
            atomic(control / (name + ".json"), checkpoints[name])
    for session in checkpoints.get("sessions", []):
        require(snapshot.identifier(session.get("operation")), "Invalid legacy session operation", 5)
        atomic(safe_path(control, "sessions/" + session["operation"] + ".json"), reconcile_session(session, signed["id"]))
    return len(members), ["Legacy backup omitted complete tasks, custody copies, policy and retention state"]


def allocated(journal, journal_path, stage):
    if stage.exists():
        current = directory_identity(stage)
        require(current == journal.get("stage_identity") or
                journal.get("stage_identity") is None and not any(stage.iterdir()),
                "Intermediate recovery directory identity changed", 5)
        if journal.get("stage_identity") is not None:
            def writable(function, path, error):
                os.chmod(path, 0o700)
                function(path)
            shutil.rmtree(stage, onexc=writable)
    stage.mkdir(mode=0o700, exist_ok=True)
    journal.update(phase="building", stage_identity=directory_identity(stage))
    atomic(journal_path, journal)


def directory_inventory(stage):
    inventory = {}

    def unreadable(error):
        raise error

    for folder, directories, files in os.walk(stage, followlinks=False, onerror=unreadable):
        root = Path(folder)
        for name in directories:
            directory = safe_path(root, name)
            require(not directory.is_junction(), "Unsafe intermediate recovery directory", 5)
            inventory[directory.relative_to(stage).as_posix()] = None
        for name in files:
            file = safe_path(root, name, exists=True)
            inventory[file.relative_to(stage).as_posix()] = file_digest(file)
    return inventory


def staging_digest(stage):
    return digest(directory_inventory(stage))


def recovered_state_digest(state):
    inventory = {}
    for name in ("binding.json", "config.json", "custody", "recovered-copies"):
        path = safe_path(state, name)
        require(not path.is_junction(), "Unsafe external recovery state: " + name, 5)
        if path.exists():
            inventory[name] = directory_inventory(path) if path.is_dir() else file_digest(safe_path(state, name, exists=True))
    return digest(inventory)


def publish(stage, destination, empty, journal):
    expected = journal.get("empty_identity")
    if destination.exists() and directory_identity(destination) == journal["stage_identity"]:
        require(not stage.exists(), "Recovery destination and staging both exist", 5)
        if journal["phase"] == "ready":
            require(staging_digest(destination) == journal["stage_sha256"],
                    "Recovery destination changed before completion", 5)
        return
    require(stage.exists() and directory_identity(stage) == journal["stage_identity"],
            "Verified recovery staging directory is missing", 5)
    require(staging_digest(stage) == journal["stage_sha256"], "Recovery staging bytes changed before publication", 5)
    if empty.exists():
        require(directory_identity(empty) == expected and not destination.exists(),
                "Original empty recovery destination changed", 5)
    elif expected is not None:
        empty_destination(destination)
        require(directory_identity(destination) == expected, "Original recovery destination identity changed", 5)
        destination.rename(empty)
    else:
        require(not destination.exists(), "Restore destination became occupied", 5)
    try:
        if empty.exists():
            empty_destination(empty)
        stage.rename(destination)
        sync_directory(destination.parent)
    except BaseException:
        if empty.exists() and not destination.exists():
            empty.rename(destination)
        raise


def recover(verified, destination, state, report, *, allowed_signers, backup_signers, age_identity=None, remap=None,
            legacy_source=None, source_root=None, source_state=None):
    replica, raw_manifest, plain, signed, checked = verified
    destination = location(destination)
    bind = state is not None or raw_manifest is not None
    state = location(state if state is not None else destination.with_name(destination.name + ".healdan-state"))
    require(separate(destination, state) and all(separate(target, origin) for target in (destination, state)
            for origin in (source_root, source_state, replica) if origin is not None),
            "Recovery destination and state must be independent of each other and the source", 5)
    source_id = signed.get("source_vault") if raw_manifest is not None else legacy_source
    require(snapshot.identifier(source_id), "Backup source vault identity is unavailable", 5)
    original_materials = checked[2]["materials.json"] if raw_manifest is not None else {}
    remaps = remapped_copies(remap, original_materials, destination, state) if remap is not None else {}
    origin = {"backup": signed["id"], "vault": source_id, "commit": signed["commit"],
              "plain_sha256": digest(plain), "manifest_sha256": digest(raw_manifest) if raw_manifest is not None else digest(signed)}
    request = {"destination": str(destination), "state": str(state), "bind": bind,
               "remapping": [{"material": key, "copy_index": index, "file": str(path), "sha256": digest(data)}
                             for (key, index), (path, data) in sorted(remaps.items())],
               "trust": {key: str(Path(path).resolve()) for key, path in (("allowed_signers", allowed_signers),
                          ("backup_allowed_signers", backup_signers), ("age_identity", age_identity)) if path}}
    journal_path = safe_path(state, JOURNAL_FILE)
    parent = destination.parent
    require(parent.is_dir(), "Restore destination parent must exist", 5)
    if not journal_path.exists():
        empty_destination(destination)
        require(not state.exists() or state.is_dir() and all(path.name == LOCK for path in state.iterdir()),
                "Recovery state directory must be empty", 5)
    with lock(safe_path(state, LOCK)):
        journal = read_json(journal_path)
        if journal is None:
            empty_destination(destination)
            require(all(path.name == LOCK for path in state.iterdir()), "Recovery state directory must be empty", 5)
            state.chmod(0o700)
            journal = {"format": JOURNAL, "phase": "building", "origin": origin, "request": request, "at": stamp(),
                       "stage": ".healdan-restore-" + str(uuid4()), "stage_identity": None,
                       "empty_identity": directory_identity(destination) if destination.exists() else None,
                       "inventory_sha256": signed.get("inventory_sha256", digest(plain)),
                       "inventory": snapshot.inventory(checked[0] if raw_manifest is not None else checked)}
            atomic(journal_path, journal)
        require(journal.get("format") == JOURNAL and journal.get("origin") == origin and journal.get("request") == request and
                journal.get("phase") in {"building", "ready", "complete"} and
                snapshot.identifier(journal.get("stage", "").removeprefix(".healdan-restore-")),
                "Recovery journal belongs to a different backup, destination or trust configuration", 5)
        stage = safe_path(parent, journal["stage"])
        empty = safe_path(parent, journal["stage"] + ".empty")
        if journal["phase"] == "building":
            empty_destination(destination)
            allocated(journal, journal_path, stage)
            if raw_manifest is None:
                count, pending = build_legacy(stage, checked, signed, allowed_signers or "", backup_signers or "",
                                              external_state=state if bind else None)
            else:
                count, pending = build_portable(stage, state, journal, checked, raw_manifest, remaps)
            control = stage / ".git/healdan"
            provenance = {"format": JOURNAL, **origin, "destination": str(destination), "state": str(state)}
            if raw_manifest is not None:
                provenance["backup_format"] = snapshot.MANIFEST
            if bind:
                config = dict(request["trust"])
                if raw_manifest is not None and checked[0][snapshot.SOURCE_AUTHORITIES]:
                    config[snapshot.SOURCE_AUTHORITIES] = checked[0][snapshot.SOURCE_AUTHORITIES]
                atomic(state / "config.json", config)
                binding.stage_recovered_binding(stage, destination, state, source_id)
                atomic(control / "restored-from.json", provenance)
            else:
                atomic(control / "restored-from.json", {"format": "healdan-restored-vault-v1", "source_vault": source_id,
                                                         "backup": origin["backup"], "commit": origin["commit"]})
            receipt = proof_receipt(control, "backup-restored", provenance, journal["at"])
            journal.update(phase="ready", files=count, pending_copies=pending, receipt=receipt, stage_sha256=staging_digest(stage),
                           state_sha256=recovered_state_digest(state))
            atomic(journal_path, journal)
        if journal["phase"] == "ready":
            require(recovered_state_digest(state) == journal.get("state_sha256"),
                    "External recovery state changed before publication", 5)
        publish(stage, destination, empty, journal)
        if journal["phase"] == "ready":
            require(recovered_state_digest(state) == journal.get("state_sha256"),
                    "External recovery state changed before completion", 5)
        repository = binding.Repository.open(destination)
        if bind:
            require(binding.bound(repository, state)["vault_id"] == source_id,
                    "Recovered vault binding does not match the backup", 5)
        require((journal["phase"] == "complete" or git(destination, "rev-parse", "HEAD") == signed["commit"]) and
                digest(read_json(safe_path(repository.control, f"receipts/{journal['receipt']}.json", exists=True))) == journal["receipt"],
                "Recovered Git, binding or completion receipt verification failed", 5)
        if empty.exists():
            require(directory_identity(empty) == journal["empty_identity"] and not any(empty.iterdir()),
                    "Original empty destination staging changed", 5)
            empty.rmdir()
        if journal["phase"] != "complete":
            journal["phase"] = "complete"
            atomic(journal_path, journal)
        return {**report, "status": "complete", "source_vault": source_id, "commit": signed["commit"],
                "state": str(state) if bind else None, "journal": str(journal_path),
                "receipt": journal["receipt"], "destination": str(destination), "archive_sha256": digest(plain),
                "files": journal["files"], "pending_copies": journal["pending_copies"]}
