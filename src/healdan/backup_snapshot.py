"""Git and operational snapshots for authenticated portable backups."""
import base64
from io import BytesIO
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import tempfile
from types import SimpleNamespace
import unicodedata
from uuid import UUID

from . import originals, trials
from .core import (REQUIRED_REGISTRIES, Blocked, atomic, decode, digest, git, git_bytes, json_paths,
                   parse_jsonl, require, safe_path, stamp)
from .custody import unresolved_material_copy
from .lineage import sha256
from .signing import verify

FORMAT = "healdan-backup-snapshot-v1"
MANIFEST = "healdan-backup-manifest-v1"
RECOVERY_HISTORY = "healdan-backup-history-v1"
BUNDLE = "control/repository.bundle"
MATERIALS = "control/custody-manifests.json"
STATE = "control/backup-state/"
RESERVED = (BUNDLE, MATERIALS, "control/controller-checkpoints.json", STATE.rstrip("/"), "custody")
KNOWLEDGE = ("wiki/", "resources/sources/", "templates/", "config/", "control/approvals/")
SOURCE_AUTHORITIES = "source_classification_authorities"
SOURCE_BINDING = "source_binding"
ROOT_FILES = {".gitattributes", ".gitignore", "inbox/.gitkeep", "archive/.gitkeep", "projects/.gitkeep", "control/tasks/.gitkeep"}
STATE_FILES = {"csp.json", "followups.json", "inbox.json", "lint-state.json", "materials.json",
               "reservations.json", "restored-from.json", "source-classification.json", "source-ingest.json", "storage-policy.json",
               "transaction.json", "zero-byte-archive.json"}
STATE_FOLDERS = {"backup-preservation", "deletions", "lint", "packages", "receipts", "restorations",
                 "reviews", "sessions", "tasks"}
HISTORICAL_STATE = {"transaction.json", "source-ingest.json", "zero-byte-archive.json", "restored-from.json"}
HISTORICAL_FOLDERS = {"restorations", "sessions", "tasks"}
RESTORE_JOURNAL = "healdan-backup-restore-v1"
SIGNATURE_FIELDS = {"payload", "digest", "namespace", "identity", "signature"}
HUMAN_DOMAINS = {"package", "case", "alias", "trial", "decision", "recovery"}
FORBIDDEN_NAMES = re.compile(
    r"(^|/)(?:wiki-1\.4\.md|transcripts|authentication|recovery-profiles|\.ssh|\.env(?:\.[^/]*)?|"
    r"\.credentials\.json|S-[0-9]+\.jsonl)(/|$)|\.(?:age|agekey|key|pem|p12|pfx)$"
    r"|^(?:config/local\.json|\.claude/settings\.local\.json)$", re.I)
PRIVATE_KEY = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|AGE-SECRET-KEY-1[0-9A-Z]+")
DOS_NAME = re.compile(r"(?:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³])(?:\.|$)", re.I)


def identifier(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def portable_path(name, *, historical=False):
    require(isinstance(name, str) and name and all(
        part not in {"", ".", ".."} and not part.endswith((" ", ".")) and not DOS_NAME.match(part) and
        (historical or part.casefold() not in {".git", "git~1"}) and
        not any(ord(char) < 32 or char in '<>:"\\|?*' for char in part)
        for part in name.split("/")), "Unsafe backup path: " + str(name), 5)
    return name


def paths_compatible(names):
    spelling, leaves = {}, set()
    for name in names:
        parts = tuple(portable_path(name).split("/"))
        folded = tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)
        for length in range(1, len(parts) + 1):
            prefix = folded[:length]
            require(spelling.setdefault(prefix, parts[:length]) == parts[:length],
                    "Backup paths collide at " + name, 5)
        require(folded not in leaves, "Duplicate backup path: " + name, 5)
        leaves.add(folded)
    require(not any(path[:i] in leaves for path in leaves for i in range(1, len(path))),
            "Backup file collides with a directory", 5)


def reserved(name):
    lowered = name.casefold()
    return any(lowered == slot or lowered.startswith(slot + "/") or slot.startswith(lowered + "/")
               for slot in RESERVED)


def guard_content(name, body):
    require(not PRIVATE_KEY.search(body), "Private key material detected in " + name, 5)
    native = b'"sessionId"' in body and (b'"assistant"' in body or b'"user"' in body)
    require(not native, "Native conversation object detected in " + name, 5)


def tree_entries(root, revision):
    entries = git_bytes(root, "--no-replace-objects", "ls-tree", "-rz", "--full-tree", revision)
    for row in entries.split(b"\0")[:-1]:
        metadata, name = row.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        yield name.decode("utf-8"), mode, kind, oid


def git_identity(root):
    head = git(root, "--no-replace-objects", "rev-parse", "--verify", "HEAD^{commit}", check=False)
    branch = git(root, "symbolic-ref", "-q", "HEAD", check=False) or None
    refs, symbolic = {}, {}
    for row in git(root, "for-each-ref", "--format=%(objectname) %(refname) %(symref)").splitlines():
        oid, name, *target = row.split()
        refs[name] = oid
        if target:
            symbolic[name] = target[0]
    require(head and (branch is None or refs.get(branch) == head),
            "Cannot freeze Git HEAD and references; retry after the repository settles", 5)
    return {"head": head, "symbolic_head": branch, "refs": refs, "symbolic_refs": symbolic,
            "object_format": git(root, "rev-parse", "--show-object-format")}


def validate_git_identity(identity):
    require(isinstance(identity, dict) and set(identity) == {"head", "symbolic_head", "refs",
            "symbolic_refs", "object_format"} and identity["object_format"] in {"sha1", "sha256"} and
            isinstance(identity["refs"], dict) and isinstance(identity["symbolic_refs"], dict), "Invalid backup Git identity", 5)
    length = 40 if identity["object_format"] == "sha1" else 64

    def valid_oid(oid):
        return isinstance(oid, str) and re.fullmatch(r"[a-f0-9]{" + str(length) + "}", oid)

    def valid_ref(name):
        return (isinstance(name, str) and name.startswith("refs/") and not name.startswith("refs/replace/") and
                not any(part.startswith(".") or part.endswith(".lock") for part in name.split("/")) and
                not any(char in name for char in " ~^?[\\*:@") and ".." not in name)

    refs, symbolic = identity["refs"], identity["symbolic_refs"]
    head, branch = identity["head"], identity["symbolic_head"]
    require(valid_oid(head) and all(valid_ref(name) and valid_oid(oid) for name, oid in refs.items()) and
            (branch is None or valid_ref(branch) and refs.get(branch) == head) and
            all(isinstance(target, str) and name in refs and target in refs and target not in symbolic and refs[name] == refs[target]
                for name, target in symbolic.items()), "Unsafe or inconsistent Git reference in backup", 5)
    paths_compatible(refs)


def initialize_git(root, identity, *, bare=False):
    args = ["--bare"] if bare else []
    git(root, "-c", "init.templateDir=", "init", *args, "--object-format=" + identity["object_format"])


def install_refs(root, identity):
    refs = identity["refs"]
    if refs:
        commands = "".join(f"create {name} {oid}\n" for name, oid in sorted(refs.items()))
        git_bytes(root, "update-ref", "--stdin", data=commands.encode("utf-8"))
    for name, target in identity["symbolic_refs"].items():
        git(root, "symbolic-ref", name, target)
    if identity["symbolic_head"]:
        git(root, "symbolic-ref", "HEAD", identity["symbolic_head"])
    else:
        git(root, "update-ref", "--no-deref", "HEAD", identity["head"])
    require(git_identity(root) == identity, "Git reference reconstruction differs from the snapshot", 5)


def history_guard(root, identity):
    reachable = git_bytes(root, "--no-replace-objects", "rev-list", "--objects", "--no-object-names", "--all", "HEAD")
    kinds = git_bytes(root, "--no-replace-objects", "cat-file", "--batch-check=%(objectname) %(objecttype)", data=reachable)
    textual = [(oid, kind) for oid, kind in (row.split() for row in kinds.splitlines()) if kind in {b"commit", b"tag"}]
    if textual:
        batch = b"".join(oid + b"\n" for oid, _ in textual)
        stream = BytesIO(git_bytes(root, "--no-replace-objects", "cat-file", "--batch", data=batch))
        for oid, kind in textual:
            header = stream.readline().split()
            require(len(header) == 3 and header[:2] == [oid, kind] and header[2].isdigit(),
                    "Git returned an invalid historical object", 5)
            size = int(header[2])
            body = stream.read(size)
            require(len(body) == size and stream.read(1) == b"\n", "Incomplete historical Git object", 5)
            guard_content("Git " + kind.decode("ascii") + " " + oid.decode("ascii"), body)
        require(not stream.read(1), "Unexpected historical Git objects", 5)
    commits = git(root, "--no-replace-objects", "log", "--all", "--format=%T", "HEAD").splitlines()
    trees, inspected, direct_blobs = set(commits), set(), []
    for name, oid in identity["refs"].items():
        require(not FORBIDDEN_NAMES.search(name), "Forbidden historical Git reference: " + name, 5)
        peeled = git(root, "--no-replace-objects", "rev-parse", oid + "^{}")
        kind = git(root, "--no-replace-objects", "cat-file", "-t", peeled)
        if kind == "tree":
            trees.add(peeled)
        elif kind == "blob":
            direct_blobs.append((name, peeled))

    def guard_blob(name, oid):
        if oid not in inspected:
            guard_content(name, git_bytes(root, "--no-replace-objects", "cat-file", "blob", oid))
            inspected.add(oid)

    for tree in sorted(trees):
        for name, _, kind, oid in tree_entries(root, tree):
            require(not FORBIDDEN_NAMES.search(name),
                    "Historical custody/secret paths require a reviewed preservation or purge plan: " + name, 5)
            if kind == "blob":
                guard_blob(name, oid)
    for name, oid in direct_blobs:
        guard_blob(name, oid)


def bundle_heads(root, bundle, identity):
    advertised = dict(line.split(" ", 1)[::-1] for line in git(root, "bundle", "list-heads", str(bundle)).splitlines())
    require(advertised == {**identity["refs"], "HEAD": identity["head"]},
            "Git bundle references differ from the frozen references", 5)


def frozen_bundle(vault, identity):
    validate_git_identity(identity)
    require(git(vault.root, "rev-parse", "--is-shallow-repository") == "false",
            "Backup requires the complete Git history", 5)
    with tempfile.TemporaryDirectory(prefix="bundle-", dir=vault.state) as directory:
        frozen = Path(directory)
        initialize_git(frozen, identity, bare=True)
        atomic(frozen / "objects/info/alternates", (vault.common / "objects").as_posix().encode("utf-8") + b"\n")
        install_refs(frozen, identity)
        history_guard(frozen, identity)
        bundle = frozen / "repository.bundle"
        git(frozen, "bundle", "create", str(bundle), "--all", "HEAD")
        bundle_heads(frozen, bundle, identity)
        return bundle.read_bytes()


def open_bundle(root, path, identity):
    initialize_git(root, identity)
    bundle_heads(root, path, identity)
    git(root, "bundle", "verify", str(path))
    git(root, "bundle", "unbundle", str(path))
    install_refs(root, identity)
    require(not git(root, "fsck", "--full", "--no-reflogs", "--unreachable"),
            "Git bundle contains objects outside the frozen history", 5)
    git(root, "read-tree", identity["head"])


def historical_record(name):
    parts = name.split("/")
    if parts[0] != "historical" or len(parts) < 2:
        return None
    generation = None
    if parts[1] == "generations" and len(parts) >= 4 and identifier(parts[2]):
        generation, parts = parts[2], parts[3:]
    else:
        parts = parts[1:]
    relative = "/".join(parts)
    if relative in trials.RECEIPTS:
        return generation, relative
    if len(parts) == 1:
        filename = parts[0]
        if filename in HISTORICAL_STATE | {"materials.json"}:
            return generation, filename
        if generation is not None and filename == "binding.json":
            return generation, filename
        if generation is None and filename.endswith(".manifest.json") and identifier(filename.removesuffix(".manifest.json")):
            return None, "manifest"
    if len(parts) == 2 and parts[0] in HISTORICAL_FOLDERS and parts[1].endswith(".json"):
        stem = parts[1].removesuffix(".json")
        valid = sha256(stem) if parts[0] == "restorations" else identifier(stem)
        if valid:
            return generation, "/".join(parts)
    return None


def state_path(name):
    parts = portable_path(name).split("/")
    if len(parts) == 1:
        return name in STATE_FILES
    return (len(parts) == 2 and parts[0] in STATE_FOLDERS and parts[-1].endswith(".json") or
            name in trials.RECEIPTS or historical_record(name) is not None)


def trial_paths(control):
    for folder in trials.RECEIPT_FOLDERS:
        root = safe_path(control, folder)
        require(not root.is_junction() and (not root.exists() or root.is_dir()),
                "Unsafe trial receipt directory: " + folder, 5)
    return (name for name in trials.RECEIPTS if safe_path(control, name).exists())


def historical_paths(control, *, folders=None):
    generations = safe_path(control, "historical/generations")
    require(not generations.is_junction(), "Unsafe backup history directory", 5)
    prefixes = ["historical"]
    if generations.exists():
        require(generations.is_dir(), "Invalid backup history directory", 5)
        prefixes.extend("historical/generations/" + child.name for child in generations.iterdir() if identifier(child.name))
    selected = ("", *sorted(HISTORICAL_FOLDERS)) if folders is None else folders
    for prefix in prefixes:
        root = safe_path(control, prefix)
        require(not root.is_junction(), "Unsafe backup history directory", 5)
        if folders is None:
            yield from (f"{prefix}/{name}" for name in trial_paths(root))
        for folder in selected:
            directory = safe_path(root, folder) if folder else root
            require(not directory.is_junction(), "Unsafe backup history directory", 5)
            stem = f"{prefix}/{folder}" if folder else prefix
            for path in json_paths(directory):
                name = f"{stem}/{path.name}"
                if historical_record(name) is not None:
                    yield name


def control_records(vault):
    try:
        names = [name for name in sorted(STATE_FILES) if safe_path(vault.control, name).exists()]
        for folder in sorted(STATE_FOLDERS):
            root = safe_path(vault.control, folder)
            require(not root.is_junction(), "Unsafe controller record directory: " + folder, 5)
            names.extend(f"{folder}/{path.name}" for path in json_paths(root))
        names.extend(trial_paths(vault.control))
        names.extend(historical_paths(vault.control))
        paths_compatible(names)
        return {name: safe_path(vault.control, name, exists=True).read_bytes() for name in names}
    except OSError as exc:
        raise Blocked("Cannot freeze required backup records: " + str(exc), 5) from exc


def knowledge_name(name):
    return name in ROOT_FILES or name.startswith(KNOWLEDGE)


def canonical_tree(root, head):
    entries = list(tree_entries(root, head))
    paths_compatible(name for name, *_ in entries)
    content = {}
    for name, mode, kind, oid in entries:
        require(not reserved(name), "Git path collides with a backup record: " + name, 5)
        if not knowledge_name(name):
            continue
        require(mode in {"100644", "100755"} and kind == "blob", "Backup member is not a regular Git blob: " + name, 5)
        require(not FORBIDDEN_NAMES.search(name), "Forbidden canonical Git path: " + name, 5)
        data = git_bytes(root, "--no-replace-objects", "cat-file", "blob", oid)
        guard_content(name, data)
        content[name] = (mode, data)
    require(set(REQUIRED_REGISTRIES) <= content.keys(), "Frozen commit lacks required vault registries", 5)
    for name in REQUIRED_REGISTRIES:
        parse_jsonl(content[name][1], name)
    from .ids import registry_records

    sources = registry_records(originals.REGISTRY, parse_jsonl(content[originals.REGISTRY][1], originals.REGISTRY))
    admitted = set()
    for row in sources.values():
        name = row.get("path")
        require(originals.source_path(name) and name in content and name not in admitted and
                row.get("classification") in {"common", "personal", "sensitive"} and
                type(row.get("size")) is int and row["size"] >= 0 and sha256(row.get("sha256")),
                "Invalid frozen source manifest: " + row["id"], 5)
        originals.verify_body(row, content[name][1], revision=head)
        admitted.add(name)
    return {name: item for name, item in content.items() if not originals.source_path(name) or name in admitted}


def file_entry(kind, body, mode=None):
    entry = {"kind": kind, "sha256": digest(body), "size": len(body), "body": base64.b64encode(body).decode("ascii")}
    if mode is not None:
        entry["mode"] = mode
    return entry


def inventory(archive):
    return {name: {key: value for key, value in entry.items() if key != "body"}
            for name, entry in archive["files"].items()}


def assemble(vault, identity, records, members, bundle):
    files = {name: file_entry("knowledge", body, mode)
             for name, (mode, body) in canonical_tree(vault.root, identity["head"]).items()}
    files[BUNDLE] = file_entry("git", bundle)
    files.update({STATE + name: file_entry("recovery-history" if historical_record(name) else "operational", data)
                  for name, data in records.items() if name != "materials.json"})
    files[MATERIALS] = file_entry("custody-manifests", records.get("materials.json", b"{}"))
    files.update({f"custody/{member}.age": file_entry("conversation", data) for member, data in members.items()})
    authorities = vault.config.get(SOURCE_AUTHORITIES, [])
    require(isinstance(authorities, list) and all(isinstance(actor, str) and actor.strip() for actor in authorities),
            "Invalid source classification authorities", 5)
    return {"format": FORMAT, "source_vault": vault.identity, "git": identity, "files": files,
            SOURCE_AUTHORITIES: sorted(set(authorities)), SOURCE_BINDING: vault.binding}


def origin_path_type(location):
    return PureWindowsPath if PureWindowsPath(location["state"]).drive else PurePosixPath


def check_origin_binding(value, source_vault):
    from .binding import FORMAT as BINDING_FORMAT

    require(isinstance(value, dict) and set(value) == {"format", "vault_id", "location", "previous"} and
            value["format"] == BINDING_FORMAT and value["vault_id"] == source_vault and
            isinstance(value["previous"], list), "Invalid historical vault binding", 5)
    for location in [value["location"], *value["previous"]]:
        require(isinstance(location, dict) and set(location) == {"root", "common", "state"} and
                all(isinstance(path, str) for path in location.values()), "Invalid historical binding location", 5)
        path_type = origin_path_type(location)
        require(all(path_type(path).is_absolute() for path in location.values()), "Invalid historical binding paths", 5)


def check_entries(archive, manifest):
    fields = {"format", "source_vault", "git", "files", SOURCE_AUTHORITIES}
    require(isinstance(archive, dict) and fields <= archive.keys() <= fields | {SOURCE_BINDING} and
            archive["format"] == FORMAT and archive["source_vault"] == manifest["source_vault"] and
            isinstance(archive["files"], dict), "Unknown or mismatched portable snapshot", 5)
    if SOURCE_BINDING in archive or "origin_binding_sha256" in manifest:
        origin = archive.get(SOURCE_BINDING)
        check_origin_binding(origin, archive["source_vault"])
        require(digest(origin) == manifest.get("origin_binding_sha256"), "Origin vault binding differs from its manifest", 5)
    authorities = archive[SOURCE_AUTHORITIES]
    require(isinstance(authorities, list) and all(isinstance(actor, str) and actor.strip() for actor in authorities) and
            authorities == sorted(set(authorities)), "Invalid backed-up source classification authorities", 5)
    validate_git_identity(archive["git"])
    require(archive["git"]["head"] == manifest["commit"] and digest(archive["git"]) == manifest["git_sha256"],
            "Backup Git identity differs from its manifest", 5)
    paths_compatible(archive["files"])
    selected = {f"custody/{member}.age" for member in manifest["members"]}
    contents = {}
    for name, entry in archive["files"].items():
        require(isinstance(entry, dict) and {"size", "body", "kind", "sha256"} <= entry.keys() and
                type(entry["size"]) is int and entry["size"] >= 0 and sha256(entry["sha256"]),
                "Invalid backup inventory entry: " + name, 5)
        if name in {BUNDLE, MATERIALS}:
            expected = "git" if name == BUNDLE else "custody-manifests"
        elif name.startswith(STATE) and state_path(name.removeprefix(STATE)) and name != STATE + "materials.json":
            relative = name.removeprefix(STATE)
            expected = "recovery-history" if historical_record(relative) else "operational"
            if relative.startswith("historical/restorations/") and entry["kind"] == "operational":
                expected = "operational"
        elif name in selected:
            expected = "conversation"
        else:
            require(knowledge_name(name) and not reserved(name) and not FORBIDDEN_NAMES.search(name),
                    "Unexpected entry in backup inventory: " + name, 5)
            expected = "knowledge"
        fields = {"kind", "sha256", "size", "body"}
        if expected == "knowledge":
            fields.add("mode")
            require(entry.get("mode") in {"100644", "100755"}, "Invalid Git mode for " + name, 5)
        require(entry["kind"] == expected and set(entry) == fields, "Backup inventory type mismatch: " + name, 5)
        try:
            data = base64.b64decode(entry["body"], validate=True)
        except (TypeError, ValueError) as exc:
            raise Blocked("Invalid member encoding: " + name, 5) from exc
        require(len(data) == entry["size"] and digest(data) == entry["sha256"], "Backup member mismatch: " + name, 5)
        if expected in {"knowledge", "operational", "recovery-history", "custody-manifests"}:
            guard_content(name, data)
        contents[name] = data
    require({BUNDLE, MATERIALS, *REQUIRED_REGISTRIES, *selected} <= contents.keys() and
            digest(inventory(archive)) == manifest["inventory_sha256"], "Backup inventory differs from the signed manifest", 5)
    return contents


def records_from(contents):
    return {**{name.removeprefix(STATE): data for name, data in contents.items() if name.startswith(STATE)},
            "materials.json": contents[MATERIALS]}


def check_signatures(value, signers, backup_signers, proven):
    if isinstance(value, list):
        for item in value:
            check_signatures(item, signers, backup_signers, proven)
    elif isinstance(value, dict):
        if {"signature", "namespace", "identity"} & value.keys() == {"signature", "namespace", "identity"} or (
                "payload" in value and value.get("namespace") in HUMAN_DOMAINS | {"backup"}):
            require(set(value) == SIGNATURE_FIELDS and value["namespace"] in HUMAN_DOMAINS | {"backup"},
                    "Unknown signature envelope in snapshot", 5)
            token = digest(value)
            if token not in proven:
                verify(value, value["namespace"], backup_signers if value["namespace"] == "backup" else signers)
                proven.add(token)
        for item in value.values():
            check_signatures(item, signers, backup_signers, proven)


def portable_backup_record(record):
    return record.get("kind") == "backup" and record.get("format") == MANIFEST


def valid_origin_root(value):
    if not isinstance(value, str) or any(ord(char) < 32 for char in value):
        return False
    return any(path.is_absolute() and ".." not in path.parts for path in (PurePosixPath(value), PureWindowsPath(value)))


def check_material_copy(key, copy):
    require(isinstance(copy, dict) and valid_origin_root(copy.get("root")) and sha256(copy.get("sha256")) and
            copy.get("kind") in ("archive", "checkpoint", "ciphertext", "export", "native") and
            copy.get("status") in ("present", "planned", "deleted", "moved", "absent", "unavailable"),
            "Invalid backed-up custody copy: " + key, 5)
    portable_path(copy.get("path"), historical=True)


def project_material_copies(record):
    key = record["id"]
    portable = portable_backup_record(record)
    projected = []
    for copy in record["copies"]:
        try:
            check_material_copy(key, copy)
            if record["kind"] == "backup":
                require(copy["kind"] == "ciphertext", "Invalid backed-up replica kind: " + key, 5)
            if portable:
                require(copy["path"] == key + ".age" and copy.get("manifest") == key + ".manifest.json" and
                        copy["status"] in ("planned", "present", "deleted", "absent", "unavailable"),
                        "Invalid backed-up replica location: " + key, 5)
        except Blocked as exc:
            projected.append(unresolved_material_copy(record["kind"], copy, str(exc)))
        else:
            projected.append(copy)
    return projected


def check_materials(inventory):
    # The raw catalog is kept as evidence. Selected and recovered copies are checked before use.
    for key, record in inventory.items():
        require(isinstance(key, str) and "/" not in portable_path(key) and isinstance(record, dict) and record.get("id") == key and
                record.get("kind") in {"conversation", "export", "backup"} and isinstance(record.get("copies"), list) and
                isinstance(record.get("holds"), list) and isinstance(record.get("dependencies"), list),
                "Invalid backed-up custody record: " + key, 5)
        require(record["kind"] == "export" or identifier(key), "Invalid backup or conversation identity: " + key, 5)


def check_recovery_history(archive, contents, records, backup_signers):
    from .backups import verify_portable_manifest

    receipts = [record["payload"] for name, record in records.items()
                if name.startswith("receipts/") and record["kind"] == "backup-restored"]
    require(all(isinstance(receipt, dict) for receipt in receipts), "Invalid backup recovery receipt", 5)
    manifests = {}
    for name, value in records.items():
        entry = historical_record(name)
        if entry and entry[1] == "manifest":
            backup_id = Path(name).name.removesuffix(".manifest.json")
            manifest = verify_portable_manifest(backup_id, value, backup_signers)
            manifests[backup_id] = manifest
            expected = {"format": RESTORE_JOURNAL, "backup": backup_id, "vault": manifest["source_vault"],
                        "commit": manifest["commit"], "plain_sha256": manifest["plain_sha256"],
                        "manifest_sha256": digest(contents[STATE + name])}
            require(manifest["source_vault"] == archive["source_vault"] and
                    any(all(receipt.get(key) == value for key, value in expected.items()) for receipt in receipts),
                    "Historical backup manifest has no matching recovery receipt: " + backup_id, 5)
    for receipt in receipts:
        if receipt.get("backup_format") == MANIFEST:
            require(receipt.get("backup") in manifests, "A recovery receipt is missing its historical backup manifest", 5)
    for name, value in records.items():
        entry = historical_record(name)
        if entry and entry[0]:
            require(entry[0] in manifests, "Historical recovery record has no generation manifest: " + name, 5)
            if entry[1] == "binding.json":
                check_origin_binding(value, archive["source_vault"])
                require(digest(value) == manifests[entry[0]].get("origin_binding_sha256"),
                        "Historical binding differs from its generation manifest", 5)
        if name == "restored-from.json" or entry and entry[1] == "restored-from.json":
            if value.get("format") == RESTORE_JOURNAL:
                require(value in receipts, "Recovered vault provenance has no matching receipt", 5)
            else:
                require(value.get("format") == "healdan-restored-vault-v1" and identifier(value.get("backup")) and
                        identifier(value.get("source_vault")) and isinstance(value.get("commit"), str) and
                        re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value["commit"]),
                        "Invalid legacy recovered vault provenance", 5)


def check_historical_journal(name, value, source_vault):
    if name == "transaction.json" and value:
        from .compatibility import _journal_format

        _journal_format(value)
        for field in ("files", "before_files"):
            files = value.get(field, {})
            require(isinstance(files, dict), "Invalid historical integration entries", 5)
            paths_compatible(files)
            for path, body in files.items():
                require(knowledge_name(path) and not reserved(path) and not FORBIDDEN_NAMES.search(path),
                        "Unsafe historical integration entry: " + path, 5)
                try:
                    data = base64.b64decode(body, validate=True)
                except (ValueError, TypeError) as exc:
                    raise Blocked("Invalid historical integration entry: " + path, 5) from exc
                guard_content(path, data)
    elif name == "source-ingest.json" and value:
        require(value.get("status") in {"complete", "aborted"} and isinstance(value.get("record"), dict) and
                originals.source_path(value["record"].get("path")) and identifier(value.get("operation")),
                "Invalid historical source ingestion journal", 5)
    elif name == "zero-byte-archive.json":
        for source, move in value.items():
            require(isinstance(move, dict) and isinstance(move.get("payload"), dict), "Invalid historical archive move", 5)
            payload = move["payload"]
            require(payload.get("source") == source and portable_path(source).startswith("inbox/") and
                    portable_path(payload.get("destination")).startswith("archive/") and payload.get("sha256") == digest(b"") and
                    payload.get("size") == 0, "Invalid historical archive move", 5)
    elif name.startswith("restorations/"):
        binding = value.get("binding")
        require(value.get("format") == "healdan-restore-v1" and value.get("status") in {"preparing", "staging", "publishing", "complete"} and
                isinstance(binding, dict) and binding.get("vault") == source_vault and
                identifier(value.get("material")) and binding.get("material") == value["material"] and
                isinstance(binding.get("destination"), str), "Invalid historical conversation restoration journal", 5)


def check_trial_receipt(name, receipt, source_vault, signers, proven, expected=None):
    require(isinstance(receipt, dict) and SIGNATURE_FIELDS == receipt.keys() and receipt["namespace"] == "trial" and
            sha256(receipt["digest"]) and all(isinstance(receipt[key], str) and receipt[key] for key in ("signature", "identity")),
            "Invalid signed trial receipt: " + name, 5)
    payload = receipt["payload"]
    require(isinstance(payload, dict), "Invalid signed trial payload: " + name, 5)
    if expected is None:
        # Without a matching nominal record, only the complete measured shape identifies v2.
        versioned = payload.get("format") == trials.TRIAL_FORMAT and trials.measured_environment_shape(payload.get("environment"))
        expected = payload.get("name"), versioned
    trial, versioned = expected
    try:
        trials.check_preserved_evidence(payload, trial, source_vault, versioned=versioned)
    except (Blocked, ValueError, OverflowError) as exc:
        raise Blocked(f"Invalid historical trial receipt {name}: {exc}", 5) from exc
    token = digest(receipt)
    if token not in proven:
        verify(receipt, "trial", signers)
        proven.add(token)


def check_records(archive, contents, signers, backup_signers):
    from .ids import identity as id_identity
    from .retention import plan_digest
    from .review import csp_state_streak

    proven, records = set(), {}
    trial_versions, trial_mirrors = {}, {}
    for name, data in records_from(contents).items():
        value = decode(data)
        require(isinstance(value, list if name == "storage-policy.json" else dict),
                "Invalid controller backup record: " + name, 5)
        records[name] = value
        history = historical_record(name)
        logical_name = history[1] if history else name
        parent, _, filename = logical_name.partition("/")
        stem = filename.removesuffix(".json")
        if logical_name in trials.RECEIPTS:
            expected = trials.RECEIPTS[logical_name]
            check_trial_receipt(name, value, archive["source_vault"], signers, proven, expected)
            trial_versions[digest(value)] = expected
        elif parent == "receipts" and value.get("kind") == "trial-signature":
            trial_mirrors[name] = value.get("payload")
        else:
            check_signatures(value, signers, backup_signers, proven)
        if history:
            check_historical_journal(logical_name, value, archive["source_vault"])
        if logical_name == "materials.json":
            check_materials(value)
        if parent == "receipts":
            require(digest(value) == stem and {"kind", "at", "payload"} == value.keys() and
                    value["at"] == stamp(value["at"]), "Backup receipt identity mismatch", 5)
        if parent == "deletions":
            require(value.get("id") == stem and isinstance(value.get("entries"), list) and
                    plan_digest(value) == value.get("digest"), "Backup deletion plan identity mismatch", 5)
        if parent == "tasks":
            require(identifier(stem) and value.get("id") == stem and
                    value.get("state") in {"active", "waiting", "creating", "closed", "cancelled", "reconciliation_required"} and
                    isinstance(value.get("sessions"), list) and isinstance(value.get("processes", []), list) and
                    type(value.get("capacity_held")) is bool and isinstance(value.get("worktree"), str) and
                    value.get("created_at") == stamp(value.get("created_at")), "Invalid backed-up task record: " + stem, 5)
        if parent == "sessions":
            usage = value.get("usage")
            require(identifier(stem) and value.get("operation") == stem and identifier(value.get("uuid")) and
                    identifier(value.get("task")) and isinstance(value.get("launches"), list) and
                    isinstance(value.get("action"), str) and isinstance(value.get("state"), str) and
                    isinstance(usage, dict) and all(type(amount) is int and amount >= 0 for amount in usage.values()) and
                    id_identity(value.get("id"))[0] == "S", "Invalid backed-up session record: " + stem, 5)
    for name, receipt in trial_mirrors.items():
        check_trial_receipt(name, receipt, archive["source_vault"], signers, proven, trial_versions.get(digest(receipt)))
    csp_state_streak(records.get("csp.json", {"streak": 0}))
    for operation, reservation in records.get("reservations.json", {}).items():
        require(identifier(operation) and isinstance(reservation, dict) and isinstance(reservation.get("ids"), list) and
                all(id_identity(value)[0] == reservation.get("prefix") for value in reservation["ids"]),
                "Invalid backed-up ID reservation", 5)
    check_recovery_history(archive, contents, records, backup_signers)
    for name, entry in archive["files"].items():
        if entry["kind"] == "knowledge" and name.endswith(".jsonl"):
            rows = parse_jsonl(contents[name], name)
            if name == "control/approvals/packages.jsonl":
                require(all(SIGNATURE_FIELDS == row.keys() and row.get("namespace") == "package" for row in rows),
                        "Invalid backed-up package approval", 5)
            elif name in {"wiki/control/query-cases.jsonl", "wiki/control/aliases.jsonl"}:
                domain = "case" if name.endswith("query-cases.jsonl") else "alias"
                require(all(isinstance(row.get("approval"), dict) and row["approval"].get("namespace") == domain
                            and row["approval"].get("payload") == {key: value for key, value in row.items()
                                                                   if key not in {"history", "approval"}} for row in rows),
                        "Invalid backed-up human approval in " + name, 5)
            check_signatures(rows, signers, backup_signers, proven)
    return records


def check_members(manifest, records, contents):
    from .backups import validate_generation
    from .custody import validate_purpose

    members = records["materials.json"]
    policy = records.get("storage-policy.json", [])
    selected = [members.get(key) for key in manifest["members"]]
    require(all(record and record.get("kind") == "conversation" and record.get("decryption_verified") and
                record.get("classification") != "secret" and sha256(record.get("plain_sha256"))
                for record in selected), "Ineligible conversation material in backup", 5)
    validate_generation(manifest["generation"], selected, manifest["expires_at"] or "permanent", manifest["created_at"],
                        policy=policy[-1]["payload"] if policy else None)
    for record in selected:
        validate_purpose(record)
        for copy in record["copies"]:
            check_material_copy(record["id"], copy)
        data = contents[f"custody/{record['id']}.age"]
        require(digest(data) == record.get("cipher_sha256") and len(data) == record.get("size") and
                any(copy["kind"] == "ciphertext" and copy["sha256"] == record["cipher_sha256"] and copy["status"] == "present"
                    for copy in record["copies"]), "Conversation capture does not match its custody manifest", 5)


def check_snapshot(plain, manifest, signers, backup_signers, *, temporary_root=None):
    archive = decode(plain)
    contents = check_entries(archive, manifest)
    records = check_records(archive, contents, signers, backup_signers)
    check_members(manifest, records, contents)
    with tempfile.TemporaryDirectory(prefix="healdan-verify-bundle-", dir=temporary_root) as directory:
        scratch = Path(directory)
        path = scratch / "repository.bundle"
        atomic(path, contents[BUNDLE])
        open_bundle(scratch, path, archive["git"])
        history_guard(scratch, archive["git"])
        frozen = canonical_tree(scratch, archive["git"]["head"])
        require(frozen == {name: (entry["mode"], contents[name]) for name, entry in archive["files"].items()
                          if entry["kind"] == "knowledge"}, "Snapshot knowledge differs from the frozen commit", 5)
        check_knowledge(scratch, archive, frozen, contents, records["materials.json"], signers, backup_signers)
    return archive, contents, records


def check_knowledge(root, archive, frozen, contents, materials, signers, backup_signers):
    from . import storage_policy
    from .knowledge import Knowledge

    control = root / ".git/healdan"
    for name, (_, data) in frozen.items():
        atomic(safe_path(root, name), data)
    records = records_from(contents)
    for name in ("inbox.json", "storage-policy.json", "source-classification.json"):
        if name in records:
            atomic(safe_path(control, name), records[name])
    projected = {key: {**record, "copies": project_material_copies(record)} for key, record in materials.items()}
    atomic(safe_path(control, "materials.json"), projected)
    for name, data in records.items():
        if name.startswith("receipts/"):
            atomic(safe_path(control, name), data)
    view = SimpleNamespace(root=root, control=control, repository=SimpleNamespace(root=root),
                           identity=archive["source_vault"], head=lambda: archive["git"]["head"],
                           rows=lambda name: parse_jsonl(frozen[name][1], name),
                           config={"allowed_signers": signers, "backup_allowed_signers": backup_signers,
                                   SOURCE_AUTHORITIES: archive[SOURCE_AUTHORITIES]})
    storage_policy.history(view)
    knowledge = Knowledge(view, check_all_committed=False)
    for row, _ in knowledge.sources.values():
        current, decision = knowledge.classification.current(row["sha256"])
        require(current in {"common", "personal", "sensitive"} and (current == row["classification"] or decision),
                "Current classification does not permit source " + row["id"], 5)
        for parent in knowledge.lineage.restriction_hashes(row["id"]) - {row["sha256"]}:
            parent_class, _ = knowledge.classification.current(parent)
            require(parent_class in {"common", current}, "Source inherits a more restrictive classification: " + row["id"], 5)
