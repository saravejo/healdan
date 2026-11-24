"""Git and operational snapshots for authenticated portable backups."""
import base64
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unicodedata
from uuid import UUID

from . import originals
from .core import (REQUIRED_REGISTRIES, Blocked, atomic, decode, digest, git, git_bytes, json_paths,
                   parse_jsonl, require, safe_path, stamp)
from .lineage import sha256
from .signing import verify

FORMAT = "healdan-backup-snapshot-v1"
MANIFEST = "healdan-backup-manifest-v1"
BUNDLE = "control/repository.bundle"
MATERIALS = "control/custody-manifests.json"
STATE = "control/backup-state/"
RESERVED = (BUNDLE, MATERIALS, "control/controller-checkpoints.json", STATE.rstrip("/"), "custody")
KNOWLEDGE = ("wiki/", "resources/sources/", "templates/", "config/", "control/approvals/")
SOURCE_AUTHORITIES = "source_classification_authorities"
ROOT_FILES = {".gitattributes", ".gitignore", "inbox/.gitkeep", "archive/.gitkeep", "projects/.gitkeep", "control/tasks/.gitkeep"}
STATE_FILES = {"csp.json", "followups.json", "inbox.json", "lint-state.json", "materials.json",
               "reservations.json", "source-classification.json", "source-ingest.json", "storage-policy.json",
               "transaction.json", "zero-byte-archive.json"}
STATE_FOLDERS = {"backup-preservation", "deletions", "lint", "packages", "receipts", "restorations",
                 "reviews", "sessions", "tasks"}
HISTORICAL_FOLDERS = {"historical/restorations"}
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


def state_path(name):
    parts = portable_path(name).split("/")
    if len(parts) == 1:
        return name in STATE_FILES
    return "/".join(parts[:-1]) in STATE_FOLDERS | HISTORICAL_FOLDERS and parts[-1].endswith(".json")


def control_records(vault):
    try:
        names = [name for name in sorted(STATE_FILES) if safe_path(vault.control, name).exists()]
        for folder in sorted(STATE_FOLDERS | HISTORICAL_FOLDERS):
            root = safe_path(vault.control, folder)
            require(not root.is_junction(), "Unsafe controller record directory: " + folder, 5)
            names.extend(f"{folder}/{path.name}" for path in json_paths(root))
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
    files.update({STATE + name: file_entry("operational", data) for name, data in records.items() if name != "materials.json"})
    files[MATERIALS] = file_entry("custody-manifests", records.get("materials.json", b"{}"))
    files.update({f"custody/{member}.age": file_entry("conversation", data) for member, data in members.items()})
    authorities = vault.config.get(SOURCE_AUTHORITIES, [])
    require(isinstance(authorities, list) and all(isinstance(actor, str) and actor.strip() for actor in authorities),
            "Invalid source classification authorities", 5)
    return {"format": FORMAT, "source_vault": vault.identity, "git": identity, "files": files,
            SOURCE_AUTHORITIES: sorted(set(authorities))}


def check_entries(archive, manifest):
    require(isinstance(archive, dict) and set(archive) == {"format", "source_vault", "git", "files", SOURCE_AUTHORITIES} and
            archive["format"] == FORMAT and archive["source_vault"] == manifest["source_vault"] and
            isinstance(archive["files"], dict), "Unknown or mismatched portable snapshot", 5)
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
        if expected in {"knowledge", "operational", "custody-manifests"}:
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


def check_records(archive, contents, signers, backup_signers):
    from .ids import identity as id_identity
    from .retention import plan_digest
    from .review import csp_state_streak

    proven, records = set(), {}
    for name, data in records_from(contents).items():
        value = decode(data)
        require(isinstance(value, list if name == "storage-policy.json" else dict),
                "Invalid controller backup record: " + name, 5)
        check_signatures(value, signers, backup_signers, proven)
        records[name] = value
        parent, _, filename = name.partition("/")
        stem = filename.removesuffix(".json")
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
    csp_state_streak(records.get("csp.json", {"streak": 0}))
    for operation, reservation in records.get("reservations.json", {}).items():
        require(identifier(operation) and isinstance(reservation, dict) and isinstance(reservation.get("ids"), list) and
                all(id_identity(value)[0] == reservation.get("prefix") for value in reservation["ids"]),
                "Invalid backed-up ID reservation", 5)
    for key, record in records["materials.json"].items():
        require(isinstance(key, str) and "/" not in portable_path(key) and isinstance(record, dict) and record.get("id") == key and
                record.get("kind") in {"conversation", "export", "backup"} and isinstance(record.get("copies"), list) and
                isinstance(record.get("holds"), list) and isinstance(record.get("dependencies"), list),
                "Invalid backed-up custody record: " + key, 5)
        require(record["kind"] == "export" or identifier(key), "Invalid backup or conversation identity: " + key, 5)
        for copy in record["copies"]:
            require(isinstance(copy, dict) and isinstance(copy.get("root"), str) and
                    sha256(copy.get("sha256")) and isinstance(copy.get("kind"), str) and
                    copy.get("status") in {"present", "planned", "deleted", "moved", "absent", "unavailable"},
                    "Invalid backed-up custody copy: " + key, 5)
            portable_path(copy.get("path"), historical=True)
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
        check_knowledge(scratch, archive, frozen, contents, signers, backup_signers)
    return archive, contents, records


def check_knowledge(root, archive, frozen, contents, signers, backup_signers):
    from . import storage_policy
    from .knowledge import Knowledge

    control = root / ".git/healdan"
    for name, (_, data) in frozen.items():
        atomic(safe_path(root, name), data)
    records = records_from(contents)
    for name in ("inbox.json", "materials.json", "storage-policy.json", "source-classification.json"):
        if name in records:
            atomic(safe_path(control, name), records[name])
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
