"""Persisted integration intent and offline validation."""
from base64 import b64decode, b64encode
from pathlib import PurePosixPath
import re

from .core import Blocked, atomic, decode, digest, read_json, require, safe_path
from .integration_git import oid

FORMAT = "healdan-transaction-v3"
JOURNAL = "transaction.json"
PHASES = ("intent", "prepared", "published", "indexing", "indexed", "admitted", "csp", "receipt")
FILE_STATES = {"pending", "preparing", "prepared", "displacing", "displaced", "installed"}
INTENT_FIELDS = {"format", "package_id", "base", "files", "before", "before_files", "destination",
                 "approval", "git_identity", "operation", "index_before", "worktree_modes", "legacy"}
RESULT_FIELDS = {"tree", "expected_commit", "written", "phase", "status", "checksum", "reconciliation",
                 "receipt", "admissions", "commit", "completed_at"}


def sha(value):
    return isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value)


def encode(data):
    return b64encode(data).decode("ascii")


def decode_bytes(value):
    try:
        return b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise Blocked("Invalid integration journal bytes") from exc


def name_safe(name):
    return (isinstance(name, str) and name and PurePosixPath(name).as_posix() == name and
            not PurePosixPath(name).is_absolute() and not any(
                part in {".", ".."} or part.casefold() == ".git" or any(c in part for c in ":\\") or
                any(ord(c) < 32 for c in part) for part in PurePosixPath(name).parts))


def valid_location(value):
    return (isinstance(value, dict) and value.keys() == {"root", "common", "state"} and
            all(isinstance(p, str) and p for p in value.values()))


def valid_destination(value):
    return (isinstance(value, dict) and value.keys() == {"vault", "binding", "worktree", "git_dir",
                "worktree_identity", "git_identity", "mode", "ref"} and
            all(isinstance(value[k], str) and value[k] for k in ("vault", "worktree", "git_dir", "ref")) and
            valid_location(value["binding"]) and
            all(isinstance(value[k], list) and len(value[k]) == 2 and all(type(v) is int and v >= 0 for v in value[k])
                for k in ("worktree_identity", "git_identity")) and
            (value["mode"] == "branch" and value["ref"].startswith("refs/heads/") or
             value["mode"] == "detached" and value["ref"] == "HEAD"))


def checksum(value):
    return digest({key: item for key, item in value.items() if key != "checksum"})


def validate(value):
    require(isinstance(value, dict) and value.get("format") == FORMAT and
            INTENT_FIELDS - {"legacy"} <= value.keys() <= INTENT_FIELDS | RESULT_FIELDS and
            {"phase", "status", "written", "reconciliation", "checksum"} <= value.keys(),
            "Unsupported or incomplete integration journal format", 5)
    phase = value["phase"]
    require(phase in PHASES and value["status"] in ("writing", "complete") and
            (value["status"] != "complete" or phase == "receipt" and
             value.get("commit") == value.get("expected_commit") and isinstance(value.get("completed_at"), str)),
            "Invalid integration journal phase", 5)
    require(valid_destination(value["destination"]), "Invalid integration destination proof", 5)
    require(sha(value["package_id"]) and sha(value["approval"]) and sha(value["operation"]) and oid(value["base"]),
            "Invalid integration journal package identity")
    require(value["checksum"] == checksum(value), "Integration journal integrity differs")
    files = value["files"]
    for key in ("before", "before_files", "written", "reconciliation", "index_before", "worktree_modes"):
        require(isinstance(value[key], dict), "Invalid integration journal " + key, 5)
    require(isinstance(files, dict) and files and files.keys() == value["before"].keys() ==
            value["written"].keys() == value["index_before"].keys() == value["worktree_modes"].keys() and
            value["before_files"].keys() == {name for name, checksum in value["before"].items() if checksum is not None}
            and value["reconciliation"].keys() <= files.keys(), "Invalid integration journal paths", 5)
    for name, encoded in files.items():
        require(name_safe(name), "Unsafe integration journal path", 5)
        decode_bytes(encoded)
        if name in value["before_files"]:
            require(value["before"][name] == digest(decode_bytes(value["before_files"][name])),
                    "Integration journal pre-image differs: " + name)
        require(isinstance(value["written"][name], str) and value["written"][name] in FILE_STATES and
                value["worktree_modes"][name] in (None, 0o644, 0o755) and
                (value["worktree_modes"][name] is None) == (value["before"][name] is None),
                "Invalid integration file state: " + name, 5)
        previous = value["index_before"][name]
        require(isinstance(previous, list) and len(previous) <= 1 and all(
            isinstance(row, list) and len(row) == 4 and row[0] in ("100644", "100755") and oid(row[1]) and
            type(row[2]) is int and row[2] == 0 and type(row[3]) is int and 0 <= row[3] <= 0x60008000
            for row in previous), "Invalid integration index state: " + name, 5)
    for name, evidence in value["reconciliation"].items():
        require(isinstance(evidence, dict) and {"name", "observed", "target"} <= evidence.keys() <=
                {"name", "observed", "target", "body"} and evidence["name"] == digest(name.encode("utf-8")) + ".before"
                and (evidence["target"] is None or isinstance(evidence["target"], list) and len(evidence["target"]) == 4
                     and all(type(item) is int for item in evidence["target"])),
                "Invalid integration reconciliation evidence: " + name, 5)
        observed = evidence["observed"]
        if "body" in evidence:
            require(isinstance(observed, list) and len(observed) == 2 and observed[1] in (0o644, 0o755)
                    and observed[0] == digest(decode_bytes(evidence["body"])),
                    "Integration reconciliation bytes differ: " + name)
        else:
            require(observed == ["non-regular", None], "Invalid integration reconciliation observation: " + name, 5)
    if phase == "intent":
        require(not {"tree", "expected_commit", "receipt", "admissions"} & value.keys(),
                "Unexpected integration preparation data", 5)
    else:
        require(oid(value.get("tree")) and oid(value.get("expected_commit")) and sha(value.get("receipt")) and
                isinstance(value.get("admissions"), list) and all(isinstance(entry, dict) and
                    isinstance(entry.get("path"), str) and sha(entry.get("sha256")) and sha(entry.get("revision"))
                    for entry in value["admissions"]), "Missing integration preparation data", 5)
    if PHASES.index(phase) < PHASES.index("published"):
        require(set(value["written"].values()) == {"pending"}, "Integration file progress precedes publication", 5)
    if PHASES.index(phase) >= PHASES.index("indexing"):
        require(set(value["written"].values()) == {"installed"}, "Integration index progress precedes files", 5)
    identity = value["git_identity"]
    require(isinstance(identity, dict) and identity.keys() == {"author", "committer", "at"} and
            isinstance(identity["at"], str) and all(isinstance(identity[key], list) and len(identity[key]) == 2
            and all(isinstance(item, str) for item in identity[key]) for key in ("author", "committer")),
            "Invalid integration commit identity", 5)
    if "legacy" in value:
        legacy = value["legacy"]
        require(isinstance(legacy, dict) and legacy.keys() == {"original", "proof"} and
                isinstance(legacy["proof"], dict) and legacy["proof"].get("namespace") == "integration-origin" and
                isinstance(legacy["proof"].get("payload"), dict), "Invalid legacy integration evidence", 5)
        source = decode_bytes(legacy["original"])
        source_journal = decode(source)
        require(isinstance(source_journal, dict) and source_journal.get("format") != FORMAT and
                legacy["proof"]["payload"].get("journal") == digest(source), "Legacy integration bytes differ", 5)
        from .compatibility import validate_legacy_journal
        validate_legacy_journal(source_journal)
    return FORMAT


def read(control):
    path = safe_path(control, JOURNAL)
    try:
        value = read_json(path)
    except Blocked as exc:
        raise Blocked("Unreadable integration journal: " + str(exc), 5) from exc
    if value is not None:
        if isinstance(value, dict) and value.get("format") == FORMAT:
            validate(value)
        else:
            from .compatibility import validate_legacy_journal
            validate_legacy_journal(value)
    return value


def persist(path, value):
    value["checksum"] = checksum(value)
    atomic(path, value)


def preserve_history(control, path):
    original = path.read_bytes()
    identifier = digest(original)
    historical = safe_path(control, f"integration-history/{identifier}.json")
    require(not historical.exists() or historical.read_bytes() == original,
            "Integration history bytes differ", 5)
    if not historical.exists():
        atomic(historical, original)
