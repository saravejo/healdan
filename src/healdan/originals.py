"""Git storage checks for preserved source bytes."""
from pathlib import Path

from .core import Blocked, atomic, digest, git, git_bytes, parse_jsonl, require, safe_path

REGISTRY = "resources/sources/index.jsonl"
ATTRIBUTES = (b"resources/sources/** -text !eol", b"resources/sources/index.jsonl text eol=lf")
UNSET = {"unset", "unspecified"}


def protect(root):
    path = safe_path(root, ".gitattributes")
    existing = path.read_bytes() if path.exists() else b""
    if tuple(existing.splitlines()[-len(ATTRIBUTES):]) != ATTRIBUTES:
        separator = b"\n" if existing and not existing.endswith(b"\n") else b""
        atomic(path, existing + separator + b"\n".join(ATTRIBUTES) + b"\n")


def source_path(path):
    return (isinstance(path, str) and path.startswith("resources/sources/") and
            Path(path).as_posix() == path and path not in {REGISTRY, "resources/sources/.gitkeep"})


def verify_attributes(root, path):
    fields = ("text", "eol", "filter", "working-tree-encoding", "ident")
    output = git_bytes(root, "check-attr", "-z", *fields, "--", path).decode("utf-8").split("\0")
    attributes = dict(zip(output[1::3], output[2::3], strict=True))
    require(set(attributes) == set(fields), "Git did not report effective attributes for " + path, 5)
    require(attributes["text"] == "unset", f"{path}: effective Git text={attributes['text']}; expected -text", 5)
    for field in fields[1:]:
        value = attributes[field]
        require(value in UNSET, f"{path}: effective Git {field}={value} can alter original bytes", 5)


def verify_storage(root, path, body):
    require(source_path(path), "Invalid preserved source path: " + str(path), 5)
    verify_attributes(root, path)
    raw = git_bytes(root, "hash-object", "--no-filters", "--stdin", data=body)
    try:
        stored = git_bytes(root, "hash-object", "--stdin", "--path=" + path, data=body)
    except Blocked as exc:
        raise Blocked(f"{path}: Git could not convert original for storage", 5) from exc
    require(stored == raw, f"{path}: Git storage conversion changes original bytes", 5)


def verify_body(row, body, *, revision=None):
    name = f"{row['id']} ({row['path']})"
    if revision:
        name += f" at Git revision {revision}; reconciliation requires verified raw bytes"
    require(len(body) == row["size"] and digest(body) == row["sha256"], "Source hash/size mismatch: " + name)
    return body


def git_blob(root, revision, path):
    reference = f"{revision}:{path}"
    require(git(root, "cat-file", "-t", reference, check=False) == "blob",
            "Missing source blob " + reference + "; reconciliation requires verified raw bytes")
    return git_bytes(root, "cat-file", "blob", reference)


def committed_sources(root, revision):
    if not revision or not git(root, "cat-file", "-t", f"{revision}:{REGISTRY}", check=False):
        return {}
    return {row["id"]: row for row in parse_jsonl(git_blob(root, revision, REGISTRY), f"{revision}:{REGISTRY}")}


def verify_committed(root, revision, rows):
    for row in rows:
        try:
            body = git_blob(root, revision, row["path"])
        except Blocked as exc:
            raise Blocked(f"{row['id']}: {exc}") from exc
        verify_body(row, body, revision=revision)


def reconcile(vault, identifier, raw):
    with vault.locked():
        vault.no_transaction()
        rows = {row["id"]: row for row in vault.rows(REGISTRY)}
        require(identifier in rows, "Unknown source: " + identifier, 2)
        row = rows[identifier]
        require(row == committed_sources(vault.root, vault.head()).get(identifier),
                "Original reconciliation requires a committed source manifest", 5)
        body = verify_body(row, Path(raw).read_bytes())
        verify_storage(vault.root, row["path"], body)
        target = safe_path(vault.root, row["path"])
        if target.exists() and target.read_bytes() != body:
            require(target.read_bytes() == git_blob(vault.root, vault.head(), row["path"]),
                    "Working copy contains a separate edit: " + row["path"], 5)
        atomic(target, body)
        return {"id": identifier, "path": row["path"], "revision": vault.head(), "sha256": row["sha256"]}
