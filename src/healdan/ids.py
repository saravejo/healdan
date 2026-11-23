"""One identity grammar and durable common-Git reservations."""
import re
from uuid import UUID

from .core import REGISTRIES, atomic, git, git_bytes, parse_jsonl, read_json, require
from .signing import trusted_signers, verify

PREFIXES = "FCDLQMS"
NEW = re.compile(r"([FCDLQMS])-(?:[0-9]{4}|[1-9][0-9]{4,})\Z", re.ASCII)
TEXT = re.compile(r"\b[FCDLQMS]-(?:[0-9]{4}|[1-9][0-9]{4,})(?![0-9])", re.ASCII)
LEGACY = re.compile(r"([FCDLQMS])-([0-9]+)\Z", re.ASCII)


def identity(value, *, new=False):
    require(isinstance(value, str), "ID must be a string", 2)
    require((NEW if new else LEGACY).fullmatch(value), "Invalid ID: " + value, 2)
    return value[0], int(value[2:])


def format_id(prefix, number):
    require(prefix in PREFIXES and type(number) is int and number >= 0, "Invalid ID parts", 2)
    return f"{prefix}-{number:04d}"


def inventory(rows):
    seen, results, collisions = {}, [], []
    for row in rows:
        spelling = row["id"]
        key = identity(spelling)
        if key in seen:
            collisions.append([seen[key], spelling])
        seen[key] = spelling
        results.append({"original": spelling, "canonical": format_id(*key),
                        "identity": list(key), "legacy": NEW.fullmatch(spelling) is None})
    return {"ids": results, "collisions": collisions}


def published(vault):
    rows = [row for name in REGISTRIES for row in vault.rows(name)]
    current = inventory(rows)
    historic = {row["id"] for row in rows}
    commits = git(vault.root, "log", "--all", "--full-history", "--format=%H", "--", *REGISTRIES).splitlines()
    for commit in commits:
        tree = git_bytes(vault.root, "ls-tree", "-z", "--full-tree", commit, "--", *REGISTRIES)
        for entry in tree.split(b"\0")[:-1]:
            info, name = entry.split(b"\t", 1)
            mode, kind, oid = info.split()
            path = f"{commit}:{name.decode('utf-8')}"
            require(kind == b"blob" and mode in {b"100644", b"100755"},
                    "Historical registry is not a regular file: " + path)
            content = git_bytes(vault.root, "cat-file", "blob", oid.decode("ascii"))
            historic.update(row["id"] for row in parse_jsonl(content, path))
    spellings = {}
    approved_aliases = aliases(vault)
    for value in sorted(historic):
        key = identity(value)
        if key in spellings and spellings[key] != value:
            other = spellings[key]
            if approved_aliases.get(value) != other and approved_aliases.get(other) != value:
                current["collisions"].append([other, value])
        spellings[key] = value
    return current, historic


def reserve(vault, prefix, count, operation, *, locked=False):
    require(prefix in PREFIXES and len(prefix) == 1 and type(count) is int and count > 0,
            "Invalid reservation", 2)
    require(str(UUID(operation)) == operation, "Operation must be a canonical UUID", 2)
    if not locked:
        with vault.locked():
            return reserve(vault, prefix, count, operation, locked=True)
    vault.no_transaction()
    path = vault.control / "reservations.json"
    journal = read_json(path, {})
    if operation in journal:
        old = journal[operation]
        require(old["prefix"] == prefix and len(old["ids"]) == count,
                "Operation UUID reused with different arguments")
        return old["ids"]
    current, historic = published(vault)
    require(not any(identity(a)[0] == prefix for a, _ in current["collisions"]),
            "Ambiguous legacy ID collision blocks this prefix")
    used = set(historic)
    for record in journal.values():
        used.update(record["ids"])
    highest = max((identity(item)[1] for item in used if identity(item)[0] == prefix), default=0)
    values = [format_id(prefix, n) for n in range(highest + 1, highest + count + 1)]
    journal[operation] = {"prefix": prefix, "ids": values}
    atomic(path, journal)
    return values


def aliases(vault):
    result = {}
    for entry in vault.rows("wiki/control/aliases.jsonl"):
        payload = verify(entry["approval"], "alias", trusted_signers(vault))
        require(payload == {k: v for k, v in entry.items() if k != "approval"}, "Alias payload mismatch")
        require(payload.get("reason") and payload.get("decided_at"), "Alias requires a human decision")
        require(identity(entry["alias"]) == identity(entry["target"]), "Alias changes identity")
        require(entry["alias"] not in result, "Duplicate alias")
        result[entry["alias"]] = entry["target"]
    return result
