"""Read the persisted formats required before changing a vault's controller."""
from base64 import b64decode
from pathlib import Path

from .binding import Repository
from .core import TRANSACTION_V2, Blocked, digest, read_json, require, safe_path
from .lineage import package_pages, sha256
from .migration import PACKAGE_FORMATS
from .regression import CASE_REGISTRY, _compatible_case
from .review import csp_state_streak, read_csp_state

JOURNAL_FIELDS = {"package_id", "status", "base", "files", "before", "written"}
TERMINAL_FIELDS = {"commit", "completed_at"}
PUBLICATION_FIELDS = {"before_files", "publication_at", "admissions", "aborted_at", "reason", "admission_conflict"}
LEGACY_JOURNAL = "healdan-transaction-legacy-v1"


def _journal_format(journal):
    require(isinstance(journal, dict) and JOURNAL_FIELDS <= journal.keys() and isinstance(journal["status"], str),
            "Unsupported integration journal format", 5)
    fields = journal.keys() - {"format"}
    inferred = TRANSACTION_V2 if fields & PUBLICATION_FIELDS or journal["status"] == "aborted" else LEGACY_JOURNAL
    version = journal.get("format", inferred)
    if version == TRANSACTION_V2:
        require(fields <= JOURNAL_FIELDS | TERMINAL_FIELDS | PUBLICATION_FIELDS and
                journal["status"] in {"writing", "complete", "aborted"}, "Unsupported integration journal format", 5)
    else:
        require(version == LEGACY_JOURNAL and fields <= JOURNAL_FIELDS | TERMINAL_FIELDS and
                journal["status"] in {"writing", "complete"}, "Unsupported integration journal format", 5)
    return version


def _journal(vault):
    path = safe_path(vault.control, "transaction.json")
    if not path.exists():
        return None
    journal = read_json(path)
    version = _journal_format(journal)
    require(isinstance(journal["package_id"], str) and isinstance(journal["base"], str) and
            isinstance(journal["files"], dict) and isinstance(journal["before"], dict) and
            set(journal["files"]) == set(journal["before"]) and isinstance(journal["written"], list) and
            all(isinstance(name, str) and name in journal["files"] for name in journal["written"]),
            "Unsupported integration journal entries", 5)
    for name, body in journal["files"].items():
        safe_path(vault.repository.primary, name)
        _journal_bytes(body)
    if version == TRANSACTION_V2:
        before_files = journal.get("before_files", {})
        require(isinstance(before_files, dict) and before_files.keys() <= journal["files"].keys(),
                "Invalid integration journal originals", 5)
        for name, body in before_files.items():
            require(digest(_journal_bytes(body)) == journal["before"][name], "Integration journal original differs: " + name, 5)
        admissions = journal.get("admissions", [])
        require(isinstance(admissions, list) and all(isinstance(entry, dict) and isinstance(entry.get("path"), str) and
                entry.get("path") in journal["files"] and sha256(entry.get("sha256")) and
                sha256(entry.get("revision")) and isinstance(entry.get("source"), str) for entry in admissions),
                "Invalid integration journal admissions", 5)
        require(all(isinstance(journal[key], str) for key in (TERMINAL_FIELDS | PUBLICATION_FIELDS) & journal.keys()
                    if key not in {"before_files", "admissions"}), "Invalid integration journal state", 5)
        require(journal["status"] != "aborted" or {"aborted_at", "reason"} <= journal.keys(),
                "Incomplete withdrawn integration journal", 5)
    return version


def _journal_bytes(body):
    try:
        return b64decode(body, validate=True)
    except (TypeError, ValueError) as exc:
        raise Blocked("Invalid integration journal bytes", 5) from exc


def _package_format(payload):
    require(isinstance(payload, dict), "Invalid persisted approval payload", 5)
    if set(payload) == {"claim_digests"}:
        return "healdan-claim-digests-v1"
    package_pages(payload)
    return PACKAGE_FORMATS.get(frozenset(payload))


def _operating_roots(vault):
    from .tasks import all_tasks

    roots = {vault.root, vault.repository.primary}
    for task in all_tasks(vault):
        if task["state"] not in {"closed", "cancelled"} and not task.get("worktree_removed"):
            worktree = Repository.open(Path(task["worktree"]))
            require(worktree.common == vault.common and worktree.primary == vault.repository.primary,
                    "Active task worktree belongs to another Git repository", 5)
            roots.add(worktree.root)
    return sorted(roots)


def check(vault, capabilities):
    def needs(kind, value):
        require(any(type(value) is type(supported) and value == supported for supported in capabilities[kind]),
                f"Build cannot read current {kind} format: {value!r}", 5)

    needs("binding", vault.binding["format"])
    needs("policy", vault.policy["schema_version"])
    config = read_json(safe_path(vault.state, "config.json"), {})
    require(isinstance(config, dict), "Invalid external configuration", 5)
    needs("config", config.get("schema_version", 1))
    payloads = []
    for root in _operating_roots(vault):
        vault.check_registries(root=root)
        for row in vault.rows(CASE_REGISTRY, root=root):
            needs("case", row.get("format"))
            _compatible_case({key: value for key, value in row.items() if key != "approval"})
        payloads.extend(row.get("payload") for row in vault.rows("control/approvals/packages.jsonl", root=root))
    for path in sorted(safe_path(vault.control, "packages").glob("*.json")):
        package = read_json(safe_path(vault.control, "packages/" + path.name, exists=True))
        approval = package.get("approval")
        payloads.append(approval["payload"] if approval else
                        dict(package["payload"], package_id=package["id"], csp=package["csp"]))
    for payload in payloads:
        version = _package_format(payload)
        require(version is not None, "Unknown persisted approval package format", 5)
        needs("package", version)
    state = read_csp_state(vault)
    needs("csp", state.get("rule"))
    csp_state_streak(state)
    journal = _journal(vault)
    if journal is not None:
        needs("journal", journal)
    if (vault.control / "materials.json").exists() or (vault.root / "control/repository.bundle").exists():
        needs("archive", "healdan-tree-v1")
