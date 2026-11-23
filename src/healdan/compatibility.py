"""Read the persisted formats required before changing a vault's controller."""
from base64 import b64decode

from .core import read_json, require, safe_path
from .migration import PACKAGE_FORMATS
from .regression import CASE_REGISTRY, _compatible_case
from .review import csp_state_streak, read_csp_state

JOURNAL_FIELDS = {"package_id", "status", "base", "files", "before", "written"}


def _journal(vault):
    path = safe_path(vault.control, "transaction.json")
    if not path.exists():
        return None
    journal = read_json(path)
    require(isinstance(journal, dict) and JOURNAL_FIELDS <= journal.keys() <=
            JOURNAL_FIELDS | {"commit", "completed_at"} and journal["status"] in {"writing", "complete"},
            "Unsupported integration journal format", 5)
    require(isinstance(journal["package_id"], str) and isinstance(journal["base"], str) and
            isinstance(journal["files"], dict) and isinstance(journal["before"], dict) and
            set(journal["files"]) == set(journal["before"]) and isinstance(journal["written"], list) and
            all(isinstance(name, str) and name in journal["files"] for name in journal["written"]),
            "Unsupported integration journal entries", 5)
    for name, body in journal["files"].items():
        safe_path(vault.root, name)
        b64decode(body, validate=True)
    return "healdan-transaction-legacy-v1"


def _package_format(payload):
    require(isinstance(payload, dict), "Invalid persisted approval payload", 5)
    if set(payload) == {"claim_digests"}:
        return "healdan-claim-digests-v1"
    return PACKAGE_FORMATS.get(frozenset(payload))


def check(vault, capabilities):
    def needs(kind, value):
        require(any(type(value) is type(supported) and value == supported for supported in capabilities[kind]),
                f"Build cannot read current {kind} format: {value!r}", 5)

    vault.check_registries()
    needs("binding", vault.binding["format"])
    needs("policy", vault.policy["schema_version"])
    config = read_json(safe_path(vault.state, "config.json"), {})
    require(isinstance(config, dict), "Invalid external configuration", 5)
    needs("config", config.get("schema_version", 1))
    for row in vault.rows(CASE_REGISTRY):
        needs("case", row.get("format"))
        _compatible_case({key: value for key, value in row.items() if key != "approval"})
    payloads = [row.get("payload") for row in vault.rows("control/approvals/packages.jsonl")]
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
