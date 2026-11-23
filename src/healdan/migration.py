"""Read-only migration projections, legacy inventory and purge prerequisites."""
import re

from .core import Blocked, REGISTRIES, digest, executable, git, read_json, require, run
from .ids import identity, inventory as id_inventory, registry_records
from .regression import case_projections
from .review import csp_state_bytes, csp_state_streak, csp_status, decode_csp_state
from .signing import trusted_signers, verify_origin
from .tasks import all_tasks

PACKAGE_FIELDS_V1 = frozenset({"task", "base", "fingerprint", "files", "claim_digests", "cutoff",
                               "review", "regression", "package_id", "csp"})
PACKAGE_FORMATS = {
    PACKAGE_FIELDS_V1: "healdan-approval-package-v1",
    PACKAGE_FIELDS_V1 | {"input_hashes"}: "healdan-approval-package-v2",
}
CSP_FIELDS_V1 = {"rule", "units", "units_digest", "seed", "initial_streak", "state_digest", "inspections"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _project_package(vault, approval, original):
    signed, origin = verify_origin(original, approval, "package", trusted_signers(vault))
    require(isinstance(signed, dict), "Approval package payload requires an object")
    version = PACKAGE_FORMATS.get(frozenset(signed))
    require(version is not None, "Approval package fields or format are unknown")
    content = {key: value for key, value in signed.items() if key not in {"package_id", "csp"}}
    require(digest(content) == signed["package_id"], "Signed package identity differs from its content")
    claims = signed["claim_digests"]
    require(isinstance(claims, dict) and
            all(isinstance(sha256, str) and SHA256.fullmatch(sha256) for sha256 in claims.values()),
            "Invalid signed claim digests")
    registry_records("wiki/claims.jsonl", [{"id": identifier} for identifier in claims])
    plan = signed["csp"]
    require(isinstance(plan, dict) and set(plan) == CSP_FIELDS_V1, "Inspection fields are incomplete or unknown")
    require(plan["units"] == sorted(claims, key=identity) and plan["units_digest"] == digest(claims),
            "Inspection units differ from signed claims")
    require(all(isinstance(plan[key], str) and SHA256.fullmatch(plan[key]) for key in ("seed", "state_digest")) and
            isinstance(plan["inspections"], dict), "Invalid inspection proof")
    result = csp_status(plan)
    require(result["complete"] and not result["defect"] and set(plan["inspections"]) == set(result["selected"]),
            "Signed inspection proof is incomplete or inconsistent")
    outside = [identifier for identifier in plan["units"] if identifier not in plan["inspections"]]
    scope = "no_units"
    if plan["units"]:
        scope = "sampled" if outside else "all_units"
    return {"format": "healdan-inspection-coverage-v1", "id": signed["package_id"],
            "origin": dict(origin, format=version), "plan": plan,
            "scope": scope,
            "inspected": result["selected"], "outside_sample": outside, "final_streak": result["streak"]}


def _package_projections(vault):
    for approval, original in vault.rows("control/approvals/packages.jsonl", include_bytes=True):
        try:
            projection = _project_package(vault, approval, original)
        except (Blocked, KeyError, OverflowError, TypeError, ValueError) as exc:
            yield {"row_sha256": digest(original), "status": "pending", "reason": str(exc)}
        else:
            yield {"id": projection["id"], "status": "compatible", "projection": projection}


def _sequence_preview(original):
    result = {"new_regime": {"human_decision_required": True, "new_sequence_required": True}}
    if original is None:
        return dict(result, status="not_established", state=None, sha256=None)
    result.update(state=None, sha256=digest(original))
    try:
        result["state"] = decode_csp_state(original)
        csp_state_streak(result["state"])
    except Blocked as exc:
        return dict(result, status="pending", reason=str(exc))
    return dict(result, status="preserved")


def preview(vault):
    before = vault.fingerprint()
    sequence = csp_state_bytes(vault)
    cases = list(case_projections(vault))
    packages = list(_package_projections(vault))
    reviews = {}
    for record in packages:
        if record["status"] != "compatible":
            continue
        package = record["projection"]
        approved = package["origin"]["approval"]["payload"]["claim_digests"]
        for identifier, sha256 in approved.items():
            inspection = "inspected" if identifier in package["plan"]["inspections"] else "outside_sample"
            reviews.setdefault((identifier, sha256), []).append(
                {"package_id": package["id"], "rule": package["plan"]["rule"], "inspection": inspection}
            )
    claims = []
    for row, original in vault.rows("wiki/claims.jsonl", include_bytes=True):
        modality = row.get("modality")
        pending = ["authority"]
        if not isinstance(modality, str) or not modality:
            pending.append("modality")
        claims.append({"id": row["id"], "modality": modality, "authority_status": "undetermined",
                       "pending_fields": pending, "row_sha256": digest(original),
                       "approvals": reviews.get((row["id"], digest(row)), [])})
    inspection_sequence = _sequence_preview(sequence)
    require(vault.fingerprint() == before and csp_state_bytes(vault) == sequence,
            "Inputs changed during migration preview", 5)
    return {"fingerprint": before, "cases": cases, "claims": claims, "packages": packages,
            "inspection_sequence": inspection_sequence}


def inventory(vault):
    ids = id_inventory([r for p in REGISTRIES for r in vault.rows(p)])
    files = []
    for name, sha256 in vault.inputs().items():
        files.append({"path": name, "sha256": sha256,
                      "signed_or_historical": any(part in name for part in ("approval", "decision", "lesson", "history"))})
    assumptions = []
    line_counts = {"implementation": 0, "tests": 0, "configuration": 0}
    names = run([executable("git"), "-C", vault.root, "ls-files", "-z"]).stdout.decode("utf-8").split("\0")
    for name in names:
        path = vault.root / name
        if path.suffix not in {".py", ".json", ".toml", ".yml"} or not path.is_file():
            continue
        category = "tests" if name.startswith("tests/") else "implementation" if path.suffix == ".py" else "configuration"
        line_counts[category] += len(path.read_bytes().splitlines())
        if path.suffix != ".py":
            continue
        for line, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(token in text for token in ("{4}", ":04d", "%04d")):
                assumptions.append({"path": path.relative_to(vault.root).as_posix(), "line": line})
    return {**ids, "files": files, "width_assumptions": assumptions, "physical_lines": line_counts,
            "historical_questions": {"available": 0, "expected_historical": 37, "status": "not_supplied"}}


def purge_check(vault):
    worktrees = git(vault.root, "worktree", "list", "--porcelain").split("\n\n")
    worktrees = [w for w in worktrees if w.strip()]
    blockers = []
    if len(worktrees) != 1:
        blockers.append("Additional detached, locked or residual worktree registrations exist")
    if any(t.get("capacity_held") or t.get("processes") for t in all_tasks(vault)):
        blockers.append("Task capacity, processes or reconciliation is pending")
    transaction = read_json(vault.control / "transaction.json")
    if transaction and transaction["status"] != "complete":
        blockers.append("Integration is pending")
    for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply"):
        if (vault.common / name).exists():
            blockers.append("Git operation is pending: " + name)
    for path in (vault.control / "sessions").glob("*.json"):
        if read_json(path).get("state") == "running":
            blockers.append("Session process needs reconciliation")
    if git(vault.root, "status", "--porcelain"):
        blockers.append("Working tree or index has unpublished changes")
    return {"eligible_for_review": not blockers, "blockers": blockers, "worktrees": worktrees,
            "execution": "Separate reviewed filter, signed map and copy verification required"}
