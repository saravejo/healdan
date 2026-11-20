"""Read-only legacy inventory and exceptional purge prerequisites."""
import re

from .core import REGISTRIES, digest, executable, git, read_json, require, run
from .ids import inventory as id_inventory
from .pages import validate_links
from .tasks import all_tasks


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
