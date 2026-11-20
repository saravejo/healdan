"""Validated candidate snapshots and recoverable human-approved integration."""
import base64
import copy
from pathlib import Path
import tempfile

from .core import REGISTRIES, Vault, atomic, canonical, digest, git, jsonl, read_json, require, safe_path, stamp
from .ids import aliases, identity, inventory
from .knowledge import Knowledge
from .pages import generated_pages, validate_pages
from .regression import require_suite
from .review import csp_status, freeze_csp, inspect, validate_review
from .signing import human_sign, trusted_signers, verify
from .tasks import get_task, get_session, require_active

EXACT = {"wiki/claims.jsonl", "wiki/control/topic-map.jsonl", "wiki/control/selectors.jsonl",
         "wiki/control/page-policy.json", "wiki/control/query-cases.jsonl", "wiki/control/aliases.jsonl",
         "wiki/control/decisions.jsonl", "wiki/control/lessons.jsonl", "wiki/index.md",
         "resources/sources/index.jsonl"}


def allowed(path):
    return path in EXACT or (path.startswith("wiki/topics/") and path.endswith(".md")) or (
        path.startswith("resources/sources/") and path != "resources/sources/.gitkeep")


class Candidate:
    def __init__(self, vault, files):
        self.vault = vault
        self.files = files

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="candidate-", dir=self.vault.state)
        root = Path(self.temporary.name)
        for name in self.vault.inputs():
            atomic(safe_path(root, name), safe_path(self.vault.root, name, exists=True).read_bytes())
        for name, encoded in self.files.items():
            require(allowed(name), "Unauthorized proposal path: " + name)
            atomic(safe_path(root, name), base64.b64decode(encoded, validate=True))
        self.candidate = copy.copy(self.vault)
        self.candidate.root = root
        self.candidate.head = self.vault.head
        return self.candidate

    def __exit__(self, *args):
        self.temporary.cleanup()


def proposed_digests(vault, candidate):
    old = {r["id"]: digest(r) for r in vault.rows("wiki/claims.jsonl")}
    return {r["id"]: digest(r) for r in candidate.rows("wiki/claims.jsonl") if old.get(r["id"]) != digest(r)}


def preserve_contracts(vault, candidate):
    for name in vault.inputs():
        if name.startswith("resources/sources/") and name != "resources/sources/index.jsonl":
            require(safe_path(candidate.root, name, exists=True).read_bytes() ==
                    safe_path(vault.root, name, exists=True).read_bytes(), "Preserved source was modified")
    for registry in ("resources/sources/index.jsonl", "wiki/control/decisions.jsonl", "wiki/control/lessons.jsonl"):
        current = {r["id"]: r for r in candidate.rows(registry)}
        for old in vault.rows(registry):
            require(current.get(old["id"]) == old, "Historical source/decision/lesson payload changed")
    # Old navigation anchors survive even when pages are split or renamed.
    import re
    for name in vault.inputs():
        if name.startswith("wiki/") and name.endswith(".md"):
            before = safe_path(vault.root, name).read_text(encoding="utf-8")
            after = safe_path(candidate.root, name, exists=True).read_text(encoding="utf-8")
            for anchor in re.findall(r'<a id="([^"]+)"', before):
                require(f'id="{anchor}"' in after, "Migration removed an old explicit anchor")


def validate_candidate(vault, candidate, cutoff):
    reservations = read_json(vault.control / "reservations.json", {})
    reserved = {i for r in reservations.values() for i in r["ids"]}
    for registry in REGISTRIES:
        old = {r["id"]: r for r in vault.rows(registry)}
        rows = candidate.rows(registry)
        require(not inventory(rows)["collisions"], "Numeric collision in candidate registry")
        current = {r["id"]: r for r in rows}
        require(set(old) <= set(current), "Historical records cannot be silently removed")
        for identifier in set(current) - set(old):
            require(identity(identifier, new=True)[1] > 0 and identifier in reserved,
                    "New identities must have durable controller reservations")
    aliases(candidate)
    changes = proposed_digests(vault, candidate)
    preserve_contracts(vault, candidate)
    Knowledge(candidate, proposed=changes.values())
    validate_pages(candidate, proposed=changes.values())
    factual = [c["id"] for c in candidate.rows("wiki/claims.jsonl")
               if c["id"] in changes and c["state"] == "accepted"]
    regression = require_suite(candidate, proposed=changes.values(), cutoff=cutoff, factual_ids=factual)
    return changes, regression


def package_path(vault, identifier):
    return safe_path(vault.control / "packages", identifier + ".json")


def prepare(vault, task_id, *, cutoff=None):
    with vault.locked():
        vault.no_transaction()
        task = get_task(vault, task_id)
        require_active(task)
        require(task["base"] == vault.head(), "Task base changed; reconcile before preparing", 5)
        before = vault.fingerprint()
        root = vault.state / "tasks" / task_id / "proposals/editor"
        editors = [get_session(vault, op) for op in task["sessions"] if get_session(vault, op)["role"] == "editor"]
        if editors:
            root = Path(editors[-1]["proposal"])
        files = {}
        for path in sorted(root.rglob("*")):
            if path.is_file() or path.is_symlink():
                name = path.relative_to(root).as_posix()
                require(allowed(name), "Unauthorized proposal file: " + name)
                files[name] = base64.b64encode(safe_path(root, name, exists=True).read_bytes()).decode("ascii")
        require(files, "No proposal files", 2)
        cutoff = stamp(cutoff)
        with Candidate(vault, files) as candidate:
            changes = proposed_digests(vault, candidate)
            # Controller renders before signing; handwritten substitutes cannot pass validation.
            for name, body in generated_pages(candidate, proposed=changes.values()).items():
                existing = safe_path(candidate.root, name)
                tail = b""
                if existing.exists() and b"<!-- healdan:history:start -->" in existing.read_bytes():
                    tail = b"<!-- healdan:history:start -->" + existing.read_bytes().split(
                        b"<!-- healdan:history:start -->", 1)[1]
                files[name] = base64.b64encode(body + tail).decode("ascii")
                atomic(existing, body + tail)
            if candidate.rows("wiki/control/selectors.jsonl"):
                links = [f"- [{s['title']}]({s['path'].removeprefix('wiki/')})"
                         for s in candidate.rows("wiki/control/selectors.jsonl")]
                # Keep old index content as history so existing explicit anchors survive.
                old_index = safe_path(candidate.root, "wiki/index.md").read_bytes()
                index = ("# Wiki\n\n" + "\n".join(links) + "\n").encode("utf-8")
                if b'<a id="' in old_index:
                    index += b"\n<!-- healdan:history:start -->\n" + old_index + b"\n<!-- healdan:history:end -->\n"
                files["wiki/index.md"] = base64.b64encode(index).decode("ascii")
                atomic(candidate.root / "wiki/index.md", index)
            changes, regression = validate_candidate(vault, candidate, cutoff)
        review = validate_review(vault, task_id, changes) if changes else None
        csp_state = read_json(vault.control / "csp.json", {"streak": 0})
        payload = {"task": task_id, "base": vault.head(), "fingerprint": before, "files": files,
                   "claim_digests": changes, "cutoff": cutoff, "review": review, "regression": regression}
        identifier = digest(payload)
        path = package_path(vault, identifier)
        existing = read_json(path)
        if existing:
            return existing
        require(vault.fingerprint() == before, "Inputs changed while preparing", 5)
        record = {"id": identifier, "payload": payload, "csp": freeze_csp(changes, csp_state), "approval": None}
        atomic(path, record)
        return record


def inspect_package(vault, identifier, results):
    with vault.locked():
        path = package_path(vault, identifier)
        record = read_json(path)
        require(record and not record["approval"], "Unknown or already signed package", 2)
        status = inspect(record["csp"], results)
        if status["defect"]:
            atomic(vault.control / "csp.json", {"streak": 0, "defect_package": identifier})
        atomic(path, record)
        return csp_status(record["csp"])


def approval_payload(record):
    return dict(record["payload"], package_id=record["id"], csp=record["csp"])


def approve(vault, identifier):
    with vault.locked():
        vault.no_transaction()
        record = read_json(package_path(vault, identifier))
        require(record, "Unknown package", 2)
        require_active(get_task(vault, record["payload"]["task"]))
        require(vault.fingerprint() == record["payload"]["fingerprint"], "Approval base/content is stale", 5)
        status = csp_status(record["csp"])
        require(status["complete"] and not status["defect"], "CSP inspection incomplete or defective", 5)
        require(digest(read_json(vault.control / "csp.json", {"streak": 0})) == record["csp"]["state_digest"],
                "CSP state changed; a new package is required", 5)
        with Candidate(vault, record["payload"]["files"]) as candidate:
            validate_candidate(vault, candidate, record["payload"]["cutoff"])
        record["approval"] = human_sign(vault, approval_payload(record), "package")
        atomic(package_path(vault, identifier), record)
        return record["approval"]


def apply(vault, identifier=None, *, recover=False):
    with vault.locked():
        journal_path = vault.control / "transaction.json"
        journal = read_json(journal_path)
        if recover:
            require(journal and journal["status"] != "complete", "No pending transaction", 2)
            identifier = journal["package_id"]
        else:
            vault.no_transaction()
        record = read_json(package_path(vault, identifier))
        require(record, "Unknown package", 2)
        signed = verify(record["approval"], "package", trusted_signers(vault))
        require(signed == approval_payload(record), "Package changed after approval")
        if not recover:
            require_active(get_task(vault, signed["task"]))
            require(vault.fingerprint() == signed["fingerprint"], "Approval invalidated by changed base/content", 5)
            require(not git(vault.root, "diff", "--cached", "--name-only"), "Index contains unrelated staged work", 5)
            with Candidate(vault, signed["files"]) as candidate:
                validate_candidate(vault, candidate, signed["cutoff"])
            require(digest(read_json(vault.control / "csp.json", {"streak": 0})) == record["csp"]["state_digest"],
                    "CSP state changed", 5)
            files = dict(signed["files"])
            ledger = "control/approvals/packages.jsonl"
            entries = vault.rows(ledger) + [record["approval"]]
            files[ledger] = base64.b64encode(jsonl(entries)).decode("ascii")
            journal = {"package_id": identifier, "status": "writing", "base": vault.head(), "files": files,
                       "before": {p: digest(safe_path(vault.root, p).read_bytes())
                                  if safe_path(vault.root, p).exists() else None for p in files}, "written": []}
            atomic(journal_path, journal)
        require(vault.head() == journal["base"] or
                f"Healdan-Package: {identifier}" in git(vault.root, "log", "-1", "--format=%B"),
                "Git changed during recovery", 5)
        for name, encoded in journal["files"].items():
            path = safe_path(vault.root, name)
            body = base64.b64decode(encoded, validate=True)
            actual = digest(path.read_bytes()) if path.exists() else None
            require(actual in {journal["before"][name], digest(body)}, "Concurrent edit during integration: " + name, 5)
            if actual != digest(body):
                atomic(path, body)
            if name not in journal["written"]:
                journal["written"].append(name)
                atomic(journal_path, journal)
        if vault.head() == journal["base"]:
            # All accepted claims now have their authentic package receipt in the vault.
            validate_pages(vault)
            require_suite(vault, cutoff=signed["cutoff"])
            git(vault.root, "add", "--", *journal["files"])
            git(vault.root, "-c", "commit.gpgsign=false", "commit", "-m",
                f"Apply approved knowledge package\n\nHealdan-Package: {identifier}", "--", *journal["files"])
        atomic(vault.control / "csp.json", {"streak": csp_status(record["csp"])["streak"], "package": identifier})
        journal.update(status="complete", commit=vault.head(), completed_at=stamp())
        atomic(journal_path, journal)
        vault.receipt("integration", {"package": identifier, "commit": vault.head()})
        return {"package": identifier, "commit": vault.head(), "status": "complete"}
