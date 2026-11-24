"""Validated candidate snapshots and recoverable human-approved integration."""
import base64
import copy
from pathlib import Path
import tempfile

from .core import REGISTRIES, TRANSACTION_V2, atomic, digest, extend_jsonl, git, git_bytes, read_json, require, safe_path, stamp, utc
from . import admission, originals
from .ids import aliases, committed_registries, identity, registry_records
from .knowledge import Knowledge
from .lineage import CLAIMS, PageHistory, page_revision
from .pages import generated_pages, validate_pages
from .regression import require_suite
from .review import csp_status, freeze_csp, inspect, read_csp_state, require_csp_state, validate_review
from .signing import human_sign, trusted_signers, verify
from .tasks import get_task, get_session, require_active, validate_evidence, task_path

EXACT = {"wiki/claims.jsonl", "wiki/control/topic-map.jsonl", "wiki/control/selectors.jsonl",
         "wiki/control/page-policy.json", "wiki/control/query-cases.jsonl", "wiki/control/aliases.jsonl",
         "wiki/control/decisions.jsonl", "wiki/control/lessons.jsonl", "wiki/index.md",
         "resources/sources/index.jsonl"}
LEDGER = "control/approvals/packages.jsonl"


def allowed(path):
    return path in EXACT or (path.startswith("wiki/topics/") and path.endswith(".md")) or originals.source_path(path)


class Candidate:
    def __init__(self, vault, files):
        self.vault = vault
        self.files = files

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="candidate-", dir=self.vault.state)
        root = Path(self.temporary.name)
        try:
            for name, data in self.vault.input_files():
                atomic(safe_path(root, name), data)
            for name, encoded in self.files.items():
                require(allowed(name), "Unauthorized proposal path: " + name)
                atomic(safe_path(root, name), base64.b64decode(encoded, validate=True))
            candidate = copy.copy(self.vault)
            candidate.root = root
            candidate.head = self.vault.head
            candidate.proposed_paths = self.files.keys()
            candidate.check_registries()
            return candidate
        except BaseException:
            self.temporary.cleanup()
            raise

    def __exit__(self, *args):
        self.temporary.cleanup()


def proposed_digests(vault, candidate):
    registry = "wiki/claims.jsonl"
    old = {r["id"]: digest(r) for r in vault.rows(registry)}
    current = {k: digest(r) for k, r in registry_records(registry, candidate.rows(registry)).items()}
    return {k: value for k, value in current.items() if old.get(k) != value}


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
        current = registry_records(registry, candidate.rows(registry))
        old = {r["id"]: r for r in vault.rows(registry)}
        require(set(old) <= set(current), "Historical records cannot be silently removed")
        for identifier in set(current) - set(old):
            require(identity(identifier, new=True)[1] > 0 and identifier in reserved,
                    "New identities must have durable controller reservations")
    aliases(candidate)
    changes = proposed_digests(vault, candidate)
    preserve_contracts(vault, candidate)
    admission.plan(vault, candidate, admission.source_rows(vault), reviewed=True)
    knowledge = Knowledge(candidate, proposed=changes.values())
    for key in changes:
        claim = knowledge.claims[key]
        if claim["state"] == "accepted":
            supported, _, reasons = knowledge.support(claim, utc(cutoff))
            require(supported, "Ineligible evidence for " + key + ": " + "; ".join(reasons), 5)
    validate_pages(candidate, proposed=changes.values())
    factual = [c["id"] for c in candidate.rows("wiki/claims.jsonl")
               if c["id"] in changes and c["state"] == "accepted"]
    regression = require_suite(candidate, proposed=changes.values(), cutoff=cutoff, factual_ids=factual)
    return changes, regression


def validate_recovery_identities(vault, signed_files, commit=None):
    committed = dict(committed_registries(vault, commit)) if commit else {}
    with Candidate(vault, signed_files) as candidate:
        for registry in REGISTRIES:
            expected = registry_records(registry, candidate.rows(registry))
            if commit:
                require(registry in committed, "Committed registry is missing: " + registry)
                actual = registry_records(registry, committed[registry])
                require(actual.keys() == expected.keys(), "Committed identities differ from the signed candidate: " + registry)


def withdraw_publication(vault, journal_path, journal, failure):
    restored = {}
    for name, encoded in journal["files"].items():
        target = safe_path(vault.root, name)
        current = digest(target.read_bytes()) if target.exists() else None
        before = journal["before"][name]
        proposed = digest(base64.b64decode(encoded, validate=True))
        require(current in {before, proposed}, "Concurrent edit prevents withdrawing integration: " + name, 5)
        if current != before:
            body = None
            if before is not None:
                frozen = journal.get("before_files", {}).get(name)
                body = (base64.b64decode(frozen, validate=True) if frozen is not None else
                        originals.git_blob(vault.root, journal["base"], name))
                require(digest(body) == before, "Original bytes unavailable for withdrawal: " + name, 5)
            restored[target] = body
        stage = git(vault.root, "rev-parse", "--verify", f":{name}", check=False)
        if stage:
            staged = digest(originals.git_blob(vault.root, "", name))
            original_stage = git(vault.root, "rev-parse", "--verify", f"{journal['base']}:{name}", check=False)
            require(stage == original_stage or staged == proposed,
                    "Concurrent staged edit prevents withdrawing integration: " + name, 5)
    for target, body in restored.items():
        if body is None:
            target.unlink()
        else:
            atomic(target, body)
    git(vault.root, "--literal-pathspecs", "reset", journal["base"], "--", *journal["files"])
    at = journal.get("publication_at") or stamp()
    admission.publication(vault, journal.get("admissions", []), "withdrawn", at=at)
    journal.update(status="aborted", aborted_at=stamp(), reason=str(failure))
    atomic(journal_path, journal)
    vault.receipt("integration-withdrawn", {"package": journal["package_id"], "reason": str(failure)}, at=at)


def package_path(vault, identifier):
    return safe_path(vault.control / "packages", identifier + ".json")


def prepare(vault, task_id, *, cutoff=None):
    with vault.locked():
        vault.no_transaction()
        csp_state = read_csp_state(vault)
        task = get_task(vault, task_id)
        require_active(task)
        validate_evidence(vault, task)
        require(task["base"] == vault.head(), "Task base changed; reconcile before preparing", 5)
        require(task["base_fingerprint"] == vault.fingerprint(), "Task canonical inputs changed; prepare a fresh task", 5)
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
        revisions = []
        with Candidate(vault, files) as candidate:
            changes = proposed_digests(vault, candidate)
            require(not changes or candidate.rows("resources/sources/index.jsonl") == task["source_manifest"],
                    "Promoted claims must use the source snapshot seen by both independent sessions", 5)
            baseline = admission.source_rows(vault)
            proposed_sources = admission.source_rows(candidate)
            if proposed_sources.keys() != baseline.keys() and all(proposed_sources.get(key) == row for key, row in baseline.items()):
                additions = []
                history = PageHistory(vault)
                for key, original in proposed_sources.items():
                    if key not in baseline:
                        row = dict(original)
                        body = safe_path(candidate.root, row["path"], exists=True).read_bytes()
                        if "origin" not in row:
                            row["origin"] = history.origin(body, row["path"])
                        additions.append(row)
                manifest = admission.append_sources(vault, additions)
                files[originals.REGISTRY] = base64.b64encode(manifest).decode("ascii")
                atomic(candidate.root / originals.REGISTRY, manifest)
            # Controller renders before signing; handwritten substitutes cannot pass validation.
            for name, body in generated_pages(candidate, proposed=changes.values()).items():
                existing = safe_path(candidate.root, name)
                tail = b""
                if existing.exists() and b"<!-- healdan:history:start -->" in existing.read_bytes():
                    tail = b"<!-- healdan:history:start -->" + existing.read_bytes().split(
                        b"<!-- healdan:history:start -->", 1)[1]
                files[name] = base64.b64encode(body + tail).decode("ascii")
                atomic(existing, body + tail)
                claims = registry_records(CLAIMS, candidate.rows(CLAIMS))
                revisions.append(page_revision(name, body + tail, claims, admission.source_rows(candidate), aliases(candidate)))
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
        payload = {"task": task_id, "base": vault.head(), "fingerprint": before, "files": files,
                   "input_hashes": vault.inputs(),
                   "claim_digests": changes, "cutoff": cutoff, "review": review, "regression": regression}
        if revisions:
            payload["page_revisions"] = revisions
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
        state = read_csp_state(vault)
        plan = record["csp"]
        legacy_reset = {"streak": 0, "defect_package": identifier}
        reset = dict(legacy_reset, rule=plan["rule"])
        already_reset = state in (reset, legacy_reset)
        if already_reset:
            recorded = plan["inspections"]
            require(all(unit not in recorded or recorded[unit] == outcome for unit, outcome in results.items()),
                    "Inspection result differs from the recorded decision", 5)
            results = {unit: outcome for unit, outcome in results.items() if unit not in recorded}
        else:
            require_csp_state(plan, state)
        status = inspect(plan, results)
        if already_reset:
            require(status["defect"], "Retry the defect inspection to finish recording the reset", 5)
        elif status["defect"]:
            atomic(vault.control / "csp.json", reset)
        if results:
            atomic(path, record)
        return status


def approval_payload(record):
    return dict(record["payload"], package_id=record["id"], csp=record["csp"])


def approve(vault, identifier):
    with vault.locked():
        vault.no_transaction()
        record = read_json(package_path(vault, identifier))
        require(record, "Unknown package", 2)
        require(record["id"] == digest(record["payload"]), "Frozen package content changed")
        require_active(get_task(vault, record["payload"]["task"]))
        require(vault.fingerprint() == record["payload"]["fingerprint"], "Approval base/content is stale", 5)
        plan = record["csp"]
        require_csp_state(plan, read_csp_state(vault))
        status = csp_status(plan)
        require(status["complete"] and not status["defect"], "CSP inspection incomplete or defective", 5)
        with Candidate(vault, record["payload"]["files"]) as candidate:
            changes, _ = validate_candidate(vault, candidate, record["payload"]["cutoff"])
            require(changes == record["payload"]["claim_digests"], "Frozen claim digests changed")
        record["approval"] = human_sign(vault, approval_payload(record), "package")
        atomic(package_path(vault, identifier), record)
        task = get_task(vault, record["payload"]["task"])
        if task["state"] == "waiting":
            task.update(answered_at=stamp(), state="active", response_package=identifier)
            atomic(task_path(vault, task["id"]), task)
        return record["approval"]


def apply(vault, identifier=None, *, recover=False):
    with vault.locked():
        journal_path = vault.control / "transaction.json"
        journal = read_json(journal_path)
        if recover:
            require(journal and journal["status"] not in {"complete", "aborted"}, "No pending transaction", 2)
            identifier = journal["package_id"]
        else:
            vault.no_transaction()
        record = read_json(package_path(vault, identifier))
        require(record, "Unknown package", 2)
        require(record["id"] == digest(record["payload"]), "Frozen package content changed")
        signed = verify(record["approval"], "package", trusted_signers(vault))
        require(signed == approval_payload(record), "Package changed after approval")
        csp_state = read_csp_state(vault)
        plan = signed["csp"]
        status = csp_status(plan)
        require(status["complete"] and not status["defect"], "CSP inspection incomplete or defective", 5)
        next_csp_state = {"rule": plan["rule"], "streak": status["streak"], "package": identifier}
        if not recover:
            require_csp_state(plan, csp_state)
            require_active(get_task(vault, signed["task"]))
            require(vault.fingerprint() == signed["fingerprint"], "Approval invalidated by changed base/content", 5)
            require(not git(vault.root, "diff", "--cached", "--name-only"), "Index contains unrelated staged work", 5)
            with Candidate(vault, signed["files"]) as candidate:
                validate_candidate(vault, candidate, signed["cutoff"])
            files = dict(signed["files"])
            ledger = safe_path(vault.root, LEDGER, exists=True).read_bytes()
            files[LEDGER] = base64.b64encode(extend_jsonl(ledger, [record["approval"]])).decode("ascii")
            before_files = {name: safe_path(vault.root, name).read_bytes() for name in files
                            if safe_path(vault.root, name).exists()}
            journal = {"format": TRANSACTION_V2, "package_id": identifier, "status": "writing", "base": vault.head(), "files": files,
                       "before": {p: digest(before_files[p]) if p in before_files else None for p in files},
                       "before_files": {p: base64.b64encode(body).decode("ascii") for p, body in before_files.items()},
                       "publication_at": stamp(), "written": []}
            atomic(journal_path, journal)
        else:
            require(journal["base"] == signed["base"], "Recovery journal base differs from the signed package")
            require(LEDGER in journal["files"] and
                    {name: data for name, data in journal["files"].items() if name != LEDGER} == signed["files"],
                    "Recovery journal files differ from the signed package")
            require(journal["before"] == {name: signed["input_hashes"].get(name) for name in journal["files"]},
                    "Recovery journal originals differ from the signed base")
        head = vault.head()
        require(head == journal["base"] or
                f"Healdan-Package: {identifier}" in git(vault.root, "log", "-1", "--format=%B"),
                "Git changed during recovery", 5)
        current_inputs = vault.inputs()
        untouched = set(current_inputs) | set(signed["input_hashes"])
        for name in untouched - set(journal["files"]):
            require(current_inputs.get(name) == signed["input_hashes"].get(name),
                    "An unsigned input changed during integration: " + name, 5)
        if recover:
            committed = head if head != journal["base"] else None
            legacy_next_state = {"streak": status["streak"], "package": identifier}
            if not committed or csp_state not in (next_csp_state, legacy_next_state):
                require_csp_state(plan, csp_state)
            validate_recovery_identities(vault, signed["files"], committed)
        baseline = originals.committed_sources(vault.root, journal["base"])
        at = journal.get("publication_at") or stamp()
        try:
            with Candidate(vault, signed["files"]) as candidate:
                admissions = admission.plan(vault, candidate, baseline, reviewed=True,
                                            check_storage=head == journal["base"])
            recorded = journal.get("admissions")
            if recorded is not None and recorded != admissions:
                # Completing a publication may have recorded its first decision before the journal was finalized.
                same_sources = len(recorded) == len(admissions) and all(
                    dict(before, state=after["state"]) == after for before, after in zip(recorded, admissions))
                if head == journal["base"] or not same_sources:
                    raise admission.AdmissionBlocked("Source admission changed during integration", 5)
                admissions = recorded
        except admission.AdmissionBlocked as exc:
            if recover and head == journal["base"]:
                withdraw_publication(vault, journal_path, journal, exc)
            elif recover and head != journal["base"]:
                admission.publication(vault, journal.get("admissions", []), "committed", at=at)
                atomic(vault.control / "csp.json", next_csp_state)
                journal.update(status="complete", commit=head, completed_at=stamp(), admission_conflict=str(exc))
                atomic(journal_path, journal)
            raise
        journal.update(admissions=admissions, publication_at=at)
        atomic(journal_path, journal)
        admission.publication(vault, admissions, "planned", at=at)
        source_files = {name: base64.b64decode(encoded, validate=True)
                        for name, encoded in signed["files"].items() if originals.source_path(name)}
        for name, body in source_files.items():
            if head == journal["base"]:
                originals.verify_storage(vault.root, name, body)
            else:
                require(originals.git_blob(vault.root, head, name) == body,
                        f"{name}: Git revision {head} differs from the approved original", 5)
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
            git(vault.root, "--literal-pathspecs", "add", "--", *journal["files"])
            staged = set(git_bytes(vault.root, "diff", "--cached", "--name-only", "-z").decode("utf-8").split("\0")) - {""}
            require(staged <= set(journal["files"]), "Index contains unrelated staged work", 5)
            for name, body in source_files.items():
                require(originals.git_blob(vault.root, "", name) == body,
                        name + ": Git index differs from the approved original", 5)
            git(vault.root, "-c", "commit.gpgsign=false", "commit", "-m",
                f"Apply approved knowledge package\n\nHealdan-Package: {identifier}")
            for name, body in source_files.items():
                require(originals.git_blob(vault.root, vault.head(), name) == body,
                        name + ": Git commit differs from the approved original", 5)
        admission.publication(vault, admissions, "present", at=at)
        atomic(vault.control / "csp.json", next_csp_state)
        journal.update(status="complete", commit=vault.head(), completed_at=stamp())
        atomic(journal_path, journal)
        vault.receipt("integration", {"package": identifier, "commit": vault.head()})
        return {"package": identifier, "commit": vault.head(), "status": "complete"}
