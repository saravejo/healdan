"""Validated candidate snapshots and recoverable human-approved integration."""
import base64
import copy
import os
from pathlib import Path
from secrets import token_hex
import tempfile

from .core import Blocked, REQUIRED_REGISTRIES, REGISTRIES, atomic, decode, digest, extend_jsonl, file_digest, git, parse_jsonl, read_json, require, safe_path, stamp, utc
from . import admission, integration_git as git_tx, integration_journal as journal_store, originals
from .ids import aliases, identity, registry_records
from .integration_effects import WorktreeEffects, cleanup_completed, confirmed_index, reconcile_index, secure_target
from .integration_files import read_integration_file
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


def validate_candidate(vault, candidate, cutoff, *, check_admission=True):
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
    if check_admission:
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


def approved_package(vault, identifier, *, recover):
    require(journal_store.sha(identifier), "Invalid package identifier")
    record = read_json(package_path(vault, identifier))
    require(record, "Unknown package", 4 if recover else 2)
    require(isinstance(record, dict) and {"id", "payload", "csp", "approval"} <= record.keys() and
            isinstance(record["payload"], dict) and valid_envelope(record["approval"]) and
            record["id"] == identifier == digest(record["payload"]), "Frozen package content changed")
    signed = verify(record.get("approval"), "package", trusted_signers(vault))
    require(signed == approval_payload(record), "Package changed after approval")
    require(git_tx.oid(signed.get("base")) and isinstance(signed.get("files"), dict) and signed["files"] and
            isinstance(signed.get("input_hashes"), dict) and
            all(journal_store.name_safe(name) and allowed(name) for name in signed["files"]),
            "Invalid signed integration paths or base")
    return record["approval"], signed


def valid_envelope(value):
    return (isinstance(value, dict) and value.keys() == {"namespace", "payload", "digest", "identity", "signature"} and
            all(isinstance(value[key], str) and value[key].isascii() for key in ("signature", "digest")) and
            isinstance(value["identity"], str) and isinstance(value["payload"], dict))


def exact_files(vault, approval, signed):
    bodies = {name: journal_store.decode_bytes(encoded) for name, encoded in signed["files"].items()}
    modes = git_tx.overlay_modes(vault.root, signed["base"], [*bodies, LEDGER])
    require(modes[LEDGER], "Required approval ledger is missing from the Git base")
    ledger = git_tx.blob(vault.root, modes[LEDGER][1])
    require(not any(row == approval or row.get("payload", {}).get("package_id") == signed["package_id"]
                    for row in parse_jsonl(ledger, LEDGER)), "Package is already in the approval ledger", 5)
    bodies[LEDGER] = extend_jsonl(ledger, [approval])
    return bodies, modes


def verify_untouched_inputs(vault, signed, bodies):
    for name, expected in signed["input_hashes"].items():
        if name in bodies:
            continue
        path = safe_path(vault.root, name)
        require(path.is_file() and file_digest(path) == expected,
                "An unsigned input changed during integration: " + name, 5)


def verify_signed_originals(vault, bodies):
    for name, body in bodies.items():
        if originals.source_path(name):
            originals.verify_storage(vault.root, name, body)


def staged_before(modes):
    return {name: [[*entry, 0, 0]] if entry is not None else [] for name, entry in modes.items()}


def starting_journal(vault, signed, approval, bodies, modes):
    binding = git_tx.destination(vault)
    base = signed["base"]
    require(git_tx.ref_value(vault, binding) == base, "Approval base differs from its destination", 5)
    before, originals, worktree_modes = {}, {}, {}
    for name in bodies:
        path = secure_target(vault.root, name)
        observed, body = read_integration_file(path)
        expected = signed["input_hashes"].get(name)
        require((observed[0] if observed else None) == expected,
                "Integration pre-image changed: " + name, 5)
        before[name] = expected
        worktree_modes[name] = observed[1] if observed else None
        if observed:
            originals[name] = journal_store.encode(body)
    index_before = staged_before(modes)
    require(git_tx.index_entries(vault.root, bodies) == index_before,
            "An affected Git index entry differs from the base", 5)
    return {"format": journal_store.FORMAT, "package_id": signed["package_id"], "base": base,
            "destination": binding, "approval": digest(approval), "operation": token_hex(32),
            "git_identity": git_tx.commit_identity(vault.root), "phase": "intent", "status": "writing",
            "files": {name: journal_store.encode(body) for name, body in bodies.items()}, "before": before,
            "before_files": originals, "worktree_modes": worktree_modes, "index_before": index_before,
            "written": dict.fromkeys(bodies, "pending"), "reconciliation": {}}


def validate_intent(vault, journal, signed, approval, bodies, modes):
    git_tx.verify_destination(vault, journal["destination"])
    require(journal["base"] == signed["base"] and journal["approval"] == digest(approval),
            "Integration journal base or signed approval differs")
    require(all(journal_store.decode_bytes(value) == bodies.get(name) for name, value in journal["files"].items()) and
            bodies.keys() == journal["files"].keys(), "Integration journal blobs or derived ledger differ")
    require(journal["before"] == {name: signed["input_hashes"].get(name) for name in bodies} and
            journal["index_before"] == staged_before(modes), "Integration journal pre-images differ")
    if "legacy" in journal:
        value = journal["legacy"]
        source = journal_store.decode_bytes(value["original"])
        validate_legacy_origin(vault, source, value["proof"], signed, approval, expected=journal["destination"])


def validate_legacy_origin(vault, source, proof, signed, approval, *, expected=None):
    require(valid_envelope(proof),
            "Legacy integration has no valid contemporaneous destination evidence", 5)
    attestation = verify(proof, "integration-origin", trusted_signers(vault))
    require(isinstance(attestation, dict) and attestation.keys() == {
            "format", "journal", "destination", "package", "approval", "base", "commit"} and
            attestation["format"] == "healdan-integration-origin-v1" and attestation["journal"] == digest(source) and
            attestation["package"] == signed["package_id"] and attestation["approval"] == digest(approval) and
            attestation["base"] == signed["base"] and journal_store.valid_destination(attestation["destination"]) and
            (attestation["commit"] is None or git_tx.oid(attestation["commit"])),
            "Legacy integration origin evidence differs", 5)
    if expected is not None:
        require(attestation["destination"] == expected, "Legacy integration destination proof changed", 5)
    git_tx.verify_destination(vault, attestation["destination"])
    return attestation


def legacy_csp(commit, state, result):
    return bool(commit) and state in (result, {key: value for key, value in result.items() if key != "rule"})


def migrate_legacy(vault, path, old, signed, approval, bodies, modes, next_csp):
    source = path.read_bytes()
    require(decode(source) == old, "Legacy integration journal changed", 5)
    proof = read_json(safe_path(vault.state, "integration-origins/" + digest(source) + ".json"))
    attestation = validate_legacy_origin(vault, source, proof, signed, approval)
    base, destination = signed["base"], attestation["destination"]
    current = git_tx.ref_value(vault, destination)
    require(current == (attestation["commit"] or base), "Legacy integration ref differs from origin evidence", 5)
    before = {name: signed["input_hashes"].get(name) for name in bodies}
    require(old["base"] == base and old["before"] == before and old["files"] ==
            {name: journal_store.encode(body) for name, body in bodies.items()},
            "Legacy integration files, pre-images or ledger differ")
    originals, worktree_modes = {}, {}
    for name, body_hash in before.items():
        if body_hash is None:
            worktree_modes[name] = None
            continue
        mode = 0o755 if os.name != "nt" and modes[name] and modes[name][0] == "100755" else 0o644
        frozen = old.get("before_files", {}).get(name)
        if frozen is None:
            require(modes[name], "Legacy integration lacks pre-image proof: " + name, 5)
            body = git_tx.blob(vault.root, modes[name][1])
            if digest(body) != body_hash:
                # V1 signed the original worktree bytes, which may differ from a normalized Git blob.
                observed, body = read_integration_file(secure_target(vault.root, name))
                require(observed is not None and observed[0] == body_hash,
                        "Legacy integration pre-image bytes differ: " + name)
                mode = observed[1]
            frozen = journal_store.encode(body)
        require(digest(journal_store.decode_bytes(frozen)) == body_hash,
                "Legacy integration pre-image bytes differ: " + name)
        originals[name] = frozen
        worktree_modes[name] = mode
    csp = read_csp_state(vault)
    if not legacy_csp(attestation["commit"], csp, next_csp):
        require_csp_state(signed["csp"], csp)
    identity = git_tx.commit_identity(vault.root)
    if old.get("publication_at"):
        identity["at"] = stamp(old["publication_at"])
    result = {"format": journal_store.FORMAT, "package_id": signed["package_id"], "base": base,
              "destination": destination, "approval": digest(approval), "operation": token_hex(32),
              "git_identity": identity, "phase": "intent", "status": "writing", "files": old["files"],
              "before": before, "before_files": originals, "worktree_modes": worktree_modes,
              "index_before": staged_before(modes), "written": dict.fromkeys(bodies, "pending"),
              "reconciliation": {}, "legacy": {"original": journal_store.encode(source), "proof": proof}}
    tree, overlay = git_tx.prepare_tree(vault, base, modes, bodies)
    expected = attestation["commit"] or git_tx.make_commit(vault.root, base, tree, signed["package_id"], identity)
    git_tx.verify_commit(vault.root, expected, base, tree, overlay, bodies)
    admissions = isolated_validation(vault, result, tree, signed)
    if old.get("admissions") is not None:
        result.update(admissions=old["admissions"], phase="indexed" if attestation["commit"] else "prepared")
        check_admission(vault, result, admissions)
        admissions = old["admissions"]
    result.update(phase="published" if attestation["commit"] else "prepared", tree=tree,
                  expected_commit=expected, receipt=digest(integration_receipt(result, expected)), admissions=admissions)
    WorktreeEffects(vault, path, result, bodies, overlay).verify()
    journal_store.persist(path, result)
    return result


def isolated_validation(vault, journal, tree, signed):
    base = journal["base"]
    with tempfile.TemporaryDirectory(prefix="integration-validation-", dir=vault.state) as directory:
        prior, result = copy.copy(vault), copy.copy(vault)
        prior.root = Path(directory) / "base"
        result.root = Path(directory) / "result"
        prior.head = result.head = lambda: base
        result.proposed_paths = signed["files"].keys()
        git_tx.materialize_inputs(vault.root, base, prior.root)
        git_tx.materialize_inputs(vault.root, tree, result.root)
        prior.check_registries()
        result.check_registries()
        changes, _ = validate_candidate(prior, result, signed["cutoff"], check_admission=False)
        require(changes == signed["claim_digests"], "Signed claim digests differ from the Git candidate")
        validate_pages(result)
        require_suite(result, cutoff=signed["cutoff"])
        return admission.plan(vault, result, admission.source_rows(prior), reviewed=True)


def integration_receipt(journal, commit):
    return {"kind": "integration", "at": journal["git_identity"]["at"],
            "payload": {"package": journal["package_id"], "commit": commit}}


def record_receipt(vault, journal, commit):
    receipt = integration_receipt(journal, commit)
    identifier = journal["receipt"]
    path = safe_path(vault.control, f"receipts/{identifier}.json")
    previous = read_json(path)
    require(previous in (None, receipt), "Integration receipt bytes differ")
    if previous is None:
        require(vault.receipt(receipt["kind"], receipt["payload"], at=receipt["at"]) == identifier,
                "Integration receipt identity differs")
    require(read_json(path) == receipt, "Integration receipt was not persisted", 5)


def check_admission(vault, journal, current):
    before = journal["admissions"]
    if before == current:
        return
    # A retry may see the initial B03 decision written by this admission.
    if journal["phase"] in ("indexed", "admitted", "csp", "receipt") and len(before) == len(current):
        for recorded, observed in zip(before, current):
            if recorded == observed:
                continue
            at = journal["git_identity"]["at"]
            receipt = digest({"kind": "source-admission", "at": at, "payload": recorded})
            item = read_json(vault.control / "inbox.json", {}).get(recorded["sha256"], {})
            if (recorded["state"] != "initial" or dict(recorded, state="confirmed") != observed or
                    item.get("decision_receipt") != receipt or
                    admission.receipt(vault, receipt, "source-admission") != recorded):
                break
        else:
            return
    raise admission.AdmissionBlocked("Source admission changed during integration", 5)


def apply(vault, identifier=None, *, recover=False):
    with vault.locked():
        path = safe_path(vault.control, journal_store.JOURNAL)
        journal = None
        if recover:
            journal = journal_store.read(vault.control)
            clear_completed_effects(vault, journal)
            require(journal and journal["status"] not in ("complete", "aborted"), "No pending transaction", 2)
            identifier = journal["package_id"]
            if journal.get("format") == journal_store.FORMAT:
                git_tx.verify_destination(vault, journal["destination"])
        else:
            terminal = vault.no_transaction()
            clear_completed_effects(vault, terminal)
        approval, signed = approved_package(vault, identifier, recover=recover)
        if not recover:
            require(vault.head() == signed["base"], "Approval invalidated by changed Git base", 5)
        elif journal.get("format") == journal_store.FORMAT:
            require(journal["base"] == signed["base"] and journal["approval"] == digest(approval),
                    "Integration journal base or signed approval differs")
        bodies, modes = exact_files(vault, approval, signed)
        plan = signed["csp"]
        result = csp_status(plan)
        require(result["complete"] and not result["defect"], "CSP inspection incomplete or defective", 5)
        next_csp = {"rule": plan["rule"], "streak": result["streak"], "package": identifier}
        if not recover:
            require_csp_state(plan, read_csp_state(vault))
            require_active(get_task(vault, signed["task"]))
            require(vault.fingerprint() == signed["fingerprint"], "Approval invalidated by changed base/content", 5)
            require(not git(vault.root, "diff", "--cached", "--name-only"), "Index contains unrelated staged work", 5)
            with Candidate(vault, signed["files"]) as candidate:
                validate_candidate(vault, candidate, signed["cutoff"])
            verify_signed_originals(vault, bodies)
            journal = starting_journal(vault, signed, approval, bodies, modes)
            if terminal is not None:
                journal_store.preserve_history(vault.control, path)
            journal_store.persist(path, journal)
        elif journal.get("format") != journal_store.FORMAT:
            journal = migrate_legacy(vault, path, journal, signed, approval, bodies, modes, next_csp)
        validate_intent(vault, journal, signed, approval, bodies, modes)
        return continue_apply(vault, path, journal, signed, next_csp, bodies, modes)


def clear_completed_effects(vault, journal):
    if not journal or journal.get("format") != journal_store.FORMAT or journal["status"] != "complete":
        return
    try:
        git_tx.verify_destination(vault, journal["destination"], verify_head=False)
        cleanup_completed(vault, journal)
    except (Blocked, OSError):
        # Terminal evidence remains available if scratch cannot be verified or removed.
        pass


def continue_apply(vault, path, journal, signed, next_csp, bodies, modes):
    binding, base = journal["destination"], journal["base"]
    current = git_tx.ref_value(vault, binding)
    phase = journal["phase"]
    previous = journal.get("expected_commit")
    eligible = {previous}
    if phase in ("intent", "prepared"):
        eligible.add(base)
    require(current in eligible, "Integration destination ref differs from its recorded publication", 5)
    for registry in REQUIRED_REGISTRIES:
        if registry not in bodies:
            rows = vault.rows(registry)
            if registry in REGISTRIES:
                registry_records(registry, rows)
    if current == base:
        verify_untouched_inputs(vault, signed, bodies)
    csp = read_csp_state(vault)
    legacy_commit = (journal.get("legacy") or {}).get("proof", {}).get("payload", {}).get("commit")
    if phase in ("csp", "receipt"):
        require(csp == next_csp, "Integration CSP result changed", 5)
    elif not legacy_csp(legacy_commit, csp, next_csp) and (phase != "admitted" or csp != next_csp):
        require_csp_state(signed["csp"], csp)
    tree, overlay = git_tx.prepare_tree(vault, base, modes, bodies)
    expected = legacy_commit or git_tx.make_commit(vault.root, base, tree, journal["package_id"], journal["git_identity"])
    git_tx.verify_commit(vault.root, expected, base, tree, overlay, bodies)
    admissions = isolated_validation(vault, journal, tree, signed)
    receipt_id = digest(integration_receipt(journal, expected))
    if phase == "intent":
        journal.update(phase="prepared", tree=tree, expected_commit=expected,
                       receipt=receipt_id, admissions=admissions)
        journal_store.persist(path, journal)
    else:
        require(journal["tree"] == tree and previous == expected and journal["receipt"] == receipt_id,
                "Integration journal prepared objects or receipt differ")
        check_admission(vault, journal, admissions)
    effects = WorktreeEffects(vault, path, journal, bodies, overlay)
    effects.verify()
    if current == base:
        require(not git_tx.was_published(vault.root, binding["ref"], journal["operation"], expected),
                "Integration ref returned to the base after publication", 5)
        require_csp_state(signed["csp"], read_csp_state(vault))
        verify_signed_originals(vault, bodies)
        verify_untouched_inputs(vault, signed, bodies)
        git_tx.publish(vault, binding, base, expected, journal["operation"])
    def verify_ref():
        require(git_tx.ref_value(vault, binding) == expected, "Integration published ref changed", 5)

    verify_ref()
    if journal["phase"] == "prepared":
        journal["phase"] = "published"
        journal_store.persist(path, journal)
    for name in bodies:
        verify_ref()
        effects.reconcile(name)
    if journal["phase"] == "published":
        journal["phase"] = "indexing"
        journal_store.persist(path, journal)
    if journal["phase"] == "indexing":
        reconcile_index(vault, effects.index_directory, journal["index_before"], overlay, verify_ref=verify_ref)
        journal["phase"] = "indexed"
        journal_store.persist(path, journal)
    with confirmed_index(vault, effects.index_directory, overlay):
        finish_apply(vault, path, journal, signed, legacy_commit, next_csp, effects, verify_ref)
    clear_completed_effects(vault, journal)
    return {"package": journal["package_id"], "commit": expected, "status": "complete"}


def finish_apply(vault, path, journal, signed, legacy_commit, next_csp, effects, verify_ref):
    expected, base, tree = journal["expected_commit"], journal["base"], journal["tree"]
    effects.verify()
    verify_ref()
    git_tx.verify_commit(vault.root, expected, base, tree, effects.overlay, effects.bodies)
    if journal["phase"] == "indexed":
        check_admission(vault, journal, isolated_validation(vault, journal, tree, signed))
        admission.publication(vault, journal["admissions"], "present", at=journal["git_identity"]["at"],
                              exact_location=True)
        journal["phase"] = "admitted"
        journal_store.persist(path, journal)
    admission.verify_integration_publication(vault, journal["admissions"], journal["git_identity"]["at"])
    if journal["phase"] == "admitted":
        verify_ref()
        current_csp = read_csp_state(vault)
        if current_csp != next_csp:
            if not legacy_csp(legacy_commit, current_csp, next_csp):
                require_csp_state(signed["csp"], current_csp)
            atomic(vault.control / "csp.json", next_csp)
        journal["phase"] = "csp"
        journal_store.persist(path, journal)
    require(read_csp_state(vault) == next_csp, "Integration CSP result changed", 5)
    verify_ref()
    record_receipt(vault, journal, expected)
    if journal["phase"] != "receipt":
        journal["phase"] = "receipt"
        journal_store.persist(path, journal)
    verify_ref()
    effects.verify()
    journal.update(status="complete", commit=expected, completed_at=stamp())
    journal_store.persist(path, journal)
