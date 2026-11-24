"""The public local controller interface. Complex values use JSON files."""
import argparse
from pathlib import Path
import sys

from . import __version__
from .core import Blocked, Vault, atomic, canonical, read_json, require


def parser():
    result = argparse.ArgumentParser(prog="healdan", description="Local evidence-based wiki controller")
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--vault")
    result.add_argument("--state", help="External controller state directory")
    result.add_argument("--vault-id", help="Require the selected vault identity")
    commands = result.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup")
    setup.add_argument("--interactive", action="store_true")
    state = commands.add_parser("state", help="Inspect and confirm changes to the vault binding")
    state_actions = state.add_subparsers(dest="action", required=True)
    for name, description in (("adopt", "Adopt proven legacy or restored state"),
                              ("rebind", "Check the vault and state at their new locations")):
        operation = state_actions.add_parser(name, help=description)
        operation.add_argument("--confirm", help="Confirmation digest from the preview")
    build = commands.add_parser("build", help="Prepare, identify, or select the vault's controller")
    build_actions = build.add_subparsers(dest="action", required=True)
    build_actions.add_parser("identity")
    prepare = build_actions.add_parser("prepare")
    prepare.add_argument("wheel", type=Path)
    prepare.add_argument("--store", type=Path)
    activate = build_actions.add_parser("activate")
    activate.add_argument("sha256")
    activate.add_argument("--store", type=Path)
    commands.add_parser("doctor")
    commands.add_parser("status")
    query = commands.add_parser("query")
    for field in ("entity", "property", "environment", "modality", "topic", "term", "cutoff"):
        query.add_argument("--" + field)
    query.add_argument("--max-records", type=int)
    preview = commands.add_parser("preview")
    preview.add_argument("--cutoff")
    commands.add_parser("lint")
    inbox = commands.add_parser("inbox").add_subparsers(dest="action", required=True)
    inbox.add_parser("inventory")
    decision = inbox.add_parser("decide")
    decision.add_argument("sha256")
    decision.add_argument("decision", choices=["ingest", "project", "resource", "discard", "archive", "defer"])
    for name in ("owner", "classification"):
        decision.add_argument("--" + name, required=True)
    for name in ("entered-at", "entry-origin", "defer-until", "destination"):
        decision.add_argument("--" + name)
    decision.add_argument("--purpose", type=Path)
    empty = inbox.add_parser("archive-empty")
    empty.add_argument("sha256")
    source = inbox.add_parser("ingest")
    source.add_argument("path")
    source.add_argument("--provenance", required=True)
    source.add_argument("--captured-at", required=True)
    source.add_argument("--classification", required=True, choices=["common", "personal", "sensitive"])
    source.add_argument("--purpose", type=Path)
    source.add_argument("--derived-from", type=Path)
    reconcile_original = inbox.add_parser("reconcile-original")
    reconcile_original.add_argument("id")
    reconcile_original.add_argument("raw", type=Path)
    inbox.add_parser("reconcile-sources")
    sign_classification = inbox.add_parser("sign-reclassification")
    sign_classification.add_argument("sha256")
    sign_classification.add_argument("request", type=Path)
    sign_classification.add_argument("--output", required=True, type=Path)
    reclassification = inbox.add_parser("reclassify")
    reclassification.add_argument("approval", type=Path)
    quarantine = inbox.add_parser("quarantine")
    quarantine.add_argument("path")
    quarantine.add_argument("--owner", required=True)
    task = commands.add_parser("task").add_subparsers(dest="action", required=True)
    new_task = task.add_parser("create")
    new_task.add_argument("title")
    task.add_parser("list")
    present = task.add_parser("present")
    present.add_argument("id")
    present.add_argument("--question", required=True)
    present.add_argument("--receipt", required=True)
    close = task.add_parser("close")
    close.add_argument("id")
    close.add_argument("--reason", default="completed")
    reconcile = task.add_parser("reconcile")
    reconcile.add_argument("id")
    reconcile_restored = task.add_parser("reconcile-restored", help="Close a restored task after verifying its recovered custody")
    reconcile_restored.add_argument("id")
    reconcile_restored.add_argument("--confirm", action="store_true")
    for operation in ("answer", "reopen"):
        response = task.add_parser(operation)
        response.add_argument("id")
        response.add_argument("decision", type=Path)
    reserve = task.add_parser("reserve-id")
    reserve.add_argument("prefix")
    reserve.add_argument("--count", type=int, default=1)
    reserve.add_argument("--operation", required=True)
    session = commands.add_parser("session").add_subparsers(dest="action", required=True)
    new_session = session.add_parser("create")
    new_session.add_argument("task")
    new_session.add_argument("--role", required=True, choices=["reader", "extractor", "reviewer", "editor"])
    new_session.add_argument("--action-name", required=True)
    new_session.add_argument("--context", type=Path, required=True)
    new_session.add_argument("--operation")
    session.add_parser("probe")
    profile = session.add_parser("profile")
    profile.add_argument("operation")
    launch = session.add_parser("launch")
    launch.add_argument("operation")
    launch.add_argument("--resume", action="store_true")
    launch.add_argument("--recovery-material")
    capture = session.add_parser("capture")
    capture.add_argument("operation")
    capture.add_argument("--classification", default="unknown")
    capture.add_argument("--purpose", type=Path)
    restore = session.add_parser("restore")
    restore.add_argument("material")
    restore.add_argument("destination", type=Path)
    recovery = session.add_parser("approve-recovery")
    recovery.add_argument("material")
    recovery.add_argument("evidence", type=Path)
    review = commands.add_parser("review").add_subparsers(dest="action", required=True)
    freeze = review.add_parser("freeze")
    freeze.add_argument("task")
    freeze.add_argument("--extractor", required=True)
    freeze.add_argument("--reviewer", required=True)
    package = review.add_parser("package")
    package.add_argument("task")
    package.add_argument("--cutoff")
    inspection = review.add_parser("inspect")
    inspection.add_argument("package")
    inspection.add_argument("results", type=Path)
    case = review.add_parser("sign-case")
    case.add_argument("input", type=Path)
    case.add_argument("--output", type=Path, required=True)
    review.add_parser("regression")
    approve = commands.add_parser("approve")
    approve.add_argument("package")
    apply = commands.add_parser("apply")
    apply.add_argument("package", nargs="?")
    apply.add_argument("--recover", action="store_true")
    maintenance = commands.add_parser("maintenance").add_subparsers(dest="action", required=True)
    maintenance.add_parser("daily")
    maintenance.add_parser("plan")
    execute = maintenance.add_parser("execute")
    execute.add_argument("plan")
    policy = maintenance.add_parser("policy").add_subparsers(dest="decision", required=True)
    policy.add_parser("show")
    policy_sign = policy.add_parser("sign")
    policy_sign.add_argument("input", type=Path)
    policy_sign.add_argument("--output", type=Path, required=True)
    policy.add_parser("apply").add_argument("approval", type=Path)
    preservation = maintenance.add_parser("preserve-backup").add_subparsers(dest="decision", required=True)
    preservation_sign = preservation.add_parser("sign")
    preservation_sign.add_argument("generation")
    preservation_sign.add_argument("--reason", required=True)
    preservation_sign.add_argument("--output", type=Path, required=True)
    preservation_apply = preservation.add_parser("apply")
    preservation_apply.add_argument("generation")
    preservation_apply.add_argument("approval", type=Path)
    schedule = maintenance.add_parser("schedule")
    schedule.add_argument("--activate", action="store_true")
    schedule.add_argument("--trial", action="store_true", help="Use a disposable launchd trial vault")
    trial = maintenance.add_parser("prepare-launchd-trial", help="Create a disposable launchd trial vault")
    trial.add_argument("directory", type=Path)
    scheduled = maintenance.add_parser("run-scheduled", help=argparse.SUPPRESS)
    scheduled.add_argument("job", choices=("lint", "daily"))
    scheduled.add_argument("--trial", action="store_true")
    attest = maintenance.add_parser("attest")
    attest.add_argument("trial")
    attest.add_argument("evidence", type=Path)
    environment = maintenance.add_parser("trial-environment", help="Measure the installed native trial environment")
    environment.add_argument("trial")
    environment.add_argument("--profile", type=Path)
    hold = maintenance.add_parser("hold")
    hold.add_argument("material")
    hold.add_argument("--owner", required=True)
    hold.add_argument("--reason", required=True)
    hold.add_argument("--review-at")
    release = maintenance.add_parser("release-hold")
    release.add_argument("material")
    release.add_argument("hold")
    release.add_argument("--resolved", nargs="*", default=[])
    incident = maintenance.add_parser("incident")
    incident.add_argument("material")
    incident.add_argument("step", choices=["rotation", "deletion"])
    incident.add_argument("decision", type=Path)
    backup = commands.add_parser("backup").add_subparsers(dest="action", required=True)
    create = backup.add_parser("create")
    create.add_argument("--kind", choices=["long", "short"], required=True)
    create.add_argument("--expires-at", required=True)
    create.add_argument("--members", nargs="*", default=[])
    verify = backup.add_parser("verify")
    verify.add_argument("id")
    backup.add_parser("reconcile").add_argument("id")
    restore = commands.add_parser("restore")
    restore.add_argument("backup")
    restore.add_argument("destination", type=Path)
    for portable in (verify, restore):
        portable.add_argument("--manifest", type=Path)
        portable.add_argument("--replica", type=Path)
        portable.add_argument("--age-identity", type=Path)
        portable.add_argument("--backup-allowed-signers", type=Path)
        portable.add_argument("--allowed-signers", type=Path)
        portable.add_argument("--state", dest="portable_state", type=Path)
    restore.add_argument("--recovery-state", type=Path)
    restore.add_argument("--remap", type=Path)
    migration = commands.add_parser("migration").add_subparsers(dest="action", required=True)
    migration.add_parser("inventory")
    migration.add_parser("preview")
    migration.add_parser("purge-check")
    alias = migration.add_parser("sign-alias")
    alias.add_argument("input", type=Path)
    alias.add_argument("--output", type=Path, required=True)
    return result


def dispatch(args):
    from . import admission, backups, binding, build, custody, ids, inbox, incidents, launcher, linting, maintenance, migration
    from . import originals, pages, regression, review, setup, tasks, transactions
    from .knowledge import query
    from .signing import human_sign
    if args.command == "setup":
        return setup.initialize(args.vault, args.state, interactive=args.interactive)
    if args.command == "state":
        change = binding.adopt if args.action == "adopt" else binding.rebind
        return change(args.vault, args.state, args.confirm)
    if portable_backup(args):
        trust = {"age_identity": args.age_identity, "backup_signers": args.backup_allowed_signers,
                 "allowed_signers": args.allowed_signers, "expected_vault": args.vault_id}
        if args.command == "restore":
            return backups.restore_portable(args.backup, args.destination, args.manifest, args.replica,
                                            state=args.portable_state or args.recovery_state or args.state,
                                            remap=args.remap, **trust)
        return backups.verify_portable(args.id, args.manifest, args.replica, **trust)
    if args.command == "build" and args.action == "prepare":
        from .installation import prepare
        if (Path(args.vault).resolve() / ".git").exists() or args.state is not None:
            build.validate_store(args.store if args.store is not None else build.store_path(), args.vault, args.state)
        prepared = prepare(args.wheel, args.store)
        return {"build": prepared.identity, "controller": str(prepared.entry_point)}
    external_recovery = (args.command, getattr(args, "action", None)) in {
        ("restore", None), ("backup", "verify"), ("session", "restore"), ("session", "approve-recovery")
    }
    vault = Vault(args.vault, args.state, operational=not external_recovery,
                  expected_binding=getattr(args, "vault_binding", None))
    if hasattr(args, "controller_selection"):
        vault.controller_selection = args.controller_selection
    if args.command == "build":
        if args.action == "activate":
            return build.activate(vault, args.sha256, args.store)
        return {"build": build.require_active(vault).identity, "vault_id": vault.identity}
    if args.command == "doctor":
        with vault.reading():
            result = setup.doctor(vault)
        return result, 0 if result["ready"] else 5
    if args.command == "status":
        with vault.reading():
            state = read_json(vault.control / "lint-state.json", {})
            return {"commit": vault.head(), "vault_id": vault.identity, "state": str(vault.state),
                    "lint_overdue": linting.stale(state.get("last_complete_lint_at")),
                    "last_complete_lint_at": state.get("last_complete_lint_at"),
                    "tasks": [{"id": t["id"], "state": t["state"], "worktree_age": tasks.age_status(t),
                               "capacity_held": t["capacity_held"], "reminders": t.get("reminders", []),
                               "waiting_since": t.get("presented_at"), "closure_pending": t.get("closure_pending", False)}
                              for t in tasks.all_tasks(vault)],
                    "transaction": read_json(vault.control / "transaction.json", {}).get("status"),
                    "native_trials": maintenance.trial_status(vault)}
    if args.command == "query":
        filters = {k: getattr(args, k) for k in ("entity", "property", "environment", "modality", "topic", "term") if getattr(args, k)}
        with vault.reading(stable_integration=True):
            result = query(vault, filters, args.cutoff, max_records=args.max_records)
        return result, result["code"]
    if args.command == "preview":
        with vault.reading(stable_integration=True):
            return pages.preview(vault, args.cutoff)
    if args.command == "lint":
        result = linting.lint(vault)
        return result, 5 if result["status"] != "complete" or result["findings"] else 0
    if args.command == "inbox":
        if args.action == "inventory":
            return inbox.inventory(vault)
        if args.action == "decide":
            return inbox.decide(vault, args.sha256, args.decision, purpose=read_json(args.purpose) if args.purpose else None,
                               **{k: getattr(args, k) for k in
                ("owner", "classification", "entered_at", "entry_origin", "defer_until", "destination")})
        if args.action == "archive-empty":
            return inbox.archive_empty(vault, args.sha256)
        if args.action == "reconcile-original":
            return originals.reconcile(vault, args.id, args.raw)
        if args.action == "reconcile-sources":
            result = admission.reconcile_sources(vault)
            return result, 5 if result["status"] == "pending" else 0
        if args.action == "sign-reclassification":
            signed = admission.sign_reclassification(vault, args.sha256, read_json(args.request))
            atomic(args.output, signed)
            return {"output": str(args.output), "digest": signed["digest"]}
        if args.action == "reclassify":
            return admission.reclassify(vault, read_json(args.approval))
        if args.action == "quarantine":
            return incidents.quarantine(vault, args.path, args.owner)
        if args.action == "ingest":
            derived = read_json(args.derived_from) if args.derived_from else None
            require(not args.derived_from or isinstance(derived, dict), "Derived capture requires a conversion JSON object", 2)
            return admission.ingest(vault, args.path, provenance=args.provenance, captured_at=args.captured_at,
                                    classification=args.classification, derived=derived)
    if args.command == "task":
        if args.action == "create":
            return tasks.create(vault, args.title)
        if args.action == "list":
            return tasks.all_tasks(vault)
        if args.action == "present":
            return tasks.present(vault, args.id, args.question, args.receipt)
        if args.action == "close":
            return tasks.preserve_and_close(vault, args.id, reason=args.reason)
        if args.action == "reconcile":
            return tasks.reconcile_expired(vault, args.id)
        if args.action == "reconcile-restored":
            return tasks.reconcile_restored(vault, args.id, confirmed=args.confirm)
        if args.action == "answer":
            return tasks.answer(vault, args.id, read_json(args.decision))
        if args.action == "reopen":
            return tasks.reopen(vault, args.id, read_json(args.decision))
        if args.action == "reserve-id":
            return ids.reserve(vault, args.prefix, args.count, args.operation)
    if args.command == "session":
        if args.action == "create":
            return tasks.new_session(vault, args.task, args.action_name, args.role,
                                     args.context.read_text(encoding="utf-8"), operation=args.operation)
        if args.action == "probe":
            return launcher.probe(vault)
        if args.action == "profile":
            return {"profile": str(launcher.profile(vault, args.operation)), "next": "Authenticate this profile with claude auth login"}
        if args.action == "launch":
            return launcher.launch(vault, args.operation, resume=args.resume, recovery_material=args.recovery_material)
        if args.action == "capture":
            session = tasks.get_session(vault, args.operation)
            with vault.locked():
                return {"material": custody.capture_tree(vault, Path(session.get("active_profile") or launcher.profile(vault, args.operation)), task=session["task"],
                        session=args.operation, classification=args.classification,
                        purpose=read_json(args.purpose) if args.purpose else None)}
        if args.action == "restore":
            return custody.restore_capture(vault, args.material, args.destination)
        if args.action == "approve-recovery":
            with vault.locked():
                record = custody.materials(vault)[args.material]
                record["native_recovery"] = human_sign(vault, read_json(args.evidence), "recovery")
                custody.native_guard(vault, record)
                custody.save_material(vault, record)
                return record["native_recovery"]
    if args.command == "review":
        if args.action == "freeze":
            return review.freeze_review(vault, args.task, args.extractor, args.reviewer)
        if args.action == "package":
            return transactions.prepare(vault, args.task, cutoff=args.cutoff)
        if args.action == "inspect":
            return transactions.inspect_package(vault, args.package, read_json(args.results))
        if args.action == "sign-case":
            with vault.locked():
                signed = regression.sign_case(vault, read_json(args.input))
                atomic(args.output, signed)
                return {"output": str(args.output), "digest": signed["approval"]["digest"]}
        if args.action == "regression":
            result = regression.suite(vault)
            return result, 5 if result["failed"] or result["pending"] else 0
    if args.command == "approve":
        return transactions.approve(vault, args.package)
    if args.command == "apply":
        return transactions.apply(vault, args.package, recover=args.recover)
    if args.command == "maintenance":
        if args.action == "run-scheduled":
            result = maintenance.run_scheduled(vault, args.job, args.vault_id, trial=args.trial)
            return result, 5 if result["status"] != "complete" or (args.job == "lint" and result["findings"]) else 0
        if args.action == "daily":
            result = maintenance.daily(vault)
            return result, 0 if result["status"] == "complete" else 5
        if args.action == "plan":
            from .retention import plan
            with vault.locked():
                result = plan(vault)
            return result, 5 if result.get("pending") else 0
        if args.action == "execute":
            result = maintenance.execute_plan(vault, args.plan)
            return result, 0 if result["status"] == "complete" else 5
        if args.action == "policy":
            from . import storage_policy
            if args.decision == "show":
                with vault.reading():
                    return {"policy": storage_policy.effective(vault), "history": storage_policy.history(vault)}
            if args.decision == "apply":
                return storage_policy.apply_policy(vault, read_json(args.approval))
            approval = storage_policy.policy_request(vault, read_json(args.input))
            atomic(args.output, approval)
            return {"output": str(args.output), "digest": approval["digest"]}
        if args.action == "preserve-backup":
            from . import storage_policy
            if args.decision == "apply":
                return storage_policy.apply_preservation(vault, args.generation, read_json(args.approval))
            approval = storage_policy.preservation_request(vault, args.generation, args.reason)
            atomic(args.output, approval)
            return {"output": str(args.output), "digest": approval["digest"]}
        if args.action == "schedule":
            return maintenance.schedule(vault, activate=args.activate, trial=args.trial)
        if args.action == "prepare-launchd-trial":
            return maintenance.prepare_launchd_trial(vault, args.directory)
        if args.action == "attest":
            return maintenance.attest(vault, args.trial, read_json(args.evidence))
        if args.action == "trial-environment":
            from .trials import environment
            with vault.reading():
                return environment(vault, args.trial, args.profile)
        if args.action == "hold":
            with vault.locked():
                return custody.hold(vault, args.material, args.reason, args.owner, review_at=args.review_at)
        if args.action == "release-hold":
            with vault.locked():
                return custody.release_hold(vault, args.material, args.hold, args.resolved)
        if args.action == "incident":
            return incidents.incident_decision(vault, args.material, args.step, read_json(args.decision))
    if args.command == "backup":
        if args.action == "create":
            return backups.create(vault, args.kind, args.expires_at, args.members)
        if args.action == "reconcile":
            return backups.reconcile(vault, args.id)
        return backups.verify_backup(vault, args.id)
    if args.command == "restore":
        return backups.restore(vault, args.backup, args.destination,
                               state=args.recovery_state or args.portable_state, remap=args.remap)
    if args.command == "migration":
        if args.action == "inventory":
            return migration.inventory(vault)
        if args.action == "preview":
            result = migration.preview(vault)
            pending = any(record["status"] == "pending" for record in result["cases"] + result["packages"])
            return result, 5 if pending or result["inspection_sequence"]["status"] == "pending" else 0
        if args.action == "purge-check":
            result = migration.purge_check(vault)
            return result, 0 if result["eligible_for_review"] else 5
        if args.action == "sign-alias":
            with vault.locked():
                value = read_json(args.input)
                require(ids.identity(value["alias"]) == ids.identity(value["target"]), "Alias changes identity")
                require(value.get("reason") and value.get("decided_at"), "Alias needs a human decision", 2)
                value["approval"] = human_sign(vault, value.copy(), "alias")
                atomic(args.output, value)
                return {"output": str(args.output)}
    raise Blocked("Unsupported operation", 2)


def portable_backup(args):
    return any(getattr(args, key, None) for key in ("manifest", "replica", "backup_allowed_signers", "age_identity"))


def redirect(args, argv):
    if args.command in {"setup", "state"} or portable_backup(args) or (args.command == "build" and args.action in {"prepare", "activate"}):
        return None
    from .binding import Repository, bound
    from .build import read_selection, selected_build
    from .installation import run_installed

    repository = Repository.open(args.vault)
    binding = bound(repository, args.state)
    require(args.vault_id is None or args.vault_id == binding["vault_id"], "The selected vault identity differs", 5)
    args.vault_binding = binding
    args.controller_selection = read_selection(repository.control, binding["vault_id"])
    if args.controller_selection:
        build = selected_build(repository, binding, args.controller_selection)
        if not build.running():
            return run_installed(build, argv)
    return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    commands = parser()
    args = commands.parse_args(argv)
    # The original B02 plists supplied all three selectors with the manual command spelling.
    if args.vault_id is not None and args.state is not None and args.vault is not None:
        job = (args.command,) if args.command == "lint" else (args.command, getattr(args, "action", None))
        if job in {("lint",), ("maintenance", "daily")}:
            argv = [*argv[:-len(job)], "maintenance", "run-scheduled", job[-1]]
            args = commands.parse_args(argv)
    if args.vault is None:
        args.vault = "."
    try:
        redirected = redirect(args, argv)
        if redirected is not None:
            return redirected
        result = dispatch(args)
        value, code = result if isinstance(result, tuple) else (result, 0)
    except Blocked as exc:
        value, code = {"error": str(exc), "code": exc.code}, exc.code
    except (OSError, KeyError, ValueError, TypeError) as exc:
        value, code = {"error": str(exc), "code": 1}, 1
    sys.stdout.buffer.write(canonical(value) + b"\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
