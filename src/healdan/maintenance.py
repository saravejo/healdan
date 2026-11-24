"""Daily retention-before-backup orchestration, signed trials and launchd."""
from datetime import timedelta
import os
from pathlib import Path
import platform
import plistlib
from tempfile import mkdtemp

from .build import active
from .core import Blocked, Vault, atomic, executable, read_json, require, run, safe_path, utc
from .launchd import JOBS, gui_domain, job_label
from .trials import TRIALS, attest, status as trial_status

TRIAL_MARKER = "launchd-trial.json"


def daily(vault, now=None):
    from . import retention
    from .tasks import all_tasks, get_task, reconcile_clock, reconcile_expired, preserve_and_close

    now = utc(now)
    notices, pending, results = [], [], []
    legacy_backup_error = {}

    def execute_plan(identifier):
        try:
            return retention.execute(vault, identifier, now)
        except (Blocked, OSError, KeyError, ValueError, TypeError) as exc:
            return {"id": identifier, "status": "pending", "pending": [{"reason": str(exc)}]}

    for task in all_tasks(vault):
        with vault.locked():
            task = get_task(vault, task["id"])
            if task.get("capacity_held"):
                updates = reconcile_clock(vault, task, now)
                notices.extend({"task": task["id"], "notice": update} for update in updates)
                try:
                    if task.get("closure_pending"):
                        preserve_and_close(vault, task["id"], reason="human_timeout")
                    elif task.get("worktree_expired"):
                        reconcile_expired(vault, task["id"], now=now)
                except (Blocked, OSError) as exc:
                    pending.append({"task": task["id"], "reason": str(exc)})
    with vault.locked():
        vault.no_transaction()
        try:
            plans = retention.pending_plans(vault)
            exclude = {retention.slot(entry) for plan in plans for entry in plan["entries"]
                       if entry["status"] not in retention.RESOLVED}
        except (Blocked, OSError, KeyError, ValueError, TypeError) as exc:
            pending.append({"retention": "inventory", "reason": str(exc)})
        else:
            try:
                discovered = retention.plan(vault, now, exclude=exclude, skip_empty=bool(plans))
                if discovered is not None:
                    plans.append(discovered)
            except (Blocked, OSError, KeyError, ValueError, TypeError) as exc:
                pending.append({"retention": "discovery", "reason": str(exc)})
            results = [execute_plan(plan["id"]) for plan in plans]
            for index, result in enumerate(results):
                if any(item.get("reason") in {retention.NATIVE_REPLICAS_PENDING, retention.CHECKPOINT_REPLICAS_PENDING}
                       for item in result.get("pending", [])):
                    results[index] = execute_plan(result["id"])
        pending.extend({"plan": result["id"], **item} for result in results for item in result.get("pending", []))
        backup = backup_round(vault, now)
        if backup["status"] == "pending":
            if not pending and backup.get("legacy_error"):
                legacy_backup_error = {"error": backup["legacy_error"], "code": 5}
            pending.append({"backup": backup["reason"]})
    legacy = pending[0] if pending and "task" in pending[0] else {}
    return {**legacy, **legacy_backup_error, "status": "pending" if pending else "complete", "notices": notices,
            "retention": results[0]["id"] if results else None, "plans": results, "pending": pending,
            "backup": backup.get("id"), "backup_result": backup}


def backup_round(vault, now):
    from . import backups, storage_policy
    from .custody import materials

    try:
        policy = storage_policy.effective(vault)
        mode = policy["backup"]["mode"]
        if mode in {"off", "manual"}:
            return {"status": "disabled" if mode == "off" else "manual", "mode": mode}
        days = vault.config.get("backup_generation_days")
        if policy["version"] == 0 and days != "permanent" and (type(days) is not int or days <= 0):
            message = "Approved backup generation lifetime is required"
            return {"status": "pending", "configuration": "missing" if days is None else "invalid",
                    "reason": message, "legacy_error": message}
        status, reason = storage_policy.backup_status(vault, policy, scheduled=True)
        if status != "configured":
            return {"status": "pending", "configuration": status, "reason": reason}
        interval = timedelta(hours=storage_policy.backup_interval(vault, policy))
        for record in materials(vault).values():
            if (record.get("kind") == "backup" and record.get("generation") == "long" and record.get("verified_at") and
                    utc(record["verified_at"]) <= now < utc(record["verified_at"]) + interval):
                try:
                    backups.verify_backup(vault, record["id"])
                    return {"status": "not_due", "mode": mode, "last_generation": record["id"]}
                except (Blocked, OSError):
                    continue
        expiry = "permanent" if days == "permanent" else now + timedelta(days=days)
        record = backups.create(vault, "long", expiry, now=now, scheduled=True)
        return {"status": "complete", "id": record["id"], "mode": mode}
    except (Blocked, OSError, KeyError, ValueError, TypeError, OverflowError) as exc:
        return {"status": "pending", "reason": str(exc)}


def prepare_launchd_trial(vault, directory):
    from .build import activate, external, require_active
    from .setup import initialize

    require(platform.system() == "Darwin", "launchd trials require macOS", 5)
    with vault.locked():
        require(trial_workspace(vault) is None, "Start launchd trial preparation from the target vault", 5)
        build = require_active(vault)
        directory = Path(directory).absolute()
        require(directory.is_dir() and directory.resolve() == directory,
                "Choose an existing canonical directory outside the target vault and state", 5)
        external(directory, vault.repository, vault.state)
        require(not directory.is_relative_to(build.prefix.parent), "Keep the trial outside the controller build store", 5)
        workspace = Path(mkdtemp(prefix="healdan-launchd-trial-", dir=directory))

    root, state = workspace / "vault", workspace / "state"
    setup = initialize(root, state)
    fixture = Vault(root, state)
    with fixture.locked():
        atomic(fixture.control / TRIAL_MARKER, {"format": "healdan-launchd-trial-v1", "binding": fixture.binding})
    activate(fixture, build.identity["sha256"], build.prefix.parent)
    return {**setup, "workspace": str(workspace), "trial_vault_id": fixture.identity,
            "controller": str(build.entry_point), "build": build.identity}


def trial_workspace(vault):
    marker = safe_path(vault.control, TRIAL_MARKER)
    if not marker.exists():
        return None
    workspace = vault.repository.primary.parent
    require(read_json(marker) == {"format": "healdan-launchd-trial-v1", "binding": vault.binding} and
            workspace.name.startswith("healdan-launchd-trial-") and vault.repository.primary == workspace / "vault" and
            vault.common == vault.root / ".git" and vault.state == workspace / "state",
            "The disposable launchd trial must use its original vault and state", 5)
    return workspace


def _check_trial_settings(vault, workspace):
    from .binding import CONFIG_PATHS, CONFIG_ROOTS

    paths = [vault.config[name] for name in CONFIG_PATHS if vault.config.get(name)]
    for name in CONFIG_ROOTS:
        paths.extend(vault.config.get(name, []))
    for name in paths:
        path = Path(name)
        require(path != workspace and path.is_relative_to(workspace),
                "Launchd trial keys, storage roots and backup destinations must stay in its workspace", 5)
        safe_path(workspace, path.relative_to(workspace))
    for root, directories in ((vault.root, ("inbox", "wiki")),
                              (vault.state, ("custody", "tasks", "launchd")),
                              (vault.control, ("deletions", "lint", "receipts", "sessions", "tasks"))):
        for name in directories:
            relative = (root / name).relative_to(workspace)
            path = safe_path(workspace, relative)
            require(path.resolve() == path and (not path.exists() or path.is_dir()),
                    "Launchd trial requires a canonical workspace directory at " + str(relative), 5)
    require(all(root.is_relative_to(workspace) for root in vault.repository.worktree_roots()),
            "Launchd trial worktrees must stay in its workspace", 5)


def _schedule_scope(vault, trial):
    workspace = trial_workspace(vault)
    require(trial == (workspace is not None), "Select the matching production or disposable launchd trial vault", 5)
    if trial:
        _check_trial_settings(vault, workspace)


def _check_readiness(vault, trial, operation, *, allow_custody_findings=False):
    from .setup import doctor

    report = doctor(vault)
    ready = report["ready"]
    checks = report.get("checks", [])
    if allow_custody_findings and checks:
        checks = [row for row in checks if not row["name"].startswith("custody:")]
        ready = all(row["passed"] for row in checks)
    if trial:
        ready = (sum(row["name"] == "trial:launchd" for row in checks) == 1 and
                 all(row["passed"] for row in checks if row["name"] != "trial:launchd"))
    require(ready, "Configuration and native trials must pass before " + operation, 5)


def schedule(vault, *, activate=False, trial=False):
    with vault.locked():
        return _schedule(vault, activate=activate, trial=trial)


def run_scheduled(vault, job, expected_vault, *, trial=False):
    from .linting import lint

    require(job in JOBS, "Unknown scheduled job", 2)
    require(expected_vault == vault.identity and vault.root == vault.repository.primary,
            "The scheduled command must name its vault identity and primary worktree", 5)
    with vault.locked():
        vault.refresh_settings()
        _schedule_scope(vault, trial)
        _check_readiness(vault, trial, "running a scheduled job", allow_custody_findings=job == "daily")
        return lint(vault) if job == "lint" else daily(vault)


def schedule_definitions(vault, build=None, *, trial=False):
    build = build if build is not None else active(vault)
    search_path = os.pathsep.join(path for path in os.environ.get("PATH", os.defpath).split(os.pathsep)
                                  if Path(path).is_absolute())
    definitions = []
    for job, calendar in vault.policy["schedules"].items():
        label = job_label(vault.identity, job, trial=trial)
        definitions.append({"Label": label, "ProgramArguments": [str(build.entry_point), "--vault", str(vault.repository.primary),
                 "--state", str(vault.state), "--vault-id", vault.identity, "maintenance", "run-scheduled", job,
                 *(["--trial"] if trial else [])], "EnvironmentVariables": {"PATH": search_path},
                 "StartCalendarInterval": calendar,
                 "StandardOutPath": str(vault.state / (job + ".out")),
                 "StandardErrorPath": str(vault.state / (job + ".err"))})
    return definitions


def _schedule(vault, *, activate, trial):
    require(platform.system() == "Darwin", "launchd schedules require macOS", 5)
    vault.refresh_settings()
    _schedule_scope(vault, trial)
    if activate:
        _check_readiness(vault, trial, "activating a schedule")
    output = []
    for plist in schedule_definitions(vault, trial=trial):
        destination = safe_path(vault.state, "launchd/" + plist["Label"] + ".plist")
        for name in ("StandardOutPath", "StandardErrorPath"):
            safe_path(vault.state, Path(plist[name]).relative_to(vault.state))
        atomic(destination, plistlib.dumps(plist))
        if activate:
            target = Path.home() / "Library/LaunchAgents" / destination.name
            atomic(target, destination.read_bytes())
            result = run([executable("launchctl"), "bootstrap", gui_domain(), target], check=False)
            require(result.returncode == 0, "launchd activation failed; inspect the job before retry", 5)
        output.append(str(destination))
    return {"plists": output, "activated": activate}
