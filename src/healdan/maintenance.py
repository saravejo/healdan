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
    from . import backups, retention
    from .tasks import all_tasks, reconcile_clock, reconcile_expired, preserve_and_close
    notices = []
    for task in all_tasks(vault):
        if task.get("capacity_held"):
            with vault.locked():
                updates = reconcile_clock(vault, task, now)
                notices.extend({"task": task["id"], "notice": update} for update in updates)
            try:
                if task.get("closure_pending"):
                    preserve_and_close(vault, task["id"], reason="human_timeout")
                elif task.get("worktree_expired"):
                    reconcile_expired(vault, task["id"])
            except Blocked as exc:
                return {"status": "pending", "task": task["id"], "reason": str(exc), "backup": None, "notices": notices}
    with vault.locked():
        vault.no_transaction()
        for task in all_tasks(vault):
            reconcile_clock(vault, task, now)
        pending = [read_json(p) for p in (vault.control / "deletions").glob("*.json")
                   if read_json(p)["status"] != "complete"]
        deletion = pending[0] if pending else retention.plan(vault, now)
    result = retention.execute(vault, deletion["id"], now)
    if result["status"] != "complete":
        return {"status": "pending", "retention": result["id"], "backup": None, "notices": notices}
    lifetime = vault.config.get("backup_generation_days")
    require(type(lifetime) is int and lifetime > 0, "Approved backup generation lifetime is required", 5)
    backup = backups.create(vault, "long", utc(now) + timedelta(days=lifetime), now=now)
    return {"status": "complete", "retention": result["id"], "backup": backup["id"], "notices": notices}


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
    require(all(root.is_relative_to(workspace) for root in vault.repository.worktree_roots()),
            "Launchd trial worktrees must stay in its workspace", 5)


def _schedule_scope(vault, trial):
    workspace = trial_workspace(vault)
    require(trial == (workspace is not None), "Select the matching production or disposable launchd trial vault", 5)
    if trial:
        _check_trial_settings(vault, workspace)


def _check_readiness(vault, trial, operation):
    from .setup import doctor

    report = doctor(vault)
    ready = report["ready"]
    if trial:
        checks = report["checks"]
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
        _check_readiness(vault, trial, "running a scheduled job")
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
