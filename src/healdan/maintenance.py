"""Daily retention-before-backup orchestration, signed trials and launchd."""
from datetime import timedelta
from pathlib import Path
import platform
import plistlib

from .build import active
from .core import Blocked, atomic, read_json, require, run, utc
from .trials import TRIALS, attest, status as trial_status


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


def schedule(vault, *, activate=False):
    with vault.locked():
        return _schedule(vault, activate=activate)


def schedule_definitions(vault, build=None):
    build = build if build is not None else active(vault)
    definitions = []
    for job, calendar in vault.policy["schedules"].items():
        label = f"org.healdan.{vault.identity}.{job}"
        command = ["lint"] if job == "lint" else ["maintenance", "daily"]
        definitions.append({"Label": label, "ProgramArguments": [str(build.entry_point), "--vault", str(vault.repository.primary),
                 "--state", str(vault.state), "--vault-id", vault.identity, *command], "StartCalendarInterval": calendar,
                 "StandardOutPath": str(vault.state / (job + ".out")),
                 "StandardErrorPath": str(vault.state / (job + ".err"))})
    return definitions


def _schedule(vault, *, activate):
    require(platform.system() == "Darwin", "launchd schedules require macOS", 5)
    from .setup import doctor
    if activate:
        require(doctor(vault)["ready"], "Configuration and native trials must pass before activating a schedule", 5)
    output = []
    for plist in schedule_definitions(vault):
        destination = vault.state / "launchd" / (plist["Label"] + ".plist")
        atomic(destination, plistlib.dumps(plist))
        if activate:
            import os
            target = Path.home() / "Library/LaunchAgents" / destination.name
            atomic(target, destination.read_bytes())
            result = run(["launchctl", "bootstrap", f"gui/{os.getuid()}", target], check=False)
            require(result.returncode == 0, "launchd activation failed; inspect the job before retry", 5)
        output.append(str(destination))
    return {"plists": output, "activated": activate}
