"""Daily retention-before-backup orchestration, signed trials and launchd."""
from datetime import timedelta
from pathlib import Path
import platform
import plistlib
import sys

from .core import Blocked, atomic, digest, executable, read_json, require, run, stamp, utc
from .signing import human_sign, trusted_signers, verify

TRIALS = ("claude-auth", "native-resume", "native-cleanup", "offline-recovery", "launchd")


def attest(vault, name, evidence):
    require(name in TRIALS, "Unknown native acceptance trial", 2)
    require(evidence.get("platform") == "Darwin" and evidence.get("commit") == vault.head() and
            evidence.get("passed") is True and evidence.get("versions") and evidence.get("artifacts") and
            evidence.get("procedure") and evidence.get("started_at") and evidence.get("completed_at"),
            "Trial needs real macOS evidence, exact commit, procedure, times, versions and artifact hashes", 2)
    require(utc(evidence["completed_at"]) >= utc(evidence["started_at"]), "Invalid trial times", 2)
    for artifact in evidence["artifacts"]:
        path = Path(artifact["path"])
        require(path.is_file() and digest(path.read_bytes()) == artifact["sha256"], "Trial artifact mismatch")
    payload = {"name": name, **evidence}
    approval = human_sign(vault, payload, "trial")
    atomic(vault.control / "trials" / (name + ".json"), approval)
    return approval


def trial_status(vault):
    results = []
    for name in TRIALS:
        try:
            value = read_json(vault.control / "trials" / (name + ".json"))
            payload = verify(value, "trial", trusted_signers(vault))
            require(payload.get("name") == name and payload.get("commit") == vault.head() and payload.get("passed") is True,
                    "Trial is stale or failed")
            for artifact in payload["artifacts"]:
                require(Path(artifact["path"]).is_file() and digest(Path(artifact["path"]).read_bytes()) == artifact["sha256"],
                        "Trial artifact is unavailable or changed")
            results.append({"name": name, "passed": True, "reason": "Signed native evidence verified"})
        except (Blocked, OSError, KeyError, TypeError) as exc:
            results.append({"name": name, "passed": False, "reason": str(exc)})
    return results


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
    require(platform.system() == "Darwin", "launchd schedules require macOS", 5)
    from .setup import doctor
    require(doctor(vault)["ready"], "Configuration/recovery must pass before scheduling", 5)
    executable_path = Path(sys.executable).parent / "healdan"
    require(executable_path.is_file() and not executable_path.resolve().is_relative_to(vault.root),
            "External installed controller required", 5)
    output = []
    for job, calendar in vault.policy["schedules"].items():
        label = "org.healdan." + digest(str(vault.common))[:12] + "." + job
        command = ["lint"] if job == "lint" else ["maintenance", "daily"]
        plist = {"Label": label, "ProgramArguments": [str(executable_path), "--vault", str(vault.root),
                 "--state", str(vault.state), *command], "StartCalendarInterval": calendar,
                 "StandardOutPath": str(vault.state / (job + ".out")),
                 "StandardErrorPath": str(vault.state / (job + ".err"))}
        destination = vault.state / "launchd" / (label + ".plist")
        atomic(destination, plistlib.dumps(plist))
        if activate:
            import os
            target = Path.home() / "Library/LaunchAgents" / destination.name
            atomic(target, destination.read_bytes())
            result = run(["launchctl", "bootstrap", f"gui/{os.getuid()}", target], check=False)
            require(result.returncode == 0, "launchd activation failed; inspect the job before retry", 5)
        output.append(str(destination))
    return {"plists": output, "activated": activate}
