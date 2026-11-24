"""Inspect launchd jobs without changing the user's installed agents."""
import os
from pathlib import Path
import platform

from .core import digest, executable, require, run

JOBS = ("lint", "daily")


def legacy_labels(common):
    prefix = "org.healdan." + digest(common)[:12]
    return {f"{prefix}.{job}" for job in JOBS}


def job_label(vault_id, job, *, trial=False):
    prefix = "org.healdan.trial" if trial else "org.healdan"
    return f"{prefix}.{vault_id}.{job}"


def gui_domain():
    return f"gui/{os.getuid()}"


def _service_loaded(label):
    if platform.system() != "Darwin":
        return False
    target = f"{gui_domain()}/{label}"
    result = run([executable("launchctl"), "print", target], check=False, env={**os.environ, "LC_ALL": "C"})
    if result.returncode == 0:
        return True
    message = result.stderr.lower()
    unavailable = b"could not find service" in message or b"could not find domain" in message
    headless = result.returncode == 125 and b"domain does not support specified action" in message
    require(unavailable or headless, "Cannot determine whether this LaunchAgent is loaded: " + label, 5)
    return False


def installed_jobs(labels):
    directory = Path.home() / "Library/LaunchAgents"
    jobs = []
    for label in sorted(labels):
        path = directory / (label + ".plist")
        installed = path.exists() or path.is_symlink()
        loaded = _service_loaded(label)
        if installed or loaded:
            jobs.append({"label": label, "loaded": loaded, "installed_plist": str(path) if installed else None})
    return jobs


def legacy_jobs(location, previous=()):
    return installed_jobs({label for item in [location, *previous] for label in legacy_labels(item["common"])})


def require_removed(jobs, operation):
    require(not jobs, f"Unload and remove the installed LaunchAgent before {operation}: " +
            ", ".join(job["label"] for job in jobs), 5)
