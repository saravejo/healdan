"""Idempotent vault setup and read-only installation diagnostics."""
import json
import os
from pathlib import Path
import platform
import shutil
import sys

from .core import REQUIRED_REGISTRIES, Blocked, Vault, atomic, executable, git, read_json, require, run
from .binding import setup_binding

DIRECTORIES = ("inbox", "projects", "wiki/topics", "archive", "control/tasks", "templates")


def distribution_remote(url):
    normalized = url.strip().rstrip("/").removesuffix(".git").lower()
    return normalized in {"https://github.com/saravejo/healdan", "http://github.com/saravejo/healdan",
                          "git@github.com:saravejo/healdan", "ssh://git@github.com/saravejo/healdan"}


def initialize(root, state=None, *, interactive=False):
    if interactive:
        require(sys.stdin.isatty(), "Interactive setup requires a terminal", 2)
    setup_binding(root, state)
    vault = Vault(root, state, operational=False)
    with vault.locked():
        return _initialize(vault, interactive)


def _initialize(vault, interactive):
    root = vault.root
    for name in REQUIRED_REGISTRIES:
        path = root / name
        if not path.exists():
            atomic(path, b"")
    for folder in DIRECTORIES:
        path = root / folder
        path.mkdir(parents=True, exist_ok=True)
        if not any(path.iterdir()):
            atomic(path / ".gitkeep", b"")
    for name, body in (("wiki/index.md", b"# Wiki\n\nApproved topic pages appear after promotion.\n"),
                       (".claude/settings.json", b'{"cleanupPeriodDays":30}\n')):
        if not (root / name).exists():
            atomic(root / name, body)
    ignore = root / ".gitignore"
    previous = ignore.read_bytes() if ignore.exists() else b""
    text = previous
    for pattern in ("wiki-1.4.md", "config/local.json", ".claude/settings.local.json", "*.age", "*.key", "*.pem"):
        if pattern.encode() not in text.splitlines():
            text += (b"\n" if text and not text.endswith(b"\n") else b"") + pattern.encode() + b"\n"
    if previous != text:
        atomic(ignore, text)
    removed = []
    for remote in git(root, "remote").splitlines():
        urls = git(root, "remote", "get-url", "--all", remote).splitlines()
        push_urls = git(root, "remote", "get-url", "--push", "--all", remote).splitlines()
        # A mixed/custom remote is not the inherited distribution remote.
        if urls and all(distribution_remote(url) for url in urls + push_urls):
            git(root, "remote", "remove", remote)
            removed.append(remote)
    if not vault.config_path.exists():
        atomic(vault.config_path, {"git_name": None, "git_email": None, "signing_identity": None,
                                  "signing_key": None, "allowed_signers": None, "age_recipients": [],
                                  "offline_recipients": [], "age_identity": None, "storage_roots": [],
                                  "backup_signing_key": None, "backup_signing_identity": None, "backup_allowed_signers": None,
                                  "backup_destinations": [], "backup_interval_hours": None,
                                  "backup_generation_days": None})
    if interactive:
        config = read_json(vault.config_path)
        fields = {"git_name": "Git name", "git_email": "Git email", "signing_identity": "Human SSH signing identity",
                  "signing_key": "External human SSH private key path", "allowed_signers": "External allowed-signers file",
                  "age_identity": "External operational age identity path", "age_recipients": "Operational age recipients (comma separated)",
                  "offline_recipients": "Offline recovery age recipients (comma separated)",
                  "storage_roots": "Authorized external storage roots (comma separated)",
                  "backup_destinations": "Backup directories (comma separated)",
                  "backup_signing_key": "Separate external backup SSH key path", "backup_signing_identity": "Backup signer identity",
                  "backup_allowed_signers": "External backup allowed-signers file",
                  "backup_interval_hours": "Approved backup interval in hours", "backup_generation_days": "Long generation lifetime in days"}
        for key, label in fields.items():
            if not config.get(key):
                answer = input(label + " (blank leaves pending): ").strip()
                if answer:
                    config[key] = [v.strip() for v in answer.split(",")] if isinstance(config[key], list) else (
                        int(answer) if key in {"backup_interval_hours", "backup_generation_days"} else answer)
        atomic(vault.config_path, config)
        for key in ("name", "email"):
            if config.get("git_" + key) and not git(root, "config", "--get", "user." + key, check=False):
                git(root, "config", "user." + key, config["git_" + key])
    profile = vault.state / "authentication"
    profile.mkdir(exist_ok=True)
    if not (profile / "settings.json").exists():
        atomic(profile / "settings.json", {"cleanupPeriodDays": 30})
    return {"vault": str(root), "state": str(vault.state), "config": str(vault.config_path),
            "removed_distribution_remotes": removed, "authentication_profile": str(profile),
            "next": "Complete external config, authenticate dedicated profiles, then run doctor and recovery trials"}


def doctor(vault):
    checks = []
    def check(name, passed, detail):
        checks.append({"name": name, "passed": bool(passed), "detail": detail})
    check("python", sys.version_info >= (3, 12), platform.python_version())
    check("production_platform", platform.system() == "Darwin", platform.system())
    for name in ("git", "ssh-keygen", "claude", "age", "node", "srt"):
        try:
            check(name, True, executable(name))
        except Blocked as exc:
            check(name, False, str(exc))
    check("external_controller", not Path(__file__).resolve().is_relative_to(vault.root),
          "Install non-editably outside the vault before production launch")
    for name in ("git_name", "git_email", "signing_identity", "signing_key", "allowed_signers", "age_identity",
                 "age_recipients", "offline_recipients", "backup_destinations", "backup_interval_hours", "backup_generation_days",
                 "backup_signing_key", "backup_signing_identity", "backup_allowed_signers"):
        check("config:" + name, vault.config.get(name), "Configured" if vault.config.get(name) else "Required configuration missing")
    for name in ("signing_key", "allowed_signers", "age_identity"):
        value = vault.config.get(name)
        valid = value and Path(value).is_absolute() and Path(value).is_file() and not Path(value).resolve().is_relative_to(vault.root)
        check("external:" + name, valid, "Must be an existing external file")
    if shutil.which("srt") and platform.system() == "Darwin":
        try:
            from .launcher import runtime_version
            check("runtime_pin", True, runtime_version(vault))
        except Blocked as exc:
            check("runtime_pin", False, str(exc))
    from .maintenance import trial_status
    for row in trial_status(vault):
        check("trial:" + row["name"], row["passed"], row["reason"])
    return {"ready": all(c["passed"] for c in checks), "checks": checks}
