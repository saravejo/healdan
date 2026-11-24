"""Capture and verify the effective environment of signed native acceptance trials."""
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import sys

from .build import require_active
from .core import Blocked, atomic, digest, executable, read_json, require, run, safe_path, utc
from .lineage import sha256
from .signing import human_sign, trusted_signers, verify

TRIAL_FORMAT = "healdan-native-trial-v2"
TRIALS = ("claude-auth", "native-resume", "native-cleanup", "offline-recovery", "launchd")
RECEIPT_FOLDERS = ("trials", "trials/v2")
RECEIPTS = {f"{folder}/{name}.json": (name, folder == "trials/v2") for folder in RECEIPT_FOLDERS for name in TRIALS}
PROFILE_TRIALS = frozenset(TRIALS[:3])
PROFILE_CONFIG = ("signing_key", "age_identity", "backup_signing_key", "storage_roots", "backup_destinations")
RECOVERY_CONFIG = ("age_recipients", "offline_recipients", "age_identity", "backup_signing_identity", "backup_signing_key",
                   "backup_allowed_signers", "backup_destinations", "storage_roots")
SCHEDULE_CONFIG = (*RECOVERY_CONFIG, "backup_generation_days", "backup_interval_hours")
TOOL_ARGUMENTS = {"claude": ("--version",), "node": ("--version",), "srt": ("--version",),
                  "age": ("--version",), "git": ("--version",), "ssh": ("-V",)}


def _tool(name):
    path = Path(executable(name)).resolve()
    result = {"path": str(path), "sha256": digest(path.read_bytes())}
    if name in TOOL_ARGUMENTS:
        output = run([path, *TOOL_ARGUMENTS[name]])
        version = (output.stdout or output.stderr).decode("utf-8").strip()
        require(version, "Could not measure dependency: " + name, 5)
        result["version"] = version
    return result


def _profile_directory(vault, path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts and path != vault.state and path.is_relative_to(vault.state),
            "Native trial profile must use a canonical path in the selected vault state", 5)
    path = safe_path(vault.state, path.relative_to(vault.state))
    require(path.is_dir() and path.resolve() == path, "Native trial profile directory is unavailable or aliased", 5)
    require(not any(path.is_relative_to(root) for root in vault.repository.worktree_roots()),
            "Native trial profile must remain outside vault worktrees", 5)
    return path


def _profile(vault, name, requested):
    options = vault.config.get("native_trial_profiles", {})
    require(isinstance(options, dict), "Native trial profiles must map trial names to paths", 5)
    configured = options.get(name)
    if configured is not None:
        configured = _profile_directory(vault, vault.relocated_path(configured))
    if requested is not None:
        requested = _profile_directory(vault, requested)
    require(configured is None or requested is None or requested == configured, "Trial used a different configured profile", 5)
    path = configured or requested or _profile_directory(vault, vault.state / "authentication")
    settings = safe_path(path, "settings.json", exists=True)
    files = {"settings.json": digest(settings.read_bytes())}
    for name in (".claude.json", "settings.local.json"):
        candidate = safe_path(path, name)
        if candidate.is_file():
            files[name] = digest(candidate.read_bytes())
    return {"path": str(path), "configuration": files}


def _config_receipt(vault, names, *, recovery):
    values = {name: vault.config.get(name) for name in names}
    if values.get("signing_key"):
        key = Path(values["signing_key"])
        effective = key.resolve()
        require(key.is_absolute() and effective.is_file() and
                not any(effective.is_relative_to(root) for root in vault.repository.worktree_roots()),
                "External human signing key is unavailable", 5)
        values["signing_key"] = {"path": str(effective), "sha256": digest(effective.read_bytes())}
    if "backup_allowed_signers" in values and values["backup_allowed_signers"]:
        path = Path(values["backup_allowed_signers"])
        require(path.is_absolute() and path.is_file(), "Backup signer policy is unavailable", 5)
        values["backup_signers_sha256"] = digest(path.read_bytes())
    if "age_identity" in values and values["age_identity"]:
        path = Path(values["age_identity"])
        require(path.is_absolute() and path.is_file(), "Operational age identity is unavailable", 5)
        values["age_identity_sha256"] = digest(path.read_bytes())
    if recovery and values.get("backup_signing_key"):
        key = Path(values["backup_signing_key"])
        require(key.is_absolute() and key.is_file(), "Backup signing key is unavailable", 5)
        effective = key.resolve()
        require(effective != Path(vault.config.get("signing_key") or "").resolve() and
                not any(effective.is_relative_to(root) for root in vault.repository.worktree_roots()),
                "A separate external backup signing key is required", 5)
        values["backup_signing_key"] = {"path": str(effective), "sha256": digest(effective.read_bytes())}
    return digest(values)


def environment(vault, name, profile=None, *, build=None, measured_tools=None):
    require(name in TRIALS, "Unknown native acceptance trial", 2)
    require(platform.system() == "Darwin", "Native acceptance trials require real macOS evidence", 5)
    build = build if build is not None else require_active(vault)
    measured_tools = measured_tools if measured_tools is not None else {}

    def tool(name):
        if name not in measured_tools:
            measured_tools[name] = _tool(name)
        return measured_tools[name]

    values = {"vault_id": vault.identity, "controller": build.identity, "profile": {"trial": name},
              "platform": {"system": "Darwin", "release": platform.release(), "machine": platform.machine(),
                           "version": platform.mac_ver()[0]},
              "python": {"version": platform.python_version(), "command": str(Path(sys.executable).resolve())}}
    if name in PROFILE_TRIALS:
        values["profile"].update(_profile(vault, name, profile))
        tools = ["claude", "node", "srt"]
        relevant = PROFILE_CONFIG
        values["policy"] = {key: vault.policy[key] for key in ("srt_version", "cleanupPeriodDays", "context_bytes")}
        if name in {"native-resume", "native-cleanup"}:
            tools.extend(("age", "ssh", "ssh-keygen"))
            relevant = (*relevant, *RECOVERY_CONFIG)
    else:
        require(profile is None, "This trial uses the vault's recovery or schedule configuration", 2)
        tools = ["age", "git", "ssh", "ssh-keygen"]
        relevant = RECOVERY_CONFIG
        if name == "launchd":
            from .maintenance import schedule_definitions, trial_workspace
            values["schedules"] = schedule_definitions(vault, build, trial=trial_workspace(vault) is not None)
            tools.append("launchctl")
            relevant = SCHEDULE_CONFIG
    values["tools"] = {name: tool(name) for name in tools}
    if "srt" in values["tools"]:
        from .launcher import validate_runtime
        validate_runtime(vault, values["tools"]["srt"]["version"], values["tools"]["node"]["version"])
    values["config_sha256"] = _config_receipt(vault, relevant, recovery=name in {"offline-recovery", "launchd"})
    return values


def _artifacts(vault, values):
    require(isinstance(values, list) and values, "Trial needs artifact hashes", 2)
    paths = set()
    for artifact in values:
        path = vault.relocated_path(artifact["path"])
        require(path.is_absolute() and path not in paths, "Trial artifact path must be absolute and unique", 2)
        paths.add(path)
        require(digest(safe_path(path.parent, path.name, exists=True).read_bytes()) == artifact["sha256"],
                "Trial artifact is unavailable or changed", 5)


def _receipt_path(vault, name):
    return safe_path(vault.control, f"trials/v2/{name}.json")


def _validate_evidence(evidence):
    require(isinstance(evidence, dict) and evidence.get("platform") == "Darwin" and evidence.get("passed") is True and
            isinstance(evidence.get("procedure"), str) and evidence["procedure"].strip() and
            evidence.get("started_at") and evidence.get("completed_at"),
            "Trial needs real macOS evidence, a procedure, start and completion times, and a passing result", 2)
    require(utc(evidence["completed_at"]) >= utc(evidence["started_at"]), "Invalid trial times", 2)


def check_preserved_evidence(payload, name, vault_id, *, versioned):
    require(isinstance(payload, dict) and name in TRIALS and payload.get("name") == name and
            all(isinstance(payload.get(key), str) for key in ("started_at", "completed_at")),
            "Trial evidence has an invalid name or timestamps", 5)
    _validate_evidence(payload)
    artifacts = payload.get("artifacts")
    require(isinstance(artifacts, list) and artifacts and all(
        isinstance(artifact, dict) and isinstance(artifact.get("path"), str) and artifact["path"] and
        sha256(artifact.get("sha256")) for artifact in artifacts), "Invalid trial artifact inventory", 5)
    if versioned:
        measured = payload.get("environment")
        require(payload.get("format") == TRIAL_FORMAT and isinstance(measured, dict) and measured.get("vault_id") == vault_id,
                "Trial receipt has the wrong format or source vault identity", 5)
        profile, controller = measured.get("profile"), measured.get("controller")
        require(isinstance(profile, dict) and profile.get("trial") == name and isinstance(controller, dict) and
                isinstance(controller.get("version"), str) and sha256(controller.get("sha256")) and
                sha256(measured.get("config_sha256")) and all(isinstance(measured.get(key), dict) and measured[key]
                                                            for key in ("platform", "python", "tools")),
                "Invalid measured trial environment", 5)
        paths = [artifact["path"] for artifact in artifacts]
        require(len(set(paths)) == len(paths) and all(PurePosixPath(path).is_absolute() or PureWindowsPath(path).is_absolute()
                                                     for path in paths), "Invalid measured trial artifact paths", 5)
    else:
        commit = payload.get("commit")
        require("format" not in payload and isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit) and
                payload.get("versions"), "Invalid legacy trial commit or dependency versions", 5)


def attest(vault, name, evidence):
    with vault.locked():
        require(name in TRIALS, "Unknown native acceptance trial", 2)
        _validate_evidence(evidence)
        measured = environment(vault, name, evidence.get("profile"))
        require(evidence.get("environment") == measured, "Trial environment differs from the recorded measurements", 5)
        _artifacts(vault, evidence.get("artifacts"))
        payload = {**evidence, "name": name, "format": TRIAL_FORMAT, "environment": measured}
        approval = human_sign(vault, payload, "trial")
        atomic(_receipt_path(vault, name), approval)
        return approval


def status(vault):
    results = []
    tools = {}
    with vault.reading():
        for name in TRIALS:
            try:
                path = _receipt_path(vault, name)
                if not path.exists():
                    legacy = safe_path(vault.control, f"trials/{name}.json").exists()
                    raise Blocked("Legacy receipt needs new environment evidence" if legacy else "Personal macOS trial is pending", 5)
                payload = verify(read_json(path), "trial", trusted_signers(vault))
                require(payload.get("format") == TRIAL_FORMAT and payload.get("name") == name,
                        "Trial receipt does not identify a passing native trial", 5)
                _validate_evidence(payload)
                current = environment(vault, name, payload.get("profile"), measured_tools=tools)
                require(payload.get("environment") == current, "Trial vault, build, profile or environment changed", 5)
                _artifacts(vault, payload["artifacts"])
                results.append({"name": name, "passed": True, "reason": "Signed native evidence verified"})
            except (Blocked, OSError, KeyError, TypeError, ValueError) as exc:
                results.append({"name": name, "passed": False, "reason": str(exc)})
    return results
