"""macOS outer-process sandbox, mandatory probes and supervised native launches."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

from .core import atomic, decode, digest, executable, read_json, require, run, safe_path, stamp, utc
from .tasks import get_session, get_task, require_active, task_path, validate_evidence


def runtime_version(vault):
    require(platform.system() == "Darwin", "Production sandbox launch requires macOS", 5)
    version = run([executable("srt"), "--version"]).stdout.decode().strip()
    node = run([executable("node"), "--version"]).stdout.decode().strip()
    validate_runtime(vault, version, node)
    return version


def validate_runtime(vault, version, node):
    require(version == vault.policy["srt_version"], "srt version differs from pinned policy", 5)
    parts = node.removeprefix("v").split(".")
    require(len(parts) == 3 and all(part.isascii() and part.isdecimal() for part in parts) and
            tuple(map(int, parts)) >= (22, 12, 0), "Node.js 22.12+ is required", 5)


def settings(vault, writable, readable, *, network=False):
    # An explicit outer sandbox covers the native tools and every child process.
    private = [vault.config.get(k) for k in ("signing_key", "age_identity", "backup_signing_key") if vault.config.get(k)]
    private += vault.config.get("storage_roots", []) + vault.config.get("backup_destinations", [])
    def literal(path):
        return {"path": str(Path(path).resolve()), "literal": True}
    shared_temp = ["/tmp/claude", "/private/tmp/claude", Path.home() / ".npm/_logs", Path.home() / ".claude/debug"]
    return {"network": {"allowedDomains": ["api.anthropic.com", "claude.ai", "platform.claude.com"] if network else [],
                        "deniedDomains": [], "allowUnixSockets": [], "allowLocalBinding": False},
            "filesystem": {"denyRead": [literal(p) for p in [Path.home(), vault.root, vault.state, vault.common,
                                            "/tmp", "/private/tmp", "/var/folders", "/private/var/folders", *private]],
                           "allowRead": [literal(p) for p in readable],
                           "allowWrite": [literal(p) for p in writable],
                           "denyWrite": [literal(p) for p in [vault.root, vault.common, Path(__file__).parent,
                                                              vault.config_path, *shared_temp, *private]]}}


def clean_env(temporary, profile=None):
    env = {k: v for k, v in os.environ.items() if k in {"PATH", "LANG", "LC_ALL", "TERM", "SYSTEMROOT"}}
    env.update(HOME=str(Path.home()), TMPDIR=str(temporary), CLAUDE_CODE_TMPDIR=str(temporary), PYTHONDONTWRITEBYTECODE="1",
               CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_AUTOUPDATER="1")
    if profile:
        env["CLAUDE_CONFIG_DIR"] = str(profile)
    return env


def probe(vault):
    with vault.locked():
        return _probe(vault)


def _probe(vault):
    version = runtime_version(vault)
    vault.state.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="probe-", dir=vault.state) as temp, \
            tempfile.TemporaryDirectory(prefix="hs-", dir="/tmp") as socket_directory:
        root = Path(temp)
        allowed = root / "allowed"
        allowed.mkdir()
        secret = root / "protected"
        secret.write_text("probe sentinel", encoding="utf-8")
        socket_path = Path(socket_directory) / "s"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(socket_path))
        sock.listen(1)
        sentinel = "denial-probe-" + str(uuid4())
        targets = [secret, vault.root / sentinel, vault.common / sentinel,
                   vault.state / sentinel, Path(__file__).parent / sentinel, Path("/tmp/claude") / sentinel]
        config = settings(vault, [allowed], [allowed, Path(sys.prefix), Path(sys.base_prefix),
                                            Path(sys.executable).resolve().parent.parent])
        config_path = root / "sandbox.json"
        atomic(config_path, config)
        script = """import json, os, pathlib, socket, subprocess, sys
targets=json.loads(sys.argv[1]); allowed=pathlib.Path(sys.argv[2]); result={}
for name in targets:
    try:
        pathlib.Path(name).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(name).write_bytes(b'ESCAPE'); result[name]=False
    except OSError:
        result[name]=True
try:
    pathlib.Path(targets[0]).read_bytes(); result['secret_read']=False
except OSError:
    result['secret_read']=True
try:
    s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[3]); result['socket']=False
except OSError:
    result['socket']=True
child=subprocess.run([sys.executable,'-c','from pathlib import Path; Path(__import__("sys").argv[1]).write_text("ESCAPE")',targets[0]],capture_output=True)
result['child_write']=child.returncode!=0
(allowed/'ok').write_text('allowed'); result['allowed_write']=(allowed/'ok').read_text()=='allowed'
print(json.dumps(result))
"""
        try:
            result = run([executable("srt"), "--settings", config_path, "--", sys.executable, "-c", script,
                          json.dumps([str(p) for p in targets]), allowed, socket_path],
                         cwd=allowed, env=clean_env(allowed), check=False)
            require(result.returncode == 0, "Sandbox probe failed to execute: " + result.stderr.decode("utf-8", errors="replace")[-2000:], 5)
            checks = decode(result.stdout)
            require(all(checks.values()) and secret.read_text() == "probe sentinel", "OS isolation probe detected escape", 5)
        finally:
            sock.close()
        proof = {"platform": platform.platform(), "srt_version": version, "checks": checks, "at": stamp()}
        atomic(vault.control / "sandbox-probe.json", proof)
        return proof


def profile(vault, operation):
    with vault.locked():
        return _profile(vault, operation)


def _profile(vault, operation):
    session = get_session(vault, operation)
    directory = vault.state / "tasks" / session["task"] / "temporary" / session["role"] / session["uuid"] / "native"
    directory.mkdir(parents=True, exist_ok=True)
    config = directory / "settings.json"
    expected = {"cleanupPeriodDays": 30, "permissions": {"defaultMode": "acceptEdits"}}
    if config.exists():
        require(read_json(config) == expected, "Native profile settings changed", 5)
    else:
        atomic(config, expected)
    return directory


def launch(vault, operation, *, resume=False, recovery_material=None):
    from .build import require_active

    with vault.locked():
        require_active(vault)
        _probe(vault)  # Run a fresh OS isolation probe before every launch.
        vault.no_transaction()
        session = get_session(vault, operation)
        task = get_task(vault, session["task"])
        if not recovery_material:
            require_active(task)
            validate_evidence(vault, task)
        else:
            require(resume and session.get("reconstruction", {}).get("material") == recovery_material,
                    "Recovery must resume the reconstructed original session", 5)
        require(session["state"] != "running", "Session already running or needs process reconciliation", 5)
        require(bool(session["launches"]) == resume, "Use resume for an existing session; new launches need a new S-", 2)
        base = vault.state / "tasks" / session["task"]
        proposal = Path(session["proposal"])
        require(proposal.resolve().is_relative_to(base / "proposals"), "Session proposal belongs outside this vault state", 5)
        temporary = base / "temporary" / session["role"] / session["uuid"]
        native = Path(session["recovery_profile"]) if recovery_material else profile(vault, operation)
        require(native.resolve().is_relative_to(vault.state), "Native recovery profile must stay in controller state")
        context = (base / "contexts" / (session["id"] + ".txt")).read_bytes()
        require(digest(context) == session["context_sha256"] and len(context) <= vault.policy["context_bytes"][session["role"]],
                "Prepared context changed or exceeds limit", 5)
        if recovery_material:
            context = b"Recovery verification only. Confirm that this conversation resumed. Do not perform task actions or use tools."
        env = clean_env(temporary, native)
        auth = run([executable("claude"), "auth", "status"], env=env, check=False)
        require(auth.returncode == 0, "Authenticate this dedicated native profile before launch", 5)
        readable = [proposal, temporary, base / "evidence", base / "contexts" / (session["id"] + ".txt"),
                    Path(executable("claude")).resolve().parent, Path(executable("node")).resolve().parent]
        readable.append(native)
        config = settings(vault, [temporary, native] + ([] if recovery_material else [proposal]), readable, network=True)
        config["filesystem"]["denyWrite"].extend([{"path": str(native / name), "literal": True}
                                                   for name in ("settings.json", ".credentials.json")])
        settings_path = base / "sandbox" / (operation + ".json")
        atomic(settings_path, config)
        args = [executable("srt"), "--settings", settings_path, "--", executable("claude"),
                "--print", "--output-format", "json", "--settings", native / "settings.json",
                "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--setting-sources", "user",
                "--resume" if resume else "--session-id", session["uuid"]]
        launch_id = str(uuid4())
        output = temporary / (launch_id + ".result.json")
        error = temporary / (launch_id + ".stderr")
        session["state"] = "running"
        session["launch_intent"] = {"id": launch_id, "at": stamp(), "resumed": resume}
        atomic(vault.control / "sessions" / (operation + ".json"), session)
        stdout, stderr = output.open("wb"), error.open("wb")
        try:
            process = subprocess.Popen([str(a) for a in args], cwd=proposal, stdin=subprocess.PIPE,
                                       stdout=stdout, stderr=stderr, env=env, start_new_session=True)
        except BaseException:
            stdout.close()
            stderr.close()
            raise
        process_identity = run(["ps", "-p", str(process.pid), "-o", "lstart="], check=False).stdout.decode().strip()
        task["processes"].append({"pid": process.pid, "session": operation, "launch": launch_id,
                                  "started_identity": process_identity})
        atomic(task_path(vault, task["id"]), task)
    remaining = 300 if recovery_material else 86400 - (utc() - utc(task["created_at"])).total_seconds()
    expired = False
    try:
        process.communicate(context, timeout=max(0.01, remaining))
    except subprocess.TimeoutExpired:
        expired = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
    finally:
        stdout.close()
        stderr.close()
    with vault.locked():
        session = get_session(vault, operation)
        task = get_task(vault, task["id"])
        result = read_json(output, {}) if output.stat().st_size else {}
        success = process.returncode == 0 and not expired and not result.get("is_error") and result.get("session_id") == session["uuid"]
        usage = result.get("usage", {})
        for key in ("input_tokens", "output_tokens"):
            amount = usage.get(key, 0)
            require(type(amount) is int and amount >= 0, "Invalid native usage result", 5)
            session["usage"][key] += amount
        session["usage"]["evidence_bytes"] += sum(p.stat().st_size for p in (base / "evidence").rglob("*") if p.is_file())
        receipt = {"id": launch_id, "uuid": session["uuid"], "action": session["action"], "at": stamp(),
                   "resumed": resume, "success": success, "expired": expired, "result_sha256": digest(output.read_bytes()),
                   "recovery_material": recovery_material,
                   "cumulative_usage": dict(session["usage"]), "native_profile": str(native)}
        session["launches"].append(receipt)
        session["active_profile"] = str(native)
        session["state"] = "completed" if success else "reconciliation_required"
        atomic(vault.control / "sessions" / (operation + ".json"), session)
        task["processes"] = [p for p in task["processes"] if p["launch"] != launch_id]
        if expired:
            task["worktree_expired"] = True
        atomic(task_path(vault, task["id"]), task)
        vault.receipt("native-launch", receipt)
        require(success, "Native session failed or expired; preservation/reconciliation required", 5)
        return receipt
