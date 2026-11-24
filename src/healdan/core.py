"""Strict serialization, durable files, UTC time and common-repository locking."""
from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import platform
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone


class Blocked(Exception):
    def __init__(self, message: str, code: int = 4):
        super().__init__(message)
        self.code = code


def require(condition, message, code=4):
    if not condition:
        raise Blocked(message, code)


def utc(value=None):
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(value.tzinfo is not None, "Timestamp requires a UTC offset", 2)
    return value.astimezone(timezone.utc)


def stamp(value=None):
    return utc(value).isoformat().replace("+00:00", "Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def decode(data):
    def invalid(value):
        raise Blocked("Non-finite JSON number: " + value)
    try:
        return json.loads(data, object_pairs_hook=_pairs, parse_constant=invalid)
    except (ValueError, UnicodeError) as exc:
        raise Blocked("Invalid JSON: " + str(exc)) from exc


def read_json(path, default=None):
    return decode(Path(path).read_bytes()) if Path(path).exists() else default


def json_paths(directory):
    try:
        scan = os.scandir(directory)
    except FileNotFoundError:
        return []
    with scan:
        return sorted(Path(entry.path) for entry in scan if os.path.normcase(entry.name).endswith(".json"))


def parse_jsonl(data, path, *, include_bytes=False):
    if not data:
        return []
    terminated = data.endswith(b"\n")
    lines = data.removesuffix(b"\n").split(b"\n")
    rows = []
    for number, line in enumerate(lines, 1):
        require(bool(line.strip()), f"Blank JSONL row at {path}:{number}")
        try:
            row = decode(line)
        except Blocked as exc:
            raise Blocked(f"{path}:{number}: {exc}", exc.code) from exc
        require(isinstance(row, dict), f"JSONL row is not an object: {path}:{number}")
        if include_bytes:
            original = line + b"\n" if terminated or number < len(lines) else line
            rows.append((row, original))
            continue
        rows.append(row)
    return rows


def _read_jsonl_bytes(path, *, required):
    try:
        return path.read_bytes()
    except FileNotFoundError:
        require(not required, "Required JSONL registry is missing: " + str(path))
        return b""


def read_jsonl(path, *, required=False, include_bytes=False):
    path = Path(path)
    return parse_jsonl(_read_jsonl_bytes(path, required=required), path, include_bytes=include_bytes)


def jsonl(rows):
    return b"".join(canonical(row) + b"\n" for row in rows)


def extend_jsonl(data, rows):
    addition = jsonl(rows)
    separator = b"\n" if data and addition and not data.endswith(b"\n") else b""
    return data + separator + addition


def sync_directory(path):
    if os.name != "nt":
        directory = os.open(path, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def canonical_storage_path(path):
    original = current = Path(path)
    message = "Cannot verify storage location: " + str(original)
    require(original.is_absolute(), message, 5)
    missing = []
    try:
        while True:
            try:
                resolved = current.resolve(strict=True)
                require(not missing or resolved.is_dir(), message, 5)
                return resolved.joinpath(*reversed(missing))
            except FileNotFoundError:
                require(current.parent != current and not current.is_symlink() and not current.is_junction(), message, 5)
                missing.append(current.name)
                current = current.parent
    except (OSError, RuntimeError) as exc:
        raise Blocked(message, 5) from exc


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink(), "Refusing symlink destination")
    if not isinstance(data, bytes):
        data = canonical(data) + b"\n"
    fd, name = tempfile.mkstemp(prefix=".healdan-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def safe_path(root, relative, *, exists=False):
    root = Path(root).absolute()
    path = Path(relative)
    require(not path.is_absolute() and ".." not in path.parts and path.parts,
            "Path must be relative and confined", 2)
    require(not any(":" in part or "\\" in part or any(ord(c) < 32 for c in part) for part in path.parts), "Unsafe path", 2)
    candidate = root / path
    current = candidate
    while True:
        system_alias = (platform.system() == "Darwin" and str(current) in {"/var", "/tmp", "/etc"} and
                        current.is_symlink() and current.resolve() == Path("/private") / current.name and
                        current.lstat().st_uid == 0)
        require(not current.is_symlink() or system_alias, "Symlink path is forbidden")
        if current == current.parent:
            break
        current = current.parent
    require(candidate.resolve().is_relative_to(root.resolve()), "Path escapes root")
    try:
        metadata = candidate.stat()
    except (FileNotFoundError, NotADirectoryError):
        metadata = None
    regular = metadata is not None and stat.S_ISREG(metadata.st_mode)
    require(not exists or regular, "Required regular file is missing: " + str(relative))
    if regular:
        require(metadata.st_nlink == 1, "Hard-linked files are forbidden")
    return candidate


def executable(name):
    path = shutil.which(name)
    if not path and name == "git" and os.name == "nt":
        candidate = Path("C:/Program Files/Git/cmd/git.exe")
        path = str(candidate) if candidate.exists() else None
    require(path, "Missing executable: " + name, 1)
    return path


def run(argv, *, cwd=None, data=None, check=True, env=None, timeout=120):
    try:
        result = subprocess.run([str(a) for a in argv], cwd=cwd, input=data,
                                capture_output=True, env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("Process unavailable: " + str(argv[0]), 1) from exc
    if check and result.returncode:
        # Never include tool stdout, which may contain conversation bodies or keys.
        raise Blocked(f"Process failed ({result.returncode}): {Path(argv[0]).name}", 1)
    return result


def git_bytes(root, *args, check=True, data=None):
    # The explicit vault path selects the real worktree, refs, objects and index.
    overrides = {"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_IMPLICIT_WORK_TREE", "GIT_INDEX_FILE",
                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_GRAFT_FILE",
                 "GIT_PREFIX", "GIT_INTERNAL_SUPER_PREFIX", "GIT_SHALLOW_FILE", "GIT_REPLACE_REF_BASE",
                 "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"}
    env = {key: value for key, value in os.environ.items() if key.upper() not in overrides}
    return run([executable("git"), "-c", "core.quotepath=false", "-C", root, *args],
               env=env, check=check, data=data).stdout


def git(root, *args, check=True):
    return git_bytes(root, *args, check=check).decode("utf-8").strip()


@contextlib.contextmanager
def lock(path, timeout=15):
    """OS-held lock: a crashed process releases ownership, never deletes a lock."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = path.open("a+b")
    deadline = time.monotonic() + timeout
    acquired = False
    try:
        while not acquired:
            try:
                stream.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError:
                require(time.monotonic() < deadline, "Controller lock is busy", 5)
                time.sleep(0.03)
        stream.seek(0)
        if stream.read(1) == b"":
            stream.write(b"0")
            stream.flush()
        yield
    finally:
        if acquired:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


REGISTRY_PREFIXES = {
    "wiki/claims.jsonl": "C",
    "resources/sources/index.jsonl": "F",
    "wiki/control/decisions.jsonl": "D",
    "wiki/control/lessons.jsonl": "L",
    "wiki/control/query-cases.jsonl": "Q",
}
REGISTRIES = tuple(REGISTRY_PREFIXES)
REQUIRED_REGISTRIES = (*REGISTRIES, "wiki/control/topic-map.jsonl", "wiki/control/selectors.jsonl",
                       "wiki/control/aliases.jsonl", "control/approvals/packages.jsonl")
INGEST_JOURNAL = "source-ingest.json"
TRANSACTION_V2 = "healdan-transaction-v2"


class Vault:
    def __init__(self, root, state=None, *, operational=True, expected_binding=None):
        from .binding import Repository, bound
        self.repository = Repository.open(root)
        self.root = self.repository.root
        self.common = self.repository.common
        self.control = self.repository.control
        self.binding = bound(self.repository, state, expected=expected_binding)
        self.identity = self.binding["vault_id"]
        self.state = Path(self.binding["location"]["state"])
        self.config_path = self.state / "config.json"
        self._lock = threading.local()
        self.refresh_settings()
        if operational:
            with self.reading():
                self.check_registries()

    def refresh_settings(self):
        from .binding import project_config

        with self.reading():
            self.config = project_config(read_json(safe_path(self.state, "config.json"), {}), self.binding)
            self.policy = read_json(Path(__file__).with_name("defaults.json"))
            if "context_bytes" in self.config:
                limits = self.config["context_bytes"]
                require(set(limits) == set(self.policy["context_bytes"]) and
                        all(type(v) is int and v > 0 for v in limits.values()), "Invalid configured context budgets")
                self.policy["context_bytes"] = limits

    def _check_binding(self):
        from .binding import bound
        bound(self.repository, self.state, expected=self.binding)
        if hasattr(self, "controller_selection"):
            from .build import read_selection
            require(read_selection(self.control, self.identity) == self.controller_selection,
                    "Controller selection changed; run the command again", 5)

    @contextlib.contextmanager
    def reading(self, *, stable_integration=False):
        """Revalidate the read view without waiting for unrelated controller writes."""
        if getattr(self._lock, "held", False):
            yield
            return
        self._check_binding()
        before = self.no_transaction() if stable_integration else None
        yield
        if stable_integration:
            require(self.no_transaction() == before, "An integration changed while the command was reading", 5)
        self._check_binding()

    @contextlib.contextmanager
    def locked(self):
        from .binding import pair_lock
        if getattr(self._lock, "held", False):
            yield
            return
        self._check_binding()
        with pair_lock(self.repository, self.state):
            self._check_binding()
            self._lock.held = True
            try:
                yield
            finally:
                self._lock.held = False

    def relocated_path(self, path):
        from .binding import relocated_path
        return relocated_path(path, self.binding)

    def rows(self, name, *, include_bytes=False, root=None):
        required = Path(name).as_posix() in REQUIRED_REGISTRIES
        return read_jsonl(safe_path(root if root is not None else self.root, name, exists=required),
                          required=required, include_bytes=include_bytes)

    def check_registries(self, *, root=None):
        for name in REQUIRED_REGISTRIES:
            self.rows(name, root=root)

    def head(self):
        result = git(self.root, "rev-parse", "--verify", "HEAD", check=False)
        return result or None

    def input_files(self):
        for name in REQUIRED_REGISTRIES:
            path = safe_path(self.root, name, exists=True)
            data = _read_jsonl_bytes(path, required=True)
            parse_jsonl(data, path)
            yield name, data
        for folder in ("wiki", "resources/sources", "templates", "config", "control/approvals"):
            base = self.root / folder
            if base.exists():
                for path in sorted(base.rglob("*")):
                    if path.is_file() or path.is_symlink():
                        rel = path.relative_to(self.root).as_posix()
                        if rel not in REQUIRED_REGISTRIES:
                            yield rel, safe_path(self.root, rel, exists=True).read_bytes()

    def inputs(self):
        return {name: digest(data) for name, data in self.input_files()}

    def fingerprint(self):
        signers = self.config.get("allowed_signers")
        policy_files = {"config": digest(self.config_path.read_bytes()) if self.config_path.is_file() else None,
                        "signers": digest(Path(signers).read_bytes()) if signers and Path(signers).is_file() else None}
        controller = {p.name: digest(p.read_bytes()) for p in Path(__file__).parent.iterdir()
                      if p.suffix in {".py", ".json"}}
        return digest({"head": self.head(), "files": self.inputs(), "policy": self.policy,
                       "config": self.config, "policy_files": policy_files, "controller": controller})

    def receipt(self, kind, payload, *, at=None):
        value = {"kind": kind, "at": stamp(at), "payload": payload}
        identifier = digest(value)
        with self.locked():
            atomic(self.control / "receipts" / (identifier + ".json"), value)
        return identifier

    def no_transaction(self, *, allow_ingest=False):
        pending = read_json(safe_path(self.control, "transaction.json"))
        require(not pending or pending["status"] in {"complete", "aborted"},
                "An integration needs recovery", 5)
        if not allow_ingest:
            ingestion = read_json(safe_path(self.control, INGEST_JOURNAL), {})
            require(ingestion.get("status") != "writing", "An Inbox ingestion needs recovery", 5)
        return pending

    def clean_inputs(self):
        tracked = git_bytes(self.root, "ls-files", "-z").decode("utf-8").split("\0")
        require(set(self.inputs()) <= set(tracked), "Commit preserved sources and canonical inputs before creating a task", 5)
        changed = git(self.root, "diff", "HEAD", "--name-only", "--", "wiki", "resources/sources", "config", "templates", "control/approvals")
        require(not changed, "Canonical task inputs have uncommitted changes", 5)
