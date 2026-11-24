"""A reciprocal vault binding, independent of branches and linked worktrees."""
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

from .core import Blocked, atomic, digest, git, git_bytes, lock, read_json, require, safe_path
from .launchd import legacy_jobs, require_removed

FORMAT = "healdan-vault-binding-v1"
MARKER = "binding.json"
PENDING = "binding-pending.json"
CONFIG_PATHS = ("allowed_signers", "signing_key", "age_identity", "backup_signing_key", "backup_allowed_signers")
CONFIG_ROOTS = ("storage_roots", "backup_destinations")


def git_location(directory, value):
    path = Path(value)
    return (path if path.is_absolute() else directory / path).resolve()


@dataclass(frozen=True)
class Repository:
    root: Path
    primary: Path
    common: Path

    @classmethod
    def open(cls, root):
        root = Path(root).resolve()
        require(root.is_dir() and (root / ".git").exists(), "No Git worktree at the selected vault", 5)
        top = Path(git(root, "rev-parse", "--show-toplevel")).resolve()
        require(top == root, "Select the root of the Git worktree", 5)
        common = Path(git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
        worktrees = git_bytes(root, "worktree", "list", "--porcelain", "-z").split(b"\0")
        first = worktrees[0].decode("utf-8")
        require(first.startswith("worktree "), "Git did not identify the primary worktree")
        return cls(root, Path(first.removeprefix("worktree ")).resolve(), common)

    @property
    def control(self):
        return safe_path(self.common, "healdan")

    @property
    def default_state(self):
        return (Path.home() / ".local/share/healdan" / digest(str(self.common))[:20]).resolve()

    def linked_worktrees(self):
        for admin in sorted(safe_path(self.common, "worktrees").glob("*")):
            pointer = safe_path(self.common, f"worktrees/{admin.name}/gitdir", exists=True)
            linked = git_location(admin, pointer.read_text(encoding="utf-8").rstrip("\r\n"))
            require(linked.name == ".git", "Invalid linked worktree Git metadata", 5)
            yield admin, linked

    def worktree_roots(self):
        return {self.root, self.primary, *(path.parent for _, path in self.linked_worktrees())}

    def location(self, state):
        state = Path(state).resolve()
        require(all(not state.is_relative_to(p) and not p.is_relative_to(state)
                    for p in (self.primary, self.common)),
                "Controller state must be separate from the primary vault and Git common directory", 5)
        require(not any(state.is_relative_to(root) for root in self.worktree_roots()),
                "Controller state must be outside every registered vault worktree", 5)
        require(not state.exists() or state.is_dir(), "Controller state must be a directory")
        return dict(root=str(self.primary), common=str(self.common), state=str(state))


def _optional_file(root, name):
    path = safe_path(root, name)
    if not path.exists():
        return None
    require(path.is_file(), "Expected a regular binding file: " + str(path))
    return path


def _read_location(value):
    require(isinstance(value, dict) and set(value) == {"root", "common", "state"} and
            all(isinstance(p, str) and Path(p).is_absolute() for p in value.values()), "Invalid vault binding location")
    return value


def _validate_marker(value):
    require(isinstance(value, dict) and set(value) == {"format", "vault_id", "location", "previous"} and
            value["format"] == FORMAT and isinstance(value["previous"], list), "Invalid vault binding marker")
    try:
        require(str(UUID(value["vault_id"])) == value["vault_id"], "Invalid vault identity")
    except (ValueError, AttributeError, TypeError) as exc:
        raise Blocked("Invalid vault identity") from exc
    for location in [value["location"], *value["previous"]]:
        _read_location(location)
    return value


def marker(directory):
    path = _optional_file(directory, MARKER)
    return _validate_marker(read_json(path)) if path else None


def _pending(repository):
    path = _optional_file(repository.control, PENDING)
    if not path:
        return None
    value = read_json(path)
    require(isinstance(value, dict) and set(value) == {"transaction", "sha256"} and
            isinstance(value["transaction"], dict) and digest(value["transaction"]) == value["sha256"],
            "Invalid vault binding journal")
    transaction = value["transaction"]
    require(set(transaction) == {"mode", "old", "new", "confirmation", "relocation"} and
            transaction["mode"] in {"setup", "adopt", "rebind"}, "Invalid vault binding journal")
    _validate_marker(transaction["new"])
    if transaction["mode"] == "rebind":
        _validate_marker(transaction["old"])
        require(transaction["old"]["vault_id"] == transaction["new"]["vault_id"] and
                isinstance(transaction["relocation"], dict), "Invalid vault binding transition")
    else:
        require(transaction["old"] is None and transaction["relocation"] is None, "Invalid vault binding transition")
    return transaction


def bound(repository, state=None, *, expected=None):
    require(not _optional_file(repository.control, PENDING), "Vault binding is interrupted; repeat its setup or state operation", 5)
    value = marker(repository.control)
    if not value:
        candidate = Path(state).resolve() if state is not None else repository.default_state
        repository.location(candidate)
        require(not marker(candidate), "External state has a binding that the Git directory does not share", 5)
        raise Blocked("Vault state is unbound; use setup for a new vault or state adopt for a legacy vault", 5)
    selected = Path(value["location"]["state"])
    require(state is None or Path(state).resolve() == selected, "Selected state differs from this vault's binding", 5)
    require(repository.location(selected) == value["location"], "Vault location has changed; use state rebind", 5)
    require(marker(selected) == value, "Git and external state binding markers do not agree", 5)
    require(not _optional_file(repository.control, PENDING), "Vault binding is interrupted; repeat its setup or state operation", 5)
    require(expected is None or expected == value, "Vault binding changed while the operation was open", 5)
    return value


@contextmanager
def pair_lock(repository, state):
    with lock(safe_path(repository.control, "controller.lock")), lock(safe_path(state, "binding.lock")):
        yield


def _loose_entries(directory, ignored):
    return directory.exists() and any(p.name not in ignored for p in directory.iterdir())


def _new_marker(location):
    return {"format": FORMAT, "vault_id": str(uuid4()), "location": location, "previous": []}


def _start(repository, mode, new, *, old=None, confirmation=None, relocation=None):
    transaction = {"mode": mode, "old": old, "new": new, "confirmation": confirmation, "relocation": relocation}
    atomic(repository.control / PENDING, {"transaction": transaction, "sha256": digest(transaction)})
    return _finish(repository, transaction)


def _finish(repository, transaction):
    old, new = transaction["old"], transaction["new"]
    state = Path(new["location"]["state"])
    require(repository.location(state) == new["location"], "Binding journal belongs to a different vault location", 5)
    common_marker, state_marker = marker(repository.control), marker(state)
    require(common_marker in (old, new) and state_marker in (old, new),
            "Binding recovery found an unexpected marker; no marker was replaced", 5)
    if transaction["mode"] == "adopt":
        require_removed(legacy_jobs(new["location"]), "adoption")
    if transaction["relocation"] is not None:
        from .relocation import apply_relocation
        apply_relocation(repository, new, transaction["relocation"])
    if state_marker != new:
        atomic(state / MARKER, new)
    if common_marker != new:
        atomic(repository.control / MARKER, new)
    (repository.control / PENDING).unlink()
    return new


def _resume(repository, transaction, state, mode, confirmation):
    require(transaction["mode"] == mode and transaction["confirmation"] == confirmation,
            "An interrupted binding needs the original operation and confirmation", 5)
    path = Path(transaction["new"]["location"]["state"])
    require(state is None or Path(state).resolve() == path, "Interrupted binding names a different external state", 5)
    repository.location(path)
    with pair_lock(repository, path):
        current = _pending(repository)
        if current is None:
            return bound(repository, path, expected=transaction["new"])
        require(current == transaction, "Binding journal changed while reopening the operation", 5)
        return _finish(repository, current)


def _new_state(repository, state):
    require(not marker(state), "External state is already bound to a vault", 5)
    require(not _loose_entries(state, {"binding.lock"}),
            "Existing external state requires explicit state adoption", 5)
    require(not _loose_entries(repository.control, {"controller.lock"}) and
            (state == repository.default_state or not _loose_entries(repository.default_state, {"binding.lock"})),
            "Legacy controller data requires explicit state adoption", 5)


def setup_binding(root, state):
    root = Path(root).resolve()
    if not (root / ".git").exists():
        prospective = Repository(root, root, root / ".git")
        candidate = Path(state).resolve() if state is not None else prospective.default_state
        prospective.location(candidate)
        _new_state(prospective, candidate)
        with lock(safe_path(candidate, "binding.lock")):
            if not (root / ".git").exists():
                _new_state(prospective, candidate)
                root.mkdir(parents=True, exist_ok=True)
                git(root, "init", "-b", "main")
    repository = Repository.open(root)
    pending = _pending(repository)
    if pending:
        return _resume(repository, pending, state, "setup", None)
    existing = marker(repository.control)
    if existing:
        return bound(repository, state)
    candidate = Path(state).resolve() if state is not None else repository.default_state
    location = repository.location(candidate)
    _new_state(repository, candidate)
    with pair_lock(repository, candidate):
        pending = _pending(repository)
        if pending:
            require(pending["mode"] == "setup" and pending["new"]["location"] == location,
                    "An interrupted binding names another operation or state", 5)
            return _finish(repository, pending)
        if marker(repository.control):
            return bound(repository, state if state is not None else candidate)
        _new_state(repository, candidate)
        candidate.chmod(0o700)
        return _start(repository, "setup", _new_marker(location))


def stage_recovered_binding(staging, destination, state, vault_id):
    """Prepare the reciprocal markers for publication at the recovered location."""
    staged = Repository.open(staging)
    require(staged.root == staged.primary and staged.common == staging / ".git",
            "Recovery staging is not a standalone repository", 5)
    repository = Repository(destination, destination, destination / ".git")
    value = _validate_marker({"format": FORMAT, "vault_id": vault_id,
                              "location": repository.location(state), "previous": []})
    with pair_lock(staged, state):
        require(marker(state) in (None, value) and marker(staged.control) in (None, value),
                "Recovery binding would replace a foreign state marker", 5)
        atomic(state / MARKER, value)
        atomic(staged.control / MARKER, value)
    return value


def relocated_path(path, binding):
    original = Path(path)
    if not original.is_absolute():
        return original
    current = {name: Path(value) for name, value in binding["location"].items()}
    if any(original.is_relative_to(location) for location in current.values()):
        return original
    candidates = [(name, Path(value)) for locations in binding["previous"] for name, value in locations.items()
                  if original.is_relative_to(Path(value))]
    if not candidates:
        return original
    name, location = max(candidates, key=lambda entry: len(entry[1].parts))
    return current[name] / original.relative_to(location)


def project_config(config, binding):
    require(isinstance(config, dict), "Controller configuration must be an object")
    projected = dict(config)
    for name in CONFIG_PATHS:
        if isinstance(config.get(name), str) and config[name]:
            path = relocated_path(config[name], binding)
            if path != Path(config[name]):
                projected[name] = str(path)
    for name in CONFIG_ROOTS:
        if isinstance(config.get(name), list) and all(isinstance(value, str) for value in config[name]):
            projected[name] = [str(relocated_path(value, binding)) for value in config[name]]
    return projected


def project_record(record, binding, fields):
    if record:
        for field in fields:
            if record.get(field):
                path = relocated_path(record[field], binding)
                if path != Path(record[field]):
                    record[field] = str(path)
    return record


def _legacy_plan(repository, state):
    location = repository.location(state)
    require(not marker(repository.control) and not marker(state), "Cannot adopt a unilateral or foreign binding", 5)
    config = _optional_file(state, "config.json")
    restored = _optional_file(repository.control, "restored-from.json")
    proof = []
    if restored and not _loose_entries(state, {"binding.lock"}):
        source = read_json(restored)
        require(source.get("format") == "healdan-restored-vault-v1" and
                source.get("commit") == git(repository.root, "rev-parse", "--verify", "HEAD", check=False),
                "Restored vault provenance is unavailable or ambiguous", 5)
        proof.append({"kind": "restored-backup", "sha256": digest(restored.read_bytes())})
    else:
        require(config, "Legacy external state configuration is unavailable", 5)
        require(isinstance(read_json(config), dict), "Legacy external configuration is invalid", 5)
        if state == repository.default_state:
            proof.append({"kind": "legacy-default-location", "path": str(state)})
        from .relocation import legacy_proof
        proof.extend(legacy_proof(repository, state))
        require(proof, "Custom state origin is ambiguous; no Git worktree or custody record identifies it", 5)
    return {"mode": "adopt", "location": location, "provenance": proof,
            "config_sha256": digest(config.read_bytes()) if config else None}


def adopt(root, state=None, confirmation=None):
    repository = Repository.open(root)
    pending = _pending(repository)
    if pending:
        require(confirmation is not None, "Interrupted adoption requires its original confirmation", 5)
        value = _resume(repository, pending, state, "adopt", confirmation)
        return {"status": "adopted", "binding": value}
    existing = marker(repository.control)
    if existing:
        existing = bound(repository, state)
        jobs = legacy_jobs(existing["location"], existing["previous"])
        if confirmation is not None:
            require_removed(jobs, "adoption")
        return {"status": "already-bound", "binding": existing, "legacy_launchagents": jobs}
    candidate = Path(state).resolve() if state is not None else repository.default_state
    plan = _legacy_plan(repository, candidate)
    if confirmation is None:
        return {"status": "preview", "confirmation": digest(plan), **plan,
                "legacy_launchagents": legacy_jobs(plan["location"])}
    require(confirmation == digest(plan), "Adoption differs from the confirmed preview", 5)
    with pair_lock(repository, candidate):
        require_removed(legacy_jobs(plan["location"]), "adoption")
        pending = _pending(repository)
        if pending:
            require(pending["mode"] == "adopt" and pending["confirmation"] == confirmation and
                    pending["new"]["location"] == plan["location"], "Another binding operation is pending", 5)
            value = _finish(repository, pending)
        elif marker(repository.control):
            value = bound(repository, candidate)
        else:
            require(_legacy_plan(repository, candidate) == plan, "Adoption changed after the preview", 5)
            candidate.chmod(0o700)
            value = _start(repository, "adopt", _new_marker(plan["location"]), confirmation=confirmation)
    return {"status": "adopted", "binding": value}


def rebind(root, state=None, confirmation=None):
    from .relocation import relocation_plan, relocation_summary

    repository = Repository.open(root)
    pending = _pending(repository)
    if pending:
        require(confirmation is not None, "Interrupted reassociation requires its original confirmation", 5)
        value = _resume(repository, pending, state, "rebind", confirmation)
        return {"status": "rebound", "binding": value}
    old = marker(repository.control)
    require(old, "Reassociation requires the original Git binding marker", 5)
    candidate = Path(state).resolve() if state is not None else Path(old["location"]["state"])
    location = repository.location(candidate)
    require(marker(candidate) == old, "Moved external state must carry the vault's original marker", 5)
    if location == old["location"]:
        return {"status": "already-bound", "binding": bound(repository, candidate)}
    new = {**old, "location": location, "previous": old["previous"] + [old["location"]]}
    plan = relocation_plan(repository, old, new)
    token = digest({"old": old, "new": new, "plan": plan})
    if confirmation is None:
        return {"status": "preview", "confirmation": token, "from": old["location"], "to": location,
                **relocation_summary(plan)}
    require(confirmation == token, "Reassociation differs from the confirmed preview", 5)
    with pair_lock(repository, candidate):
        pending = _pending(repository)
        if pending:
            require(pending["mode"] == "rebind" and pending["confirmation"] == confirmation and
                    pending["new"] == new, "Another binding operation is pending", 5)
            value = _finish(repository, pending)
        elif marker(repository.control) == new:
            value = bound(repository, candidate)
        else:
            require(marker(repository.control) == marker(candidate) == old and
                    relocation_plan(repository, old, new) == plan, "Reassociation changed after the preview", 5)
            value = _start(repository, "rebind", new, old=old, confirmation=confirmation, relocation=plan)
    return {"status": "rebound", "binding": value}
