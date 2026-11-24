"""Preflight a moved vault without rewriting signed custody or historical records."""
import base64
from pathlib import Path
import plistlib

from .binding import CONFIG_PATHS, CONFIG_ROOTS, git_location, relocated_path
from .core import atomic, digest, git, read_json, require, safe_path
from .launchd import JOBS, installed_jobs, job_label, legacy_labels, require_removed

SESSION_PATHS = ("proposal", "active_profile", "recovery_profile")


def _records(repository, directory):
    for path in sorted(safe_path(repository.control, directory).glob("*.json")):
        yield read_json(safe_path(repository.control, f"{directory}/{path.name}", exists=True))


def _backlink(linked):
    text = safe_path(linked.parent, ".git", exists=True).read_text(encoding="utf-8").rstrip("\r\n")
    require(text.startswith("gitdir: "), "Invalid linked worktree backlink: " + str(linked), 5)
    return git_location(linked.parent, text.removeprefix("gitdir: "))


def _materials(repository):
    return read_json(safe_path(repository.control, "materials.json"), {}).values()


def legacy_proof(repository, state):
    """Only a recorded path and independently verifiable evidence establish custom provenance."""
    proof = []
    linked = {path.parent: admin for admin, path in repository.linked_worktrees()}
    for task in _records(repository, "tasks"):
        worktree = Path(task["worktree"])
        require(worktree == state / "tasks" / task["id"] / "worktree",
                "Recorded task worktree identifies a different external state", 5)
        if worktree in linked and worktree.is_dir():
            require(_backlink(worktree / ".git") == linked[worktree],
                    "Legacy task worktree administrative links disagree", 5)
            proof.append({"kind": "git-worktree", "path": str(worktree), "git_directory": str(linked[worktree])})
    for session in _records(repository, "sessions"):
        for field in ("proposal", "active_profile"):
            if session.get(field):
                require(Path(session[field]).is_relative_to(state / "tasks"),
                        "Recorded session identifies a different external state", 5)
    for record in _materials(repository):
        if record.get("kind") == "backup":
            continue
        for copy in record["copies"]:
            if copy["kind"] != "ciphertext":
                continue
            root = Path(copy["root"])
            require(root == state / "custody", "Controller ciphertext identifies a different external state", 5)
            if copy.get("status") == "present":
                cipher = safe_path(root, copy["path"], exists=True)
                require(digest(cipher.read_bytes()) == copy["sha256"], "Legacy custody bytes disagree with Git control", 5)
                proof.append({"kind": "custody", "path": str(cipher), "sha256": copy["sha256"]})
    return proof


def _linked_worktrees(repository, old, new):
    """Validate both ends of every registered link, including links that need repair."""
    worktrees = []
    targets = set()
    previous_common = Path(old["location"]["common"])
    for admin, linked in repository.linked_worktrees():
        target = relocated_path(linked, new)
        require(target not in targets, "Multiple Git worktrees point to: " + str(target.parent), 5)
        targets.add(target)
        original_present = linked.parent.exists() or linked.parent.is_symlink()
        target_present = target.parent.exists() or target.parent.is_symlink()
        if not original_present and not target_present:
            require(_removed_task_worktree(repository, target, new) and
                    not (admin / "locked").exists() and not (admin / "locked").is_symlink(),
                    "Missing Git worktree has no confirmed removal. Reconcile it before reassociation: " + str(target.parent), 5)
            worktrees.append({"path": str(target.parent), "git_directory": str(admin),
                              "needs_repair": False, "removed": True})
            continue
        require(target.is_file(), "Linked worktree backlink is unavailable: " + str(target), 5)
        expected = previous_common / admin.relative_to(repository.common)
        backlink = _backlink(target)
        require(backlink in (admin, expected), "Linked worktree points to another Git directory: " + str(target), 5)
        require(target == linked or not linked.exists(), "Both original and relocated worktrees exist: " + str(linked), 5)
        worktrees.append({"path": str(target.parent), "git_directory": str(admin),
                          "needs_repair": linked != target or backlink != admin})
    return worktrees


def _removed_task_worktree(repository, target, binding):
    worktree = target.parent
    state = Path(binding["location"]["state"])
    if worktree.name != "worktree" or worktree.parent.parent != state / "tasks":
        return False
    safe_path(state, worktree.relative_to(state))
    require(worktree.resolve() == worktree, "Missing worktree path is aliased: " + str(worktree), 5)
    task_id = worktree.parent.name
    task = read_json(safe_path(repository.control, f"tasks/{task_id}.json"))
    return (isinstance(task, dict) and task.get("id") == task_id and task.get("worktree_removed") is True and
            not task.get("processes") and isinstance(task.get("worktree"), str) and
            relocated_path(task["worktree"], binding) == worktree)


def _references(repository, binding, worktrees):
    state = Path(binding["location"]["state"])
    config = read_json(safe_path(state, "config.json"), {})
    locations = []

    def report(kind, original, target):
        locations.append({"kind": kind, "from": str(original), "to": str(target)})

    for name in (*CONFIG_PATHS, *CONFIG_ROOTS):
        values = config.get(name)
        for value in (values or []) if name in CONFIG_ROOTS else ([values] if values else []):
            original = Path(value)
            target = relocated_path(original, binding)
            if target != original or name in CONFIG_ROOTS:
                target = safe_path(target.parent, target.name)
                available = target.is_dir() if name in CONFIG_ROOTS else target.is_file()
                require(available, "Reassociation configuration path is unavailable: " + str(target), 5)
                report("config:" + name, original, target)

    registered = {Path(tree["path"]) for tree in worktrees if not tree.get("removed")}
    for task in _records(repository, "tasks"):
        require(not task.get("processes"), "Reconcile active native tasks before moving the vault", 5)
        original = Path(task["worktree"])
        target = relocated_path(original, binding)
        if target != original:
            require(target in registered or task.get("worktree_removed") or task["state"] in {"closed", "cancelled"},
                    "Relocated task worktree is unavailable: " + str(target), 5)
            report("task:worktree", original, target)

    for session in _records(repository, "sessions"):
        require(session.get("state") != "running", "Reconcile running sessions before moving the vault", 5)
        for name in SESSION_PATHS:
            if not session.get(name):
                continue
            original = Path(session[name])
            target = relocated_path(original, binding)
            if target != original:
                require(safe_path(target.parent, target.name).is_dir(),
                        "Relocated session directory is unavailable: " + str(target), 5)
                report("session:" + name, original, target)

    for record in _materials(repository):
        for copy in record["copies"]:
            if copy.get("status") == "unavailable" and copy.get("kind") is None:
                continue
            original = Path(copy["root"])
            target = relocated_path(original, binding)
            status = copy.get("status")
            ciphertext = status == "present" and copy["kind"] == "ciphertext"
            if target == original and not ciphertext:
                continue
            file = safe_path(target, copy["path"])
            if ciphertext:
                require(file.is_file(), "Relocated ciphertext is unavailable: " + str(file), 5)
            if status == "present" and file.exists():
                # A Git worktree backlink is repaired in place. Its archived bytes stay in custody.
                backlink = file.name == ".git" and file.parent in registered and copy["kind"] == "checkpoint"
                require(backlink or (file.is_file() and digest(file.read_bytes()) == copy["sha256"]),
                        "Relocated custody bytes changed: " + str(file), 5)
            report("custody:" + status, original / copy["path"], file)

    for deletion in _records(repository, "deletions"):
        for entry in deletion["entries"]:
            copy = entry["copy"]
            original = Path(copy["root"])
            target = relocated_path(original, binding)
            if target != original:
                report("deletion:" + entry["status"], original / copy["path"], safe_path(target, copy["path"]))
    return locations


def _plists(binding):
    state = Path(binding["location"]["state"])
    plists = []
    for path in sorted(safe_path(state, "launchd").glob("*.plist")):
        original = safe_path(state, f"launchd/{path.name}", exists=True).read_bytes()
        value = plistlib.loads(original)
        label = value.get("Label", "")
        args = value.get("ProgramArguments")
        require(label.startswith("org.healdan.") and path.name == label + ".plist" and isinstance(args, list) and
                len(args) >= 6 and isinstance(args[0], str) and Path(args[0]).is_absolute() and
                args[1] == "--vault" and args[3] == "--state", "Unrecognized launchd definition: " + str(path), 5)
        command = args[5:]
        if command[0] == "--vault-id":
            require(command[1:2] == [binding["vault_id"]], "Launchd definition has a different vault identity", 5)
            command = command[2:]
        else:
            args[5:5] = ["--vault-id", binding["vault_id"]]
        if command in (["lint"], ["maintenance", "daily"]):
            args[-len(command):] = ["maintenance", "run-scheduled", command[-1]]
        else:
            require(len(command) == 3 and command[:2] == ["maintenance", "run-scheduled"] and command[2] in {"lint", "daily"},
                    "Unrecognized launchd command: " + str(path), 5)
        args[2] = str(relocated_path(args[2], binding))
        args[4] = str(relocated_path(args[4], binding))
        require(Path(args[2]) == Path(binding["location"]["root"]) and Path(args[4]) == state,
                "Launchd definition points to a different vault: " + str(path), 5)
        program = relocated_path(args[0], binding)
        if program != Path(args[0]):
            require(program.is_file(), "Relocated launchd controller is unavailable: " + str(program), 5)
            args[0] = str(program)
        for log in ("StandardOutPath", "StandardErrorPath"):
            target = relocated_path(value[log], binding)
            require(target.is_relative_to(state), "Launchd log is outside controller state: " + str(target), 5)
            value[log] = str(safe_path(state, target.relative_to(state)))
        updated = plistlib.dumps(value)
        if plistlib.loads(original) == value:
            continue
        plists.append({"name": path.name, "before": digest(original), "after": digest(updated),
                       "value": base64.b64encode(updated).decode("ascii")})
    return plists


def _validate_jobs(old, new):
    state = Path(new["location"]["state"])
    labels = {path.stem for path in safe_path(state, "launchd").glob("org.healdan.*.plist")}
    labels.update(job_label(old["vault_id"], job) for job in JOBS)
    labels.update(job_label(old["vault_id"], job, trial=True) for job in JOBS)
    for location in [old["location"], *old["previous"]]:
        labels.update(legacy_labels(location["common"]))
    require_removed(installed_jobs(labels), "reassociation")


def _validate_move(repository, old, new):
    for name, value in old["location"].items():
        previous = Path(value)
        current = Path(new["location"][name])
        if previous != current:
            require(not previous.exists() and not previous.is_symlink(),
                    "Original location is still occupied: " + value, 5)
            require(not current.is_relative_to(previous) and not previous.is_relative_to(current),
                    "Original and relocated paths overlap: " + value, 5)
    for location in new["previous"]:
        for name, value in location.items():
            previous = Path(value)
            current = Path(new["location"][name])
            require(previous == current or not (current.is_relative_to(previous) or previous.is_relative_to(current)),
                    "Relocation overlaps a historical path: " + value, 5)
        historic_state = Path(location["state"])
        for name in ("root", "common"):
            current = Path(new["location"][name])
            require(not current.is_relative_to(historic_state) and not historic_state.is_relative_to(current),
                    "Vault location overlaps a historical state path: " + str(historic_state), 5)
            current_state = Path(new["location"]["state"])
            historic_git = Path(location[name])
            require(not current_state.is_relative_to(historic_git) and not historic_git.is_relative_to(current_state),
                    "External state overlaps a historical vault path: " + str(historic_git), 5)
    journal = read_json(safe_path(repository.control, "transaction.json"))
    require(not journal or journal.get("status") == "complete", "Recover the integration before reassociation", 5)
    _validate_jobs(old, new)


def relocation_plan(repository, old, new):
    _validate_move(repository, old, new)
    worktrees = _linked_worktrees(repository, old, new)
    return {"old": old, "worktrees": worktrees, "paths": _references(repository, new, worktrees), "plists": _plists(new)}


def relocation_summary(plan):
    return {"worktrees": plan["worktrees"], "paths": plan["paths"],
            "plists": [{k: v for k, v in item.items() if k != "value"} for item in plan["plists"]]}


def apply_relocation(repository, binding, plan):
    _validate_move(repository, plan["old"], binding)
    worktrees = _linked_worktrees(repository, plan["old"], binding)
    fields = ("path", "git_directory", "removed")
    require([tuple(tree.get(key) for key in fields) for tree in worktrees] ==
            [tuple(tree.get(key) for key in fields) for tree in plan["worktrees"]] and
            _references(repository, binding, worktrees) == plan["paths"],
            "Reassociation paths changed after confirmation", 5)
    changes = []
    state = Path(binding["location"]["state"])
    for plist in plan["plists"]:
        path = safe_path(state / "launchd", plist["name"], exists=True)
        updated = base64.b64decode(plist["value"], validate=True)
        current = digest(path.read_bytes())
        require(digest(updated) == plist["after"] and current in (plist["before"], plist["after"]),
                "Launchd definition changed after confirmation: " + str(path), 5)
        if current == plist["before"]:
            changes.append((path, updated))
    repair = [tree["path"] for tree in worktrees if tree["needs_repair"]]
    if repair:
        git(repository.root, "worktree", "repair", *repair)
        require(not any(t["needs_repair"] for t in _linked_worktrees(repository, plan["old"], binding)),
                "Git worktree repair needs reconciliation", 5)
    for path, updated in changes:
        atomic(path, updated)
