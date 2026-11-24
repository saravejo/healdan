"""Reconcile the worktree and its index after publishing an integration."""
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import stat

from .core import Blocked, atomic, digest, file_digest, require, safe_path, sync_directory
from .integration_git import admin_dir, index_entries, index_settings, line, update_index
from .integration_files import (directory_handle, prepare_file, read_integration_file, remove_empty_directory,
                                remove_verified, rename_exclusive, snapshot)
from .integration_journal import decode_bytes, encode, persist, sha


def modification(path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    return [metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns]


def secure_target(root, name):
    try:
        target = safe_path(root, name)
    except Blocked as exc:
        raise Blocked("Integration file path changed: " + name, 5) from exc
    for parent in target.relative_to(root).parents:
        directory = root / parent
        require(not directory.is_junction() and (not directory.exists() or directory.is_dir()),
                "Integration path parent changed: " + name, 5)
    return target


def scratch_directories(vault, operation):
    admin = admin_dir(vault.root)
    index_directory = secure_target(admin, "healdan-integration/" + operation)
    directory = index_directory
    if admin.stat().st_dev != vault.root.stat().st_dev:
        directory = secure_target(vault.root, ".healdan-integration/" + operation)
    return directory, index_directory


def file_scratch(directory, name):
    key = digest(name.encode("utf-8"))
    return directory / (key + ".next"), directory / (key + ".before")


class WorktreeEffects:
    def __init__(self, vault, path, journal, bodies, overlay):
        self.vault = vault
        self.path = path
        self.journal = journal
        self.bodies = bodies
        self.overlay = overlay
        self.directory, self.index_directory = scratch_directories(vault, journal["operation"])

    def change(self, name, phase):
        self.journal["written"][name] = phase
        persist(self.path, self.journal)

    def known_paths(self, name):
        return secure_target(self.vault.root, name), *file_scratch(self.directory, name)

    def previous(self, name):
        checksum = self.journal["before"][name]
        return [checksum, self.journal["worktree_modes"][name]] if checksum is not None else None

    def approved(self, name):
        mode = 0o755 if os.name != "nt" and self.overlay[name][0] == "100755" else 0o644
        return [digest(self.bodies[name]), mode]

    def conflict(self, name, phase):
        raise Blocked(f"Integration {phase} conflict: {name}", 5)

    def keep_displaced(self, name, target, displaced, actual):
        recorded = self.journal["reconciliation"].get(name)
        if recorded is not None and recorded["observed"] == actual:
            return recorded
        evidence = {"name": displaced.name, "observed": actual, "target": modification(target)}
        if actual and actual[0] != "non-regular":
            observed, body = read_integration_file(displaced)
            require(observed == actual, "Integration displaced copy is changing: " + name, 5)
            evidence["body"] = encode(body)
        self.journal["reconciliation"][name] = evidence
        persist(self.path, self.journal)
        return evidence

    def examine(self, name):
        """Check effects already in flight before advancing any other path."""
        target, prepared, displaced = self.known_paths(name)
        phase = self.journal["written"][name]
        before, expected = self.previous(name), self.approved(name)
        actual, ready, saved = snapshot(target), snapshot(prepared), snapshot(displaced)
        pristine = actual == before
        if phase == "pending":
            require(ready is None and saved is None, "Unexpected integration files: " + name, 5)
            if not pristine and not (self.journal.get("legacy") and actual == expected):
                self.conflict(name, phase)
        if phase == "installed" and actual != expected:
            self.conflict(name, phase)
        if phase == "preparing" and (not pristine or saved is not None or ready not in (None, expected)):
            self.conflict(name, phase)
        if phase == "prepared" and before is not None and (not pristine or ready != expected or saved is not None):
            self.conflict(name, phase)
        if phase == "displacing" and not (
                saved is None and pristine and ready == expected or
                saved is not None and ready == expected or
                saved is not None and ready is None and actual == expected):
            self.conflict(name, phase)
        if phase == "displaced" and (saved is None or not (
                ready == expected and actual is None or ready is None and actual == expected)):
            self.conflict(name, phase)
        if saved is not None and saved != before:
            recorded = self.keep_displaced(name, target, displaced, saved)
            # An explicit restoration of the approved target leaves the external copy recoverable.
            if actual != expected or modification(target) == recorded["target"]:
                self.conflict(name, "displaced copy")
        if phase == "installed" and before not in (None, expected) and saved is None and not self.journal.get("legacy"):
            self.conflict(name, "missing displaced copy")
        if name in self.journal["reconciliation"] and saved is None:
            self.conflict(name, "missing reconciliation copy")
        if phase == "prepared" and before is None and not (
                actual is None and ready == expected or actual == expected and ready is None):
            self.conflict(name, phase)
        return actual, ready, saved

    def reconcile(self, name):
        target, prepared, displaced = self.known_paths(name)
        expected = self.approved(name)
        actual, ready, saved = self.examine(name)
        phase = self.journal["written"][name]
        if phase == "installed":
            return
        if actual == expected and (phase == "pending" or ready is None or saved is not None and
                                   name in self.journal["reconciliation"]):
            self.change(name, "installed")
            return
        if phase == "pending":
            self.change(name, "preparing")
            phase = "preparing"
        if phase == "preparing":
            if ready is None:
                prepare_file(prepared, self.bodies[name], expected[1])
            require(snapshot(prepared) == expected, "Prepared integration bytes differ: " + name)
            self.change(name, "prepared")
            phase = "prepared"
        with directory_handle(target.parent, create=True):
            pass
        if self.previous(name) is not None:
            if phase == "prepared":
                self.examine(name)
                self.change(name, "displacing")
            if saved is None:
                try:
                    rename_exclusive(target, displaced)
                except (FileNotFoundError, FileExistsError):
                    self.conflict(name, "displacing")
            saved = snapshot(displaced)
            if saved != self.previous(name):
                if saved is not None:
                    self.keep_displaced(name, target, displaced, saved)
                self.conflict(name, "displaced copy")
            self.change(name, "displaced")
        try:
            rename_exclusive(prepared, target)
        except (FileNotFoundError, FileExistsError):
            self.conflict(name, "installing")
        require(snapshot(target) == expected, "Integration installed file changed: " + name, 5)
        self.change(name, "installed")

    def verify(self):
        for name in self.bodies:
            self.examine(name)


def index_paths(vault, directory):
    index = Path(line(vault.root, "rev-parse", "--path-format=absolute", "--git-path", "index"))
    require(index.parent == admin_dir(vault.root), "Git index is outside the integration worktree", 5)
    return index, index.with_name("index.lock"), directory / "index-owner"


def owns_index_lock(lock_path, owner):
    try:
        return not lock_path.is_symlink() and not owner.is_symlink() and lock_path.samefile(owner)
    except FileNotFoundError:
        return False


def release_index_lock(lock_path, owner):
    if owns_index_lock(lock_path, owner):
        lock_path.unlink()


@contextmanager
def locked_index(vault, directory):
    index, lock_path, owner = index_paths(vault, directory)
    with directory_handle(directory, create=True):
        pass
    if owner.exists() and index.exists() and index.samefile(owner):
        owner.unlink()  # The previous attempt published this inode before it could unlink the token.
    if not owner.exists():
        prepare_file(owner, b"", 0o600)
    try:
        os.link(owner, lock_path)
    except FileExistsError:
        require(owns_index_lock(lock_path, owner), "Git index is locked by another process", 5)
    try:
        yield index, lock_path, owner
    finally:
        release_index_lock(lock_path, owner)


def expected_index(proposed):
    return {name: [[mode, object_id, 0, 0]] for name, (mode, object_id) in proposed.items()}


def check_index(current, expected):
    names = [name for name in expected if current[name] != expected[name]]
    require(not names, "Integration index differs: " + ", ".join(names), 5)


def reconcile_index(vault, directory, before, proposed, *, verify_ref):
    with locked_index(vault, directory) as (index, lock_path, owner):
        verify_ref()
        after = expected_index(proposed)
        current = index_entries(vault.root, before, settings={"GIT_OPTIONAL_LOCKS": "0"})
        if current == after:
            return
        check_index(current, before)
        private = directory / "index-next"
        private_lock = private.with_name("index-next.lock")
        # These are scratch files for a Git subprocess within an owned index lock.
        private.unlink(missing_ok=True)
        private_lock.unlink(missing_ok=True)
        if index.exists():
            shutil.copyfile(safe_path(index.parent, index.name, exists=True), private)
            if os.name != "nt":
                os.chmod(owner, stat.S_IMODE(index.stat().st_mode))
        settings = index_settings(private)
        update_index(vault.root, proposed, settings)
        require(index_entries(vault.root, before, settings=settings) == after,
                "Prepared integration index differs", 5)
        atomic(directory / "index-next.sha256", file_digest(private).encode("ascii"))
        with private.open("rb") as source, owner.open("r+b") as staged:
            staged.seek(0)
            shutil.copyfileobj(source, staged)
            staged.truncate()
            staged.flush()
            os.fsync(staged.fileno())
        verify_ref()
        require(owns_index_lock(lock_path, owner), "Git index lock changed during integration", 5)
        os.replace(lock_path, index)
        sync_directory(index.parent)
        owner.unlink()


@contextmanager
def confirmed_index(vault, directory, proposed):
    """Hold Git's writer lock from the last index check through completion."""
    with locked_index(vault, directory) as (_, lock_path, owner):
        check_index(index_entries(vault.root, proposed, settings={"GIT_OPTIONAL_LOCKS": "0"}),
                    expected_index(proposed))
        yield
        require(owns_index_lock(lock_path, owner), "Git index lock changed during integration", 5)


def cleanup_completed(vault, journal):
    directory, index_directory = scratch_directories(vault, journal["operation"])
    index, lock_path, owner = index_paths(vault, index_directory)
    release_index_lock(lock_path, owner)
    for name, encoded in journal["files"].items():
        prepared, displaced = file_scratch(directory, name)
        remove_verified(prepared, digest(decode_bytes(encoded)))
        if name not in journal["reconciliation"] and journal["before"][name] is not None:
            remove_verified(displaced, journal["before"][name])
    proof = index_directory / "index-next.sha256"
    _, declared = read_integration_file(proof)
    private = index_directory / "index-next"
    if declared is not None:
        checksum = declared.decode("ascii", errors="replace")
        if sha(checksum) and remove_verified(private, checksum):
            remove_verified(proof, digest(declared))
    elif private.is_file() and index.is_file():
        # R1 recorded no separate checksum for the private index.
        remove_verified(private, file_digest(index))
    remove_verified(owner, digest(b""))
    for scratch in {directory, index_directory}:
        remove_empty_directory(scratch)
        remove_empty_directory(scratch.parent)
