"""Reconcile the worktree and its index after publishing an integration."""
from contextlib import ExitStack, contextmanager
import ctypes
import errno
import os
from pathlib import Path
import shutil
import stat
import sys

from .core import Blocked, atomic, digest, require, safe_path, sync_directory
from .integration_git import admin_dir, index_entries, index_settings, line, update_index
from .integration_journal import encode, persist


def snapshot(path):
    try:
        metadata = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        return ["non-regular", None]
    try:
        with path.open("rb") as stream:
            current = os.fstat(stream.fileno())
            require(os.path.samestat(current, metadata), "Concurrent file replacement: " + str(path), 5)
            return [digest(stream.read()), 0o755 if current.st_mode & stat.S_IXUSR else 0o644]
    except FileNotFoundError:
        return None


def modification(path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    return [metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns]


@contextmanager
def parent_fd(path):
    if os.name == "nt":
        yield None
        return
    with ExitStack() as stack:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parts = path.absolute().parts
        descriptor = os.open(parts[0], flags)
        stack.callback(os.close, descriptor)
        for part in parts[1:]:
            descriptor = os.open(part, flags, dir_fd=descriptor)
            stack.callback(os.close, descriptor)
        yield descriptor


def rename_exclusive(source, destination):
    """Consume source atomically, only if the destination name is unoccupied."""
    if os.name == "nt":
        os.rename(source, destination)
    else:
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform.startswith("linux"):
            rename, flag = getattr(library, "renameat2", None), 1  # RENAME_NOREPLACE
        elif sys.platform == "darwin":
            rename, flag = getattr(library, "renameatx_np", None), 4  # RENAME_EXCL
        else:
            rename, flag = None, 0
        require(rename is not None, "Exclusive integration rename is unavailable", 5)
        with parent_fd(source.parent) as src, parent_fd(destination.parent) as dst:
            if rename(src, os.fsencode(source.name), dst, os.fsencode(destination.name), flag):
                code = ctypes.get_errno()
                if code in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL, errno.EXDEV}:
                    raise Blocked("Exclusive integration rename is unavailable on this volume", 5)
                raise OSError(code, os.strerror(code), str(destination))
    sync_directory(source.parent)
    if destination.parent != source.parent:
        sync_directory(destination.parent)


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


class WorktreeEffects:
    def __init__(self, vault, path, journal, bodies, overlay):
        self.vault = vault
        self.path = path
        self.journal = journal
        self.bodies = bodies
        self.overlay = overlay
        admin = admin_dir(vault.root)
        self.index_directory = safe_path(admin, "healdan-integration/" + journal["operation"])
        if admin.stat().st_dev == vault.root.stat().st_dev:
            self.directory = self.index_directory
        else:
            self.directory = secure_target(vault.root, ".healdan-integration/" + journal["operation"])

    def change(self, name, phase):
        self.journal["written"][name] = phase
        persist(self.path, self.journal)

    def known_paths(self, name):
        key = digest(name.encode("utf-8"))
        return (secure_target(self.vault.root, name), self.directory / (key + ".next"),
                self.directory / (key + ".before"))

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
            body = displaced.read_bytes()
            require(digest(body) == actual[0], "Integration displaced copy is changing: " + name, 5)
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
            self.directory.mkdir(parents=True, exist_ok=True)
            if ready is None:
                atomic(prepared, self.bodies[name], mode=expected[1])
                os.chmod(prepared, expected[1])
            require(snapshot(prepared) == expected, "Prepared integration bytes differ: " + name)
            self.change(name, "prepared")
            phase = "prepared"
        target.parent.mkdir(parents=True, exist_ok=True)
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


def reconcile_index(vault, directory, before, proposed, *, verify_ref, completed=False):
    index = Path(line(vault.root, "rev-parse", "--path-format=absolute", "--git-path", "index"))
    require(index.parent == admin_dir(vault.root), "Git index is outside the integration worktree", 5)
    lock_path = index.with_name("index.lock")
    directory.mkdir(parents=True, exist_ok=True)
    owner = directory / "index-owner"
    if owner.exists() and index.exists() and index.samefile(owner):
        owner.unlink()  # The previous attempt published this inode before it could unlink the token.
    if not owner.exists():
        atomic(owner, b"")
    try:
        verify_ref()
        os.link(owner, lock_path)
    except FileExistsError:
        require(not lock_path.is_symlink() and lock_path.samefile(owner), "Git index is locked by another process", 5)
    try:
        after = {name: [[mode, object_id, 0, 0]] for name, (mode, object_id) in proposed.items()}
        current = index_entries(vault.root, before, settings={"GIT_OPTIONAL_LOCKS": "0"})
        if current == after:
            return
        if current != before or completed:
            names = [name for name in before if current[name] != (after if completed else before)[name]]
            raise Blocked("Integration index differs: " + ", ".join(names), 5)
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
        with private.open("rb") as source, owner.open("r+b") as staged:
            staged.seek(0)
            shutil.copyfileobj(source, staged)
            staged.truncate()
            staged.flush()
            os.fsync(staged.fileno())
        verify_ref()
        require(lock_path.exists() and not lock_path.is_symlink() and lock_path.samefile(owner),
                "Git index lock changed during integration", 5)
        os.replace(lock_path, index)
        sync_directory(index.parent)
        owner.unlink()
    finally:
        if owner.exists() and lock_path.exists() and not lock_path.is_symlink() and lock_path.samefile(owner):
            lock_path.unlink()
