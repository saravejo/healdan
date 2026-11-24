"""Confined filesystem operations for integration paths and scratch files."""
from contextlib import ExitStack, contextmanager
import ctypes
import errno
import os
from pathlib import Path
from secrets import token_hex
import stat
import sys

from .core import Blocked, digest, require


@contextmanager
def windows_directory(path):
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    info = kernel.GetFileInformationByHandleEx
    info.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    info.restype = wintypes.BOOL
    spelling = str(path)
    extended = ("\\\\?\\UNC\\" + spelling[2:] if spelling.startswith("\\\\")
                else "\\\\?\\" + spelling)
    # FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING,
    # and FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT.
    handle = create(extended, 0x80, 3, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = (wintypes.DWORD * 2)()
        if not info(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        require(attributes[0] & stat.FILE_ATTRIBUTE_DIRECTORY and not attributes[0] & stat.FILE_ATTRIBUTE_REPARSE_POINT,
                "Integration directory path changed: " + spelling, 5)
        yield
    finally:
        close(handle)


@contextmanager
def directory_handle(path, *, create=False):
    """Open each component without following links and retain the ancestor handles."""
    parts = path.absolute().parts
    with ExitStack() as stack:
        if os.name == "nt":
            directory = Path(parts[0])
            stack.enter_context(windows_directory(directory))
            for part in parts[1:]:
                directory /= part
                if create:
                    try:
                        directory.mkdir()
                    except FileExistsError:
                        pass
                stack.enter_context(windows_directory(directory))
            yield None
            return
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(parts[0], flags)
        stack.callback(os.close, descriptor)
        for part in parts[1:]:
            if create:
                try:
                    os.mkdir(part, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
            try:
                descriptor = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                if exc.errno in {errno.ENOTDIR, errno.ELOOP}:
                    raise Blocked("Integration directory path changed: " + str(path), 5) from exc
                raise
            stack.callback(os.close, descriptor)
        yield descriptor


def slot(path, directory_fd):
    return path.name if directory_fd is not None else path


def read_file(path, directory_fd):
    name = slot(path, directory_fd)
    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        return ["non-regular", None], None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Blocked("Concurrent file replacement: " + str(path), 5) from exc
        raise
    with os.fdopen(descriptor, "rb") as stream:
        current = os.fstat(stream.fileno())
        require(os.path.samestat(current, metadata), "Concurrent file replacement: " + str(path), 5)
        body = stream.read()
        return [digest(body), 0o755 if current.st_mode & stat.S_IXUSR else 0o644], body


def read_integration_file(path):
    try:
        with directory_handle(path.parent) as directory_fd:
            return read_file(path, directory_fd)
    except FileNotFoundError:
        return None, None


def snapshot(path):
    return read_integration_file(path)[0]


def rename_exclusive(source, destination):
    """Consume source atomically, only if the destination name is unoccupied."""
    with directory_handle(source.parent) as src, directory_handle(destination.parent) as dst:
        if os.name == "nt":
            os.rename(source, destination)
            return
        rename_at(src, source.name, dst, destination.name)
        os.fsync(src)
        if destination.parent != source.parent:
            os.fsync(dst)


def rename_at(src, name, dst, destination):
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        rename, flag = getattr(library, "renameat2", None), 1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        rename, flag = getattr(library, "renameatx_np", None), 4  # RENAME_EXCL
    else:
        rename, flag = None, 0
    require(rename is not None, "Exclusive integration rename is unavailable", 5)
    if rename(src, os.fsencode(name), dst, os.fsencode(destination), flag):
        code = ctypes.get_errno()
        if code in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL, errno.EXDEV}:
            raise Blocked("Exclusive integration rename is unavailable on this volume", 5)
        raise OSError(code, os.strerror(code), destination)


def prepare_file(path, body, mode):
    with directory_handle(path.parent, create=True) as directory_fd:
        destination = slot(path, directory_fd)
        temporary = slot(path.with_name(".healdan-" + token_hex(16)), directory_fd)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(temporary, flags, mode, dir_fd=directory_fd)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(body)
                if directory_fd is not None:
                    os.fchmod(stream.fileno(), mode)
                stream.flush()
                os.fsync(stream.fileno())
            if directory_fd is None:
                os.rename(temporary, destination)
            else:
                rename_at(directory_fd, temporary, directory_fd, destination)
        finally:
            # A successful exclusive rename consumed the temporary.
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            if directory_fd is not None:
                os.fsync(directory_fd)


def remove_verified(path, checksum):
    try:
        with directory_handle(path.parent) as directory_fd:
            current, _ = read_file(path, directory_fd)
            if current[0] == checksum:
                os.unlink(slot(path, directory_fd), dir_fd=directory_fd)
                return True
    except FileNotFoundError:
        return True
    except PermissionError:
        pass
    return False


def remove_empty_directory(path):
    try:
        with directory_handle(path.parent) as directory_fd:
            os.rmdir(slot(path, directory_fd), dir_fd=directory_fd)
    except (FileNotFoundError, PermissionError):
        pass
    except OSError as exc:
        if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
            raise
