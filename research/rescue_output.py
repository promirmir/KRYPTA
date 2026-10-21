"""Pinned, private rescue output. See docs/RESCUE_OUTPUT_SECURITY.md.

The caller must authenticate ALL input before entering this context. This
module never reopens a plaintext file by pathname, including verification.
"""
from __future__ import annotations

import hashlib
import hmac
import ctypes
import os
from pathlib import Path
import stat
import sys


class RescueError(ValueError):
    """Recovery validation or output safety failure."""


def _leaf(name: str) -> None:
    if (not name or name in (".", "..") or any(c in name for c in "/\\:\0")
            or name.endswith((".", " "))):
        raise RescueError("Invalid recovery output name")


def _identity(info):
    return info.st_dev, info.st_ino


class PosixOutput:
    """Linux dirfd operations; private output under trusted ownership.

    Root and the current UID are trusted. Root-owned sticky temporary
    ancestors are allowed, but their next component must have trusted owner.
    Processes running as the same UID and root are outside the threat model.
    """

    def __init__(self, path):
        self.path = Path(path).absolute()
        _leaf(self.path.name)
        self.chain = []
        self.files = []
        self.fd = None
        self.created = False

    @staticmethod
    def _check_directory(fd):
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()):
            raise RescueError("Untrusted recovery directory owner")
        if info.st_mode & 0o022:
            if not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                raise RescueError("Shared writable recovery hierarchy is forbidden")
        # Fail closed for network/FUSE/unknown filesystems. These local Linux
        # filesystem implementations provide the descriptor semantics used here.
        libc = ctypes.CDLL(None, use_errno=True)
        fstatfs = libc.fstatfs
        fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
        fstatfs.restype = ctypes.c_int
        buffer = (ctypes.c_long * 64)()
        if fstatfs(fd, ctypes.byref(buffer)) != 0:
            raise OSError(ctypes.get_errno(), "Cannot establish output filesystem type")
        if buffer[0] & 0xffffffff not in {0xEF53, 0x58465342, 0x9123683E, 0x01021994, 0x794C7630}:
            raise RescueError("Unsupported recovery output filesystem")
        return info

    def __enter__(self):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open("/", flags)
            # Register the handle before any validation that may raise.
            self.chain.append((None, fd, None))
            self.chain[-1] = (None, fd, _identity(self._check_directory(fd)))
            for name in self.path.parent.parts[1:]:
                _leaf(name)
                fd = os.open(name, flags, dir_fd=self.chain[-1][1])
                self.chain.append((name, fd, None))
                self.chain[-1] = (name, fd, _identity(self._check_directory(fd)))
            parent = self.chain[-1][1]
            os.mkdir(self.path.name, mode=0o700, dir_fd=parent)
            # No untrusted user can replace the new entry: parent ownership
            # and permissions were checked through the pinned descriptor.
            self.fd = os.open(self.path.name, flags, dir_fd=parent)
            info = self._check_directory(self.fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise RescueError("Recovery output must be private to current user")
            self.output_id = _identity(info)
            self.created = True
            self.check()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def check(self):
        # These are diagnostic checks, not the protection against redirection.
        # All subsequent I/O stays relative to the pinned descriptors.
        for index, (name, fd, identity) in enumerate(self.chain):
            self._check_directory(fd)
            if index and _identity(os.stat(name, dir_fd=self.chain[index-1][1],
                                           follow_symlinks=False)) != identity:
                raise RescueError("Recovery ancestor identity changed")
        info = os.stat(self.path.name, dir_fd=self.chain[-1][1], follow_symlinks=False)
        if _identity(info) != self.output_id or not stat.S_ISDIR(info.st_mode):
            raise RescueError("Recovery output directory identity changed")
        if os.fstat(self.fd).st_mode & 0o077:
            raise RescueError("Recovery output permissions changed")

    def write(self, name, data):
        _leaf(name)
        self.check()
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        # Register immediately, before the first fallible write/fsync.
        try:
            identity = _identity(os.fstat(fd))
        except BaseException:
            os.close(fd)  # Unknown identity: preserve the empty entry.
            raise
        self.files.append((name, fd, identity))
        _write_verify(fd, data)
        self.check()

    def sync(self):
        self.check()
        os.fsync(self.fd)
        os.fsync(self.chain[-1][1])

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None and self.created:
            for name, fd, identity in reversed(self.files):
                try:
                    current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                    if _identity(current) == identity and current.st_nlink == 1:
                        os.unlink(name, dir_fd=self.fd)
                except OSError:
                    pass  # Preserve unfamiliar/replaced entries, never recurse.
            try:
                current = os.stat(self.path.name, dir_fd=self.chain[-1][1],
                                  follow_symlinks=False)
                if _identity(current) == self.output_id:
                    os.rmdir(self.path.name, dir_fd=self.chain[-1][1])
            except OSError:
                pass
        for _, fd, _ in self.files:
            os.close(fd)
        if self.fd is not None:
            os.close(self.fd)
        for _, fd, _ in reversed(self.chain):
            os.close(fd)


def _write_verify(fd, data):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RescueError("Recovery file must be ordinary and single-link")
    remaining = memoryview(data)
    while remaining:
        count = os.write(fd, remaining)
        if count <= 0:
            raise OSError("Short recovery write")
        remaining = remaining[count:]
    os.fsync(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while chunk := os.read(fd, 1024 * 1024):
        count += len(chunk)
        if count > len(data):
            raise RescueError("Recovery output size changed")
        digest.update(chunk)
    after = os.fstat(fd)
    if (after.st_nlink != 1 or _identity(info) != _identity(after)
            or count != len(data)
            or not hmac.compare_digest(digest.digest(), hashlib.sha256(data).digest())):
        raise RescueError("Exported file does not match authenticated source")


def private_output(path):
    if sys.platform == "linux":
        return PosixOutput(path)
    if os.name == "nt":
        try:
            from .rescue_output_windows import WindowsOutput
        except ImportError as exc:
            raise RescueError("Secure Windows recovery requires pywin32") from exc
        return WindowsOutput(path)
    raise RescueError("Secure recovery output is unsupported on this platform")
