"""Linux kernel loop BLOCK transport for an already-created .kdevtest AEAD v2 image.

LAB ONLY: writes are allowed exclusively through /dev/loopN when the kernel
reports that it is backed by the caller's own, single-linked, private regular
.kdevtest image, starting at byte zero with full size. Never initializes,
partitions, attaches loops, or accepts USB/SATA/NVMe devices. This is not a
general-purpose physical-disk backend and is not a production security claim.

Requires a separately trusted, latest AEAD receipt before decrypting or writing.
Kernel loop open uses O_EXCL; it must not already be mounted or in use.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import re
import stat
import struct
import threading

from .test_sector_transport import SECTOR_BYTES
from .paged_aead_v2 import PagedAEADImage

_LOOP_PATH = re.compile(r"/dev/loop(0|[1-9][0-9]*)\Z")
_MIN_SECTORS = 16
_MAX_SECTORS = 65536  # 256 MiB research fixture, NOT whole-disk scalability
_BLKGETSIZE64 = 0x80081272
_LOOP_GET_STATUS64 = 0x4C05
_LOOP_INFO64_BYTES = 232
_LOOP_READ_ONLY = 1


class LoopLabError(RuntimeError):
    """The device is not an isolated scratch loop, or I/O is uncertain."""


class _LinuxLoopKernel:
    """Narrow native Linux syscalls; no loop attach, format or detach API."""

    def open_backing(self, path):
        return os.open(path, os.O_RDONLY | os.O_NONBLOCK |
                       os.O_CLOEXEC | os.O_NOFOLLOW)

    def open_loop(self, path, read_only):
        access = os.O_RDONLY if read_only else os.O_RDWR
        return os.open(path, access | os.O_EXCL | os.O_NONBLOCK |
                       os.O_CLOEXEC | os.O_NOFOLLOW)

    def stat(self, path):
        return os.stat(path, follow_symlinks=False)

    def fstat(self, fd):
        return os.fstat(fd)

    def lock(self, fd):
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def unlock(self, fd):
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)

    def loop_info(self, fd):
        import fcntl
        raw = bytearray(_LOOP_INFO64_BYTES)
        fcntl.ioctl(fd, _LOOP_GET_STATUS64, raw, True)
        dev, ino, _, offset, limit, number, _, _, flags = struct.unpack_from(
            "=QQQQQIIII", raw
        )
        return (dev, ino, offset, limit, number, flags)

    def capacity(self, fd):
        import fcntl
        return struct.unpack("=Q", fcntl.ioctl(fd, _BLKGETSIZE64, bytes(8)))[0]

    def pread(self, fd, size, offset):
        return os.pread(fd, size, offset)

    def pwrite(self, fd, data, offset):
        return os.pwrite(fd, data, offset)

    def fsync(self, fd):
        os.fsync(fd)

    def close(self, fd):
        os.close(fd)


def _identity(meta):
    return meta.st_dev, meta.st_ino, meta.st_rdev


def _scratch(meta, *, length):
    return (stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and
            meta.st_uid == os.getuid() and meta.st_mode & 0o077 == 0 and
            meta.st_size == length)


class LabLoopSectorTransport:
    """Fixed-size kernel block I/O with fail-closed identity + durability gates."""

    def __init__(self, device: str, backing: str | Path, *,
                 read_only: bool = True, system=None, kernel=None):
        self._closed = True
        self._poisoned = False
        self._dirty = False
        self._mutex = threading.RLock()
        self._backing_fd = None
        self._loop_fd = None
        self._locked = False
        self._kernel = _LinuxLoopKernel() if kernel is None else kernel
        self.read_only = read_only
        if (system or platform.system()) != "Linux":
            raise LoopLabError("Linux loop block fixtures only")
        if type(read_only) is not bool:
            raise LoopLabError("read_only must be a boolean")
        if type(device) is not str or _LOOP_PATH.fullmatch(device) is None:
            raise LoopLabError("Only /dev/loopN is accepted; never physical disks")
        path = Path(backing)
        if (not path.is_absolute() or path.suffix != ".kdevtest" or
                path.is_symlink() or str(path) != str(path.resolve(strict=False))):
            raise LoopLabError("Use an absolute, non-aliased .kdevtest file")
        if any(path == Path(root) or Path(root) in path.parents
               for root in ("/dev", "/sys", "/proc")):
            raise LoopLabError("Kernel virtual filesystem is not a scratch location")
        self.device = device
        self.path = path
        self._number = int(device.removeprefix("/dev/loop"))
        k = self._kernel
        try:
            self._backing_fd = k.open_backing(str(path))
            backing_stat = k.fstat(self._backing_fd)
            if (not stat.S_ISREG(backing_stat.st_mode) or
                    not _MIN_SECTORS * SECTOR_BYTES <= backing_stat.st_size <=
                    _MAX_SECTORS * SECTOR_BYTES or
                    backing_stat.st_size % SECTOR_BYTES != 0 or
                    not _scratch(backing_stat, length=backing_stat.st_size) or
                    (k.stat(str(path)).st_dev, k.stat(str(path)).st_ino) !=
                    (backing_stat.st_dev, backing_stat.st_ino)):
                raise LoopLabError("Backing image is not private, fixed or unaliased")
            k.lock(self._backing_fd)
            self._locked = True
            self._backing_identity = _identity(backing_stat)
            self.sectors = backing_stat.st_size // SECTOR_BYTES
            self._bytes = backing_stat.st_size

            prior = k.stat(device)
            if not stat.S_ISBLK(prior.st_mode):
                raise LoopLabError("Loop path is not a block device")
            self._loop_fd = k.open_loop(device, read_only)
            opened = k.fstat(self._loop_fd)
            current = k.stat(device)
            if (not stat.S_ISBLK(opened.st_mode) or
                    not stat.S_ISBLK(current.st_mode) or
                    _identity(prior) != _identity(opened) or
                    _identity(opened) != _identity(current)):
                raise LoopLabError("Loop block identity changed while opening")
            self._loop_identity = _identity(opened)
            self._validate_kernel()
            self._closed = False
        except BaseException:
            self._cleanup()
            raise

    def _validate_kernel(self):
        k = self._kernel
        info = k.loop_info(self._loop_fd)
        if (type(info) is not tuple or len(info) != 6 or
                any(type(x) is not int for x in info)):
            raise LoopLabError("Malformed LOOP_GET_STATUS64")
        dev, ino, offset, sizelimit, number, flags = info
        if (dev != self._backing_identity[0] or
                ino != self._backing_identity[1] or
                offset != 0 or sizelimit != 0 or number != self._number or
                (not self.read_only and flags & _LOOP_READ_ONLY) or
                k.capacity(self._loop_fd) != self._bytes):
            raise LoopLabError("Loop no longer maps exactly the approved scratch file")

    def _check(self):
        if self._closed:
            raise LoopLabError("Loop transport closed")
        if self._poisoned:
            raise LoopLabError("Uncertain loop I/O: stop and review trusted receipt")
        try:
            k = self._kernel
            file_meta = k.fstat(self._backing_fd)
            path_meta = k.stat(str(self.path))
            loop_meta = k.fstat(self._loop_fd)
            loop_path = k.stat(self.device)
            if (not _scratch(file_meta, length=self._bytes) or
                    _identity(file_meta) != self._backing_identity or
                    _identity(path_meta) != self._backing_identity or
                    not stat.S_ISREG(path_meta.st_mode) or
                    _identity(loop_meta) != self._loop_identity or
                    _identity(loop_path) != self._loop_identity or
                    not stat.S_ISBLK(loop_meta.st_mode) or
                    not stat.S_ISBLK(loop_path.st_mode)):
                raise LoopLabError("Scratch/loop path replaced, resized or aliased")
            self._validate_kernel()
        except (OSError, ValueError, OverflowError, LoopLabError) as exc:
            self._poisoned = True
            raise LoopLabError("Uncertain scratch loop identity or capacity") from exc

    def _offset(self, index):
        if type(index) is not int or not 0 <= index < self.sectors:
            raise LoopLabError("Sector outside scratch capacity")
        return index * SECTOR_BYTES

    def read_sector(self, index: int) -> bytes:
        with self._mutex:
            self._check()
            pos = self._offset(index)
            try:
                data = self._kernel.pread(self._loop_fd, SECTOR_BYTES, pos)
                if type(data) is not bytes or len(data) != SECTOR_BYTES:
                    raise LoopLabError("Short kernel loop read")
                return data
            except (OSError, LoopLabError) as exc:
                self._poisoned = True
                raise LoopLabError("Uncertain fixed-sector read") from exc

    def write_sector(self, index: int, data: bytes):
        with self._mutex:
            self._check()
            if self.read_only:
                raise LoopLabError("Lab loop is read-only")
            pos = self._offset(index)
            if type(data) is not bytes or len(data) != SECTOR_BYTES:
                raise LoopLabError("Exactly 4096 immutable bytes required")
            try:
                # A partial write is NOT retried: commit state is uncertain.
                length = self._kernel.pwrite(self._loop_fd, data, pos)
                if length != SECTOR_BYTES:
                    raise LoopLabError("Short/partial kernel loop write")
                self._dirty = True
            except (OSError, LoopLabError) as exc:
                self._poisoned = True
                raise LoopLabError("Uncertain sector write; do not commit") from exc

    def flush(self):
        with self._mutex:
            self._check()
            if self._dirty:
                try:
                    self._kernel.fsync(self._loop_fd)
                    self._check()
                    self._dirty = False
                except (OSError, LoopLabError) as exc:
                    self._poisoned = True
                    raise LoopLabError("Uncertain loop flush/fsync") from exc

    def _cleanup(self):
        k = self._kernel
        if self._loop_fd is not None:
            try:
                k.close(self._loop_fd)
            finally:
                self._loop_fd = None
        if self._backing_fd is not None:
            try:
                if self._locked:
                    k.unlock(self._backing_fd)
                    self._locked = False
            finally:
                try:
                    k.close(self._backing_fd)
                finally:
                    self._backing_fd = None
        self._closed = True

    def close(self):
        with self._mutex:
            if self._closed:
                return
            error = None
            if self._dirty and not self._poisoned:
                try:
                    self.flush()
                except BaseException as exc:
                    error = exc
            try:
                self._cleanup()
            except BaseException as exc:
                if error is None:
                    error = exc
            if error is not None:
                raise error

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *_):
        self.close()


def open_lab_loop_v2(device, backing, master_key: bytes, expected_receipt: str,
                     *, read_only=True, system=None, kernel=None) -> PagedAEADImage:
    """Open an EXISTING encrypted image through Linux loop block I/O.

    Never initializes, formats or authorizes a physical device. Caller must
    retain the resulting NEW receipt in independent trusted storage after each
    authenticated write; stale receipts are rejected on next open.
    """
    io = LabLoopSectorTransport(
        device, backing, read_only=read_only, system=system, kernel=kernel
    )
    try:
        return PagedAEADImage(io, master_key, expected_receipt)
    except BaseException:
        io.close()
        raise
