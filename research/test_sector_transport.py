"""Fixed 4096-byte sector I/O contract for disposable regular files ONLY.

Prepares a safely testable backend boundary for eventual physical-device
encryption. It never accepts block/character devices, partitions, mount paths,
symlinks or hardlinks. Scratch sectors are NOT encrypted by this layer.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import threading

SECTOR_BYTES = 4096
MIN_SECTORS = 16
MAX_TEST_SECTORS = 65536  # 256 MiB sparse test capacity


class SectorTransportError(RuntimeError):
    """Invalid device boundary, unsafe alias, poisoned I/O or short transfer."""


def _test_path(value) -> Path:
    path = Path(value)
    if path.suffix.lower() != ".kdevtest" or path.is_symlink():
        raise SectorTransportError("Only disposable .kdevtest regular-file paths")
    return path


class TestSectorTransport:
    """A bounded, fixed-capacity regular-file sector store, not a raw disk API."""

    def __init__(self, path, sectors: int, *, create: bool = False,
                 read_only: bool = False):
        if type(sectors) is not int or not MIN_SECTORS <= sectors <= MAX_TEST_SECTORS:
            raise SectorTransportError("Invalid test sector count")
        if create and read_only:
            raise SectorTransportError("Cannot create in read-only mode")
        self.path = _test_path(path)
        self.sectors = sectors
        self.read_only = bool(read_only)
        self._mutex = threading.RLock()
        self._closed = True
        self._poisoned = False
        self._dirty = False
        self._fd = -1
        self._locked = False
        flags = os.O_RDONLY if read_only else os.O_RDWR
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_BINARY", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            link = os.stat(self.path, follow_symlinks=False)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or
                    not stat.S_ISREG(link.st_mode) or
                    (link.st_dev, link.st_ino) != (info.st_dev, info.st_ino) or
                    info.st_nlink != 1):
                raise SectorTransportError("Only unaliased ordinary scratch files")
            if create:
                os.ftruncate(fd, sectors * SECTOR_BYTES)
                info = os.fstat(fd)
            if info.st_size != sectors * SECTOR_BYTES:
                raise SectorTransportError("Unexpected scratch device size")
            if not read_only:
                self._lock_writer(fd)
            self._fd = fd
            self._identity = (info.st_dev, info.st_ino)
            self._closed = False
        except BaseException:
            os.close(fd)
            raise

    def _lock_writer(self, fd: int) -> None:
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError) as exc:
            raise SectorTransportError("Scratch writer is already locked") from exc
        self._locked = True

    def _unlock_writer(self) -> None:
        if not self._locked:
            return
        if os.name == "nt":
            import msvcrt
            os.lseek(self._fd, 0, os.SEEK_SET)
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        self._locked = False

    def _check(self) -> None:
        if self._closed:
            raise SectorTransportError("Sector store is closed")
        if self._poisoned:
            raise SectorTransportError("Uncertain sector I/O: reopen and verify")
        try:
            link = os.stat(self.path, follow_symlinks=False)
            info = os.fstat(self._fd)
        except OSError as exc:
            self._poisoned = True
            raise SectorTransportError("Scratch store identity is inaccessible") from exc
        if (not stat.S_ISREG(link.st_mode) or
                (link.st_dev, link.st_ino) != self._identity or
                (info.st_dev, info.st_ino) != self._identity or
                info.st_nlink != 1 or info.st_size != self.sectors * SECTOR_BYTES):
            self._poisoned = True
            raise SectorTransportError("Scratch store replaced, resized or aliased")

    def _seek(self, index: int) -> None:
        if type(index) is not int or not 0 <= index < self.sectors:
            raise SectorTransportError("Sector address outside test capacity")
        os.lseek(self._fd, index * SECTOR_BYTES, os.SEEK_SET)

    def read_sector(self, index: int) -> bytes:
        with self._mutex:
            self._check()
            self._seek(index)
            data = bytearray()
            try:
                while len(data) < SECTOR_BYTES:
                    part = os.read(self._fd, SECTOR_BYTES - len(data))
                    if not part:
                        raise SectorTransportError("Short fixed-sector read")
                    data.extend(part)
            except (OSError, SectorTransportError):
                self._poisoned = True
                raise
            return bytes(data)

    def write_sector(self, index: int, data: bytes) -> None:
        with self._mutex:
            self._check()
            if self.read_only:
                raise SectorTransportError("Read-only scratch sector store")
            if type(data) is not bytes or len(data) != SECTOR_BYTES:
                raise SectorTransportError("Exactly 4096 immutable bytes required")
            self._seek(index)
            done = 0
            try:
                while done < SECTOR_BYTES:
                    n = os.write(self._fd, data[done:])
                    if n <= 0:
                        raise SectorTransportError("Short fixed-sector write")
                    done += n
                self._dirty = True
            except (OSError, SectorTransportError):
                self._poisoned = True
                raise

    def flush(self) -> None:
        with self._mutex:
            self._check()
            if self._dirty:
                try:
                    os.fsync(self._fd)
                except OSError:
                    self._poisoned = True
                    raise
                self._dirty = False

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            error = None
            try:
                if self._dirty and not self._poisoned:
                    self.flush()
            except BaseException as exc:
                error = exc
            try:
                self._unlock_writer()
            except BaseException as exc:
                if error is None:
                    error = exc
            finally:
                os.close(self._fd)
                self._fd = -1
                self._closed = True
            if error is not None:
                raise error

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *_):
        self.close()
