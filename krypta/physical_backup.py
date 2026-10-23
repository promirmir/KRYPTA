"""Linux USB read-only whole-device encrypted backup (development only).

Does not format, partition, mount, or write to ANY physical device. Reads the
entire explicitly selected unmounted USB block disk via O_RDONLY and publishes
a new authenticated KRYPTA-FILE/2 archive. This is NOT transparent/in-place
encryption or a crash-consistent filesystem snapshot.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import platform
import stat

from .core import _encrypt_reader
from .physical_disks import inspect_physical_disks
from .physical_read_probe import (
    _allowed, _DEVICE, _identity, LinuxReadOnlyBlockIO, PhysicalProbeError,
)


class _VerifiedUSBStream:
    """Bounded sequential, read-only view of one verified block descriptor."""

    def __init__(self, backend, fd, capacity, identity):
        self.backend = backend
        self.fd = fd
        self.capacity = capacity
        self.identity = identity
        self.position = 0

    def read(self, count: int) -> bytes:
        if type(count) is not int or not 0 < count <= 1024 * 1024:
            raise PhysicalProbeError("Invalid bounded USB backup read")
        if self.position == self.capacity:
            return b""
        try:
            if _identity(self.backend.fstat(self.fd)) != self.identity:
                raise PhysicalProbeError("USB device descriptor identity changed")
            size = min(count, self.capacity - self.position)
            chunk = self.backend.pread(self.fd, size, self.position)
            if type(chunk) is not bytes or len(chunk) != size:
                raise PhysicalProbeError("Short/invalid USB backup read")
            self.position += size
            return chunk
        except OSError as exc:
            raise PhysicalProbeError("USB read failed; no backup was published") from exc


@contextmanager
def _verified_usb_reader(device, *, scanner, backend):
    capacity = _allowed(device, scanner())
    fd = None
    try:
        previous = backend.stat(device)
        if not stat.S_ISBLK(previous.st_mode):
            raise PhysicalProbeError("Backup source must be a real block disk")
        fd = backend.open(device)  # O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC
        opened = backend.fstat(fd)
        current = backend.stat(device)
        if (not stat.S_ISBLK(opened.st_mode) or
                not stat.S_ISBLK(current.st_mode) or
                _identity(previous) != _identity(opened) or
                _identity(opened) != _identity(current)):
            raise PhysicalProbeError("USB identity changed during open")
        if backend.capacity(fd) != capacity:
            raise PhysicalProbeError("USB capacity differs from OS inventory")
        if _allowed(device, scanner()) != capacity:
            raise PhysicalProbeError("USB became unsafe before reading")
        reader = _VerifiedUSBStream(backend, fd, capacity, _identity(opened))
        yield reader
        if reader.position != capacity:
            raise PhysicalProbeError("Incomplete USB image; backup rejected")
        if (not stat.S_ISBLK(backend.stat(device).st_mode) or
                _identity(backend.stat(device)) != reader.identity or
                _identity(backend.fstat(fd)) != reader.identity or
                backend.capacity(fd) != capacity or
                _allowed(device, scanner()) != capacity):
            raise PhysicalProbeError("USB identity, geometry or mount state changed")
    except (OSError, OverflowError, ValueError) as exc:
        raise PhysicalProbeError("USB backup kernel/inventory validation failed") from exc
    finally:
        if fd is not None:
            backend.close(fd)


def backup_linux_usb_encrypted(device: str, output: str | Path, password: str,
                               keyfile: str | Path, *, scanner=None,
                               backend=None, system=None) -> dict:
    """Back up an unmounted Linux USB disk into a NEW encrypted ordinary file.

    Keyfile is mandatory (prefer separately stored backup) to avoid treating
    weak PINs as adequate. Explicit external validation and recovery tests are
    required before anyone relies on the resulting archive.
    """
    if (system or platform.system()) != "Linux":
        raise PhysicalProbeError("Whole-device USB backup is Linux-only")
    if type(device) is not str or _DEVICE.fullmatch(device) is None:
        raise PhysicalProbeError("Expected exact whole-disk /dev/ path")
    if keyfile is None:
        raise PhysicalProbeError("An independent secret keyfile is mandatory")
    target = Path(output)
    if (target.suffix.lower() != ".krypta" or target.is_symlink() or
            target.exists() or not target.parent.is_dir() or
            target.parent.is_symlink()):
        raise PhysicalProbeError("Output must be a new .krypta file in an existing regular directory")
    # Never create temporary output inside /dev, /sys or /proc.
    parent = target.parent.resolve()
    if any(parent == Path(x) or Path(x) in parent.parents
           for x in ("/dev", "/proc", "/sys")):
        raise PhysicalProbeError("Output on a kernel virtual filesystem is forbidden")
    scan = inspect_physical_disks if scanner is None else scanner
    io = LinuxReadOnlyBlockIO() if backend is None else backend
    _encrypt_reader(
        lambda: _verified_usb_reader(device, scanner=scan, backend=io),
        target, password, keyfile,
    )
    return {
        "operation": "LINUX USB READ-ONLY ENCRYPTED BACKUP",
        "source_device": device,
        "encrypted_archive": str(target),
        "format": "KRYPTA-FILE/2",
        "source_write_authorized": False,
        "physical_disk_encrypted": False,
        "warning": "Not a consistent snapshot of a changing disk. Verify recovery before relying on this archive.",
    }
