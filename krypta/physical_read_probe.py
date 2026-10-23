"""Read-only hardware probe of an explicitly named Linux USB block device.

An independent P0 hardware boundary milestone. This module cannot format,
mount, decrypt, encrypt or write sectors. It rejects system/mounted disks,
symlinks, ordinary files, non-USB transports and unstable device geometry.
Not an authorization mechanism for later raw device writes.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import stat
import struct

from .physical_disks import inspect_physical_disks

BLKGETSIZE64 = 0x80081272  # Linux <linux/fs.h>; unsigned 64-bit capacity
SAMPLE_BYTES = 4096
_DEVICE = re.compile(r"/dev/[A-Za-z0-9._+-]+")


class PhysicalProbeError(RuntimeError):
    """Unsafe, unidentifiable or unreadable physical disk."""


class LinuxReadOnlyBlockIO:
    """Kernel calls; deliberately no write, truncate, mount or ioctl-write API."""

    def stat(self, path):
        return os.stat(path, follow_symlinks=False)

    def fstat(self, fd):
        return os.fstat(fd)

    def open(self, path):
        flags = (os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC |
                 getattr(os, "O_NOFOLLOW", 0))
        return os.open(path, flags)

    def capacity(self, fd):
        import fcntl
        return struct.unpack("=Q", fcntl.ioctl(fd, BLKGETSIZE64, bytes(8)))[0]

    def pread(self, fd, count, offset):
        return os.pread(fd, count, offset)

    def close(self, fd):
        os.close(fd)


def _identity(info):
    return info.st_dev, info.st_ino, info.st_rdev


def _allowed(device, report):
    if (type(report) is not dict or report.get("platform") != "Linux" or
            report.get("physical_disk_encryption_enabled") is not False or
            type(report.get("devices")) is not list):
        raise PhysicalProbeError("OS inventory is untrusted or incomplete")
    matches = [d for d in report["devices"]
               if type(d) is dict and d.get("device") == device]
    if len(matches) != 1:
        raise PhysicalProbeError("Exactly one listed whole disk must match")
    d = matches[0]
    if (d.get("write_authorized") is not False or
            type(d.get("bus")) is not str or d["bus"].lower() != "usb" or
            d.get("inspection_complete") is not True or
            d.get("system_or_boot") is not False or
            d.get("mounted") is not False or
            type(d.get("bytes")) is not int or d["bytes"] < SAMPLE_BYTES):
        raise PhysicalProbeError("Only an identified, unmounted non-system USB disk")
    return d["bytes"]


def probe_linux_usb_readonly(device: str, *, system=None, scanner=None, backend=None) -> dict:
    """Read 4 KiB from beginning, middle and end of a real USB block device.

    The caller must explicitly name a whole disk from the OS inventory.
    Three sample hashes are diagnostic fingerprints, NOT proof of data
    integrity, media health, encryption, or safe future writes.
    """
    if (system or platform.system()) != "Linux":
        raise PhysicalProbeError("Raw read-only probe is implemented for Linux only")
    if type(device) is not str or _DEVICE.fullmatch(device) is None:
        raise PhysicalProbeError("Expected a canonical whole-disk /dev/ path")
    scanner = inspect_physical_disks if scanner is None else scanner
    backend = LinuxReadOnlyBlockIO() if backend is None else backend
    capacity = _allowed(device, scanner())
    fd = None
    try:
        previous = backend.stat(device)
        if not stat.S_ISBLK(previous.st_mode):
            raise PhysicalProbeError("Only actual block devices can be probed")
        fd = backend.open(device)
        opened = backend.fstat(fd)
        current = backend.stat(device)
        if (not stat.S_ISBLK(opened.st_mode) or
                not stat.S_ISBLK(current.st_mode) or
                _identity(previous) != _identity(opened) or
                _identity(opened) != _identity(current)):
            raise PhysicalProbeError("Block device identity changed during open")
        real_capacity = backend.capacity(fd)
        if type(real_capacity) is not int or real_capacity != capacity:
            raise PhysicalProbeError("Kernel block capacity differs from OS inventory")
        last = ((capacity - SAMPLE_BYTES) // SAMPLE_BYTES) * SAMPLE_BYTES
        middle = ((capacity // 2) // SAMPLE_BYTES) * SAMPLE_BYTES
        positions = sorted({0, middle, last})
        samples = []
        for offset in positions:
            data = backend.pread(fd, SAMPLE_BYTES, offset)
            if type(data) is not bytes or len(data) != SAMPLE_BYTES:
                raise PhysicalProbeError("Short or invalid physical-sector read")
            samples.append({"offset_bytes": offset,
                            "sha256": hashlib.sha256(data).hexdigest()})
        if _identity(backend.stat(device)) != _identity(opened):
            raise PhysicalProbeError("Block device changed during inspection")
        if _allowed(device, scanner()) != capacity:
            raise PhysicalProbeError("USB mount/system/identity inventory changed")
        return {
            "operation": "LINUX USB PHYSICAL READ-ONLY SAMPLE",
            "device": device,
            "capacity_bytes": capacity,
            "sample_bytes": SAMPLE_BYTES,
            "samples": samples,
            "write_authorized": False,
            "encryption_available": False,
            "warning": "Read-only diagnostics only. No authorization for encryption.",
        }
    except PhysicalProbeError:
        raise
    except (OSError, ValueError, OverflowError, struct.error) as exc:
        raise PhysicalProbeError("Kernel rejected read-only USB inspection") from exc
    finally:
        if fd is not None:
            backend.close(fd)
