"""Linux USB read-only whole-device encrypted backup (development only).

Does not format, partition, mount, or write to ANY physical device. Reads the
entire explicitly selected unmounted USB block disk via O_RDONLY and publishes
a new authenticated KRYPTA-FILE/2 archive. This is NOT transparent/in-place
encryption or a crash-consistent filesystem snapshot.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import platform
import secrets
import stat

from .core import _encrypt_reader, verify_file
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
        self.sha256 = hashlib.sha256()

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
            self.sha256.update(chunk)
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
    expected = {}

    @contextmanager
    def source_reader():
        with _verified_usb_reader(device, scanner=scan, backend=io) as reader:
            yield reader
            # Only recorded after descriptor, capacity and final inventory
            # validation in the underlying context manager have succeeded.
        expected["bytes"] = reader.position
        expected["sha256"] = reader.sha256.hexdigest()

    # Keep the public destination ABSENT until a separate full authenticated
    # re-read has proved that the encrypted archive matches the USB read
    # stream. The staging name is random and is never returned as a backup.
    # Only the containing ordinary filesystem is written; the USB is O_RDONLY.
    pending = target.with_name(".krypta-pending-" + secrets.token_hex(16) + ".krypta")
    pending_identity = None
    published = False
    try:
        _encrypt_reader(source_reader, pending, password, keyfile)
        info = pending.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PhysicalProbeError("Temporary encrypted archive is not a private regular file")
        pending_identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)

        # Verify every authenticated data chunk and the final EOF tag before
        # linking the archive into the user-visible destination. No plaintext
        # is ever written to a temporary or final file during this check.
        try:
            checked = verify_file(pending, password, keyfile)
            if (not checked["authenticated"]
                    or checked["plaintext_bytes"] != expected["bytes"]
                    or checked["plaintext_sha256"] != expected["sha256"]):
                raise PhysicalProbeError("Encrypted archive does not match the USB read stream")
        except Exception as exc:
            raise PhysicalProbeError(
                "USB backup archive verification failed; no backup was published"
            ) from exc

        current = pending.stat(follow_symlinks=False)
        if ((current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                != pending_identity or not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1):
            raise PhysicalProbeError("Temporary archive changed after verification")
        # os.link is a no-clobber, same-filesystem atomic publication on
        # supported filesystems. Never substitute os.replace/os.rename.
        # An unexpected existing target MUST stay byte-for-byte unchanged.
        os.link(pending, target, follow_symlinks=False)
        published = True
        # The link itself must refer to the validated inode, not a swapped
        # stage path. Hostile same-user races are NOT fully preventable here.
        output_info = target.stat(follow_symlinks=False)
        if ((output_info.st_dev, output_info.st_ino) != pending_identity[:2]
                or not stat.S_ISREG(output_info.st_mode)):
            raise PhysicalProbeError("Published archive identity mismatch")
        if os.name == "posix":
            # Crash durability of the directory entry is separate from the
            # already fsynced encrypted ciphertext. No power-loss guarantee.
            folder = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(folder)
            finally:
                os.close(folder)
    except FileExistsError as exc:
        raise PhysicalProbeError("Backup destination already exists; no overwrite permitted") from exc
    except OSError as exc:
        if published:
            raise PhysicalProbeError(
                "Encrypted backup was published but persistence is uncertain; "
                "verify archive and destination independently"
            ) from exc
        raise PhysicalProbeError("USB backup could not be safely published") from exc
    finally:
        # Remove only the very staging inode that was created by this call.
        # Never follow a substituted symlink or unlink another user's path.
        if pending_identity is not None:
            try:
                current = pending.stat(follow_symlinks=False)
                if (current.st_dev, current.st_ino) == pending_identity[:2]:
                    pending.unlink()
            except FileNotFoundError:
                pass

    return {
        "operation": "LINUX USB READ-ONLY ENCRYPTED BACKUP",
        "source_device": device,
        "encrypted_archive": str(target),
        "format": "KRYPTA-FILE/2",
        "backup_verified": True,
        "verified_plaintext_bytes": checked["plaintext_bytes"],
        "verification_plaintext_written": False,
        "source_write_authorized": False,
        "physical_disk_encrypted": False,
        "warning": "Authenticated bytes match USB read stream; NOT a crash-consistent snapshot. Test independent recovery.",
    }
