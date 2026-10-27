"""Verified, non-destructive USB archive restoration to a NEW regular .img file.

This is a recovery drill for KRYPTA-FILE/2 encrypted backups, not a physical
block-device restore. Only an ordinary file is ever opened for writing.
Plaintext is written to a private staging file on the destination filesystem;
users must choose an encrypted/test destination, never their only backup.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import stat

from .core import decrypt_file, file_info, verify_file
from .physical_read_probe import PhysicalProbeError


def _readback_image(path: Path) -> tuple[int, str, tuple[int, int]]:
    """Hash a private regular file by descriptor; reject symlink substitution."""
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_BINARY", 0))
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PhysicalProbeError("Restored image is not a private regular file")
        digest = hashlib.sha256()
        amount = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            amount += len(chunk)
            digest.update(chunk)
        after = os.fstat(fd)
        path_after = path.stat(follow_symlinks=False)
        identity = (before.st_dev, before.st_ino)
        if (not stat.S_ISREG(path_after.st_mode) or
                (path_after.st_dev, path_after.st_ino) != identity or
                (after.st_dev, after.st_ino) != identity or
                before.st_size != amount or after.st_size != amount or
                before.st_mtime_ns != after.st_mtime_ns or
                after.st_mtime_ns != path_after.st_mtime_ns or
                path_after.st_nlink != 1):
            raise PhysicalProbeError("Restored image changed during independent readback")
        return amount, digest.hexdigest(), identity
    finally:
        os.close(fd)


def restore_usb_archive_to_image(archive: str | Path, destination: str | Path,
                                 password: str, keyfile: str | Path) -> dict:
    """Authenticate, restore, independently verify, then publish a new .img.

    Reject all physical-device paths, existing outputs, symlinks and unexpected
    archive formats. The newly restored image has NO automatic write-back path
    to USB/SSD/HDD. A hash match proves bytes of this archive only, not that
    the original live USB read was a crash-consistent snapshot.
    """
    source, target = Path(archive), Path(destination)
    if keyfile is None:
        raise PhysicalProbeError("An independent secret keyfile is mandatory")
    if (source.suffix.lower() != ".krypta" or
            not source.is_file() or source.is_symlink()):
        raise PhysicalProbeError("Source must be a regular .krypta archive")
    if (target.suffix.lower() != ".img" or target.exists() or
            target.is_symlink() or not target.parent.is_dir() or
            target.parent.is_symlink()):
        raise PhysicalProbeError("Destination must be a NEW regular .img file")
    resolved_parent = target.parent.resolve()
    if (str(target).startswith(("\\\\.\\", "\\\\?\\")) or
            any(resolved_parent == Path(x) or Path(x) in resolved_parent.parents
                for x in ("/dev", "/proc", "/sys"))):
        raise PhysicalProbeError("Physical devices and virtual kernel paths are forbidden")
    if file_info(source)["version"] != 2:
        raise PhysicalProbeError("Only authenticated KRYPTA-FILE/2 is supported")

    # Pass 1: authenticate ALL ciphertext, without creating plaintext.
    expected = verify_file(source, password, keyfile)
    if (expected["authenticated"] is not True or
            expected["plaintext_bytes"] < 4096 or
            expected["plaintext_bytes"] % 512):
        raise PhysicalProbeError("Archive is not a complete block-aligned disk image")

    # decrypt_file itself performs TWO more authenticated passes and
    # atomically publishes this private, unadvertised staging path.
    pending = target.with_name(".krypta-restore-pending-"
                               + secrets.token_hex(16) + ".img")
    identity = None
    published = False
    try:
        decrypt_file(source, pending, password, keyfile)
        info = pending.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PhysicalProbeError("Invalid private restoration staging file")
        identity = (info.st_dev, info.st_ino)
        amount, digest, seen_identity = _readback_image(pending)
        if (seen_identity != identity or
                amount != expected["plaintext_bytes"] or
                digest != expected["plaintext_sha256"]):
            raise PhysicalProbeError("Restored bytes differ from authenticated archive")
        # No-clobber publication; never rename over an existing user file.
        os.link(pending, target, follow_symlinks=False)
        published = True
        final = target.stat(follow_symlinks=False)
        if (not stat.S_ISREG(final.st_mode) or
                (final.st_dev, final.st_ino) != identity):
            raise PhysicalProbeError("Published recovery image identity mismatch")
        if os.name == "posix":
            directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as exc:
        if published:
            raise PhysicalProbeError(
                "Restored image is published but durability is uncertain; "
                "verify it independently before use"
            ) from exc
        raise PhysicalProbeError("Image restore or no-clobber publication failed") from exc
    finally:
        # Remove only our own staging inode. Never delete a path replaced by
        # another process. This cannot defeat a malicious same-user race.
        if identity is not None:
            try:
                current = pending.stat(follow_symlinks=False)
                if (current.st_dev, current.st_ino) == identity:
                    pending.unlink()
            except FileNotFoundError:
                pass

    return {
        "operation": "VERIFIED USB ARCHIVE RESTORE TO REGULAR IMAGE",
        "restored_image": str(target),
        "format": "KRYPTA-FILE/2",
        "restored_bytes": amount,
        "restored_sha256": digest,
        "independent_readback_verified": True,
        "physical_disk_written": False,
        "plaintext_image_written": True,
        "warning": "Plaintext .img is sensitive; this is not physical-disk recovery or a crash-consistent source snapshot.",
    }
