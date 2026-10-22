"""Externally sealed, write-once PFS/2 receipt checkpoints for disposable images.

A pin is NOT a monotonic hardware counter. Its SHA-256 seal must be kept on a
separate trusted medium/channel and supplied on EVERY read. Reading a digest
from the same attacker-controlled location as the pin defeats anti-rollback.
No API here silently enrolls a candidate receipt or advances trust.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path

from .paged_fs2 import PagedFS2
from .paged_volume import PagedResearchVolume, PagedVolumeError

PIN_FORMAT = "KRYPTA-PFS2-RECEIPT-PIN/1"
SEAL_DOMAIN = b"KRYPTA-PFS2-RECEIPT-PIN/1\x00"
MAX_PIN_BYTES = 512
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_HEX32 = re.compile(r"[0-9a-f]{32}", re.ASCII)


class ReceiptPinError(PagedVolumeError):
    """Untrusted pin, absent external seal or unsafe pin file."""


def _hex64(value: object, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ReceiptPinError("Invalid " + label + "; expected 64 lowercase hex characters")
    return value


def _canonical(doc: dict) -> bytes:
    return json.dumps(
        doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("ascii") + b"\n"


def _seal(blob: bytes) -> str:
    return hashlib.sha256(SEAL_DOMAIN + blob).hexdigest()


def _pin_path(value: str | Path) -> Path:
    path = Path(value)
    if path.suffix.lower() != ".kpin":
        raise ReceiptPinError("Receipt pin must be an ordinary .kpin file")
    if not path.is_absolute():
        raise ReceiptPinError("Use an absolute, explicitly selected pin path")
    # Reject ordinary symlink ancestors; cannot defend against a privileged
    # attacker racing replacements of an untrusted parent directory.
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ReceiptPinError("Symlink pin path or ancestor is forbidden")
    parent = path.parent
    try:
        info = parent.stat()
    except OSError as exc:
        raise ReceiptPinError("Receipt pin parent directory is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise ReceiptPinError("Pin parent is not a directory")
    if os.name == "posix" and (
        info.st_uid != os.getuid() or info.st_mode & 0o022
    ):
        raise ReceiptPinError("Pin directory must be owned by caller and not group/world writable")
    return path


def _regular_private(fd: int) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ReceiptPinError("Pin must be an unlinked-to-others regular file")
    if os.name == "posix" and (
        info.st_uid != os.getuid() or info.st_mode & 0o077
    ):
        raise ReceiptPinError("Receipt pin must be owned by caller, mode 0600/0400")
    return info


def _read_pin(path: Path) -> bytes:
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReceiptPinError("Cannot open receipt pin") from exc
    try:
        before = _regular_private(fd)
        if not 0 < before.st_size <= MAX_PIN_BYTES:
            raise ReceiptPinError("Receipt pin length is invalid")
        with os.fdopen(fd, "rb") as reader:
            fd = -1
            blob = reader.read(MAX_PIN_BYTES + 1)
            after = os.fstat(reader.fileno())
        if (len(blob) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ReceiptPinError("Receipt pin changed during inspection")
        return blob
    finally:
        if fd >= 0:
            os.close(fd)


def _parse(blob: bytes) -> dict:
    if not blob or len(blob) > MAX_PIN_BYTES or not blob.endswith(b"\n"):
        raise ReceiptPinError("Invalid receipt pin encoding")
    try:
        def unique(pairs):
            out = {}
            for k, v in pairs:
                if k in out:
                    raise ValueError("Duplicate receipt pin property")
                out[k] = v
            return out
        doc = json.loads(blob.decode("ascii"), object_pairs_hook=unique)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ReceiptPinError("Malformed receipt pin") from exc
    if (type(doc) is not dict or set(doc) != {
            "format", "image_id", "sequence", "receipt"
        } or doc["format"] != PIN_FORMAT
            or type(doc["image_id"]) is not str
            or _HEX32.fullmatch(doc["image_id"]) is None
            or type(doc["sequence"]) is not int
            or not 0 <= doc["sequence"] < 2**64
            or type(doc["receipt"]) is not str
            or _HEX64.fullmatch(doc["receipt"]) is None
            or _canonical(doc) != blob):
        raise ReceiptPinError("Noncanonical or invalid receipt pin")
    return doc


def load_sealed_pin(pin_path: str | Path, trusted_seal: str) -> dict:
    """Fail closed without an externally supplied, 64-hex SHA-256 seal.

    A copied or rolled-back .kpin is not trusted merely because it is valid
    JSON, mode 0600, or located near an authenticated encrypted image.
    """
    trusted_seal = _hex64(trusted_seal, "independently trusted pin seal")
    blob = _read_pin(_pin_path(pin_path))
    if not hmac.compare_digest(_seal(blob), trusted_seal):
        raise ReceiptPinError("Independent receipt pin seal mismatch; possible rollback")
    return _parse(blob)


def _flush_parent(path: Path) -> None:
    # POSIX directory sync makes the newly created directory entry durable
    # when the local filesystem honors fsync. Windows has no portable Python
    # directory-fsync primitive: file fsync only, NOT a power-loss guarantee.
    if os.name == "posix":
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        fd = os.open(path.parent, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def pin_trusted_image(
    image: str | Path, key: bytes, trusted_receipt: str,
    destination: str | Path, *, expected_image_id: bytes | None = None
) -> dict:
    """Write once ONLY after the caller supplies an independently trusted receipt.

    A valid image alone never enrolls its observed receipt. The resulting
    seal MUST be independently retained before this pin is trusted. Calling
    again with the same destination fails without overwriting a trusted pin.
    """
    trusted_receipt = _hex64(trusted_receipt, "prior trusted image receipt")
    target = _pin_path(destination)
    image_path = Path(image)
    if target.parent.resolve() == image_path.absolute().parent.resolve():
        raise ReceiptPinError("Pin must not share the image directory")
    if expected_image_id is not None and (
        type(expected_image_id) is not bytes or len(expected_image_id) != 16
    ):
        raise ReceiptPinError("Invalid independently bound image identity")
    with PagedResearchVolume(
        image_path, key, expected_receipt=trusted_receipt, read_only=True
    ) as volume:
        if expected_image_id is not None and not hmac.compare_digest(
            volume.id, expected_image_id
        ):
            raise ReceiptPinError("Expected image identity mismatch")
        PagedFS2(volume).verify_all()
        doc = {
            "format": PIN_FORMAT, "image_id": volume.id.hex(),
            "sequence": volume.sequence, "receipt": trusted_receipt,
        }
    blob = _canonical(doc)
    if len(blob) > MAX_PIN_BYTES:
        raise ReceiptPinError("Receipt pin exceeds size quota")
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_BINARY", 0))
    try:
        fd = os.open(target, flags, 0o600)
    except OSError as exc:
        raise ReceiptPinError("Refusing to overwrite or create unsafe receipt pin") from exc
    try:
        _regular_private(fd)
        with os.fdopen(fd, "wb", buffering=0) as writer:
            fd = -1
            writer.write(blob)
            os.fsync(writer.fileno())
        _flush_parent(target)
    finally:
        if fd >= 0:
            os.close(fd)
    return {
        "pin_path": str(target),
        "seal_sha256": _seal(blob),
        "image_id": doc["image_id"],
        "sequence": doc["sequence"],
        "read_only_verified": True,
        "trust_promoted": False,
        "warning": "Keep seal independently, outside image and pin storage. "
                   "An image or pin snapshot alone cannot establish freshness.",
    }


def verify_image_with_sealed_pin(
    image: str | Path, key: bytes, pin_path: str | Path, trusted_seal: str
) -> dict:
    """No writes, no receipt update, no fallback to the observed image state."""
    pin = load_sealed_pin(pin_path, trusted_seal)
    with PagedResearchVolume(
        image, key, expected_sequence=pin["sequence"],
        expected_receipt=pin["receipt"], read_only=True,
    ) as volume:
        if not hmac.compare_digest(volume.id.hex(), pin["image_id"]):
            raise ReceiptPinError("Pinned image identity mismatch")
        result = PagedFS2(volume).verify_all()
        return {
            "status": "SEALED_PIN_MATCH",
            "read_only_verified": True,
            "trust_promoted": False,
            "image_id": pin["image_id"],
            "sequence": pin["sequence"],
            "receipt": pin["receipt"],
            "files_verified": result["files_verified"],
            "bytes_verified": result["bytes_verified"],
            "uncommitted_tail_present": volume._trim_offset is not None,
        }
