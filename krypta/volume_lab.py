"""Safe, explicit operations for disposable PVIMG/PFS2 ordinary-file images.

This service is the boundary between a desktop UI and the research volume
engine. It cannot mount/format a physical disk or modify a system partition.
Every image open REQUIRES the latest independent external receipt; no implicit
receipt acceptance is permitted for an existing image.
"""
from __future__ import annotations

import contextlib
import hmac
import os
from pathlib import Path
import secrets
import stat

from .core import _open_checked_file
from research.paged_fs2 import PagedFS2, MAX_FILE_BYTES
from research.paged_keys import (
    PagedKeyError, _new_private_file, _password_bytes, _remove_only_own,
    provision_keys, unlock_password, unlock_recovery,
    rewrap_password_with_recovery,
)
from research.paged_volume import PagedResearchVolume
from research.paged_rekey import rotate_pfs2_data_key


def _image_path(value: str | Path) -> Path:
    p = Path(value)
    if p.suffix.lower() != ".kpv" or p.is_symlink():
        raise ValueError("Only ordinary .kpv file-image paths are accepted")
    return p


def _distinct(*paths: str | Path) -> None:
    canonical = [Path(p).resolve(strict=False) for p in paths]
    if len(canonical) != len(set(canonical)):
        raise ValueError("Image, key, recovery and output paths must be distinct")
    if any(Path(p).is_symlink() for p in paths):
        raise ValueError("Symlinks are not accepted")
    # Two different paths can still be hardlinks to the exact same inode.
    # Reject such aliases before any operation that may write or export.
    identities = []
    for p in paths:
        try:
            identity = os.stat(p, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(identity.st_mode):
            raise ValueError("Volume Lab accepts regular files only")
        pair = (identity.st_dev, identity.st_ino)
        if pair in identities:
            raise ValueError("Hardlinked file paths must be distinct")
        identities.append(pair)


def _get_key(envelope: str | Path, *, password: str | None = None,
             recovery: str | Path | None = None) -> tuple[bytes, bytes]:
    if (password is None) == (recovery is None):
        raise PagedKeyError("Choose exactly one secret: password or recovery file")
    if password is not None:
        return unlock_password(envelope, password)
    return unlock_recovery(envelope, recovery)


@contextlib.contextmanager
def _open(image: str | Path, envelope: str | Path, receipt: str,
          *, password: str | None = None, recovery: str | Path | None = None,
          read_only: bool = False):
    """Open only with explicit authenticated image ID and external receipt."""
    image = _image_path(image)
    _distinct(image, envelope)
    if type(receipt) is not str or len(receipt) != 64 or any(
        x not in "0123456789abcdef" for x in receipt
    ):
        raise PagedKeyError("Supply the trusted, latest 64-hex external receipt")
    key, bound_id = _get_key(envelope, password=password, recovery=recovery)
    with PagedResearchVolume(image, key, expected_receipt=receipt,
                             read_only=read_only) as volume:
        if not hmac.compare_digest(bound_id, volume.id):
            raise PagedKeyError("Credential is bound to a different volume image")
        yield PagedFS2(volume)


def create_image(image: str | Path, envelope: str | Path, recovery: str | Path,
                 password: str, confirmation: str) -> dict:
    """Create a fresh, exclusive-create encrypted test volume and backup key."""
    if password != confirmation:
        raise PagedKeyError("Passwords do not match")
    _password_bytes(password)
    image = _image_path(image)
    _distinct(image, envelope, recovery)
    identity = None
    created_credentials: list[tuple[Path, tuple[int, int]]] = []
    try:
        with PagedResearchVolume(image, secrets.token_bytes(32), create=True) as v:
            info = os.fstat(v._f.fileno())
            identity = (info.st_dev, info.st_ino)
            fs = PagedFS2.format(v)
            provision_keys(v, password, envelope, recovery)
            # If any post-provisioning step fails, avoid leaving a complete
            # recovery key and envelope for an image that will be removed.
            for path in (Path(envelope), Path(recovery)):
                info = os.stat(path, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise PagedKeyError("Expected ordinary credential output")
                created_credentials.append((path, (info.st_dev, info.st_ino)))
            report = {
                "operation": "Created NEW development image",
                "receipt_changed": True,
                "image_id": v.id.hex(),
                "receipt": fs.receipt,
                "files_verified": 0,
                "warning": "Back up recovery OFF-device; retain receipt independently.",
            }

        # Do not report a volume as successfully created simply because the
        # encrypted bytes and key envelopes were written. Reopen the finalized
        # image with BOTH independently provisioned recovery methods and the
        # exact trusted receipt. If the key bundle is unusable, clean up the
        # newly created files while they are still owned by this operation.
        for credential in ({"password": password}, {"recovery": recovery}):
            with _open(image, envelope, report["receipt"],
                       read_only=True, **credential) as reopened:
                if reopened._volume.id.hex() != report["image_id"]:
                    raise PagedKeyError("Reopened image identity mismatch")
                result = reopened.verify_all()
                if (result["files_verified"] != 0
                        or result["bytes_verified"] != 0
                        or result["receipt"] != report["receipt"]):
                    raise PagedKeyError("New image or independent unlock failed")
        return report
    except BaseException:
        for path, created_identity in reversed(created_credentials):
            _remove_only_own(path, created_identity)
        if identity is not None:
            _remove_only_own(image, identity)
        raise


def verify_image(image: str | Path, envelope: str | Path, receipt: str,
                 *, password: str | None = None,
                 recovery: str | Path | None = None) -> dict:
    with _open(image, envelope, receipt, password=password, recovery=recovery,
               read_only=True) as fs:
        outcome = fs.verify_all()
        return {
            "operation": "Authenticated image verification",
            "receipt_changed": False,
            "image_id": fs._volume.id.hex(),
            "receipt": outcome["receipt"],
            "files_verified": outcome["files_verified"],
            "bytes_verified": outcome["bytes_verified"],
            "files": [
                {"name": name, "size": fs.stat(name)["size"]}
                for name in fs.list_files()
            ],
        }


class PostCommitVerificationError(RuntimeError):
    """Commit succeeded but later content authentication failed.

    unverified_receipt is only forensic recovery metadata, NOT a trusted
    anti-rollback anchor or proof the data is sound.
    """

    def __init__(self, unverified_receipt: str):
        super().__init__(
            "Write may have committed, but verification failed. "
            "DO NOT trust old receipt or updated state without recovery review."
        )
        self.unverified_receipt = unverified_receipt


def import_file(image: str | Path, envelope: str | Path, receipt: str,
                source: str | Path, *, password: str | None = None,
                recovery: str | Path | None = None) -> dict:
    """Import a verified REGULAR plaintext file without modifying its source."""
    image = _image_path(image)
    _distinct(image, envelope, source)
    source = Path(source)
    with _open_checked_file(source) as handle:
        if os.fstat(handle.fileno()).st_size > MAX_FILE_BYTES:
            raise ValueError("Plaintext file exceeds PFS/2 32-MiB per-file limit")
        payload = handle.read(MAX_FILE_BYTES + 1)
        if len(payload) > MAX_FILE_BYTES:
            raise ValueError("File grew past the 32-MiB limit while reading")
    with _open(image, envelope, receipt, password=password, recovery=recovery) as fs:
        # Check ALL live ciphertext before another COW commit. A valid
        # directory/receipt alone cannot detect damaged file contents.
        fs.verify_all()
        # Never overwrite an existing encrypted file; publish one COW commit.
        name = source.name
        fs.write_file(name, payload, replace=False)
        committed_receipt = fs.receipt
        try:
            if fs.read_file(name) != payload:
                raise ValueError("New authenticated file failed verification")
            fs.verify_all()
        except Exception as exc:
            # The new commit already exists. Expose its receipt only as
            # UNVERIFIED recovery metadata, never as a trusted new anchor.
            raise PostCommitVerificationError(committed_receipt) from exc
        return {
            "operation": "Imported encrypted file",
            "receipt_changed": True,
            "file": name,
            "bytes_verified": len(payload),
            "receipt": fs.receipt,
            "warning": "Plaintext original remains unchanged. Update trusted receipt NOW.",
        }


def export_file(image: str | Path, envelope: str | Path, receipt: str,
                name: str, output: str | Path, *, password: str | None = None,
                recovery: str | Path | None = None) -> dict:
    """Verify authenticated plaintext BEFORE exclusive-create export."""
    image = _image_path(image)
    _distinct(image, envelope, output)
    with _open(image, envelope, receipt, password=password, recovery=recovery,
               read_only=True) as fs:
        payload = fs.read_file(name)
        _new_private_file(output, payload)
        return {
            "operation": "Exported authenticated plaintext",
            "receipt_changed": False,
            "file": name,
            "bytes_verified": len(payload),
            "receipt": fs.receipt,
            "warning": "Output is UNENCRYPTED; use private storage. Never overwrite.",
        }


def recover_password(envelope: str | Path, recovery: str | Path,
                     new_envelope: str | Path, password: str,
                     confirmation: str) -> dict:
    if password != confirmation:
        raise PagedKeyError("Passwords do not match")
    _distinct(envelope, recovery, new_envelope)
    result = rewrap_password_with_recovery(
        envelope, recovery, password, new_envelope
    )
    return {
        "operation": "Created independent password envelope",
        "image_id": result["image_id"],
        "warning": "Old envelope AND old password still decrypt the SAME data key.",
    }


def rotate_image(image: str | Path, envelope: str | Path, receipt: str,
                 new_image: str | Path, new_envelope: str | Path,
                 new_recovery: str | Path, new_password: str,
                 confirmation: str, *, old_password: str | None = None,
                 old_recovery: str | Path | None = None) -> dict:
    if new_password != confirmation:
        raise PagedKeyError("Passwords do not match")
    _image_path(image)
    _image_path(new_image)
    _distinct(image, envelope, new_image, new_envelope, new_recovery)
    result = rotate_pfs2_data_key(
        image, envelope, receipt, new_image, new_envelope, new_recovery,
        new_password, old_password=old_password, old_recovery=old_recovery,
    )
    return {
        "operation": "Re-encrypted current files using NEW random data key",
        "receipt_changed": True,
        "image_id": result["destination_image_id"],
        "receipt": result["destination_receipt"],
        "files_verified": result["files_verified"],
        "bytes_verified": result["bytes_verified"],
        "warning": "Old snapshots remain readable with OLD credentials. "
                   "Securely back up NEW recovery secret and NEW trusted receipt.",
    }


def review_uncertain_image(image: str | Path, envelope: str | Path,
                           receipt: str, *, password: str | None = None,
                           recovery: str | Path | None = None) -> dict:
    """Forensic read-only history check against a PRIOR independently trusted receipt.

    Unlike verify_image(), the prior receipt need not equal the newest commit.
    A descendant is not a trusted new receipt: this function never makes
    another write safe, modifies the image, or authorizes receipt promotion.
    """
    from research.paged_receipt_reconcile import review_uncertain_commit

    image = _image_path(image)
    if recovery is not None:
        _distinct(image, envelope, recovery)
    else:
        _distinct(image, envelope)
    key, bound_id = _get_key(envelope, password=password, recovery=recovery)
    result = review_uncertain_commit(
        image, key, receipt, expected_image_id=bound_id
    )
    if result["review_only"] is not True:
        raise PagedKeyError("Expected read-only forensic review")
    # Deliberately do not add the generic 'receipt' field: the GUI's
    # receipt-export control must NEVER enable for forensic candidates.
    return {
        "operation": "Read-only forensic history analysis (TEST IMAGE)",
        **result,
        "receipt_changed": False,
        "operator_action": (
            "NO WRITES. Preserve the image and independent old receipt; "
            "a later authenticated commit is not authorization or freshness. "
            "Manual offline recovery and independent validation required."
        ),
    }


def seal_existing_trusted_receipt(
    image: str | Path, envelope: str | Path, trusted_receipt: str,
    destination: str | Path, *, password: str | None = None,
    recovery: str | Path | None = None,
) -> dict:
    """Create a write-once external pin ONLY for an already trusted receipt.

    The caller must protect the returned seal out-of-band; this cannot turn
    an unauthenticated or rolled-back candidate into a trusted baseline.
    """
    from research.receipt_anchor import pin_trusted_image

    image = _image_path(image)
    if recovery is not None:
        _distinct(image, envelope, recovery, destination)
    else:
        _distinct(image, envelope, destination)
    key, bound_id = _get_key(envelope, password=password, recovery=recovery)
    result = pin_trusted_image(
        image, key, trusted_receipt, destination, expected_image_id=bound_id
    )
    return {
        "operation": "Created write-once receipt pin for pre-trusted state",
        "receipt_changed": False,
        **result,
    }


def verify_sealed_receipt_image(
    image: str | Path, envelope: str | Path, pin_path: str | Path,
    independently_trusted_seal: str, *, password: str | None = None,
    recovery: str | Path | None = None,
) -> dict:
    """Read-only full-file check requiring an out-of-band anti-replay seal."""
    from research.receipt_anchor import verify_image_with_sealed_pin, ReceiptPinError

    image = _image_path(image)
    if recovery is not None:
        _distinct(image, envelope, pin_path, recovery)
    else:
        _distinct(image, envelope, pin_path)
    key, bound_id = _get_key(envelope, password=password, recovery=recovery)
    result = verify_image_with_sealed_pin(
        image, key, pin_path, independently_trusted_seal
    )
    if not hmac.compare_digest(result["image_id"], bound_id.hex()):
        raise ReceiptPinError("Credential image ID disagrees with trusted pin")
    return {
        "operation": "Read-only image check against externally sealed receipt pin",
        **result,
        "receipt_changed": False,
        "warning": "No implicit trust update. Keep the latest seal on independent storage.",
    }
