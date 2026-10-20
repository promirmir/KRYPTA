"""KRYPTA: verified PFS/2 migration to an INDEPENDENT data-encryption key.

This procedure is a non-destructive, no-overwrite *new image* migration.
It does NOT rewrite the original image in place. Any old copy of the original
image together with the old key can STILL be read by its holder. Password
envelope rewrap alone does not revoke access; this creates a different
PVIMG image ID, random volume key and independent password/recovery slots.

No real/physical disk writes; never use on irreplaceable data before audit.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path
import secrets
import stat

from .paged_fs2 import PagedFS2, PagedFS2Error
from .paged_keys import (
    PagedKeyError, _password_bytes, _remove_only_own,
    provision_keys, unlock_password, unlock_recovery,
)
from .paged_volume import PagedResearchVolume, PagedVolumeError


def _unique_destination_paths(paths: tuple[Path, ...]) -> None:
    resolved = [p.resolve(strict=False) for p in paths]
    if len(set(resolved)) != len(resolved):
        raise PagedKeyError("Encrypted image/credential paths must all be distinct")
    for path in paths:
        if path.is_symlink():
            raise PagedKeyError("Symlink credential/image destinations are forbidden")


def _identity(path: Path) -> tuple[int, int]:
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise PagedKeyError("Only normal encrypted image and credential files allowed")
    return info.st_dev, info.st_ino


def rotate_pfs2_data_key(
    source_image: str | Path,
    source_envelope: str | Path,
    source_receipt: str,
    destination_image: str | Path,
    destination_envelope: str | Path,
    destination_recovery: str | Path,
    new_password: str,
    *,
    old_password: str | None = None,
    old_recovery: str | Path | None = None,
) -> dict:
    """Create a NEW PFS/2 image, with a NEW random DEK and recovery secret.

    The source must be independently authenticated against its currently
    TRUSTED external receipt. Exactly one existing credential is required.
    Every LIVE source file is fully AEAD/digest-verified before a new target
    file is created. New files are written with authenticated PVIMG/PFS/2
    commits and compared to the source again before returning success.

    Output paths are exclusive-create, and failures remove only outputs
    created by this invocation, matched by inode; no partial migration is
    considered a completed recovery. A hardware-backed trusted receipt store
    is NOT provisioned by this routine.
    """
    if (old_password is None) == (old_recovery is None):
        raise PagedKeyError("Select exactly one existing password or recovery file")
    _password_bytes(new_password)
    if old_password is not None and new_password == old_password:
        raise PagedKeyError("Rekey requires a DIFFERENT new passphrase")
    source_image, source_envelope = Path(source_image), Path(source_envelope)
    destination_image, destination_envelope, destination_recovery = (
        Path(destination_image), Path(destination_envelope),
        Path(destination_recovery),
    )
    _unique_destination_paths((
        source_image, source_envelope, destination_image,
        destination_envelope, destination_recovery,
        *((Path(old_recovery),) if old_recovery is not None else ()),
    ))
    for target in (destination_image, destination_envelope, destination_recovery):
        if target.exists() or target.is_symlink():
            raise PagedKeyError("Refusing to overwrite existing migration destination")

    if old_recovery is not None:
        old_key, source_image_id = unlock_recovery(source_envelope, old_recovery)
    else:
        old_key, source_image_id = unlock_password(source_envelope, old_password)

    owned: list[tuple[Path, tuple[int, int]]] = []
    try:
        with PagedResearchVolume(source_image, old_key,
                                 expected_receipt=source_receipt) as original:
            if not hmac.compare_digest(original.id, source_image_id):
                raise PagedKeyError("Credential belongs to a different encrypted image")
            old_fs = PagedFS2(original)
            initial = old_fs.verify_all()
            old_names = old_fs.list_files()
            fresh_key = secrets.token_bytes(32)
            if hmac.compare_digest(fresh_key, old_key):
                raise PagedKeyError("Independent encryption key generation failed")
            with PagedResearchVolume(destination_image, fresh_key,
                                     create=True) as target:
                owned.append((destination_image, _identity(destination_image)))
                new_fs = PagedFS2.format(target)
                for name in old_names:
                    plaintext = old_fs.read_file(name)
                    new_fs.write_file(name, plaintext)
                    # Round-trip compares independent authenticated ciphertext
                    # under a fresh image ID and fresh key.
                    if not hmac.compare_digest(plaintext, new_fs.read_file(name)):
                        raise PagedFS2Error("Re-encrypted file verification failed")
                copied = new_fs.verify_all()
                if (copied["files_verified"] != initial["files_verified"]
                        or copied["bytes_verified"] != initial["bytes_verified"]
                        or new_fs.list_files() != old_names
                        or hmac.compare_digest(target.id, original.id)):
                    raise PagedFS2Error("Rekeyed filesystem catalogue verification failed")

                provision_keys(target, new_password, destination_envelope,
                               destination_recovery)
                owned.append((destination_envelope, _identity(destination_envelope)))
                owned.append((destination_recovery, _identity(destination_recovery)))
                if unlock_password(destination_envelope, new_password) != (
                    fresh_key, target.id
                ):
                    raise PagedKeyError("New password slot cannot unlock new key")
                if unlock_recovery(destination_envelope, destination_recovery) != (
                    fresh_key, target.id
                ):
                    raise PagedKeyError("New recovery slot cannot unlock new key")
                if original.receipt != initial["receipt"]:
                    raise PagedKeyError("Source receipt changed during migration")
                receipt, image_id, seq = target.receipt, target.id.hex(), target.sequence

            # Verify the finalized on-disk image using the new independent key
            # and its own external receipt, not just live Python handles.
            with PagedResearchVolume(destination_image, fresh_key,
                                     expected_receipt=receipt) as opened:
                if opened.id.hex() != image_id:
                    raise PagedKeyError("New PVIMG image identity mismatch")
                check = PagedFS2(opened).verify_all()
                if (check["files_verified"] != initial["files_verified"]
                        or check["bytes_verified"] != initial["bytes_verified"]):
                    raise PagedFS2Error("Reopened rekeyed image verification failed")

            return {
                "source_image_id": original.id.hex(),
                "source_receipt": initial["receipt"],
                "destination_image_id": image_id,
                "destination_receipt": receipt,
                "destination_sequence": seq,
                "files_verified": copied["files_verified"],
                "bytes_verified": copied["bytes_verified"],
            }
    except BaseException:
        # Failure cleanup never unlinks the user's original image/envelope.
        # It also never deletes a destination pathname replaced by a
        # different inode while the operation was running.
        for path, identity in reversed(owned):
            _remove_only_own(path, identity)
        raise
