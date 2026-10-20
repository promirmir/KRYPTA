"""KRYPTA-PVKEY/1: independent password + recovery envelopes for PVIMG.

This is NOT a TPM or PIN security protocol. No offline guess throttling is
possible when an attacker copies the password envelope. A long passphrase is
REQUIRED; a 1-4 digit PIN can only be safely offered later when a real
hardware-enforced non-exportable second factor is integrated and audited.

PVKEY does not change PVIMG/PFS formats or authenticate rollback of the image.
Keep the newest PVIMG receipt in a truly independent trusted store.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .paged_volume import PagedResearchVolume

FORMAT = "KRYPTA-PVKEY/1"
DOMAIN = b"KRYPTA-PVKEY/1/WRAPPING"
MEMORY_KIB = 65536
TIME_COST = 3
PARALLELISM = 2
SALT_BYTES = 32
NONCE_BYTES = 12
VOLUME_KEY_BYTES = 32
RECOVERY_BYTES = 32
MAX_ENVELOPE_BYTES = 4096


class PagedKeyError(ValueError):
    """Wrong secret, unauthenticated envelope or unsafe storage operation."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(encoded: object, length: int) -> bytes:
    if not isinstance(encoded, str):
        raise PagedKeyError("Invalid encrypted credential record")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise PagedKeyError("Invalid encrypted credential encoding") from exc
    if len(raw) != length or _b64(raw) != encoded:
        raise PagedKeyError("Noncanonical encrypted credential encoding")
    return raw


def _canonical(obj: dict) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _unique_pairs(items: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for k, v in items:
        if k in result:
            raise PagedKeyError("Duplicate credential metadata")
        result[k] = v
    return result


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str):
        raise PagedKeyError("Expected a Unicode passphrase")
    # Normalization cannot silently change a passphrase during re-enrollment.
    if unicodedata.normalize("NFC", password) != password or "\x00" in password:
        raise PagedKeyError("Passphrase must be NFC-normalized without NUL")
    data = password.encode("utf-8")
    if len(password) < 12 or len(data) > 4096:
        raise PagedKeyError(
            "This password-only mode requires at least 12 Unicode characters; "
            "short PINs need a separately verified hardware second factor"
        )
    return data


def _password_key(password: str, salt: bytes, image_id: bytes) -> bytes:
    pwd = _password_bytes(password)
    stretched = hash_secret_raw(
        secret=pwd, salt=salt, time_cost=TIME_COST,
        memory_cost=MEMORY_KIB, parallelism=PARALLELISM,
        hash_len=32, type=Type.ID,
    )
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=image_id,
        info=DOMAIN + b"/password",
    ).derive(stretched)


def _recovery_key(secret: bytes, image_id: bytes) -> bytes:
    if not isinstance(secret, bytes) or len(secret) != RECOVERY_BYTES:
        raise PagedKeyError("Recovery must be a separate random 32-byte secret")
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=image_id,
        info=DOMAIN + b"/recovery",
    ).derive(secret)


def _aad(image_id: bytes, salt: bytes, pw_nonce: bytes,
         recovery_nonce: bytes, slot: bytes) -> bytes:
    return (DOMAIN + b"\x00" + image_id + salt + pw_nonce
            + recovery_nonce + slot)


def _build(image_id: bytes, volume_key: bytes, password: str,
           recovery_secret: bytes) -> bytes:
    if not isinstance(image_id, bytes) or len(image_id) != 16:
        raise PagedKeyError("Invalid PVIMG image identity")
    if not isinstance(volume_key, bytes) or len(volume_key) != VOLUME_KEY_BYTES:
        raise PagedKeyError("Invalid PVIMG volume key")
    salt, pw_nonce, recovery_nonce = (
        secrets.token_bytes(SALT_BYTES), secrets.token_bytes(NONCE_BYTES),
        secrets.token_bytes(NONCE_BYTES)
    )
    password_encrypted = AESGCM(
        _password_key(password, salt, image_id)
    ).encrypt(
        pw_nonce, volume_key, _aad(image_id, salt, pw_nonce, recovery_nonce, b"password")
    )
    recovery_encrypted = AESGCM(
        _recovery_key(recovery_secret, image_id)
    ).encrypt(
        recovery_nonce, volume_key, _aad(image_id, salt, pw_nonce, recovery_nonce, b"recovery")
    )
    document = {
        "format": FORMAT,
        "image_id": image_id.hex(),
        "kdf": {
            "algorithm": "argon2id", "memory_kib": MEMORY_KIB,
            "time_cost": TIME_COST, "parallelism": PARALLELISM,
        },
        "salt": _b64(salt),
        "password_nonce": _b64(pw_nonce),
        "password_wrapped": _b64(password_encrypted),
        "recovery_nonce": _b64(recovery_nonce),
        "recovery_wrapped": _b64(recovery_encrypted),
    }
    result = _canonical(document) + b"\n"
    if len(result) > MAX_ENVELOPE_BYTES:
        raise PagedKeyError("Credential envelope exceeds size limit")
    return result


def _parse(blob: bytes) -> tuple[dict, bytes, bytes, bytes, bytes]:
    if (not isinstance(blob, bytes) or not 0 < len(blob) <= MAX_ENVELOPE_BYTES
            or not blob.endswith(b"\n")):
        raise PagedKeyError("Invalid credential envelope length")
    try:
        doc = json.loads(blob[:-1].decode("ascii"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise PagedKeyError("Invalid encrypted credential metadata") from exc
    if (not isinstance(doc, dict) or set(doc) != {
            "format", "image_id", "kdf", "salt", "password_nonce",
            "password_wrapped", "recovery_nonce", "recovery_wrapped",
        } or doc["format"] != FORMAT or not isinstance(doc["kdf"], dict)
            or doc["kdf"] != {
                "algorithm": "argon2id", "memory_kib": MEMORY_KIB,
                "time_cost": TIME_COST, "parallelism": PARALLELISM,
            } or type(doc["kdf"]["memory_kib"]) is not int
            or type(doc["kdf"]["time_cost"]) is not int
            or type(doc["kdf"]["parallelism"]) is not int
            or blob != _canonical(doc) + b"\n"):
        raise PagedKeyError("Invalid or noncanonical credential envelope")
    image_id_hex = doc["image_id"]
    if (not isinstance(image_id_hex, str) or len(image_id_hex) != 32
            or any(c not in "0123456789abcdef" for c in image_id_hex)):
        raise PagedKeyError("Invalid credential image identity")
    image_id = bytes.fromhex(image_id_hex)
    salt = _decode(doc["salt"], SALT_BYTES)
    pw_nonce = _decode(doc["password_nonce"], NONCE_BYTES)
    recovery_nonce = _decode(doc["recovery_nonce"], NONCE_BYTES)
    _decode(doc["password_wrapped"], VOLUME_KEY_BYTES + 16)
    _decode(doc["recovery_wrapped"], VOLUME_KEY_BYTES + 16)
    return doc, image_id, salt, pw_nonce, recovery_nonce


def _read_regular(path: str | Path, limit: int, *, require_private: bool) -> bytes:
    p = Path(path)
    if p.is_symlink():
        raise PagedKeyError("Symlink is not a trusted credential file")
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
        getattr(os, "O_NOFOLLOW", 0) |
        getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(p, flags)
    except OSError as exc:
        raise PagedKeyError("Cannot open private credential file") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise PagedKeyError("Credential is not a bounded regular file")
        if os.name == "posix" and require_private and (
            info.st_mode & 0o077 or info.st_uid != os.getuid()
        ):
            raise PagedKeyError("Credential must be privately owned, mode 0600/0400")
        with os.fdopen(fd, "rb") as f:
            fd = -1
            result = f.read(limit + 1)
        if not 0 < len(result) <= limit:
            raise PagedKeyError("Invalid private credential file size")
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _new_private_file(path: str | Path, data: bytes) -> tuple[int, int]:
    p = Path(path)
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) |
        getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(p, flags, 0o600)
    except OSError as exc:
        raise PagedKeyError("Refusing to overwrite existing credential path") from exc
    identity = None
    try:
        info = os.fstat(fd)
        identity = (info.st_dev, info.st_ino)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        return identity
    except BaseException:
        # Atomic-looking exclusive create is not atomic with fd writes/fsync.
        # A write or sync failure must not leave a partial credential bundle.
        # Never delete a destination replaced by an unrelated inode.
        if identity is not None:
            _remove_only_own(p, identity)
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def _remove_only_own(path: str | Path, identity: tuple[int, int]) -> None:
    try:
        now = os.stat(path, follow_symlinks=False)
        if stat.S_ISREG(now.st_mode) and (now.st_dev, now.st_ino) == identity:
            os.unlink(path)
    except OSError:
        pass


def provision_keys(volume: PagedResearchVolume, password: str,
                   envelope_path: str | Path, recovery_path: str | Path) -> dict:
    """Write an exclusive-create encrypted bundle + separate recovery key.

    Never overwrite, format or touch the volume data. The user must independently
    back up the recovery file away from the encrypted image and password.
    """
    if not isinstance(volume, PagedResearchVolume):
        raise TypeError("An opened encrypted PVIMG/1 volume is required")
    volume._check()
    _password_bytes(password)  # validate BEFORE writing any file
    image_path = volume.path.resolve(strict=False)
    envelope_path, recovery_path = Path(envelope_path), Path(recovery_path)
    if (image_path in (envelope_path.resolve(strict=False),
                       recovery_path.resolve(strict=False))
            or envelope_path.resolve(strict=False) == recovery_path.resolve(strict=False)):
        raise PagedKeyError("Credential, recovery and image paths must differ")
    recovery = secrets.token_bytes(RECOVERY_BYTES)
    ciphertext = _build(volume.id, volume.key, password, recovery)
    created: list[tuple[Path, tuple[int, int]]] = []
    try:
        created.append((recovery_path, _new_private_file(recovery_path, recovery)))
        created.append((envelope_path, _new_private_file(envelope_path, ciphertext)))
        return {"image_id": volume.id.hex(), "envelope_path": str(envelope_path),
                "recovery_path": str(recovery_path)}
    except BaseException:
        for path, identity in reversed(created):
            _remove_only_own(path, identity)
        raise


def unlock_password(envelope_path: str | Path, password: str) -> tuple[bytes, bytes]:
    """Return (32-byte PVIMG key, 16-byte bound image ID), or fail closed."""
    blob = _read_regular(envelope_path, MAX_ENVELOPE_BYTES, require_private=True)
    doc, image_id, salt, pw_nonce, recovery_nonce = _parse(blob)
    try:
        wrapped = _decode(doc["password_wrapped"], VOLUME_KEY_BYTES + 16)
        key = AESGCM(_password_key(password, salt, image_id)).decrypt(
            pw_nonce, wrapped, _aad(image_id, salt, pw_nonce, recovery_nonce, b"password")
        )
    except (InvalidTag, ValueError) as exc:
        raise PagedKeyError("Credential authentication failed") from exc
    if len(key) != VOLUME_KEY_BYTES:
        raise PagedKeyError("Authenticated credential key has invalid size")
    return key, image_id


def unlock_recovery(envelope_path: str | Path,
                    recovery_path: str | Path) -> tuple[bytes, bytes]:
    """Use an independent 256-bit recovery secret; never derives from PIN."""
    recovery = _read_regular(recovery_path, RECOVERY_BYTES, require_private=True)
    blob = _read_regular(envelope_path, MAX_ENVELOPE_BYTES, require_private=True)
    doc, image_id, salt, pw_nonce, recovery_nonce = _parse(blob)
    try:
        wrapped = _decode(doc["recovery_wrapped"], VOLUME_KEY_BYTES + 16)
        key = AESGCM(_recovery_key(recovery, image_id)).decrypt(
            recovery_nonce, wrapped, _aad(image_id, salt, pw_nonce, recovery_nonce, b"recovery")
        )
    except (InvalidTag, ValueError) as exc:
        raise PagedKeyError("Credential authentication failed") from exc
    if len(key) != VOLUME_KEY_BYTES:
        raise PagedKeyError("Authenticated recovery key has invalid size")
    return key, image_id


def rewrap_password_with_recovery(old_envelope: str | Path,
                                  recovery_path: str | Path,
                                  new_password: str, new_envelope: str | Path) -> dict:
    """Create a NEW, exclusive-creation password envelope using recovery key.

    The original credential file is NOT overwritten or shredded. Someone
    holding a copy of the old envelope and password can still recover the same
    volume key. True password revocation requires a new data-encryption key
    and migration; this is recovery, not credential revocation.
    """
    _password_bytes(new_password)
    original, new_envelope = Path(old_envelope), Path(new_envelope)
    if original.resolve(strict=False) == new_envelope.resolve(strict=False):
        raise PagedKeyError("Recovery requires a new destination path")
    volume_key, image_id = unlock_recovery(original, recovery_path)
    recovery = _read_regular(recovery_path, RECOVERY_BYTES, require_private=True)
    content = _build(image_id, volume_key, new_password, recovery)
    identity = _new_private_file(new_envelope, content)
    try:
        if unlock_password(new_envelope, new_password) != (volume_key, image_id):
            raise PagedKeyError("New recovery envelope verification failed")
        if unlock_recovery(new_envelope, recovery_path) != (volume_key, image_id):
            raise PagedKeyError("New recovery secret verification failed")
        return {"image_id": image_id.hex(), "new_envelope_path": str(new_envelope)}
    except BaseException:
        _remove_only_own(new_envelope, identity)
        raise
