"""KRYPTA paged AEAD v2: portable Argon2id password + recovery envelope.

Test-only image integration; no raw devices, short PIN mode, TPM, or rollback
prevention. Reuses the reviewed private-file primitives of paged_keys but has
independent format, HKDF domains, AAD and volume-identity binding.
"""
from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
import secrets

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .paged_aead_v2 import PagedAEADImage, PagedAEADError
from .paged_keys import (
    PagedKeyError, _b64, _canonical, _decode, _new_private_file,
    _password_bytes, _read_regular, _remove_only_own, _unique_pairs,
)

FORMAT = "KRYPTA-PAGED-AEAD-KEYS/1"
DOMAIN = b"KRYPTA-PAGED-AEAD-KEYS/1"
MEMORY_KIB = 65536
TIME_COST = 3
PARALLELISM = 2
SALT_BYTES = 32
NONCE_BYTES = 12
SECRET_BYTES = 32
MAX_ENVELOPE_BYTES = 4096
KDF = {"algorithm": "argon2id", "memory_kib": MEMORY_KIB,
       "time_cost": TIME_COST, "parallelism": PARALLELISM}


class V2CredentialsError(ValueError):
    """Invalid private envelope, credential mismatch or unsafe image."""


def _volume_id(raw):
    if type(raw) is not bytes or len(raw) != 16:
        raise V2CredentialsError("A valid 16-byte volume identity is required")
    return raw


def _volume_key(raw):
    if type(raw) is not bytes or len(raw) != SECRET_BYTES:
        raise V2CredentialsError("A random 32-byte volume key is required")
    return raw


def _derive_password(password: str, salt: bytes, image_id: bytes):
    try:
        passphrase = _password_bytes(password)
    except PagedKeyError as exc:
        raise V2CredentialsError(str(exc)) from exc
    stretched = hash_secret_raw(
        secret=passphrase, salt=salt, time_cost=TIME_COST,
        memory_cost=MEMORY_KIB, parallelism=PARALLELISM,
        hash_len=SECRET_BYTES, type=Type.ID,
    )
    return HKDF(algorithm=hashes.SHA256(), length=SECRET_BYTES,
                salt=image_id, info=DOMAIN + b"/password").derive(stretched)


def _derive_recovery(secret: bytes, image_id: bytes):
    _volume_key(secret)
    return HKDF(algorithm=hashes.SHA256(), length=SECRET_BYTES,
                salt=image_id, info=DOMAIN + b"/recovery").derive(secret)


def _aad(image_id, salt, password_nonce, recovery_nonce, slot):
    return (DOMAIN + b"\x00" + image_id + salt + password_nonce +
            recovery_nonce + slot)


def _build(image_id, volume_key, password, recovery):
    _volume_id(image_id)
    _volume_key(volume_key)
    _volume_key(recovery)
    salt = secrets.token_bytes(SALT_BYTES)
    pn = secrets.token_bytes(NONCE_BYTES)
    rn = secrets.token_bytes(NONCE_BYTES)
    encrypted_password = AESGCM(
        _derive_password(password, salt, image_id)
    ).encrypt(pn, volume_key, _aad(image_id, salt, pn, rn, b"password"))
    encrypted_recovery = AESGCM(
        _derive_recovery(recovery, image_id)
    ).encrypt(rn, volume_key, _aad(image_id, salt, pn, rn, b"recovery"))
    doc = {
        "format": FORMAT, "volume_id": image_id.hex(), "kdf": KDF,
        "salt": _b64(salt),
        "password_nonce": _b64(pn),
        "password_wrapped": _b64(encrypted_password),
        "recovery_nonce": _b64(rn),
        "recovery_wrapped": _b64(encrypted_recovery),
    }
    output = _canonical(doc) + b"\n"
    if len(output) > MAX_ENVELOPE_BYTES:
        raise V2CredentialsError("Credential envelope capacity exceeded")
    return output


def _parse(content):
    if (type(content) is not bytes or
            not 0 < len(content) <= MAX_ENVELOPE_BYTES or
            not content.endswith(b"\n")):
        raise V2CredentialsError("Invalid credential envelope length")
    try:
        doc = json.loads(content[:-1].decode("ascii"),
                         object_pairs_hook=_unique_pairs)
        if (type(doc) is not dict or
                set(doc) != {"format", "volume_id", "kdf", "salt",
                             "password_nonce", "password_wrapped",
                             "recovery_nonce", "recovery_wrapped"} or
                doc["format"] != FORMAT or type(doc["kdf"]) is not dict or
                doc["kdf"] != KDF or
                type(doc["kdf"].get("memory_kib")) is not int or
                type(doc["kdf"].get("time_cost")) is not int or
                type(doc["kdf"].get("parallelism")) is not int or
                _canonical(doc) + b"\n" != content):
            raise V2CredentialsError("Unsupported or modified credential metadata")
        image_hex = doc["volume_id"]
        if (type(image_hex) is not str or len(image_hex) != 32 or
                any(ch not in "0123456789abcdef" for ch in image_hex)):
            raise V2CredentialsError("Invalid envelope volume identity")
        image_id = bytes.fromhex(image_hex)
        salt = _decode(doc["salt"], SALT_BYTES)
        pn = _decode(doc["password_nonce"], NONCE_BYTES)
        rn = _decode(doc["recovery_nonce"], NONCE_BYTES)
        pw = _decode(doc["password_wrapped"], SECRET_BYTES + 16)
        rc = _decode(doc["recovery_wrapped"], SECRET_BYTES + 16)
        return image_id, salt, pn, rn, pw, rc
    except (ValueError, UnicodeError, TypeError, KeyError, PagedKeyError) as exc:
        raise V2CredentialsError("Invalid or noncanonical encrypted credentials") from exc


def _unlock(envelope_path, secret, *, use_recovery):
    try:
        content = _read_regular(envelope_path, MAX_ENVELOPE_BYTES,
                                require_private=True)
        image_id, salt, pn, rn, pw, rc = _parse(content)
        if use_recovery:
            key = _derive_recovery(secret, image_id)
            result = AESGCM(key).decrypt(
                rn, rc, _aad(image_id, salt, pn, rn, b"recovery"))
        else:
            key = _derive_password(secret, salt, image_id)
            result = AESGCM(key).decrypt(
                pn, pw, _aad(image_id, salt, pn, rn, b"password"))
        return _volume_key(result), image_id
    except (InvalidTag, ValueError, TypeError, PagedKeyError) as exc:
        raise V2CredentialsError("Credential authentication failed") from exc


def unlock_v2_password(envelope_path: str | Path, password: str):
    """Return (unwrapped 32-byte volume key, authenticated volume ID)."""
    return _unlock(envelope_path, password, use_recovery=False)


def unlock_v2_recovery(envelope_path: str | Path, recovery_path: str | Path):
    """Read independent private 32-byte recovery secret; do not print it."""
    try:
        secret = _read_regular(recovery_path, SECRET_BYTES,
                               require_private=True)
        _volume_key(secret)
    except (PagedKeyError, ValueError) as exc:
        raise V2CredentialsError("Invalid private recovery secret") from exc
    return _unlock(envelope_path, secret, use_recovery=True)


def _check_paths(image_path, envelope_path, recovery_path):
    resolved = [
        Path(p).resolve(strict=False)
        for p in (image_path, envelope_path, recovery_path)
    ]
    if len(set(resolved)) != 3:
        raise V2CredentialsError("Image, credential and recovery paths must differ")


def provision_v2_credentials(
    image_path: str | Path, volume_key: bytes, password: str,
    envelope_path: str | Path, recovery_path: str | Path, *,
    physical_sectors: int, expected_receipt: str,
) -> dict:
    """Non-destructively create separately stored password/recovery secrets.

    Opens source READ ONLY and verifies it with a pre-existing trusted receipt.
    Both private credential outputs use exclusive create (no overwrite).
    """
    _volume_key(volume_key)
    _check_paths(image_path, envelope_path, recovery_path)
    try:
        _password_bytes(password)  # validate without a wasted Argon2 invocation
    except PagedKeyError as exc:
        raise V2CredentialsError(str(exc)) from exc
    with PagedAEADImage.open(
        image_path, volume_key, physical_sectors=physical_sectors,
        expected_receipt=expected_receipt, read_only=True,
    ) as image:
        image.verify_all()
        image_id = image._vid
        recovery = secrets.token_bytes(SECRET_BYTES)
        blob = _build(image_id, volume_key, password, recovery)
        created = []
        try:
            created.append((Path(recovery_path), _new_private_file(
                recovery_path, recovery)))
            created.append((Path(envelope_path), _new_private_file(
                envelope_path, blob)))
            # Read from actual durable files and independently test both paths.
            if unlock_v2_password(envelope_path, password) != (volume_key, image_id):
                raise V2CredentialsError("Password enrollment verification failed")
            if unlock_v2_recovery(envelope_path, recovery_path) != (
                    volume_key, image_id):
                raise V2CredentialsError("Recovery enrollment verification failed")
            return {
                "volume_id": image_id.hex(), "image_modified": False,
                "envelope_path": str(envelope_path),
                "recovery_path": str(recovery_path),
                "physical_disk_write_authorized": False,
            }
        except BaseException:
            for path, identity in reversed(created):
                _remove_only_own(path, identity)
            raise


def _open_bound(image_path, volume_key, image_id, *,
                physical_sectors, expected_receipt, read_only):
    try:
        image = PagedAEADImage.open(
            image_path, volume_key, physical_sectors=physical_sectors,
            expected_receipt=expected_receipt, read_only=read_only)
    except PagedAEADError as exc:
        raise V2CredentialsError("Encrypted image authentication failed") from exc
    if not hmac.compare_digest(image._vid, image_id):
        image.close()
        raise V2CredentialsError("Credential belongs to a different image")
    return image


def open_v2_with_password(image_path, envelope_path, password, *,
                          physical_sectors: int, expected_receipt: str,
                          read_only: bool = True):
    key, image_id = unlock_v2_password(envelope_path, password)
    return _open_bound(image_path, key, image_id,
                       physical_sectors=physical_sectors,
                       expected_receipt=expected_receipt, read_only=read_only)


def open_v2_with_recovery(image_path, envelope_path, recovery_path, *,
                          physical_sectors: int, expected_receipt: str,
                          read_only: bool = True):
    key, image_id = unlock_v2_recovery(envelope_path, recovery_path)
    return _open_bound(image_path, key, image_id,
                       physical_sectors=physical_sectors,
                       expected_receipt=expected_receipt, read_only=read_only)
