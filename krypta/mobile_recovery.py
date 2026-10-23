"""KRYPTA-MOBILE/2 portable offline recovery for Android encrypted files.

Independent 32-byte recovery secret is a full AES-256 key (not a short PIN).
This does not export or emulate Android Keystore; v1 files remain device-bound.
Authenticates the entire ciphertext before publishing any plaintext.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .core import CryptoError, _atomic_write, _open_checked_file, _prepare_paths

MAGIC = b"KRYPTA-MOBILE/2\n"
RECOVERY_DOMAIN = b"RECOVERY/2"
CHUNK = 65536
TAG = 16
MAX_RECORDS = 1 << 20
HEADER_SIZE = len(MAGIC) + 8 + 12 + 48 + 12 + 48


def _exact(source, count: int) -> bytes:
    out = bytearray()
    while len(out) < count:
        fragment = source.read(count - len(out))
        if not fragment:
            raise CryptoError("Truncated KRYPTA-MOBILE/2 archive")
        out.extend(fragment)
    return bytes(out)


def _key(path: str | Path) -> bytes:
    with _open_checked_file(Path(path)) as inp:
        material = inp.read(33)
    if len(material) != 32:
        raise CryptoError("Mobile recovery keyfile must contain exactly 32 random bytes")
    return material


def _open_authenticated(source, keyfile):
    header = _exact(source, HEADER_SIZE)
    if not header.startswith(MAGIC):
        raise CryptoError("Not a portable KRYPTA-MOBILE/2 archive")
    pos = len(MAGIC)
    prefix = header[pos:pos + 8]
    pos += 8
    # Skip Android Keystore wrap IV(12) + wrapped DEK(48).
    pos += 60
    iv = header[pos:pos + 12]
    wrapped = header[pos + 12:pos + 60]
    try:
        dek = AESGCM(_key(keyfile)).decrypt(
            iv, wrapped, MAGIC + prefix + RECOVERY_DOMAIN)
    except InvalidTag as exc:
        raise CryptoError("Invalid recovery key or tampered mobile archive header") from exc
    if len(dek) != 32:
        raise CryptoError("Invalid mobile DEK length")
    return AESGCM(dek), prefix, header


def _walk(source, cipher, prefix, header, sink):
    digest = hashlib.sha256()
    total = 0
    for index in range(MAX_RECORDS + 1):
        length = struct.unpack(">I", _exact(source, 4))[0]
        if length < TAG or length > CHUNK + TAG:
            raise CryptoError("Invalid mobile record length")
        encrypted = _exact(source, length)
        terminal = length == TAG
        aad = header + struct.pack(">IIB", index, length - TAG, int(terminal))
        try:
            plaintext = cipher.decrypt(prefix + index.to_bytes(4, "big"), encrypted, aad)
        except InvalidTag as exc:
            raise CryptoError("Mobile payload authentication failed") from exc
        if terminal:
            if plaintext or source.read(1):
                raise CryptoError("Invalid authenticated end or trailing bytes")
            return {"authenticated": True, "plaintext_bytes": total,
                    "plaintext_sha256": digest.hexdigest()}
        if index >= MAX_RECORDS or len(plaintext) != length - TAG or not plaintext:
            raise CryptoError("Invalid mobile data record")
        digest.update(plaintext)
        if sink is not None:
            sink.write(plaintext)
        total += len(plaintext)
    raise CryptoError("Mobile archive record count exceeded")


def verify_mobile_archive(source: str | Path, recovery_keyfile: str | Path) -> dict:
    """Authenticate portable Android file without writing plaintext."""
    with _open_checked_file(Path(source)) as inp:
        cipher, prefix, header = _open_authenticated(inp, recovery_keyfile)
        result = _walk(inp, cipher, prefix, header, None)
    return {**result, "format": "KRYPTA-MOBILE/2",
            "plaintext_written": False}


def recover_mobile_file(source: str | Path, destination: str | Path,
                        recovery_keyfile: str | Path) -> dict:
    """Two authenticated passes; publish plaintext only after full validation."""
    source, destination = _prepare_paths(source, destination)
    with _open_checked_file(source) as inp:
        cipher, prefix, header = _open_authenticated(inp, recovery_keyfile)
        first = _walk(inp, cipher, prefix, header, None)
    # Second pass authenticates again in case the input changed after validation.
    def writer(out):
        with _open_checked_file(source) as inp:
            cipher, prefix, header = _open_authenticated(inp, recovery_keyfile)
            second = _walk(inp, cipher, prefix, header, out)
            if second != first:
                raise CryptoError("Mobile archive changed between verification passes")
    _atomic_write(destination, writer)
    return {**first, "format": "KRYPTA-MOBILE/2",
            "recovery_output": str(destination), "plaintext_written": True}
