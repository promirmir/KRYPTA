"""KRYPTA HORIZON/0 — EXPERIMENTAL authenticated block-encryption construction.

RESEARCH ONLY: never use for real files, disk encryption, recovery keys or secrets.
No mountable filesystem, crash atomicity, rollback anchor or hardware PIN defense.
The scheme deliberately does NOT replace the working File Vault format.

Construction: domain-separated HKDF-SHA512 -> AES-256-GCM -> ChaCha20-Poly1305.
Research claim: detects selected tampering, NOT proven stronger than a standard AEAD.
"""
from __future__ import annotations

import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"KRYHOR0\x00"
RECORD = struct.Struct(">8sQQI32s12s12s")
MAX_BLOCK_BYTES = 65536
MAX_AAD_BYTES = 4096
_MIN_RECORD = RECORD.size + 32  # two independent 16-byte AEAD tags
_DOMAIN = b"KRYPTA-HORIZON/0/RESEARCH-ONLY/"


class HorizonError(ValueError):
    """Invalid research record or authentication failure, no plaintext released."""


def _master_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise HorizonError("Expected exactly 32 random master-key bytes")
    return key


def _nonnegative_64(value: int, name: str) -> int:
    if type(value) is not int or not 0 <= value < (1 << 64):
        raise HorizonError(f"Invalid {name}")
    return value


def _aad(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) > MAX_AAD_BYTES:
        raise HorizonError("Invalid additional authenticated data")
    return value


def _keys(master: bytes, salt: bytes, index: int, generation: int) -> tuple[bytes, bytes]:
    material = HKDF(
        algorithm=SHA512(), length=64, salt=salt,
        info=_DOMAIN + b"KEY-SEPARATION" + struct.pack(">QQ", index, generation),
    ).derive(master)
    return material[:32], material[32:]


def _context(header: bytes, aad: bytes) -> bytes:
    return _DOMAIN + b"METADATA" + struct.pack(">I", len(aad)) + aad + header


def seal_block(master_key: bytes, index: int, generation: int,
               plaintext: bytes, aad: bytes = b"") -> bytes:
    """Seal a disposable test block. No caller-supplied nonces or keys on disk.

    Generation counters require externally guaranteed monotonicity for real disks.
    That feature does not exist in this experimental module.
    """
    master = _master_key(master_key)
    index = _nonnegative_64(index, "index")
    generation = _nonnegative_64(generation, "generation")
    context = _aad(aad)
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_BLOCK_BYTES:
        raise HorizonError("Test block exceeds maximum size")
    salt, nonce_a, nonce_c = (
        secrets.token_bytes(32), secrets.token_bytes(12), secrets.token_bytes(12))
    header = RECORD.pack(
        MAGIC, index, generation, len(plaintext), salt, nonce_a, nonce_c)
    ka, kc = _keys(master, salt, index, generation)
    bound = _context(header, context)
    inner = AESGCM(ka).encrypt(nonce_a, plaintext, bound + b"/AES-INNER")
    outer = ChaCha20Poly1305(kc).encrypt(nonce_c, inner, bound + b"/CHACHA-OUTER")
    return header + outer


def open_block(master_key: bytes, expected_index: int, expected_generation: int,
               record: bytes, aad: bytes = b"") -> bytes:
    """Authenticate record then return plaintext or raise without partial output.

    expected_generation alone does not detect rollback unless the caller stores a
    trusted latest generation OUTSIDE the attacker's mutable encrypted storage.
    """
    master = _master_key(master_key)
    expected_index = _nonnegative_64(expected_index, "index")
    expected_generation = _nonnegative_64(expected_generation, "generation")
    context = _aad(aad)
    if (not isinstance(record, bytes) or len(record) < _MIN_RECORD or
            len(record) > RECORD.size + MAX_BLOCK_BYTES + 32):
        raise HorizonError("Malformed research block length")
    header = record[:RECORD.size]
    try:
        magic, index, generation, length, salt, nonce_a, nonce_c = RECORD.unpack(header)
    except struct.error as exc:
        raise HorizonError("Malformed research header") from exc
    if magic != MAGIC or length > MAX_BLOCK_BYTES:
        raise HorizonError("Unsupported research format")
    if index != expected_index or generation != expected_generation:
        raise HorizonError("Block address or expected generation mismatch")
    if len(record) != RECORD.size + length + 32:
        raise HorizonError("Record length mismatch")
    ka, kc = _keys(master, salt, index, generation)
    bound = _context(header, context)
    try:
        inner = ChaCha20Poly1305(kc).decrypt(
            nonce_c, record[RECORD.size:], bound + b"/CHACHA-OUTER")
        plain = AESGCM(ka).decrypt(nonce_a, inner, bound + b"/AES-INNER")
    except InvalidTag as exc:
        raise HorizonError("Record authentication failed") from exc
    if len(plain) != length:
        raise HorizonError("Unexpected plaintext length")
    return plain
