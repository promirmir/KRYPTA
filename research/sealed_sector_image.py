"""KRYPTA experimental crash-consistent authenticated *test* sector image.

Not a physical disk driver. Uses existing ordinary-file-only TestSectorTransport.
Uses AES-256-GCM, domain-separated HKDF keys, copy-on-write physical sectors and
two independently authenticated metadata slots. Callers MUST separately pin the
latest receipt; a copied old valid image is otherwise indistinguishable from
current state. Intended for disposable test data, not user secrets.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .test_sector_transport import (
    SECTOR_BYTES, TestSectorTransport, SectorTransportError,
)

MAGIC = b"KRYPTA-AEAD-SECTOR/1\x00"
SLOT_MAGIC = b"KASM"
FIRST_DATA_SECTOR = 3
MAX_LOGICAL_SECTORS = 32
MAX_BATCH_SECTORS = 8
ZERO = bytes(SECTOR_BYTES)
_HEADER_LEN = len(MAGIC) + 16 + 8 + 32


class SealedSectorError(RuntimeError):
    """Invalid sealed image, missing latest independent receipt or uncertain I/O."""


def _master(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise SealedSectorError("Exactly 32 random master-key bytes required")
    return value


def _keys(master: bytes, volume_id: bytes) -> tuple[bytes, bytes, bytes]:
    # Disjoint key material for header MAC, AEAD metadata, and AEAD file sectors.
    def derive(label: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=volume_id,
                    info=b"KRYPTA-AEAD-SECTOR/1/" + label).derive(master)
    return derive(b"header"), derive(b"metadata"), derive(b"data")


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def _receipt(header: bytes, slot: bytes) -> str:
    return hashlib.sha256(b"KRYPTA-RECEIPT/1" + header + slot).hexdigest()


def _seal_header(master: bytes, vid: bytes, physical: int, logical: int) -> bytes:
    head_key, _, _ = _keys(master, vid)
    body = MAGIC + vid + struct.pack(">II", physical, logical)
    tag = hmac.digest(head_key, body, "sha256")
    return body + tag + bytes(SECTOR_BYTES - len(body) - len(tag))


def _read_header(raw: bytes, master: bytes, physical: int) -> tuple[bytes, int]:
    if len(raw) != SECTOR_BYTES or not raw.startswith(MAGIC):
        raise SealedSectorError("Unknown sealed scratch image header")
    vid = raw[len(MAGIC):len(MAGIC) + 16]
    if len(vid) != 16:
        raise SealedSectorError("Missing image identity")
    size, logical = struct.unpack(">II", raw[len(MAGIC) + 16:len(MAGIC) + 24])
    if size != physical or not 1 <= logical <= MAX_LOGICAL_SECTORS:
        raise SealedSectorError("Image geometry mismatch")
    if size < FIRST_DATA_SECTOR + logical or any(raw[_HEADER_LEN:]):
        raise SealedSectorError("Corrupt image header padding/geometry")
    body_end = len(MAGIC) + 24
    mac = raw[body_end:body_end + 32]
    key, _, _ = _keys(master, vid)
    if not hmac.compare_digest(mac, hmac.digest(key, raw[:body_end], "sha256")):
        raise SealedSectorError("Header authentication failed")
    return vid, logical


def _validate_state(doc: object, physical: int, logical: int) -> dict:
    if not isinstance(doc, dict) or set(doc) != {"version", "sequence", "next", "map"}:
        raise SealedSectorError("Invalid authenticated sector directory")
    if doc["version"] != 1 or type(doc["version"]) is not int:
        raise SealedSectorError("Unsupported image directory version")
    seq, next_free, mapping = doc["sequence"], doc["next"], doc["map"]
    if (type(seq) is not int or not 0 <= seq < 2**64 or
            type(next_free) is not int or not FIRST_DATA_SECTOR <= next_free <= physical or
            not isinstance(mapping, dict) or len(mapping) > logical):
        raise SealedSectorError("Invalid authenticated sector allocation")
    addresses = set()
    for index, entry in mapping.items():
        if (not isinstance(index, str) or not index.isascii() or
                not index.isdecimal() or str(int(index)) != index or
                not 0 <= int(index) < logical or
                not isinstance(entry, list) or len(entry) != 3):
            raise SealedSectorError("Malformed authenticated sector reference")
        addr, nonce, tag = entry
        if (type(addr) is not int or not FIRST_DATA_SECTOR <= addr < next_free or
                addr in addresses or
                type(nonce) is not str or len(nonce) != 24 or
                type(tag) is not str or len(tag) != 32 or
                any(c not in "0123456789abcdef" for c in nonce + tag)):
            raise SealedSectorError("Invalid or reused physical sector reference")
        addresses.add(addr)
    return doc


class SealedSectorImage:
    """32-logical-sector proof of crash-atomic authenticated 4096-byte updates."""

    def __init__(self, transport: TestSectorTransport, master_key: bytes,
                 *, expected_receipt: str):
        self._io = transport
        self._poisoned = False
        self._header = transport.read_sector(0)
        self._id, self.logical_sectors = _read_header(
            self._header, _master(master_key), transport.sectors)
        _, self._meta_key, self._data_key = _keys(master_key, self._id)
        candidates = []
        for slot_index in (1, 2):
            raw = transport.read_sector(slot_index)
            candidate = self._decode_slot(slot_index, raw)
            if candidate is not None:
                candidates.append((candidate["sequence"], slot_index, candidate, raw))
        if not candidates:
            raise SealedSectorError("No authenticated recovery root")
        candidates.sort(reverse=True, key=lambda item: item[0])
        if len(candidates) == 2 and candidates[0][0] == candidates[1][0]:
            raise SealedSectorError("Ambiguous authenticated root sequence")
        _, self._slot, self._state, raw = candidates[0]
        if (type(expected_receipt) is not str or len(expected_receipt) != 64 or
                any(c not in "0123456789abcdef" for c in expected_receipt) or
                not hmac.compare_digest(_receipt(self._header, raw), expected_receipt)):
            raise SealedSectorError("Latest independently trusted receipt required")
        self._slot_raw = raw

    @classmethod
    def create(cls, path: str | Path, master_key: bytes,
               *, physical_sectors: int = 128, logical_sectors: int = 16):
        master = _master(master_key)
        if (type(logical_sectors) is not int or
                not 1 <= logical_sectors <= MAX_LOGICAL_SECTORS or
                type(physical_sectors) is not int or
                physical_sectors < FIRST_DATA_SECTOR + logical_sectors):
            raise SealedSectorError("Invalid scratch image geometry")
        io = TestSectorTransport(path, physical_sectors, create=True)
        try:
            vid = secrets.token_bytes(16)
            header = _seal_header(master, vid, physical_sectors, logical_sectors)
            _, meta_key, _ = _keys(master, vid)
            state = {"version": 1, "sequence": 0,
                     "next": FIRST_DATA_SECTOR, "map": {}}
            raw = cls._encode_slot(meta_key, header, 1, state)
            io.write_sector(0, header)
            io.write_sector(1, raw)
            io.flush()
            return cls(io, master, expected_receipt=_receipt(header, raw))
        except BaseException:
            io.close()
            # A failed creation intentionally retains the scratch file for
            # investigation; it must not be silently reused or overwritten.
            raise

    @classmethod
    def open(cls, path: str | Path, master_key: bytes, *,
             physical_sectors: int, expected_receipt: str,
             read_only: bool = True):
        master = _master(master_key)
        io = TestSectorTransport(path, physical_sectors, read_only=read_only)
        try:
            return cls(io, master, expected_receipt=expected_receipt)
        except BaseException:
            io.close()
            raise

    @staticmethod
    def _encode_slot(key: bytes, header: bytes, slot: int, doc: dict) -> bytes:
        data = _canonical(doc)
        nonce = secrets.token_bytes(12)
        aad = b"KRYPTA-META/1" + hashlib.sha256(header).digest() + bytes([slot])
        encrypted = AESGCM(key).encrypt(nonce, data, aad)
        if len(encrypted) > SECTOR_BYTES - 18:
            raise SealedSectorError("Authenticated metadata sector is full")
        prefix = SLOT_MAGIC + nonce + len(encrypted).to_bytes(2, "big")
        return prefix + encrypted + bytes(SECTOR_BYTES - len(prefix) - len(encrypted))

    def _decode_slot(self, slot: int, raw: bytes) -> dict | None:
        if raw == ZERO:
            return None
        if not raw.startswith(SLOT_MAGIC) or len(raw) != SECTOR_BYTES:
            return None
        nonce = raw[4:16]
        length = int.from_bytes(raw[16:18], "big")
        if not 16 <= length <= SECTOR_BYTES - 18 or any(raw[18 + length:]):
            return None
        aad = b"KRYPTA-META/1" + hashlib.sha256(self._header).digest() + bytes([slot])
        try:
            data = AESGCM(self._meta_key).decrypt(nonce, raw[18:18 + length], aad)
            decoded = json.loads(data.decode("ascii"))
            if _canonical(decoded) != data:
                return None
            return _validate_state(decoded, self._io.sectors, self.logical_sectors)
        except (ValueError, TypeError, KeyError, UnicodeError, InvalidTag,
                SealedSectorError):
            return None

    @property
    def receipt(self) -> str:
        self._check()
        return _receipt(self._header, self._slot_raw)

    @property
    def sequence(self) -> int:
        self._check()
        return self._state["sequence"]

    def _check(self):
        if self._poisoned:
            raise SealedSectorError("Uncertain I/O: do not retry; reopen with trusted receipt")
        if self._io._closed:
            raise SealedSectorError("Sealed scratch image is closed")
        self._io._check()

    def _sector(self, index: int):
        if type(index) is not int or not 0 <= index < self.logical_sectors:
            raise SealedSectorError("Logical sector out of range")
        return self._state["map"].get(str(index))

    def read_sector(self, index: int) -> bytes:
        self._check()
        entry = self._sector(index)
        if entry is None:
            return ZERO
        physical, nonce, tag = entry
        cipher = self._io.read_sector(physical)
        aad = b"KRYPTA-DATA/1" + self._id + struct.pack(">II", index, physical)
        try:
            data = AESGCM(self._data_key).decrypt(
                bytes.fromhex(nonce), cipher + bytes.fromhex(tag), aad)
        except InvalidTag as exc:
            self._poisoned = True
            raise SealedSectorError("Authenticated sector tampering detected") from exc
        if len(data) != SECTOR_BYTES:
            self._poisoned = True
            raise SealedSectorError("Invalid authenticated plaintext length")
        return data

    def verify_all(self) -> dict:
        self._check()
        for index in self._state["map"]:
            self.read_sector(int(index))
        return {"verified_sectors": len(self._state["map"]),
                "sequence": self.sequence, "receipt": self.receipt}

    def write_sector(self, index: int, plaintext: bytes) -> int:
        return self.write_many({index: plaintext})

    def write_many(self, updates: Mapping[int, bytes]) -> int:
        self._check()
        if self._io.read_only:
            raise SealedSectorError("Read-only image: writes denied")
        if (not isinstance(updates, Mapping) or
                not 1 <= len(updates) <= MAX_BATCH_SECTORS):
            raise SealedSectorError("Invalid bounded atomic write batch")
        for index, data in updates.items():
            self._sector(index)
            if type(data) is not bytes or len(data) != SECTOR_BYTES:
                raise SealedSectorError("Each write must contain exactly 4096 bytes")
        if self._state["sequence"] >= 2**64 - 1:
            raise SealedSectorError("Sequence counter exhausted")
        if self._state["next"] + len(updates) > self._io.sectors:
            raise SealedSectorError("Append-only scratch capacity exhausted")

        # Do not commit references to already-corrupt ciphertext.
        self.verify_all()
        updated = dict(self._state["map"])
        allocations = []
        for index, data in sorted(updates.items()):
            addr = self._state["next"] + len(allocations)
            nonce = secrets.token_bytes(12)
            aad = b"KRYPTA-DATA/1" + self._id + struct.pack(">II", index, addr)
            full = AESGCM(self._data_key).encrypt(nonce, data, aad)
            updated[str(index)] = [addr, nonce.hex(), full[-16:].hex()]
            allocations.append((addr, full[:-16]))
        state = {"version": 1, "sequence": self._state["sequence"] + 1,
                 "next": self._state["next"] + len(allocations), "map": updated}
        _validate_state(state, self._io.sectors, self.logical_sectors)
        next_slot = 3 - self._slot
        raw = self._encode_slot(self._meta_key, self._header, next_slot, state)

        # Strict order: staged ciphertext -> durable flush -> alternate root
        # -> durable flush. Uncertain errors permanently poison this handle.
        try:
            for addr, ciphertext in allocations:
                self._io.write_sector(addr, ciphertext)
            self._io.flush()
            self._io.write_sector(next_slot, raw)
            self._io.flush()
            self._state, self._slot, self._slot_raw = state, next_slot, raw
            for index, data in updates.items():
                if not hmac.compare_digest(self.read_sector(index), data):
                    raise SealedSectorError("Post-commit verification mismatch")
        except BaseException:
            self._poisoned = True
            raise
        return self.sequence

    def close(self):
        self._io.close()

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *_):
        self.close()
