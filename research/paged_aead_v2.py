"""Paged authenticated sector metadata v2 for *disposable* regular-file images.

Independent format, intentionally NOT a physical disk driver. It scales the
authenticated catalogue beyond v1's single 4096-byte metadata page with
copy-on-write leaf pages; two authenticated root slots anchor every commit.
The latest independent receipt is REQUIRED to reopen a volume.

No password storage, compaction, raw-device access or automatic trust promotion.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import struct
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .test_sector_transport import SECTOR_BYTES, TestSectorTransport

MAGIC = b"KRYPTA-PAGED-AEAD/2\x00"
ROOT_MAGIC = b"KP2R"
FIRST_FREE = 3
LEAF_ENTRIES = 32
MAX_LOGICAL_SECTORS = 1024
MAX_BATCH_SECTORS = 8
ZERO = bytes(SECTOR_BYTES)
_HEADER_USED = len(MAGIC) + 16 + 8 + 32


class PagedAEADError(RuntimeError):
    """Invalid geometry, ciphertext, receipt or uncertain storage state."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _master(key):
    if type(key) is not bytes or len(key) != 32:
        raise PagedAEADError("A uniformly random 32-byte master key is required")
    return key


def _derive(key, volume_id):
    material = HKDF(algorithm=hashes.SHA256(), length=128, salt=volume_id,
                    info=b"KRYPTA-PAGED-AEAD/2/DOMAIN-KEYS").derive(key)
    return tuple(material[i:i + 32] for i in range(0, 128, 32))


def _receipt(header, raw):
    return hashlib.sha256(b"KRYPTA-PAGED-AEAD-RECEIPT/2" + header + raw).hexdigest()


def _pointer(entry, first, ceiling):
    if not isinstance(entry, list) or len(entry) != 3:
        raise PagedAEADError("Invalid authenticated sector pointer")
    addr, nonce, tag = entry
    if (type(addr) is not int or not first <= addr < ceiling or
            type(nonce) is not str or len(nonce) != 24 or
            type(tag) is not str or len(tag) != 32 or
            any(c not in "0123456789abcdef" for c in nonce + tag)):
        raise PagedAEADError("Invalid authenticated pointer fields")
    return addr, bytes.fromhex(nonce), bytes.fromhex(tag)


def _state(doc, physical, logical):
    if (type(doc) is not dict or set(doc) != {"version", "sequence", "next", "leaves"} or
            type(doc["version"]) is not int or doc["version"] != 2 or
            type(doc["sequence"]) is not int or not 0 <= doc["sequence"] < 2**64 or
            type(doc["next"]) is not int or not FIRST_FREE <= doc["next"] <= physical or
            type(doc["leaves"]) is not dict or
            len(doc["leaves"]) > (logical + LEAF_ENTRIES - 1) // LEAF_ENTRIES):
        raise PagedAEADError("Invalid authenticated v2 root")
    seen = set()
    for index, entry in doc["leaves"].items():
        if (type(index) is not str or not index.isascii() or
                not index.isdecimal() or str(int(index)) != index or
                not 0 <= int(index) < (logical + LEAF_ENTRIES - 1) // LEAF_ENTRIES):
            raise PagedAEADError("Invalid leaf index in root")
        address, _, _ = _pointer(entry, FIRST_FREE, doc["next"])
        if address in seen:
            raise PagedAEADError("Repeated leaf physical address")
        seen.add(address)
    return doc


class PagedAEADImage:
    """Bounded research v2: 1024 logical 4-KiB sectors, paged COW metadata."""

    def __init__(self, io: TestSectorTransport, master: bytes, expected_receipt: str):
        self._io = io
        self._poisoned = False
        self._header = io.read_sector(0)
        if not self._header.startswith(MAGIC) or len(self._header) != SECTOR_BYTES:
            raise PagedAEADError("Wrong sealed image format/version")
        start = len(MAGIC)
        vid = self._header[start:start + 16]
        physical, logical = struct.unpack(">II", self._header[start + 16:start + 24])
        if (physical != io.sectors or not 1 <= logical <= MAX_LOGICAL_SECTORS or
                any(self._header[_HEADER_USED:])):
            raise PagedAEADError("Authenticated geometry mismatch")
        self._vid = vid
        self.logical_sectors = logical
        self._header_key, self._root_key, self._leaf_key, self._data_key = (
            _derive(_master(master), vid))
        check = hmac.digest(self._header_key, self._header[:start + 24], "sha256")
        if not hmac.compare_digest(self._header[start + 24:start + 56], check):
            raise PagedAEADError("Header authentication failed")
        candidates = []
        for slot in (1, 2):
            raw = io.read_sector(slot)
            decoded = self._decode_root(slot, raw)
            if decoded is not None:
                candidates.append((decoded["sequence"], slot, decoded, raw))
        if not candidates:
            raise PagedAEADError("No authenticated root")
        candidates.sort(key=lambda item: item[0], reverse=True)
        if len(candidates) == 2 and candidates[0][0] == candidates[1][0]:
            raise PagedAEADError("Ambiguous authenticated roots")
        _, self._slot, self._root, self._rootraw = candidates[0]
        if (type(expected_receipt) is not str or len(expected_receipt) != 64 or
                any(c not in "0123456789abcdef" for c in expected_receipt) or
                not hmac.compare_digest(_receipt(self._header, self._rootraw),
                                        expected_receipt)):
            raise PagedAEADError("Latest independent receipt is required")

    @classmethod
    def create(cls, path: str | Path, key: bytes, *,
               physical_sectors: int = 256, logical_sectors: int = 64):
        _master(key)
        if (type(logical_sectors) is not int or
                not 1 <= logical_sectors <= MAX_LOGICAL_SECTORS or
                type(physical_sectors) is not int or
                physical_sectors < FIRST_FREE + 2):
            raise PagedAEADError("Invalid scratch-only sector geometry")
        io = TestSectorTransport(path, physical_sectors, create=True)
        try:
            vid = secrets.token_bytes(16)
            header_key, root_key, _, _ = _derive(key, vid)
            prefix = MAGIC + vid + struct.pack(">II", physical_sectors, logical_sectors)
            head = prefix + hmac.digest(header_key, prefix, "sha256")
            head += bytes(SECTOR_BYTES - len(head))
            state = {"version": 2, "sequence": 0, "next": FIRST_FREE, "leaves": {}}
            raw = cls._seal(root_key, b"KRYPTA-PAGED-ROOT/2" +
                            hashlib.sha256(head).digest() + b"\x01", state, ROOT_MAGIC)
            io.write_sector(0, head)
            io.write_sector(1, raw)
            io.flush()
            return cls(io, key, _receipt(head, raw))
        except BaseException:
            io.close()
            raise

    @classmethod
    def open(cls, path: str | Path, key: bytes, *, physical_sectors: int,
             expected_receipt: str, read_only: bool = True):
        _master(key)
        io = TestSectorTransport(path, physical_sectors, read_only=read_only)
        try:
            return cls(io, key, expected_receipt)
        except BaseException:
            io.close()
            raise

    @staticmethod
    def _seal(key, aad, doc, magic):
        blob = _canonical(doc)
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(key).encrypt(nonce, blob, aad)
        if len(cipher) > SECTOR_BYTES - 18:
            raise PagedAEADError("Authenticated page capacity exceeded")
        prefix = magic + nonce + len(cipher).to_bytes(2, "big")
        return prefix + cipher + bytes(SECTOR_BYTES - len(prefix) - len(cipher))

    @staticmethod
    def _open_page(key, aad, raw, magic):
        if len(raw) != SECTOR_BYTES or not raw.startswith(magic):
            raise PagedAEADError("Invalid authenticated page magic")
        length = int.from_bytes(raw[16:18], "big")
        if not 16 <= length <= SECTOR_BYTES - 18 or any(raw[18 + length:]):
            raise PagedAEADError("Invalid authenticated page length/padding")
        try:
            plain = AESGCM(key).decrypt(raw[4:16], raw[18:18 + length], aad)
            result = json.loads(plain.decode("ascii"))
            if _canonical(result) != plain:
                raise PagedAEADError("Noncanonical authenticated page")
            return result
        except (InvalidTag, ValueError, UnicodeError, TypeError) as exc:
            raise PagedAEADError("Authenticated page verification failed") from exc

    def _decode_root(self, slot, raw):
        if raw == ZERO:
            return None
        aad = (b"KRYPTA-PAGED-ROOT/2" +
               hashlib.sha256(self._header).digest() + bytes([slot]))
        try:
            decoded = self._open_page(self._root_key, aad, raw, ROOT_MAGIC)
            return _state(decoded, self._io.sectors, self.logical_sectors)
        except PagedAEADError:
            return None

    def _check(self):
        if self._poisoned:
            raise PagedAEADError("Uncertain I/O: stop, inspect roots before restart")
        if self._io._closed:
            raise PagedAEADError("Encrypted scratch device is closed")
        self._io._check()

    @property
    def sequence(self):
        self._check()
        return self._root["sequence"]

    @property
    def receipt(self):
        self._check()
        return _receipt(self._header, self._rootraw)

    def _leaf(self, page_number):
        reference = self._root["leaves"].get(str(page_number))
        if reference is None:
            return {}
        addr, nonce, tag = _pointer(reference, FIRST_FREE, self._root["next"])
        cipher = self._io.read_sector(addr)
        aad = (b"KRYPTA-PAGED-LEAF/2" + self._vid +
               struct.pack(">II", page_number, addr))
        try:
            plaintext = AESGCM(self._leaf_key).decrypt(
                nonce, cipher + tag, aad)
            # Metadata ciphertext is a FULL sector. Remove authenticated
            # NUL padding only after GCM has verified the complete sector.
            canonical = plaintext.rstrip(b"\x00")
            leaf = json.loads(canonical.decode("ascii"))
            if _canonical(leaf) != canonical or type(leaf) is not dict:
                raise PagedAEADError("Invalid leaf metadata")
            if len(leaf) > LEAF_ENTRIES:
                raise PagedAEADError("Leaf entry count exceeded")
            used = set()
            for offset, item in leaf.items():
                if (type(offset) is not str or not offset.isascii() or
                        not offset.isdecimal() or str(int(offset)) != offset or
                        not 0 <= int(offset) < LEAF_ENTRIES or
                        page_number * LEAF_ENTRIES + int(offset) >=
                        self.logical_sectors):
                    raise PagedAEADError("Invalid leaf logical address")
                destination, _, _ = _pointer(item, FIRST_FREE, self._root["next"])
                if destination in used or destination == addr:
                    raise PagedAEADError("Duplicate encrypted data sector")
                used.add(destination)
            return leaf
        except (InvalidTag, ValueError, UnicodeError, TypeError) as exc:
            raise PagedAEADError("Authenticated leaf verification failed") from exc

    def read_sector(self, index):
        self._check()
        if type(index) is not int or not 0 <= index < self.logical_sectors:
            raise PagedAEADError("Logical sector outside bounded image")
        page, offset = divmod(index, LEAF_ENTRIES)
        try:
            leaf = self._leaf(page)
            entry = leaf.get(str(offset))
            if entry is None:
                return ZERO
            addr, nonce, tag = _pointer(entry, FIRST_FREE, self._root["next"])
            ciphertext = self._io.read_sector(addr)
            aad = (b"KRYPTA-PAGED-DATA/2" + self._vid +
                   struct.pack(">II", index, addr))
            plaintext = AESGCM(self._data_key).decrypt(nonce, ciphertext + tag, aad)
            if len(plaintext) != SECTOR_BYTES:
                raise PagedAEADError("Invalid decrypted sector length")
            return plaintext
        except (InvalidTag, PagedAEADError):
            self._poisoned = True
            raise PagedAEADError("Encrypted page/sector authentication failed")

    def verify_all(self):
        self._check()
        checked = 0
        for page in self._root["leaves"]:
            for offset in self._leaf(int(page)):
                self.read_sector(int(page) * LEAF_ENTRIES + int(offset))
                checked += 1
        return {"verified_sectors": checked, "receipt": self.receipt,
                "sequence": self.sequence}

    @property
    def capacity_bytes(self):
        """Logical address space; physical allocation remains sparse."""
        return self.logical_sectors * SECTOR_BYTES

    def _byte_range(self, offset, length):
        if (type(offset) is not int or type(length) is not int or
                offset < 0 or length < 0 or
                offset > self.capacity_bytes or
                length > self.capacity_bytes - offset):
            raise PagedAEADError("Byte range outside bounded encrypted image")

    def read_at(self, offset: int, length: int) -> bytes:
        """Authenticated random-access byte reads over encrypted sectors."""
        self._check()
        self._byte_range(offset, length)
        if length == 0:
            return b""
        first = offset // SECTOR_BYTES
        last = (offset + length - 1) // SECTOR_BYTES
        result = bytearray()
        for index in range(first, last + 1):
            result.extend(self.read_sector(index))
        start = offset % SECTOR_BYTES
        return bytes(result[start:start + length])

    def write_at(self, offset: int, payload: bytes) -> int:
        """Commit a bounded unaligned byte range in exactly one COW root.

        A write spanning more than MAX_BATCH_SECTORS is refused instead of
        silently splitting the operation into non-atomic subtransactions.
        Read/modify/write authenticates the original sectors before staging.
        """
        self._check()
        if self._io.read_only:
            raise PagedAEADError("Scratch image is read-only")
        if type(payload) is not bytes:
            raise PagedAEADError("Byte-range write requires immutable bytes")
        self._byte_range(offset, len(payload))
        if not payload:
            return 0
        first = offset // SECTOR_BYTES
        last = (offset + len(payload) - 1) // SECTOR_BYTES
        if last - first + 1 > MAX_BATCH_SECTORS:
            raise PagedAEADError("Unaligned write exceeds atomic batch limit")
        result = {}
        for index in range(first, last + 1):
            original = bytearray(self.read_sector(index))
            segment_start = max(offset, index * SECTOR_BYTES)
            segment_end = min(offset + len(payload), (index + 1) * SECTOR_BYTES)
            destination = segment_start - index * SECTOR_BYTES
            source = segment_start - offset
            original[destination:destination + segment_end - segment_start] = (
                payload[source:source + segment_end - segment_start])
            result[index] = bytes(original)
        self.write_many(result)
        return len(payload)

    def write_sector(self, index, data):
        return self.write_many({index: data})

    def write_many(self, updates: Mapping[int, bytes]):
        """Preserve legacy write-only API: None is never an implicit delete."""
        if not isinstance(updates, Mapping) or any(
                type(value) is not bytes for value in updates.values()):
            raise PagedAEADError("Exactly 4096-byte immutable sector data required")
        return self.apply_many(updates)

    def trim_many(self, indexes):
        """Atomically unmap existing logical sectors; NEVER physically erase.

        Missing sectors remain zero without an unnecessary root commit.
        The append-only underlying ciphertext (including older snapshots)
        is still present and may be recoverable with prior keys/receipts.
        """
        if type(indexes) not in (list, tuple):
            raise PagedAEADError("Trim requires a bounded list or tuple of sectors")
        if not 1 <= len(indexes) <= MAX_BATCH_SECTORS:
            raise PagedAEADError("Invalid atomic trim batch")
        if any(type(index) is not int for index in indexes):
            raise PagedAEADError("Invalid logical trim sector")
        if len(indexes) != len(set(indexes)):
            raise PagedAEADError("Duplicate sector in atomic trim batch")
        return self.apply_many({index: None for index in indexes})

    def apply_many(self, changes: Mapping[int, bytes | None]):
        """ONE authenticated COW transaction mixing sector writes and trims.

        `None` explicitly removes a logical sector reference, yielding an
        authenticated ZERO on subsequent reads. Empty leaves are pruned.
        All impacted original ciphertext is authenticated before any writes.
        This is NOT an SSD discard/TRIM, secure wipe, compaction or release of
        old physical log capacity. A failure after root publication poisons
        the handle; only the independent latest receipt may be trusted.
        """
        self._check()
        if self._io.read_only:
            raise PagedAEADError("Scratch image is read-only")
        if not isinstance(changes, Mapping) or not 1 <= len(changes) <= MAX_BATCH_SECTORS:
            raise PagedAEADError("Invalid atomic update/trim batch")
        for index, payload in changes.items():
            if type(index) is not int or not 0 <= index < self.logical_sectors:
                raise PagedAEADError("Invalid logical index")
            if payload is not None and (
                    type(payload) is not bytes or len(payload) != SECTOR_BYTES):
                raise PagedAEADError("Exact 4096-byte data or explicit None required")
        pages = sorted(set(index // LEAF_ENTRIES for index in changes))
        if self._root["sequence"] == 2**64 - 1:
            raise PagedAEADError("Commit sequence exhausted")
        # Authenticate ALL existing sectors in affected leaves, including
        # sectors being removed, to avoid hiding corrupted storage by trim.
        originals = {page: dict(self._leaf(page)) for page in pages}
        for page, leaf in originals.items():
            for offset in leaf:
                self.read_sector(page * LEAF_ENTRIES + int(offset))
        leaves = {page: dict(leaf) for page, leaf in originals.items()}
        for index, payload in changes.items():
            page, offset = divmod(index, LEAF_ENTRIES)
            if payload is None:
                leaves[page].pop(str(offset), None)
        written_pages = {index // LEAF_ENTRIES
                         for index, payload in changes.items() if payload is not None}
        to_update = sorted(page for page in pages
                           if leaves[page] != originals[page] or page in written_pages)
        if not to_update:
            # Trimming never-allocated sectors does not spend sequence/quota.
            return self.sequence
        writes = sorted((index, payload) for index, payload in changes.items()
                        if payload is not None)
        # Leaves containing only trims may disappear entirely and require
        # ZERO extra data/leaf sectors. Other touched leaves need new copies.
        nonempty_pages = {page for page in to_update
                          if leaves[page] or page in written_pages}
        required = len(writes) + len(nonempty_pages)
        if self._root["next"] + required > self._io.sectors:
            raise PagedAEADError("COW append-only scratch capacity exhausted")

        allocated = []
        staged_leaves = {}
        newroot = dict(self._root["leaves"])
        address = self._root["next"]
        for index, plain in writes:
            nonce = secrets.token_bytes(12)
            aad = (b"KRYPTA-PAGED-DATA/2" + self._vid +
                   struct.pack(">II", index, address))
            cipher = AESGCM(self._data_key).encrypt(nonce, plain, aad)
            leaves[index // LEAF_ENTRIES][str(index % LEAF_ENTRIES)] = (
                [address, nonce.hex(), cipher[-16:].hex()])
            allocated.append((address, cipher[:-16]))
            address += 1
        for page in to_update:
            if not leaves[page]:
                newroot.pop(str(page), None)
                continue
            nonce = secrets.token_bytes(12)
            aad = (b"KRYPTA-PAGED-LEAF/2" + self._vid +
                   struct.pack(">II", page, address))
            plain = _canonical(leaves[page])
            if len(plain) > SECTOR_BYTES:
                raise PagedAEADError("Leaf map exceeds sector bound")
            cipher = AESGCM(self._leaf_key).encrypt(
                nonce, plain.ljust(SECTOR_BYTES, b"\x00"), aad)
            newroot[str(page)] = [address, nonce.hex(), cipher[-16:].hex()]
            staged_leaves[page] = (address, cipher[:-16])
            address += 1
        state = {"version": 2, "sequence": self._root["sequence"] + 1,
                 "next": address, "leaves": newroot}
        _state(state, self._io.sectors, self.logical_sectors)
        slot = 3 - self._slot
        root_aad = (b"KRYPTA-PAGED-ROOT/2" +
                    hashlib.sha256(self._header).digest() + bytes([slot]))
        raw = self._seal(self._root_key, root_aad, state, ROOT_MAGIC)
        try:
            for sector_address, cipher in allocated:
                self._io.write_sector(sector_address, cipher)
            for sector_address, cipher in staged_leaves.values():
                self._io.write_sector(sector_address, cipher)
            self._io.flush()
            self._io.write_sector(slot, raw)
            self._io.flush()
            self._slot, self._root, self._rootraw = slot, state, raw
            for index, expected in changes.items():
                actual = self.read_sector(index)
                if not hmac.compare_digest(actual, ZERO if expected is None else expected):
                    raise PagedAEADError("Post-commit sector/trim verification failed")
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
