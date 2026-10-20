"""KRYPTA-PVIMG/1: sparse authenticated radix-tree volume, RESEARCH ONLY.

This disposable .kpv *file* format is deliberately separate from VIMG/0. It
never opens a device or modifies an operating-system volume. Authenticated
copy-on-write index nodes plus a small chained commit support crash-recovery
experiments on a logical 1-GiB sparse address space. The 512-MiB physical
append-only quota, throughput, key custody, physical crash safety and rollback
protection are NOT production-ready.

A trusted latest receipt MUST be stored OUTSIDE attacker-controlled storage to
identify whole-image rollback. If the caller does not supply one, a valid old
snapshot cannot be distinguished from a current snapshot.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import struct
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .horizon_lab import HorizonError, open_block, seal_block

MAGIC = b"KRYPTA-PVIMG/1\n"
HEADER_BYTES = len(MAGIC) + 16
FRAME = struct.Struct(">4scI")
DATA_ADDRESS = struct.Struct(">QQ")
BLOCK_BYTES = 4096
FANOUT = 64
ROOT_LEVEL = 2
MAX_BLOCKS = FANOUT ** (ROOT_LEVEL + 1)  # 1 GiB logical, sparse
MAX_TX_BLOCKS = 256
MAX_IMAGE_BYTES = 512 * 1024 * 1024  # physical log, research quota
MAX_RECORD_BYTES = 65536
MAX_NODE_BYTES = 32 * 1024
MAX_COMMIT_BYTES = 4096
_HMAC_DOMAIN = b"KRYPTA-PVIMG/1/ROOT-COMMIT/RESEARCH"
_RECEIPT_DOMAIN = b"KRYPTA-PVIMG/1/EXTERNAL-RECEIPT/RESEARCH"


class PagedVolumeError(ValueError):
    """Malformed input, unauthenticated storage or disallowed research action."""


def _json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ref(value: object) -> bool:
    return (isinstance(value, list) and len(value) == 2
            and type(value[0]) is int and HEADER_BYTES <= value[0] < MAX_IMAGE_BYTES
            and isinstance(value[1], str) and len(value[1]) == 64
            and all(c in "0123456789abcdef" for c in value[1]))


def _open_regular(path: Path, create: bool) -> BinaryIO:
    name = str(path)
    if (path.suffix.lower() != ".kpv" or name.startswith(("\\\\.\\", "\\\\?\\"))
            or path.is_symlink() or (os.name == "posix" and name.startswith("/dev/"))):
        raise PagedVolumeError("Only disposable regular .kpv files are supported")
    flags = (os.O_RDWR | getattr(os, "O_BINARY", 0) |
             getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) |
             getattr(os, "O_NOFOLLOW", 0))
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise PagedVolumeError("Cannot exclusively open regular test image") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PagedVolumeError("Physical devices are forbidden")
        if os.name == "posix":
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif os.name == "nt":
            import msvcrt
            os.lseek(fd, MAX_IMAGE_BYTES + 4096, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
        return os.fdopen(fd, "r+b", buffering=0)
    except BaseException:
        os.close(fd)
        raise


class PagedResearchVolume:
    """Sparse paged *research* image, single-writer and fail-closed on writes."""

    def __init__(self, path: str | Path, key: bytes, *, create: bool = False,
                 expected_sequence: int | None = None,
                 expected_receipt: str | None = None):
        if not isinstance(key, bytes) or len(key) != 32:
            raise PagedVolumeError("Expected a separately held random 32-byte test key")
        if expected_sequence is not None and (type(expected_sequence) is not int
                                              or expected_sequence < 0):
            raise PagedVolumeError("Invalid external sequence")
        if expected_receipt is not None and not (isinstance(expected_receipt, str)
                                                and len(expected_receipt) == 64
                                                and all(x in "0123456789abcdef" for x in expected_receipt)):
            raise PagedVolumeError("Invalid external receipt")
        self.path = Path(path)
        self.key = key
        self._f = _open_regular(self.path, create)
        self._closed = False
        self._poisoned = False
        self.sequence = -1
        self.root = None
        self.receipt = None
        self._commit_offset = None
        self._trim_offset = None
        created = os.fstat(self._f.fileno()) if create else None
        try:
            if create:
                self.id = secrets.token_bytes(16)
                self._f.write(MAGIC + self.id)
                self._flush()
            else:
                header = self._f.read(HEADER_BYTES)
                if len(header) != HEADER_BYTES or not header.startswith(MAGIC):
                    raise PagedVolumeError("Invalid PVIMG header")
                self.id = header[len(MAGIC):]
            self._mac_key = HKDF(
                algorithm=hashes.SHA512(), length=32, salt=self.id,
                info=_HMAC_DOMAIN).derive(self.key)
            if create:
                self._commit(0, None)
            else:
                self._recover()
            if expected_sequence is not None and self.sequence != expected_sequence:
                raise PagedVolumeError("External sequence mismatch; possible rollback")
            if expected_receipt is not None and not hmac.compare_digest(self.receipt, expected_receipt):
                raise PagedVolumeError("External receipt mismatch; possible rollback")
            # Validate ALL reachable metadata (not all data AEAD tags) before
            # modifying any incomplete tail. Reads authenticate data on demand.
            if not create and self.root is not None:
                self._validate_tree(self.root, ROOT_LEVEL, 0, self._commit_offset, set())
            if not create and self._trim_offset is not None:
                self._f.truncate(self._trim_offset)
                self._flush()
        except BaseException:
            try:
                self._f.close()
            finally:
                self._closed = True
                if created is not None:
                    try:
                        current = os.stat(self.path, follow_symlinks=False)
                        if (stat.S_ISREG(current.st_mode) and
                                (created.st_dev, created.st_ino) == (current.st_dev, current.st_ino)):
                            self.path.unlink()
                    except OSError:
                        pass
            raise

    def _flush(self) -> None:
        self._f.flush()
        os.fsync(self._f.fileno())

    def _check(self) -> None:
        if self._closed:
            raise PagedVolumeError("Closed research volume")
        if self._poisoned:
            raise PagedVolumeError("Uncertain write outcome; close and reopen")

    def _append(self, kind: bytes, payload: bytes) -> int:
        if kind not in (b"D", b"N", b"C") or len(payload) > MAX_RECORD_BYTES:
            raise PagedVolumeError("Invalid research frame")
        self._f.seek(0, os.SEEK_END)
        off = self._f.tell()
        if off + FRAME.size + len(payload) > MAX_IMAGE_BYTES:
            raise PagedVolumeError("Physical research image limit reached")
        self._f.write(FRAME.pack(b"KPG1", kind, len(payload)))
        self._f.write(payload)
        return off

    def _receipt(self, signed: bytes) -> str:
        return hmac.digest(self._mac_key, _RECEIPT_DOMAIN + signed, "sha256").hex()

    def _commit(self, seq: int, root: list | None) -> None:
        body = _json({"seq": seq, "prev": self.receipt, "root": root})
        signed = body + hmac.digest(self._mac_key, MAGIC + self.id + body, "sha256")
        off = self._append(b"C", signed)
        self._flush()
        self.sequence, self.root = seq, root
        self.receipt = self._receipt(signed)
        self._commit_offset = off

    def _recover(self) -> None:
        self._f.seek(0, os.SEEK_END)
        total = self._f.tell()
        if total > MAX_IMAGE_BYTES:
            raise PagedVolumeError("Research image exceeds physical quota")
        cursor, committed_end = HEADER_BYTES, HEADER_BYTES
        while cursor < total:
            self._f.seek(cursor)
            head = self._f.read(FRAME.size)
            if len(head) < FRAME.size:
                break
            magic, kind, length = FRAME.unpack(head)
            if magic != b"KPG1" or kind not in (b"D", b"N", b"C") or length > MAX_RECORD_BYTES:
                raise PagedVolumeError("Malformed research record")
            if cursor + FRAME.size + length > total:
                break
            if kind == b"C":
                if length < 32 or length > MAX_COMMIT_BYTES:
                    raise PagedVolumeError("Invalid commit length")
                signed = self._f.read(length)
                content, mac = signed[:-32], signed[-32:]
                tag = hmac.digest(self._mac_key, MAGIC + self.id + content, "sha256")
                if not hmac.compare_digest(mac, tag):
                    raise PagedVolumeError("Invalid commit MAC or key")
                try:
                    body = json.loads(content)
                except (UnicodeError, ValueError, TypeError) as exc:
                    raise PagedVolumeError("Invalid authenticated commit JSON") from exc
                if (not isinstance(body, dict) or set(body) != {"seq", "prev", "root"}
                        or _json(body) != content or type(body["seq"]) is not int
                        or body["seq"] != self.sequence + 1 or body["seq"] >= 2**64
                        or body["prev"] != self.receipt
                        or (body["root"] is not None and not _ref(body["root"]))
                        or (body["seq"] == 0 and body["root"] is not None)):
                    raise PagedVolumeError("Noncanonical or inconsistent commit")
                self.sequence, self.root = body["seq"], body["root"]
                self.receipt, self._commit_offset = self._receipt(signed), cursor
                committed_end = cursor + FRAME.size + length
            cursor += FRAME.size + length
        if self.sequence < 0:
            raise PagedVolumeError("Missing authenticated genesis")
        self._trim_offset = committed_end if committed_end < total else None

    def _frame_at(self, off: int, limit: int, kind: bytes, max_length: int) -> bytes:
        if type(off) is not int or off < HEADER_BYTES or off >= limit:
            raise PagedVolumeError("Invalid authenticated frame pointer")
        self._f.seek(off)
        head = self._f.read(FRAME.size)
        if len(head) != FRAME.size:
            raise PagedVolumeError("Truncated authenticated frame")
        magic, actual, length = FRAME.unpack(head)
        if magic != b"KPG1" or actual != kind or length > max_length or off + FRAME.size + length > limit:
            raise PagedVolumeError("Corrupt authenticated frame")
        data = self._f.read(length)
        if len(data) != length:
            raise PagedVolumeError("Truncated authenticated payload")
        return data

    def _node(self, ref: list, level: int, prefix: int, limit: int) -> dict:
        if not _ref(ref):
            raise PagedVolumeError("Invalid metadata reference")
        raw = self._frame_at(ref[0], limit, b"N", MAX_NODE_BYTES)
        if not hmac.compare_digest(_digest(raw), ref[1]):
            raise PagedVolumeError("Authenticated metadata digest mismatch")
        try:
            doc = json.loads(raw)
        except (UnicodeError, ValueError, TypeError) as exc:
            raise PagedVolumeError("Malformed metadata JSON") from exc
        if (not isinstance(doc, dict) or set(doc) != {"level", "prefix", "slots"}
                or _json(doc) != raw or type(doc["level"]) is not int or doc["level"] != level
                or type(doc["prefix"]) is not int or doc["prefix"] != prefix
                or not isinstance(doc["slots"], dict) or not 1 <= len(doc["slots"]) <= FANOUT):
            raise PagedVolumeError("Noncanonical or misplaced metadata node")
        for key, pointer in doc["slots"].items():
            if (not isinstance(key, str) or not key.isascii() or not key.isdecimal()
                    or str(int(key)) != key or not 0 <= int(key) < FANOUT):
                raise PagedVolumeError("Invalid radix slot")
            if level:
                if not _ref(pointer):
                    raise PagedVolumeError("Invalid child node reference")
            elif (not isinstance(pointer, list) or len(pointer) != 3
                  or type(pointer[0]) is not int or not 1 <= pointer[0] < 2**64
                  or not _ref(pointer[1:])):
                raise PagedVolumeError("Invalid encrypted sector reference")
        return doc["slots"]

    def _validate_tree(self, ref: list, level: int, prefix: int,
                       limit: int, seen: set[int]) -> None:
        if ref[0] in seen:
            raise PagedVolumeError("Cyclic or aliased metadata tree")
        seen.add(ref[0])
        slots = self._node(ref, level, prefix, limit)
        for slot, pointer in slots.items():
            address = prefix * FANOUT + int(slot)
            if level:
                self._validate_tree(pointer, level - 1, address, limit, seen)
            else:
                idx = address
                raw = self._frame_at(pointer[1], limit, b"D", DATA_ADDRESS.size + BLOCK_BYTES + 200)
                if len(raw) < DATA_ADDRESS.size + 32:
                    raise PagedVolumeError("Short authenticated sector frame")
                stored_idx, stored_gen = DATA_ADDRESS.unpack(raw[:DATA_ADDRESS.size])
                if stored_idx != idx or stored_gen != pointer[0]:
                    raise PagedVolumeError("Sector reference address/generation mismatch")
                # Avoid full data AEAD scan at mount; verify on read/verify_all.

    def _entry(self, index: int):
        ref = self.root
        for level in range(ROOT_LEVEL, -1, -1):
            if ref is None:
                return None
            slots = self._node(ref, level, index // (FANOUT ** (level + 1)), self._commit_offset)
            pointer = slots.get(str((index // (FANOUT ** level)) % FANOUT))
            if level == 0:
                return pointer
            ref = pointer
        raise AssertionError("unreachable")

    def read(self, index: int) -> bytes:
        self._check()
        if type(index) is not int or not 0 <= index < MAX_BLOCKS:
            raise PagedVolumeError("Invalid sector address")
        entry = self._entry(index)
        if entry is None:
            return bytes(BLOCK_BYTES)
        raw = self._frame_at(entry[1], self._commit_offset, b"D", DATA_ADDRESS.size + BLOCK_BYTES + 200)
        if len(raw) < DATA_ADDRESS.size + 32:
            raise PagedVolumeError("Invalid encrypted sector")
        idx, generation = DATA_ADDRESS.unpack(raw[:DATA_ADDRESS.size])
        encrypted = raw[DATA_ADDRESS.size:]
        if idx != index or generation != entry[0] or not hmac.compare_digest(_digest(encrypted), entry[2]):
            raise PagedVolumeError("Ciphertext or address tampering")
        try:
            plaintext = open_block(self.key, index, generation, encrypted, aad=self.id)
        except HorizonError as exc:
            raise PagedVolumeError("Sector authentication failed") from exc
        if len(plaintext) != BLOCK_BYTES:
            raise PagedVolumeError("Wrong sector length")
        return plaintext

    def _update_node(self, old_ref: list | None, level: int, prefix: int,
                     changes: dict[int, list]) -> list:
        slots = {} if old_ref is None else dict(self._node(old_ref, level, prefix, self._f.tell()))
        groups: dict[int, dict[int, list]] = defaultdict(dict)
        for index, pointer in changes.items():
            groups[(index // (FANOUT ** level)) % FANOUT][index] = pointer
        for position, subset in groups.items():
            name = str(position)
            if level == 0:
                slots[name] = subset[next(iter(subset))]
            else:
                slots[name] = self._update_node(slots.get(name), level - 1,
                                                prefix * FANOUT + position, subset)
        raw = _json({"level": level, "prefix": prefix, "slots": slots})
        if len(raw) > MAX_NODE_BYTES:
            raise PagedVolumeError("Research index node quota reached")
        return [self._append(b"N", raw), _digest(raw)]

    def write_many(self, updates: Mapping[int, bytes]) -> int:
        self._check()
        if not isinstance(updates, Mapping) or not 1 <= len(updates) <= MAX_TX_BLOCKS:
            raise PagedVolumeError("Expected 1..256 changed full sectors")
        if self.sequence >= 2**64 - 1:
            raise PagedVolumeError("Commit counter exhausted")
        # Reject mixed-type keys and malformed content before sorting/encrypting.
        for index, plaintext in updates.items():
            if type(index) is not int or not 0 <= index < MAX_BLOCKS:
                raise PagedVolumeError("Invalid sector index")
            if not isinstance(plaintext, bytes) or len(plaintext) != BLOCK_BYTES:
                raise PagedVolumeError("Only full 4096-byte test sectors allowed")
        prepared = []
        for index, plaintext in sorted(updates.items()):
            old = self._entry(index)
            generation = old[0] + 1 if old else 1
            if generation >= 2**64:
                raise PagedVolumeError("Sector generation exhausted")
            encrypted = seal_block(self.key, index, generation, plaintext, aad=self.id)
            prepared.append((index, generation, encrypted))
        try:
            next_entries = {}
            for index, generation, encrypted in prepared:
                offset = self._append(b"D", DATA_ADDRESS.pack(index, generation) + encrypted)
                next_entries[index] = [generation, offset, _digest(encrypted)]
            root = self._update_node(self.root, ROOT_LEVEL, 0, next_entries)
            # Data + new index nodes must be flushed BEFORE publishing root.
            self._flush()
            self._commit(self.sequence + 1, root)
        except BaseException:
            self._poisoned = True
            raise
        return self.sequence

    def write(self, index: int, data: bytes) -> int:
        return self.write_many({index: data})

    def read_at(self, offset: int, length: int) -> bytes:
        """Bounded logical byte-range read over authenticated sparse sectors."""
        self._check()
        if (type(offset) is not int or type(length) is not int or
                offset < 0 or length < 0 or
                offset + length > MAX_BLOCKS * BLOCK_BYTES or
                length > MAX_TX_BLOCKS * BLOCK_BYTES):
            raise PagedVolumeError("Invalid bounded logical read range")
        if length == 0:
            return b""
        start = offset // BLOCK_BYTES
        end = (offset + length - 1) // BLOCK_BYTES
        combined = b"".join(self.read(index) for index in range(start, end + 1))
        begin = offset % BLOCK_BYTES
        return combined[begin:begin + length]

    def write_at(self, offset: int, data: bytes) -> int:
        """Atomic bounded byte-range update; all touched sectors commit together.

        Partial sectors are authenticated before re-encryption. The write is
        rejected without side effects if it crosses the end of the logical
        image or exceeds the per-transaction sector cap.
        """
        self._check()
        if (type(offset) is not int or offset < 0 or
                not isinstance(data, bytes) or not data or
                offset + len(data) > MAX_BLOCKS * BLOCK_BYTES):
            raise PagedVolumeError("Invalid logical byte-range write")
        start = offset // BLOCK_BYTES
        end = (offset + len(data) - 1) // BLOCK_BYTES
        if end - start + 1 > MAX_TX_BLOCKS:
            raise PagedVolumeError("Too many sectors in one byte-range transaction")
        updates = {}
        for index in range(start, end + 1):
            sector_start = index * BLOCK_BYTES
            left = max(offset, sector_start)
            right = min(offset + len(data), sector_start + BLOCK_BYTES)
            plaintext = bytearray(self.read(index))
            plaintext[left - sector_start:right - sector_start] = data[left - offset:right - offset]
            updates[index] = bytes(plaintext)
        return self.write_many(updates)

    def verify_all(self) -> dict:
        """Expensive opt-in verification of every allocated data sector."""
        self._check()
        sectors = 0
        def walk(ref, level, prefix):
            nonlocal sectors
            if ref is None:
                return
            slots = self._node(ref, level, prefix, self._commit_offset)
            for slot in slots:
                child_idx = prefix * FANOUT + int(slot)
                if level:
                    walk(slots[slot], level - 1, child_idx)
                else:
                    self.read(child_idx)
                    sectors += 1
        walk(self.root, ROOT_LEVEL, 0)
        return {"verified_sectors": sectors, "sequence": self.sequence,
                "receipt": self.receipt}

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._f.close()

    def __enter__(self) -> "PagedResearchVolume":
        self._check()
        return self

    def __exit__(self, *_):
        self.close()
