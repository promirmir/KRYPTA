"""KRYPTA-VIMG/0: file-only, single-writer, experimental encrypted sector image.

RESEARCH ONLY. Not a filesystem, block driver, system encryption, usable PIN vault
or independently reviewed encryption product. Never place irreplaceable data here.
An attacker who truncates a complete image to an older valid commit is not detected
without a protected EXTERNAL expected sequence number. This is not a secure anchor.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from collections.abc import Mapping
import secrets
import stat
import struct
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .horizon_lab import HorizonError, open_block, seal_block

MAGIC = b"KRYPTA-VIMG/0\n"
HEADER_BYTES = len(MAGIC) + 16
FRAME = struct.Struct(">4scI")
DATA_ADDRESS = struct.Struct(">IQ")
BLOCK_BYTES = 4096
MAX_BLOCKS = 128
MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD_BYTES = 48 * 1024
_DOMAIN = b"KRYPTA-VIMG/0/COMMIT-MAC/RESEARCH-ONLY"


class VolumeImageError(ValueError):
    """Experimental image cannot be safely authenticated or used."""


def _valid_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise VolumeImageError("A separately protected random 256-bit test key is required")
    return key


def _manifest_bytes(seq: int, image_id: bytes, entries: dict) -> bytes:
    return json.dumps({"seq": seq, "id": image_id.hex(), "entries": entries},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _open_regular(path: Path, create: bool) -> BinaryIO:
    # No device support at all, including Windows physical drive names.
    if path.suffix.lower() != ".kvi" or str(path).startswith(("\\\\.\\", "\\\\?\\")):
        raise VolumeImageError("Only ordinary .kvi test image files are supported")
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise VolumeImageError("Cannot open an exclusive regular test image") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise VolumeImageError("Only regular files are accepted")
        # Single writer across processes on POSIX and Windows.
        if os.name == "posix":
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif os.name == "nt":
            import msvcrt
            # Lock a sentinel byte BEYOND the maximum image size, avoiding
            # Windows mandatory byte-range locks on actual encrypted data.
            # The kernel releases the lock when this fd is closed/crashes.
            os.lseek(fd, MAX_IMAGE_BYTES + 4096, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
        return os.fdopen(fd, "r+b", buffering=0)
    except BaseException:
        os.close(fd)
        raise


class ResearchVolume:
    """Small append-only encrypted image with copy-on-write metadata commits."""

    def __init__(self, path: str | Path, key: bytes, *, create: bool = False,
                 expected_sequence: int | None = None,
                 expected_receipt: str | None = None):
        self.key = _valid_key(key)
        if expected_sequence is not None and (type(expected_sequence) is not int or expected_sequence < 0):
            raise VolumeImageError("Invalid external sequence")
        if expected_receipt is not None and (
                not isinstance(expected_receipt, str) or len(expected_receipt) != 64 or
                any(c not in "0123456789abcdef" for c in expected_receipt)):
            raise VolumeImageError("Invalid external receipt; expected lowercase SHA-256 hex")
        self.path = Path(path)
        self._f = _open_regular(self.path, create)
        self._closed = False
        self.entries: dict[str, list] = {}
        self.sequence = -1
        self.commit_receipt = None  # needs storage outside the attacker-controlled image
        self._poisoned = False
        self._recovery_trim_offset = None
        try:
            if create:
                self.id = secrets.token_bytes(16)
                self._f.write(MAGIC + self.id)
                self._f.flush()
                os.fsync(self._f.fileno())
                self._mac_key = self._derive_mac_key()
                self._commit(0, {})
            else:
                header = self._f.read(HEADER_BYTES)
                if len(header) != HEADER_BYTES or not header.startswith(MAGIC):
                    raise VolumeImageError("Invalid test image header")
                self.id = header[len(MAGIC):]
                self._mac_key = self._derive_mac_key()
                self._recover()
            if expected_sequence is not None and self.sequence != expected_sequence:
                raise VolumeImageError("External commit sequence mismatch; possible rollback")
            if expected_receipt is not None and not hmac.compare_digest(
                    self.commit_receipt, expected_receipt):
                raise VolumeImageError("External commit receipt mismatch; possible rollback")
            # Do NOT mutate the image before validating caller-supplied trust
            # anchors: a rejected/wrong-key/rollback probe must be read-only.
            if not create:
                self._trim_uncommitted_tail()
        except BaseException:
            self._f.close()
            self._closed = True
            raise

    def _derive_mac_key(self) -> bytes:
        return HKDF(algorithm=hashes.SHA512(), length=32, salt=self.id,
                    info=_DOMAIN).derive(self.key)

    def _frame(self, kind: bytes, payload: bytes) -> int:
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise VolumeImageError("Record too large")
        self._f.seek(0, os.SEEK_END)
        offset = self._f.tell()
        if offset + FRAME.size + len(payload) > MAX_IMAGE_BYTES:
            raise VolumeImageError("Research image quota reached")
        self._f.write(FRAME.pack(b"KVF0", kind, len(payload)))
        self._f.write(payload)
        self._f.flush()
        os.fsync(self._f.fileno())
        return offset

    def _receipt(self, signed: bytes) -> str:
        return hmac.digest(
            self._mac_key, b"KRYPTA-VIMG/0/EXTERNAL-RECEIPT/" + signed, "sha256"
        ).hex()

    def _commit(self, seq: int, entries: dict) -> None:
        serialized = _manifest_bytes(seq, self.id, entries)
        signed = serialized + hmac.digest(self._mac_key, MAGIC + self.id + serialized, "sha256")
        self._frame(b"C", signed)
        self.entries = entries
        self.sequence = seq
        self.commit_receipt = self._receipt(signed)

    def _recover(self) -> None:
        self._f.seek(0, os.SEEK_END)
        total = self._f.tell()
        if total > MAX_IMAGE_BYTES:
            raise VolumeImageError("Image exceeds research size cap")
        cursor = HEADER_BYTES
        last_end = HEADER_BYTES
        raw_records: dict[int, bytes] = {}
        good_entries: dict[str, list] = {}
        seq = -1
        receipt = None
        while cursor < total:
            self._f.seek(cursor)
            head = self._f.read(FRAME.size)
            if len(head) < FRAME.size:
                break  # interrupted trailing frame, no new commit
            marker, kind, length = FRAME.unpack(head)
            if marker != b"KVF0" or kind not in (b"D", b"C") or length > MAX_PAYLOAD_BYTES:
                raise VolumeImageError("Malformed frame on disk")
            if cursor + FRAME.size + length > total:
                break  # incomplete trailing frame
            payload = self._f.read(length)
            if len(payload) != length:
                break
            if kind == b"D":
                if length < DATA_ADDRESS.size + 32 or length > DATA_ADDRESS.size + BLOCK_BYTES + 200:
                    raise VolumeImageError("Invalid encrypted block frame")
                raw_records[cursor] = payload
            else:
                if length <= 32:
                    raise VolumeImageError("Invalid commit payload")
                content, mac = payload[:-32], payload[-32:]
                expected = hmac.digest(self._mac_key, MAGIC + self.id + content, "sha256")
                if not hmac.compare_digest(mac, expected):
                    raise VolumeImageError("Invalid commit MAC / incorrect key")
                try:
                    manifest = json.loads(content)
                except (ValueError, UnicodeDecodeError) as exc:
                    raise VolumeImageError("Invalid authenticated metadata") from exc
                if not isinstance(manifest, dict) or set(manifest) != {"seq", "id", "entries"}:
                    raise VolumeImageError("Malformed manifest")
                if (type(manifest["seq"]) is not int or manifest["seq"] != seq + 1 or
                        manifest["id"] != self.id.hex() or not isinstance(manifest["entries"], dict) or
                        len(manifest["entries"]) > MAX_BLOCKS):
                    raise VolumeImageError("Inconsistent commit state")
                current = manifest["entries"]
                for k, info in current.items():
                    if not isinstance(k, str) or not k.isascii() or not k.isdecimal() or str(int(k)) != k or not 0 <= int(k) < MAX_BLOCKS:
                        raise VolumeImageError("Invalid sector identity")
                    if (not isinstance(info, list) or len(info) != 3 or type(info[0]) is not int or
                            type(info[1]) is not int or not isinstance(info[2], str) or
                            not 1 <= info[0] < 2**64 or info[1] not in raw_records or len(info[2]) != 64):
                        raise VolumeImageError("Malformed sector map")
                    raw = raw_records[info[1]]
                    idx, generation = DATA_ADDRESS.unpack(raw[:DATA_ADDRESS.size])
                    if idx != int(k) or generation != info[0]:
                        raise VolumeImageError("Sector map does not match data")
                    crypt = raw[DATA_ADDRESS.size:]
                    if not hmac.compare_digest(hashlib.sha256(crypt).hexdigest(), info[2]):
                        raise VolumeImageError("Encrypted data modified")
                    try:
                        plain = open_block(self.key, idx, generation, crypt, aad=self.id)
                    except HorizonError as exc:
                        raise VolumeImageError("Encrypted sector authentication failed") from exc
                    if len(plain) != BLOCK_BYTES:
                        raise VolumeImageError("Incorrect sector size")
                seq = manifest["seq"]
                good_entries = current
                receipt = self._receipt(payload)
                last_end = cursor + FRAME.size + length
            cursor += FRAME.size + length
        if seq < 0:
            raise VolumeImageError("No authenticated genesis commit")
        self.sequence = seq
        self.entries = good_entries
        self.commit_receipt = receipt
        # Delay destructive tail cleanup until all external expected
        # sequence / receipt checks pass in __init__.
        self._recovery_trim_offset = last_end if last_end < total else None

    def _trim_uncommitted_tail(self) -> None:
        if self._recovery_trim_offset is not None:
            self._f.truncate(self._recovery_trim_offset)
            self._f.flush()
            os.fsync(self._f.fileno())
            self._recovery_trim_offset = None

    def _check_open(self):
        if self._closed:
            raise VolumeImageError("Image is closed")
        if self._poisoned:
            raise VolumeImageError("Uncertain write outcome: close and recover/reopen image")

    def read(self, index: int) -> bytes:
        self._check_open()
        if type(index) is not int or not 0 <= index < MAX_BLOCKS:
            raise VolumeImageError("Invalid block address")
        info = self.entries.get(str(index))
        if info is None:
            return bytes(BLOCK_BYTES)  # never-written sparse sector
        generation, offset, expected_digest = info
        self._f.seek(offset)
        head = self._f.read(FRAME.size)
        if len(head) != FRAME.size:
            raise VolumeImageError("Missing sector")
        magic, kind, length = FRAME.unpack(head)
        if magic != b"KVF0" or kind != b"D" or length > MAX_PAYLOAD_BYTES:
            raise VolumeImageError("Sector frame corrupted")
        payload = self._f.read(length)
        if len(payload) != length or len(payload) < DATA_ADDRESS.size:
            raise VolumeImageError("Sector payload corrupted")
        sector, ver = DATA_ADDRESS.unpack(payload[:DATA_ADDRESS.size])
        if sector != index or ver != generation:
            raise VolumeImageError("Sector address corrupted")
        ciphertext = payload[DATA_ADDRESS.size:]
        if not hmac.compare_digest(hashlib.sha256(ciphertext).hexdigest(), expected_digest):
            raise VolumeImageError("Ciphertext hash mismatch")
        try:
            return open_block(self.key, index, generation, ciphertext, aad=self.id)
        except HorizonError as exc:
            raise VolumeImageError("Sector authentication failed") from exc

    def write_many(self, updates: Mapping[int, bytes]) -> int:
        """Atomically commit multiple sectors at the research image API level.

        Appends all encrypted data frames, then ONE authenticated manifest.
        Any write/fsync failure poisons this handle; caller must close and reopen
        to determine whether the commit completed. No physical-disk guarantees.
        """
        self._check_open()
        if not isinstance(updates, Mapping) or not 1 <= len(updates) <= MAX_BLOCKS:
            raise VolumeImageError("Provide 1..MAX_BLOCKS sectors in one transaction")
        if self.sequence >= 2**64 - 1:
            raise VolumeImageError("Commit sequence exhausted")
        prepared = []
        for index, plaintext in updates.items():
            if type(index) is not int or not 0 <= index < MAX_BLOCKS:
                raise VolumeImageError("Invalid block address")
            if not isinstance(plaintext, bytes) or len(plaintext) != BLOCK_BYTES:
                raise VolumeImageError("Only full 4096-byte research sectors are accepted")
            name = str(index)
            generation = self.entries[name][0] + 1 if name in self.entries else 1
            if generation >= 2**64:
                raise VolumeImageError("Sector generation exhausted")
            encrypted = seal_block(self.key, index, generation, plaintext, aad=self.id)
            prepared.append((name, index, generation, encrypted))
        # All input validation and encryption are complete before first disk write.
        next_entries = dict(self.entries)
        try:
            for name, index, generation, encrypted in prepared:
                offset = self._frame(b"D", DATA_ADDRESS.pack(index, generation) + encrypted)
                next_entries[name] = [
                    generation, offset, hashlib.sha256(encrypted).hexdigest()
                ]
            self._commit(self.sequence + 1, next_entries)
        except BaseException:
            # Do NOT continue using state with uncertain durable commit outcome.
            self._poisoned = True
            raise
        return self.sequence

    def write(self, index: int, plaintext: bytes) -> int:
        return self.write_many({index: plaintext})

    def read_at(self, offset: int, length: int) -> bytes:
        """Read logical byte ranges using 4096-byte encrypted sectors."""
        self._check_open()
        if (type(offset) is not int or type(length) is not int or offset < 0 or
                length < 0 or offset + length > MAX_BLOCKS * BLOCK_BYTES):
            raise VolumeImageError("Invalid logical byte range")
        if length == 0:
            return b""
        first = offset // BLOCK_BYTES
        end = (offset + length - 1) // BLOCK_BYTES
        combined = b"".join(self.read(i) for i in range(first, end + 1))
        return combined[offset % BLOCK_BYTES:offset % BLOCK_BYTES + length]

    def write_at(self, offset: int, data: bytes) -> int:
        """Research-only transparent logical write; one multi-sector commit."""
        self._check_open()
        if (type(offset) is not int or offset < 0 or not isinstance(data, bytes)
                or not data or offset + len(data) > MAX_BLOCKS * BLOCK_BYTES):
            raise VolumeImageError("Invalid logical byte write")
        first = offset // BLOCK_BYTES
        last = (offset + len(data) - 1) // BLOCK_BYTES
        changes = {}
        for index in range(first, last + 1):
            sector_start = index * BLOCK_BYTES
            left = max(offset, sector_start)
            right = min(offset + len(data), sector_start + BLOCK_BYTES)
            sector = bytearray(self.read(index))
            sector[left - sector_start:right - sector_start] = data[left - offset:right - offset]
            changes[index] = bytes(sector)
        return self.write_many(changes)

    def close(self) -> None:
        if not self._closed:
            self._f.close()
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()