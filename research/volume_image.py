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
        # Refuse more than one process using one image simultaneously on POSIX.
        # Windows cross-process exclusion is NOT yet implemented: single writer only.
        if os.name == "posix":
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return os.fdopen(fd, "r+b", buffering=0)
    except BaseException:
        os.close(fd)
        raise


class ResearchVolume:
    """Small append-only encrypted image with copy-on-write metadata commits."""

    def __init__(self, path: str | Path, key: bytes, *, create: bool = False,
                 expected_sequence: int | None = None):
        self.key = _valid_key(key)
        if expected_sequence is not None and (type(expected_sequence) is not int or expected_sequence < 0):
            raise VolumeImageError("Invalid external sequence")
        self.path = Path(path)
        self._f = _open_regular(self.path, create)
        self._closed = False
        self.entries: dict[str, list] = {}
        self.sequence = -1
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

    def _commit(self, seq: int, entries: dict) -> None:
        serialized = _manifest_bytes(seq, self.id, entries)
        signed = serialized + hmac.digest(self._mac_key, MAGIC + self.id + serialized, "sha256")
        self._frame(b"C", signed)
        self.entries = entries
        self.sequence = seq

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
                last_end = cursor + FRAME.size + length
            cursor += FRAME.size + length
        if seq < 0:
            raise VolumeImageError("No authenticated genesis commit")
        self.sequence = seq
        self.entries = good_entries
        if last_end < total:
            # Only append records after the most recent completed valid commit
            # are discarded. A prior complete commit failing MAC never falls back.
            self._f.truncate(last_end)
            self._f.flush()
            os.fsync(self._f.fileno())

    def _check_open(self):
        if self._closed:
            raise VolumeImageError("Image is closed")

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

    def write(self, index: int, plaintext: bytes) -> int:
        self._check_open()
        if type(index) is not int or not 0 <= index < MAX_BLOCKS:
            raise VolumeImageError("Invalid block address")
        if not isinstance(plaintext, bytes) or len(plaintext) != BLOCK_BYTES:
            raise VolumeImageError("Only full 4096-byte research sectors are accepted")
        if self.sequence >= 2**64 - 1:
            raise VolumeImageError("Sequence exhausted")
        key = str(index)
        generation = self.entries[key][0] + 1 if key in self.entries else 1
        if generation >= 2**64:
            raise VolumeImageError("Sector generation exhausted")
        encrypted = seal_block(self.key, index, generation, plaintext, aad=self.id)
        payload = DATA_ADDRESS.pack(index, generation) + encrypted
        offset = self._frame(b"D", payload)
        next_entries = dict(self.entries)
        next_entries[key] = [generation, offset, hashlib.sha256(encrypted).hexdigest()]
        self._commit(self.sequence + 1, next_entries)
        return self.sequence

    def close(self) -> None:
        if not self._closed:
            self._f.close()
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()