"""KRYPTA-FS/0: a research-only encrypted file catalogue atop KRYPTA-VIMG/0.

This is an ORIGINAL file API with automatic authenticated encryption on writes
through ResearchVolume. It is NOT an OS filesystem/mount, kernel driver, or a
safe store for sensitive or irreplaceable real-life data.

Files are copy-on-write at the encrypted sector-record level. Catalogue and
file blocks are published in one authenticated image commit; a failed commit
poisons the underlying volume until it is closed and recovered. Deleting a
file does NOT securely erase previous ciphertext from the append-only image.
"""
from __future__ import annotations

import hashlib
import json
import math
import struct
import unicodedata
from collections.abc import Mapping
from typing import Any

from .volume_image import BLOCK_BYTES, MAX_BLOCKS, ResearchVolume, VolumeImageError

FS_MAGIC = b"KRYPTA-FS/0\x00"
CATALOGUE_SECTORS = 4
CATALOGUE_BYTES = CATALOGUE_SECTORS * BLOCK_BYTES
MAX_FILES = 48
MAX_FILENAME_BYTES = 96
MAX_FILE_BYTES = (MAX_BLOCKS - CATALOGUE_SECTORS) * BLOCK_BYTES
_HEADER_BYTES = len(FS_MAGIC) + 4
_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
_FORBIDDEN = set('/\\:*?"<>|')


class ResearchFSError(ValueError):
    """Malformed, inconsistent or unsupported research filesystem action."""


def _name(value: str) -> str:
    if not isinstance(value, str):
        raise ResearchFSError("File name must be Unicode text")
    canonical = unicodedata.normalize("NFC", value)
    if (not canonical or canonical in (".", "..") or canonical != value
            or canonical[-1] in (" ", ".") or canonical[0] == " "
            or any(c in _FORBIDDEN or ord(c) < 32 or ord(c) == 127 for c in canonical)
            or len(canonical.encode("utf-8")) > MAX_FILENAME_BYTES
            or canonical.split(".", 1)[0].upper() in _WIN_RESERVED):
        raise ResearchFSError("Unsupported portable file name")
    return canonical


def _catalogue_bytes(files: dict[str, dict]) -> bytes:
    content = json.dumps({"version": 0, "files": files}, ensure_ascii=False,
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(content) > CATALOGUE_BYTES - _HEADER_BYTES:
        raise ResearchFSError("Encrypted directory metadata quota exceeded")
    blob = FS_MAGIC + struct.pack(">I", len(content)) + content
    return blob + bytes(CATALOGUE_BYTES - len(blob))


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ResearchFSError("Duplicate authenticated metadata key")
        result[name] = value
    return result


def _validate_catalogue(value: Any) -> dict[str, dict]:
    if not isinstance(value, dict) or set(value) != {"version", "files"} or type(value["version"]) is not int or value["version"] != 0:
        raise ResearchFSError("Invalid KRYPTA-FS directory version")
    files = value["files"]
    if not isinstance(files, dict) or len(files) > MAX_FILES:
        raise ResearchFSError("Encrypted directory has invalid file count")
    allocated = set()
    for filename, meta in files.items():
        _name(filename)
        if not isinstance(meta, dict) or set(meta) != {"size", "blocks", "sha256"}:
            raise ResearchFSError("Malformed file metadata")
        size = meta["size"]
        blocks = meta["blocks"]
        digest = meta["sha256"]
        if (type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
                or not isinstance(blocks, list)
                or len(blocks) != (size + BLOCK_BYTES - 1) // BLOCK_BYTES
                or not isinstance(digest, str) or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)):
            raise ResearchFSError("Invalid file size, block count or checksum")
        for sector in blocks:
            if (type(sector) is not int or not CATALOGUE_SECTORS <= sector < MAX_BLOCKS
                    or sector in allocated):
                raise ResearchFSError("Invalid or shared encrypted sector allocation")
            allocated.add(sector)
    return files


class ResearchFileSystem:
    """Very small independent encrypted file API on an existing image.

    No hierarchical directories, ACLs, OS mounting, recovery keys, trusted
    receipt storage, secure deletion or multi-process writer service.
    """

    def __init__(self, volume: ResearchVolume):
        if not isinstance(volume, ResearchVolume):
            raise TypeError("ResearchFileSystem requires a KRYPTA ResearchVolume")
        volume._check_open()
        raw = volume.read_at(0, CATALOGUE_BYTES)
        if not raw.startswith(FS_MAGIC):
            raise ResearchFSError("Image is not formatted KRYPTA-FS/0")
        if len(raw) != CATALOGUE_BYTES:
            raise ResearchFSError("Truncated encrypted directory")
        declared = struct.unpack(">I", raw[len(FS_MAGIC):_HEADER_BYTES])[0]
        if declared < 2 or declared > CATALOGUE_BYTES - _HEADER_BYTES:
            raise ResearchFSError("Invalid encrypted directory size")
        content = raw[_HEADER_BYTES:_HEADER_BYTES + declared]
        if any(raw[_HEADER_BYTES + declared:]):
            raise ResearchFSError("Noncanonical encrypted directory padding")
        try:
            decoded = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeError, ValueError, TypeError) as exc:
            raise ResearchFSError("Authenticated directory cannot be parsed") from exc
        self._files = _validate_catalogue(decoded)
        self._volume = volume
        self._last_sequence = volume.sequence

    @classmethod
    def format(cls, volume: ResearchVolume) -> "ResearchFileSystem":
        """Format a brand-new genesis-only disposable test image exactly once."""
        if not isinstance(volume, ResearchVolume):
            raise TypeError("Expected KRYPTA test image")
        volume._check_open()
        if volume.sequence != 0 or volume.entries:
            raise ResearchFSError("Formatting refused: image is not empty genesis")
        empty_directory = _catalogue_bytes({})
        updates = {i: empty_directory[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES]
                   for i in range(CATALOGUE_SECTORS)}
        volume.write_many(updates)
        return cls(volume)

    def _check(self) -> None:
        self._volume._check_open()
        if self._last_sequence != self._volume.sequence:
            raise ResearchFSError("Stale catalogue; reopen ResearchFileSystem to avoid lost writes")

    @property
    def receipt(self) -> str:
        self._check()
        return self._volume.commit_receipt

    @property
    def sequence(self) -> int:
        self._check()
        return self._last_sequence

    def list_files(self) -> list[str]:
        self._check()
        return sorted(self._files)

    def stat(self, name: str) -> dict:
        self._check()
        entry = self._files.get(_name(name))
        if entry is None:
            raise FileNotFoundError(name)
        return {"size": entry["size"], "sha256": entry["sha256"]}

    def read_file(self, name: str) -> bytes:
        self._check()
        name = _name(name)
        entry = self._files.get(name)
        if entry is None:
            raise FileNotFoundError(name)
        contents = b"".join(self._volume.read(sector) for sector in entry["blocks"])
        size = entry["size"]
        if any(contents[size:]):
            raise ResearchFSError("Nonzero encrypted-file block padding")
        plaintext = contents[:size]
        if hashlib.sha256(plaintext).hexdigest() != entry["sha256"]:
            raise ResearchFSError("Encrypted file digest mismatch")
        return plaintext

    def _commit_files(self, files: dict[str, dict], updates: dict[int, bytes] | None = None) -> int:
        self._check()
        _validate_catalogue({"version": 0, "files": files})
        meta = _catalogue_bytes(files)
        changes = dict(updates or {})
        for i in range(CATALOGUE_SECTORS):
            changes[i] = meta[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES]
        result = self._volume.write_many(changes)
        self._files = files
        self._last_sequence = result
        return result

    def write_file(self, name: str, payload: bytes, *, replace: bool = False) -> int:
        """Write/rewrite a file in ONE encrypted image commit.

        A replaced file is not securely erased from the append-only log.
        """
        self._check()
        name = _name(name)
        if not isinstance(payload, bytes) or len(payload) > MAX_FILE_BYTES:
            raise ResearchFSError("File must be bytes and fit the research image")
        if name in self._files and not replace:
            raise FileExistsError(name)
        if name not in self._files and len(self._files) >= MAX_FILES:
            raise ResearchFSError("Maximum research file count reached")
        used = {sector for filename, desc in self._files.items() if filename != name
                for sector in desc["blocks"]}
        free = [sector for sector in range(CATALOGUE_SECTORS, MAX_BLOCKS)
                if sector not in used]
        count = math.ceil(len(payload) / BLOCK_BYTES)
        if count > len(free):
            raise ResearchFSError("Not enough virtual sectors for this operation")
        blocks = free[:count]
        chunks = {sector: payload[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES].ljust(BLOCK_BYTES, b"\x00")
                  for i, sector in enumerate(blocks)}
        new_files = dict(self._files)
        new_files[name] = {"size": len(payload), "blocks": blocks,
                           "sha256": hashlib.sha256(payload).hexdigest()}
        return self._commit_files(new_files, chunks)

    def delete_file(self, name: str) -> int:
        """Unlink directory entry; previous ciphertext persists in append-only log."""
        self._check()
        name = _name(name)
        if name not in self._files:
            raise FileNotFoundError(name)
        new_files = dict(self._files)
        del new_files[name]
        return self._commit_files(new_files)

    def rename_file(self, old: str, new: str) -> int:
        self._check()
        old, new = _name(old), _name(new)
        if old not in self._files:
            raise FileNotFoundError(old)
        if new in self._files:
            raise FileExistsError(new)
        files = dict(self._files)
        files[new] = files.pop(old)
        return self._commit_files(files)

    def append_file(self, name: str, payload: bytes) -> int:
        self._check()
        if not isinstance(payload, bytes):
            raise ResearchFSError("Append accepts bytes only")
        return self.write_file(name, self.read_file(name) + payload, replace=True)