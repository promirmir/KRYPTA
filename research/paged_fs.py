"""KRYPTA-PFS/1: transactional flat filesystem on encrypted PVIMG/1 images.

Implements file operations on a bounded, encrypted ordinary .kpv image, not on
physical disks. Both file data and directory metadata are authenticated inside
one PVIMG commit per modification. Never rely on it for unique/important data:
no complete POSIX semantics, trusted anti-rollback anchor or secure deletion.
"""
from __future__ import annotations

import hashlib
import json
import struct
from typing import Any

from .fs_image import ResearchFSError, _name as _validate_name
from .paged_volume import (
    BLOCK_BYTES, MAX_BLOCKS, MAX_TX_BLOCKS, MAX_IMAGE_BYTES,
    PagedResearchVolume,
)

FS_MAGIC = b"KRYPTA-PFS/1\x00"
CATALOGUE_SECTORS = 16
CATALOGUE_BYTES = CATALOGUE_SECTORS * BLOCK_BYTES
MAX_FILES = 128
MAX_FILENAME_BYTES = 96
MAX_FILE_BYTES = (MAX_TX_BLOCKS - CATALOGUE_SECTORS) * BLOCK_BYTES
_HEADER = len(FS_MAGIC) + 4


class PagedFSError(ResearchFSError):
    """Invalid, inconsistent or unsupported paged filesystem operation."""


def _name(value: str) -> str:
    try:
        return _validate_name(value)
    except ResearchFSError as exc:
        raise PagedFSError(str(exc)) from exc


def _pairs(items: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise PagedFSError("Duplicate encrypted catalogue key")
        result[key] = value
    return result


def _validate(files: Any) -> None:
    if not isinstance(files, dict) or len(files) > MAX_FILES:
        raise PagedFSError("Invalid encrypted file count")
    allocated: set[int] = set()
    for name, value in files.items():
        _name(name)
        if not isinstance(value, dict) or set(value) != {"size", "blocks", "sha256"}:
            raise PagedFSError("Malformed encrypted file metadata")
        size, blocks, digest = value["size"], value["blocks"], value["sha256"]
        if (type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
                or not isinstance(blocks, list)
                or len(blocks) != (size + BLOCK_BYTES - 1) // BLOCK_BYTES
                or not isinstance(digest, str) or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)):
            raise PagedFSError("Malformed file size, allocation or digest")
        for sector in blocks:
            if (type(sector) is not int
                    or not CATALOGUE_SECTORS <= sector < MAX_BLOCKS
                    or sector in allocated):
                raise PagedFSError("Invalid or shared encrypted sector")
            allocated.add(sector)


def _encode(files: dict) -> bytes:
    _validate(files)
    metadata = json.dumps(
        {"version": 1, "files": files}, ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    if len(metadata) > CATALOGUE_BYTES - _HEADER:
        raise PagedFSError("Encrypted catalogue quota exceeded")
    header = FS_MAGIC + struct.pack(">I", len(metadata)) + metadata
    return header.ljust(CATALOGUE_BYTES, b"\x00")


class PagedFileSystem:
    """Nonhierarchical authenticated catalogue, single writer via PVIMG lock.

    Per-file size is limited to 960 KiB to preserve an ALL-OR-NOTHING
    transaction containing both all file records and 16 catalogue sectors.
    This is not a full-capacity production filesystem, despite 1-GiB logical
    block addressing in the underlying sparse PVIMG layer.
    """
    max_file_bytes = MAX_FILE_BYTES
    max_files = MAX_FILES
    max_blocks = MAX_BLOCKS
    catalogue_sectors = CATALOGUE_SECTORS
    physical_quota_blocks = MAX_IMAGE_BYTES // (BLOCK_BYTES + 256)

    def __init__(self, volume: PagedResearchVolume):
        if not isinstance(volume, PagedResearchVolume):
            raise TypeError("PagedFileSystem requires a PVIMG/1 volume")
        volume._check()
        raw = volume.read_at(0, CATALOGUE_BYTES)
        if not raw.startswith(FS_MAGIC) or len(raw) != CATALOGUE_BYTES:
            raise PagedFSError("Volume is not formatted as KRYPTA-PFS/1")
        length = struct.unpack(">I", raw[len(FS_MAGIC):_HEADER])[0]
        if length < 2 or length > CATALOGUE_BYTES - _HEADER:
            raise PagedFSError("Invalid encrypted catalogue size")
        if any(raw[_HEADER + length:]):
            raise PagedFSError("Noncanonical encrypted catalogue padding")
        try:
            data = json.loads(raw[_HEADER:_HEADER + length].decode("utf-8"),
                              object_pairs_hook=_pairs)
        except (UnicodeError, TypeError, ValueError) as exc:
            raise PagedFSError("Invalid encrypted catalogue encoding") from exc
        if not isinstance(data, dict) or set(data) != {"version", "files"}:
            raise PagedFSError("Invalid encrypted catalogue")
        if type(data["version"]) is not int or data["version"] != 1:
            raise PagedFSError("Unsupported encrypted catalogue version")
        self._files = data["files"]
        _validate(self._files)
        if _encode(self._files) != raw:
            raise PagedFSError("Noncanonical encrypted catalogue")
        self._volume = volume
        self._sequence = volume.sequence

    @classmethod
    def format(cls, volume: PagedResearchVolume) -> "PagedFileSystem":
        """Create catalogue ONLY on an empty, newly initialized .kpv image."""
        if not isinstance(volume, PagedResearchVolume):
            raise TypeError("Expected an existing PVIMG/1 image")
        volume._check()
        if volume.sequence != 0 or volume.root is not None:
            raise PagedFSError("Formatting refused: nonempty or previously used image")
        metadata = _encode({})
        volume.write_many({
            i: metadata[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES]
            for i in range(CATALOGUE_SECTORS)
        })
        return cls(volume)

    def _check(self) -> None:
        self._volume._check()
        if self._sequence != self._volume.sequence:
            raise PagedFSError("Stale encrypted file catalogue; reopen before writing")

    @property
    def receipt(self) -> str:
        self._check()
        return self._volume.receipt

    @property
    def sequence(self) -> int:
        self._check()
        return self._sequence

    def list_files(self) -> list[str]:
        self._check()
        return sorted(self._files)

    def stat(self, filename: str) -> dict:
        self._check()
        entry = self._files.get(_name(filename))
        if entry is None:
            raise FileNotFoundError(filename)
        return {"size": entry["size"], "sha256": entry["sha256"]}

    def read_file(self, filename: str) -> bytes:
        """Authenticate ALL referenced blocks and file digest before output."""
        self._check()
        name = _name(filename)
        entry = self._files.get(name)
        if entry is None:
            raise FileNotFoundError(name)
        raw = b"".join(self._volume.read(sector) for sector in entry["blocks"])
        length = entry["size"]
        if any(raw[length:]):
            raise PagedFSError("Nonzero file padding")
        plaintext = raw[:length]
        if hashlib.sha256(plaintext).hexdigest() != entry["sha256"]:
            raise PagedFSError("Encrypted file digest mismatch")
        return plaintext

    def verify_all(self) -> dict:
        self._check()
        _validate(self._files)
        total = 0
        for name in self.list_files():
            total += len(self.read_file(name))
        self._check()
        return {"files_verified": len(self._files), "bytes_verified": total,
                "sequence": self._sequence, "receipt": self.receipt}

    def _commit(self, files: dict, changes: dict[int, bytes] | None = None) -> int:
        self._check()
        meta = _encode(files)
        updates = dict(changes or {})
        for i in range(CATALOGUE_SECTORS):
            updates[i] = meta[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES]
        if len(updates) > MAX_TX_BLOCKS:
            raise PagedFSError("Maximum atomic transaction sectors exceeded")
        result = self._volume.write_many(updates)
        self._files = files
        self._sequence = result
        return result

    def write_file(self, filename: str, data: bytes, *, replace: bool = False) -> int:
        """Commit complete encrypted contents + directory in one transaction."""
        self._check()
        filename = _name(filename)
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            raise PagedFSError("File size exceeds atomic 960 KiB limit")
        if filename in self._files and not replace:
            raise FileExistsError(filename)
        if filename not in self._files and len(self._files) >= MAX_FILES:
            raise PagedFSError("Maximum encrypted file count reached")
        needed = (len(data) + BLOCK_BYTES - 1) // BLOCK_BYTES
        used = {index for name, desc in self._files.items() if name != filename
                for index in desc["blocks"]}
        allocation = []
        if needed:
            for index in range(CATALOGUE_SECTORS, MAX_BLOCKS):
                if index not in used:
                    allocation.append(index)
                    if len(allocation) == needed:
                        break
        if len(allocation) < needed:
            raise PagedFSError("Not enough encrypted logical sectors")
        updates = {
            sector: data[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES].ljust(BLOCK_BYTES, b"\x00")
            for i, sector in enumerate(allocation)
        }
        new_files = dict(self._files)
        new_files[filename] = {
            "size": len(data), "blocks": allocation,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        return self._commit(new_files, updates)

    def delete_file(self, filename: str) -> int:
        self._check()
        filename = _name(filename)
        if filename not in self._files:
            raise FileNotFoundError(filename)
        files = dict(self._files)
        del files[filename]
        return self._commit(files)

    def rename_file(self, old: str, new: str) -> int:
        self._check()
        old, new = _name(old), _name(new)
        if old not in self._files:
            raise FileNotFoundError(old)
        if new in self._files:
            raise FileExistsError(new)
        files = dict(self._files)
        files[new] = files.pop(old)
        return self._commit(files)

    def append_file(self, filename: str, data: bytes) -> int:
        if not isinstance(data, bytes):
            raise PagedFSError("Append accepts bytes only")
        return self.write_file(filename, self.read_file(filename) + data, replace=True)
