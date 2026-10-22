"""KRYPTA-PFS/2: staged authenticated file updates over PVIMG/1 test images.

A separate ON-DISK filesystem version. PFS/1 remains readable unchanged.
New data frames and the authenticated directory are written as ONE PVIMG
copy-on-write transaction, which can cover 32 MiB plus 16 catalogue sectors.
The new authenticated root becomes visible only after its final durable
commit; a crash before publication retains the last trusted root/receipt.
Unreferenced historical ciphertext remains in the append-only log.

File format and all operations are development-stage, not a production mount.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
import json
from typing import Any

from .fs_image import ResearchFSError, _name as _portable_name
from .paged_volume import (
    BLOCK_BYTES, MAX_BLOCKS, MAX_IMAGE_BYTES, MAX_ATOMIC_FILE_BLOCKS,
    PagedResearchVolume,
)

MAGIC = b"KRYPTA-PFS/2\x00"
DIRECTORY_BLOCKS = 16
DIRECTORY_BYTES = DIRECTORY_BLOCKS * BLOCK_BYTES
HEADER_BYTES = len(MAGIC) + 4
MAX_FILES = 128
MAX_FILE_BYTES = 32 * 1024 * 1024
ZERO = bytes(BLOCK_BYTES)
EMPTY_HASH = hashlib.sha256(b"").hexdigest()


class PagedFS2Error(ResearchFSError):
    """Unsupported or invalid PFS/2 filesystem state or operation."""


def _name(name: str) -> str:
    try:
        return _portable_name(name)
    except ResearchFSError as exc:
        raise PagedFS2Error(str(exc)) from exc


def _unique_pairs(items: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise PagedFS2Error("Duplicate authenticated PFS/2 directory key")
        result[key] = value
    return result


def _validate(files: Any) -> None:
    if not isinstance(files, dict) or len(files) > MAX_FILES:
        raise PagedFS2Error("Invalid PFS/2 directory")
    referenced: set[int] = set()
    for filename, desc in files.items():
        _name(filename)
        if not isinstance(desc, dict) or set(desc) != {"size", "blocks", "sha256"}:
            raise PagedFS2Error("Invalid PFS/2 file descriptor")
        size, blocks, digest = desc["size"], desc["blocks"], desc["sha256"]
        if (type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
                or not isinstance(blocks, list)
                or len(blocks) != (size + BLOCK_BYTES - 1) // BLOCK_BYTES
                or not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise PagedFS2Error("Invalid PFS/2 file size or checksum")
        for sector in blocks:
            if sector is None:
                continue  # a virtual zero sector, not shared ciphertext
            if (type(sector) is not int
                    or not DIRECTORY_BLOCKS <= sector < MAX_BLOCKS
                    or sector in referenced):
                raise PagedFS2Error("Aliased or invalid encrypted data sector")
            referenced.add(sector)


def _encode(files: dict) -> bytes:
    _validate(files)
    content = json.dumps(
        {"version": 2, "files": files},
        sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")
    if len(content) > DIRECTORY_BYTES - HEADER_BYTES:
        raise PagedFS2Error("PFS/2 encrypted directory quota exceeded")
    result = MAGIC + len(content).to_bytes(4, "big") + content
    return result + bytes(DIRECTORY_BYTES - len(result))


class PagedFS2:
    """Flat encrypted file API, 32-MiB file cap, sparse and staged commits.

    The PVIMG physical log still has a HARD 512-MiB cap, and the directory
    is only 64 KiB. Neither limit can be inferred from the 1-GiB sparse
    logical block address range. Only ONE mounted writer is supported.
    """
    max_file_bytes = MAX_FILE_BYTES
    max_files = MAX_FILES
    max_blocks = MAX_BLOCKS
    catalogue_sectors = DIRECTORY_BLOCKS
    physical_quota_blocks = MAX_IMAGE_BYTES // (BLOCK_BYTES + 256)

    def __init__(self, volume: PagedResearchVolume):
        if not isinstance(volume, PagedResearchVolume):
            raise TypeError("PFS/2 expects an already opened PVIMG/1 image")
        volume._check()
        raw = volume.read_at(0, DIRECTORY_BYTES)
        if not raw.startswith(MAGIC):
            raise PagedFS2Error("Image is not formatted as KRYPTA-PFS/2")
        declared = int.from_bytes(raw[len(MAGIC):HEADER_BYTES], "big")
        if not 2 <= declared <= DIRECTORY_BYTES - HEADER_BYTES:
            raise PagedFS2Error("Invalid PFS/2 directory byte length")
        if any(raw[HEADER_BYTES + declared:]):
            raise PagedFS2Error("Noncanonical encrypted directory padding")
        try:
            doc = json.loads(raw[HEADER_BYTES:HEADER_BYTES + declared].decode("ascii"),
                             object_pairs_hook=_unique_pairs)
        except (UnicodeError, ValueError, TypeError) as exc:
            raise PagedFS2Error("Malformed authenticated PFS/2 directory JSON") from exc
        if (not isinstance(doc, dict) or set(doc) != {"version", "files"}
                or type(doc["version"]) is not int or doc["version"] != 2):
            raise PagedFS2Error("Invalid PFS/2 filesystem version")
        _validate(doc["files"])
        if _encode(doc["files"]) != raw:
            raise PagedFS2Error("Noncanonical authenticated PFS/2 directory")
        self._files = doc["files"]
        self._volume = volume
        self._sequence = volume.sequence

    @classmethod
    def format(cls, volume: PagedResearchVolume) -> "PagedFS2":
        """Format ONLY a freshly created and empty ordinary .kpv image."""
        if not isinstance(volume, PagedResearchVolume):
            raise TypeError("Expected a PVIMG/1 file-image handle")
        volume._check()
        if volume.sequence != 0 or volume.root is not None:
            raise PagedFS2Error("Refusing to format a nonempty image")
        raw = _encode({})
        volume.write_many({
            i: raw[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES]
            for i in range(DIRECTORY_BLOCKS)
        })
        return cls(volume)

    def _check(self):
        self._volume._check()
        if self._sequence != self._volume.sequence:
            raise PagedFS2Error("Stale directory after another PVIMG commit; reopen")

    @property
    def sequence(self) -> int:
        self._check()
        return self._sequence

    @property
    def receipt(self) -> str:
        self._check()
        return self._volume.receipt

    def list_files(self) -> list[str]:
        self._check()
        return sorted(self._files)

    def stat(self, filename: str) -> dict:
        self._check()
        desc = self._files.get(_name(filename))
        if desc is None:
            raise FileNotFoundError(filename)
        return {"size": desc["size"], "sha256": desc["sha256"]}

    def _block(self, desc: dict, index: int) -> bytes:
        sector = desc["blocks"][index]
        return ZERO if sector is None else self._volume.read(sector)

    def read_range(self, filename: str, offset: int, length: int) -> bytes:
        """AEAD-authenticate just the requested encrypted sectors."""
        self._check()
        desc = self._files.get(_name(filename))
        if desc is None:
            raise FileNotFoundError(filename)
        if (type(offset) is not int or type(length) is not int
                or offset < 0 or length < 0):
            raise PagedFS2Error("Invalid file read range")
        if offset >= desc["size"] or length == 0:
            return b""
        end = min(offset + length, desc["size"])
        first = offset // BLOCK_BYTES
        final = (end - 1) // BLOCK_BYTES
        data = b"".join(self._block(desc, i) for i in range(first, final + 1))
        begin = offset % BLOCK_BYTES
        return data[begin:begin + end - offset]

    def _hash(self, desc: dict) -> str:
        """Authenticate full file and canonical final-sector zero padding."""
        hasher = hashlib.sha256()
        for i in range(len(desc["blocks"])):
            block = self._block(desc, i)
            remaining = desc["size"] - i * BLOCK_BYTES
            take = min(BLOCK_BYTES, remaining)
            if any(block[take:]):
                raise PagedFS2Error("Noncanonical nonzero file sector padding")
            hasher.update(block[:take])
        return hasher.hexdigest()

    def _verify(self, desc: dict) -> None:
        if self._hash(desc) != desc["sha256"]:
            raise PagedFS2Error("Encrypted PFS/2 plaintext checksum mismatch")

    def read_file(self, filename: str) -> bytes:
        self._check()
        filename = _name(filename)
        desc = self._files.get(filename)
        if desc is None:
            raise FileNotFoundError(filename)
        self._verify(desc)
        return self.read_range(filename, 0, desc["size"])

    def verify_all(self) -> dict:
        self._check()
        _validate(self._files)
        total = 0
        for desc in self._files.values():
            self._verify(desc)
            total += desc["size"]
        return {"files_verified": len(self._files), "bytes_verified": total,
                "sequence": self._sequence, "receipt": self.receipt}

    def _commit_directory(self, updated_files: dict) -> int:
        raw = _encode(updated_files)
        self._check()
        seq = self._volume.write_many({
            i: raw[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES]
            for i in range(DIRECTORY_BLOCKS)
        })
        self._files = updated_files
        self._sequence = seq
        return seq

    def _apply(self, filename: str, *, offset: int, data: bytes,
               size: int, replace_all: bool = False) -> int:
        """Prepare new data sector references and publish one atomic root.

        The old encrypted directory and its referenced sectors remain valid
        throughout writing new uncommitted frames. Failure before the final
        commit preserves the old receipt on recovery.
        """
        self._check()
        filename = _name(filename)
        if (type(offset) is not int or offset < 0 or
                type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
                or not isinstance(data, bytes)
                or offset + len(data) > size):
            raise PagedFS2Error("Invalid large-file modification")
        old = self._files.get(filename)
        if old is None and len(self._files) >= MAX_FILES:
            raise PagedFS2Error("PFS/2 maximum file count reached")
        if old is not None:
            self._verify(old)
        old_size = old["size"] if old else 0
        old_blocks = old["blocks"] if old else []
        count = (size + BLOCK_BYTES - 1) // BLOCK_BYTES
        blocks = [None] * count if replace_all else (
            old_blocks[:count] + [None] * max(0, count - len(old_blocks))
        )

        # Calculate touched indices; for truncation the shortened final
        # sector must be rewritten with zero padding.
        changes = set()
        if data:
            changes.update(range(offset // BLOCK_BYTES,
                                 (offset + len(data) - 1) // BLOCK_BYTES + 1))
        if size < old_size and size % BLOCK_BYTES and not replace_all:
            changes.add(size // BLOCK_BYTES)
        if replace_all:
            changes.update(range(count))

        used = {s for desc in self._files.values()
                for s in desc["blocks"] if s is not None}
        free = (s for s in range(DIRECTORY_BLOCKS, MAX_BLOCKS) if s not in used)
        staged: dict[int, bytes] = {}
        changed = False
        for i in sorted(changes):
            if i >= count:
                continue
            original = ZERO if replace_all or i >= len(old_blocks) else self._block(old, i)
            value = bytearray(original)
            block_start = i * BLOCK_BYTES
            if data:
                segment_start = max(offset, block_start)
                segment_end = min(offset + len(data), block_start + BLOCK_BYTES)
                if segment_end > segment_start:
                    value[segment_start - block_start:segment_end - block_start] = (
                        data[segment_start - offset:segment_end - offset]
                    )
            if i == count - 1 and size % BLOCK_BYTES:
                value[size % BLOCK_BYTES:] = bytes(BLOCK_BYTES - size % BLOCK_BYTES)
            encoded = bytes(value)
            if not replace_all and i < len(old_blocks) and encoded == original:
                continue
            if encoded == ZERO:
                blocks[i] = None
            else:
                try:
                    sector = next(free)
                except StopIteration as exc:
                    raise PagedFS2Error("PFS/2 has insufficient unused logical sectors") from exc
                blocks[i] = sector
                staged[sector] = encoded
            changed = True

        if not changed and old is not None and old_size == size:
            return self._sequence
        updated = dict(self._files)
        updated[filename] = {
            "size": size, "blocks": blocks,
            "sha256": "0" * 64,
        }
        # PRECHECK all names, file sizes, sector aliases and directory
        # serialization limits before staging any encrypted block.
        _encode(updated)
        # Compute the new file digest using authenticated old sectors and
        # fresh prepared in-memory plaintext. No staged data is yet committed.
        digest = hashlib.sha256()
        for i, sector in enumerate(blocks):
            full = ZERO if sector is None else staged.get(sector)
            if full is None:
                full = self._volume.read(sector)
            remaining = size - i * BLOCK_BYTES
            take = min(BLOCK_BYTES, remaining)
            if any(full[take:]):
                raise PagedFS2Error("Noncanonical staged file sector padding")
            digest.update(full[:take])
        updated[filename]["sha256"] = digest.hexdigest()
        raw = _encode(updated)
        changes = dict(staged)
        changes.update({
            i: raw[i * BLOCK_BYTES:(i + 1) * BLOCK_BYTES]
            for i in range(DIRECTORY_BLOCKS)
        })
        # All new data frames, radix nodes and catalogue sectors are
        # authenticated under one FINAL PVIMG commit; a failed commit leaves
        # the previous on-disk directory and external receipt unchanged.
        sequence = self._volume.write_many_atomic_large(changes)
        self._files = updated
        self._sequence = sequence
        return sequence


    def write_files_atomic(self, files: Mapping[str, bytes]) -> int:
        """Create several NEW files in one authenticated PVIMG root commit.

        Preflight includes all names, file sizes, catalogue quota and the
        8192-sector transaction ceiling. No file is visible before the one
        durable commit. Failed/ambiguous I/O poisons the volume handle; the
        operator must reopen with an independently trusted receipt.
        """
        self._check()
        if not isinstance(files, Mapping) or not files:
            raise PagedFS2Error("Provide a nonempty mapping of new files")
        if len(self._files) + len(files) > MAX_FILES:
            raise PagedFS2Error("PFS/2 maximum file count reached")

        validated = {}
        total_blocks = 0
        for original, payload in files.items():
            name = _name(original)
            if name in self._files:
                raise FileExistsError(name)
            if name in validated:
                raise PagedFS2Error("Duplicate normalized PFS/2 filename")
            if not isinstance(payload, bytes) or len(payload) > MAX_FILE_BYTES:
                raise PagedFS2Error("Invalid PFS/2 file payload or size")
            validated[name] = payload
            total_blocks += (len(payload) + BLOCK_BYTES - 1) // BLOCK_BYTES
            if total_blocks > MAX_ATOMIC_FILE_BLOCKS - DIRECTORY_BLOCKS:
                raise PagedFS2Error("Batch exceeds the single-commit 32-MiB sector limit")

        # Authenticate all existing live content BEFORE attempting a write.
        self.verify_all()
        used = {s for desc in self._files.values()
                for s in desc["blocks"] if s is not None}
        free = (s for s in range(DIRECTORY_BLOCKS, MAX_BLOCKS) if s not in used)
        staged: dict[int, bytes] = {}
        updated = dict(self._files)
        for name, payload in validated.items():
            blocks = []
            for start in range(0, len(payload), BLOCK_BYTES):
                chunk = payload[start:start + BLOCK_BYTES]
                full = chunk + bytes(BLOCK_BYTES - len(chunk))
                if full == ZERO:
                    blocks.append(None)
                else:
                    try:
                        index = next(free)
                    except StopIteration as exc:
                        raise PagedFS2Error("Insufficient free encrypted data sectors") from exc
                    blocks.append(index)
                    staged[index] = full
            updated[name] = {
                "size": len(payload),
                "blocks": blocks,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }

        # The exact canonical directory MUST fit before any frames are appended.
        raw = _encode(updated)
        staged.update({
            index: raw[index * BLOCK_BYTES:(index + 1) * BLOCK_BYTES]
            for index in range(DIRECTORY_BLOCKS)
        })
        sequence = self._volume.write_many_atomic_large(staged)
        self._files = updated
        self._sequence = sequence
        return sequence

    def write_file(self, filename: str, data: bytes, *, replace: bool = False) -> int:
        self._check()
        filename = _name(filename)
        if not isinstance(data, bytes):
            raise PagedFS2Error("Write requires binary data")
        if filename in self._files and not replace:
            raise FileExistsError(filename)
        return self._apply(filename, offset=0, data=data,
                           size=len(data), replace_all=True)

    def write_at(self, filename: str, offset: int, data: bytes) -> int:
        self._check()
        filename = _name(filename)
        if filename not in self._files:
            raise FileNotFoundError(filename)
        if type(offset) is not int or offset < 0 or not isinstance(data, bytes):
            raise PagedFS2Error("Invalid file byte-range write")
        if len(data) == 0:
            return self._sequence
        size = max(self._files[filename]["size"], offset + len(data))
        return self._apply(filename, offset=offset, data=data, size=size)

    def truncate_file(self, filename: str, size: int) -> int:
        self._check()
        filename = _name(filename)
        if filename not in self._files:
            raise FileNotFoundError(filename)
        if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
            raise PagedFS2Error("Invalid file truncation size")
        return self._apply(filename, offset=0, data=b"", size=size)

    def delete_file(self, filename: str) -> int:
        self._check()
        filename = _name(filename)
        if filename not in self._files:
            raise FileNotFoundError(filename)
        updated = dict(self._files)
        del updated[filename]
        return self._commit_directory(updated)

    def rename_file(self, old: str, new: str) -> int:
        self._check()
        old, new = _name(old), _name(new)
        if old not in self._files:
            raise FileNotFoundError(old)
        if new in self._files:
            raise FileExistsError(new)
        updated = dict(self._files)
        updated[new] = updated.pop(old)
        return self._commit_directory(updated)
