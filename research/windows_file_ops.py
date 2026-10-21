"""Windows-oriented PFS/2 file operations, independent of WinFsp callbacks.

This is an experimental authenticated *file API*, not a mounted drive.
It reuses KRYPTA PFS/2 rather than adding another encryption algorithm.
A future WinFsp adapter must enforce Windows sharing, ACL, handle identity,
case-insensitive naming and native directory security before exposing it.
"""
from __future__ import annotations

import threading
from .paged_fs2 import PagedFS2, PagedFS2Error


class WindowsFileOperations:
    """Serialized flat-file operations on an already authenticated PFS/2 object."""

    def __init__(self, fs: PagedFS2):
        if not isinstance(fs, PagedFS2):
            raise TypeError("PFS/2 is required; never accept unauthenticated storage")
        fs._check()
        self._fs = fs
        self._lock = threading.RLock()

    @staticmethod
    def _filename(path: str) -> str:
        if not isinstance(path, str) or not path.startswith("\\") or path == "\\":
            raise PagedFS2Error("Expected a root-relative Windows file path")
        name = path[1:]
        if not name or "\\" in name or "/" in name or ":" in name:
            raise PagedFS2Error("Only flat file paths are supported")
        return name

    def list_directory(self) -> list[str]:
        with self._lock:
            self._fs._check()
            return self._fs.list_files()

    def read(self, path: str, offset: int, length: int) -> bytes:
        name = self._filename(path)
        if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
            raise PagedFS2Error("Invalid file read range")
        if length > self._fs.max_file_bytes:
            raise PagedFS2Error("Read request exceeds file size limit")
        with self._lock:
            self._fs._check()
            return self._fs.read_range(name, offset, length)

    def _require_unambiguous_new_name(self, name: str, *, original: str | None = None) -> None:
        # PFS/2 is case-sensitive; Windows applications commonly are not.
        # Refuse ambiguous collisions instead of pretending both names refer
        # to the same entry or silently overwriting either ciphertext.
        target = name.casefold()
        for existing in self._fs.list_files():
            if existing != original and existing.casefold() == target:
                raise PagedFS2Error("Ambiguous case-insensitive filename collision")

    def create(self, path: str) -> None:
        name = self._filename(path)
        with self._lock:
            self._fs._check()
            self._require_unambiguous_new_name(name)
            self._fs.write_file(name, b"", replace=False)

    def write(self, path: str, offset: int, data: bytes) -> int:
        name = self._filename(path)
        if type(offset) is not int or offset < 0 or not isinstance(data, bytes):
            raise PagedFS2Error("Invalid file write request")
        if offset + len(data) > self._fs.max_file_bytes:
            raise PagedFS2Error("Write exceeds file limit")
        with self._lock:
            self._fs._check()
            if data:
                self._fs.write_at(name, offset, data)
            return len(data)

    def truncate(self, path: str, size: int) -> None:
        name = self._filename(path)
        if type(size) is not int or not 0 <= size <= self._fs.max_file_bytes:
            raise PagedFS2Error("Invalid target file size")
        with self._lock:
            self._fs._check()
            self._fs.truncate_file(name, size)

    def delete(self, path: str) -> None:
        name = self._filename(path)
        with self._lock:
            self._fs._check()
            self._fs.delete_file(name)

    def stat(self, path: str) -> dict:
        name = self._filename(path)
        with self._lock:
            self._fs._check()
            return dict(self._fs.stat(name))

    def rename(self, source: str, destination: str) -> None:
        old_name, new_name = self._filename(source), self._filename(destination)
        with self._lock:
            self._fs._check()
            self._require_unambiguous_new_name(new_name, original=old_name)
            self._fs.rename_file(old_name, new_name)
