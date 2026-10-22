"""Disposable, one-file Windows write staging over authenticated PFS/2.

This is NOT a WinFsp writable driver, nor a production export. A session
stages bounded plaintext edits in memory, then publishes one PFS/2 copy-on-
write commit. The independently supplied current receipt is mandatory.
There is no built-in receipt storage, durability certification or recovery
from physical device power loss. Do not use irreplaceable data.
"""
from __future__ import annotations

import hmac
import re
import threading

from .paged_fs2 import PagedFS2Error
from .windows_file_ops import WindowsFileOperations

# Bound retained plaintext. PFS/2 permits 32 MiB; this staging experiment
# deliberately supports less until streaming and zeroization are reviewed.
MAX_STAGED_FILE_BYTES = 4 * 1024 * 1024


class UncertainStagedCommit(RuntimeError):
    """A write may have committed; callers MUST NOT assume the old receipt.

    unverified_receipt is forensic recovery metadata ONLY if available,
    never a validated trusted anti-rollback anchor.
    """

    def __init__(self, unverified_receipt: str | None = None):
        super().__init__(
            "Staged commit result uncertain; stop writes, preserve image and "
            "trusted external receipt, and perform independent recovery."
        )
        self.unverified_receipt = unverified_receipt


class StagedWindowsFileWrite:
    """One existing flat file; no on-disk changes before explicit commit().

    Only one successful final PFS/2 root publication is attempted. External
    writers are rejected by sequence and receipt checks before disk I/O.
    Concurrent sessions are allowed to stage but only the first commit
    against a given base receipt can succeed.
    """

    def __init__(self, ops: WindowsFileOperations, path: str,
                 expected_receipt: str):
        if not isinstance(ops, WindowsFileOperations):
            raise TypeError("Authenticated Windows PFS/2 operations required")
        if (type(expected_receipt) is not str
                or re.fullmatch(r"[0-9a-f]{64}", expected_receipt) is None):
            raise ValueError("A separately trusted current 64-hex receipt is mandatory")
        self._guard = threading.RLock()
        self._ops = ops
        self._state = "initializing"
        with ops._lock:
            fs = ops._fs
            fs._check()
            if fs._volume.read_only:
                raise PagedFS2Error("Read-only backing image cannot stage writes")
            if not hmac.compare_digest(fs.receipt, expected_receipt):
                raise PagedFS2Error("External trusted receipt mismatch")
            filename = ops._filename(path)
            # Fail closed for ambiguously named Windows files, even if they
            # happen to be valid distinct case-sensitive PFS/2 entries.
            if sum(n.casefold() == filename.casefold()
                   for n in fs.list_files()) != 1:
                raise PagedFS2Error("Missing or ambiguous Windows filename")
            stat = fs.stat(filename)
            if stat["size"] > MAX_STAGED_FILE_BYTES:
                raise PagedFS2Error("File exceeds bounded staged-write limit")
            fs.verify_all()  # Detect existing unrelated data corruption first.
            self._buffer = bytearray(fs.read_file(filename))
            self._start_sequence = fs.sequence
            self._start_receipt = expected_receipt
            self._filename = filename
            self._dirty = False
            self._state = "open"

    def _require_open(self):
        if self._state != "open":
            raise PagedFS2Error("Staged write session has ended")

    def read(self, offset: int, length: int) -> bytes:
        """Read staged plaintext in RAM; nothing is published."""
        with self._guard:
            self._require_open()
            if (type(offset) is not int or type(length) is not int
                    or offset < 0 or length < 0):
                raise PagedFS2Error("Invalid staged read range")
            return bytes(self._buffer[offset:offset + length])

    def write(self, offset: int, payload: bytes) -> int:
        with self._guard:
            self._require_open()
            if (type(offset) is not int or offset < 0
                    or type(payload) is not bytes
                    or offset + len(payload) > MAX_STAGED_FILE_BYTES):
                raise PagedFS2Error("Invalid bounded staged write")
            if not payload:
                return 0
            if offset > len(self._buffer):
                self._buffer.extend(bytes(offset - len(self._buffer)))
            end = offset + len(payload)
            if end > len(self._buffer):
                self._buffer.extend(bytes(end - len(self._buffer)))
            self._buffer[offset:end] = payload
            self._dirty = True
            return len(payload)

    def truncate(self, length: int) -> None:
        with self._guard:
            self._require_open()
            if (type(length) is not int or not 0 <= length <= MAX_STAGED_FILE_BYTES):
                raise PagedFS2Error("Invalid staged truncate size")
            if length < len(self._buffer):
                del self._buffer[length:]
                self._dirty = True
            elif length > len(self._buffer):
                self._buffer.extend(bytes(length - len(self._buffer)))
                self._dirty = True

    def _discard(self):
        # Best effort only. Python/OS and crypto backends may retain copies.
        self._buffer[:] = bytes(len(self._buffer))
        self._buffer.clear()
        self._state = "closed"

    def abort(self) -> None:
        """Discard staged edits; never modify the authenticated image."""
        with self._guard:
            if self._state == "open":
                self._discard()

    def commit(self) -> dict:
        """Publish one COW root or fail closed with an ambiguous-outcome error.

        The returned candidate receipt MUST be saved in a separately trusted
        store by the caller before more writes. This service does NOT do that.
        """
        with self._guard:
            self._require_open()
            try:
                with self._ops._lock:
                    fs = self._ops._fs
                    fs._check()
                    if (fs.sequence != self._start_sequence
                            or not hmac.compare_digest(fs.receipt, self._start_receipt)):
                        raise PagedFS2Error("Stale staged base; start again with trusted receipt")
                    fs.verify_all()
                    if not self._dirty:
                        return {
                            "receipt": self._start_receipt,
                            "receipt_changed": False,
                            "sequence": self._start_sequence,
                        }
                    # From this point onward, an exception may occur after
                    # the final commit frame was persisted but before ack.
                    candidate = None
                    self._state = "committing"
                    try:
                        fs.write_file(self._filename, bytes(self._buffer), replace=True)
                        candidate = fs.receipt
                        report = fs.verify_all()
                        if not hmac.compare_digest(
                                fs.read_file(self._filename), bytes(self._buffer)):
                            raise PagedFS2Error("Readback plaintext mismatch")
                        return {
                            "receipt": candidate,
                            "receipt_changed": True,
                            "sequence": report["sequence"],
                            "files_verified": report["files_verified"],
                        }
                    except BaseException as exc:
                        raise UncertainStagedCommit(candidate) from exc
            finally:
                self._discard()

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(self, *_):
        self.abort()
