"""KRYPTA PVIMG/1 fixed-capacity encrypted virtual block stream.

Only translates Python byte-stream operations to a previously authenticated
ordinary .kpv file. It does NOT mount a filesystem, create a system block
device, touch partitions, change boot state, or provide a trusted PIN.
"""
from __future__ import annotations

import io
import os

from .paged_volume import (
    BLOCK_BYTES, MAX_BLOCKS, MAX_TX_BLOCKS,
    PagedResearchVolume,
)

CAPACITY = BLOCK_BYTES * MAX_BLOCKS
MAX_IO_BYTES = BLOCK_BYTES * MAX_TX_BLOCKS


class PagedBlockStream(io.RawIOBase):
    """Bounded plaintext I/O facade over PVIMG/1 authenticated sector records.

    A write is a single transaction of up to MAX_TX_BLOCKS touched sectors.
    Every read returns at most one such bounded extent, even for size=-1, so
    reading a 1-GiB sparse image never allocates the entire address space by
    accident. As for io.RawIOBase, callers must handle legitimate short reads.
    """

    def __init__(self, volume: PagedResearchVolume, *, owns_volume: bool = False):
        super().__init__()
        if not isinstance(volume, PagedResearchVolume):
            raise TypeError("Expected an already opened PVIMG/1 volume")
        volume._check()
        self._volume = volume
        self._owns_volume = bool(owns_volume)
        self._position = 0

    @property
    def capacity(self) -> int:
        return CAPACITY

    @property
    def commit_receipt(self) -> str:
        self._check()
        return self._volume.receipt

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def _check(self) -> None:
        if self.closed:
            raise ValueError("Paged virtual stream is closed")
        self._volume._check()

    def tell(self) -> int:
        self._check()
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._check()
        if type(offset) is not int or type(whence) is not int:
            raise TypeError("Offset and seek origin must be integers")
        if whence == os.SEEK_SET:
            new_position = offset
        elif whence == os.SEEK_CUR:
            new_position = self._position + offset
        elif whence == os.SEEK_END:
            new_position = CAPACITY + offset
        else:
            raise ValueError("Unsupported seek origin")
        if not 0 <= new_position <= CAPACITY:
            raise ValueError("Seek outside the 1-GiB logical image")
        self._position = new_position
        return new_position

    def _max_io_here(self) -> int:
        return min(CAPACITY - self._position,
                   MAX_IO_BYTES - self._position % BLOCK_BYTES)

    def read(self, size: int = -1) -> bytes:
        self._check()
        if type(size) is not int:
            raise TypeError("Read size must be an integer")
        limit = self._max_io_here()
        count = limit if size < 0 else min(size, limit)
        if count == 0:
            return b""
        result = self._volume.read_at(self._position, count)
        self._position += len(result)
        return result

    def readinto(self, target) -> int:
        self._check()
        try:
            view = memoryview(target).cast("B")
        except (TypeError, ValueError) as exc:
            raise TypeError("Expected a writable contiguous binary buffer") from exc
        try:
            if view.readonly:
                raise TypeError("Target buffer is read-only")
            chunk = self.read(len(view))
            view[:len(chunk)] = chunk
            return len(chunk)
        finally:
            view.release()

    def write(self, data) -> int:
        self._check()
        try:
            view = memoryview(data).cast("B")
        except (TypeError, ValueError) as exc:
            raise TypeError("Expected a contiguous binary buffer") from exc
        try:
            length = len(view)
            if length == 0:
                return 0
            if length > self._max_io_here():
                raise ValueError("Write crosses the bounded 256-sector transaction or image end")
            # Validate length before copying an untrusted, possibly huge buffer.
            payload = bytes(view)
        finally:
            view.release()
        self._volume.write_at(self._position, payload)
        self._position += length
        return length

    def truncate(self, size=None):
        raise io.UnsupportedOperation("Encrypted logical block image has fixed capacity")

    def flush(self) -> None:
        if self.closed:
            raise ValueError("Paged virtual stream is closed")
        # write_at commits and fsyncs the image before returning. This is not
        # a physical controller durability guarantee.

    def close(self) -> None:
        if not self.closed:
            try:
                super().close()  # invokes the above flush
            finally:
                if self._owns_volume:
                    self._volume.close()
                    self._owns_volume = False


def open_paged_research_device(path, key: bytes, *, create: bool = False,
                               expected_sequence: int | None = None,
                               expected_receipt: str | None = None) -> PagedBlockStream:
    """Open only an ordinary .kpv test file; the returned stream owns the lock."""
    volume = PagedResearchVolume(
        path, key, create=create,
        expected_sequence=expected_sequence,
        expected_receipt=expected_receipt)
    try:
        return PagedBlockStream(volume, owns_volume=True)
    except BaseException:
        volume.close()
        raise
