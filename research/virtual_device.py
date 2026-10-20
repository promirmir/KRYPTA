"""KRYPTA research-only fixed-size encrypted virtual block stream.

Turns ordinary seek/read/write calls into authenticated volume-sector I/O.
Never exposes, enumerates, mounts or writes a real disk. No kernel driver.
Only synthetic .kvi images opened via ResearchVolume are accepted.
"""
from __future__ import annotations

import io
import os

from .volume_image import BLOCK_BYTES, MAX_BLOCKS, ResearchVolume

CAPACITY = BLOCK_BYTES * MAX_BLOCKS


class VirtualBlockStream(io.RawIOBase):
    """Fixed-capacity binary stream backed by an encrypted research image.

    A write is committed as one transaction through ResearchVolume.write_at().
    The stream does NOT implement a filesystem, partitions, real disk mount, or
    trusted anti-rollback. Avoid placing real credentials or files in it.
    """

    def __init__(self, volume: ResearchVolume, *, owns_volume: bool = False):
        super().__init__()
        if not isinstance(volume, ResearchVolume):
            raise TypeError("Expected an existing ResearchVolume test image")
        volume._check_open()
        self._volume = volume
        self._owns_volume = bool(owns_volume)
        self._position = 0

    @property
    def capacity(self) -> int:
        return CAPACITY

    @property
    def commit_receipt(self) -> str:
        self._check()
        return self._volume.commit_receipt

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def _check(self) -> None:
        if self.closed:
            raise ValueError("Encrypted research device is closed")
        self._volume._check_open()

    def tell(self) -> int:
        self._check()
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._check()
        if type(offset) is not int or type(whence) is not int:
            raise TypeError("Seek offset and whence must be integers")
        if whence == os.SEEK_SET:
            candidate = offset
        elif whence == os.SEEK_CUR:
            candidate = self._position + offset
        elif whence == os.SEEK_END:
            candidate = CAPACITY + offset
        else:
            raise ValueError("Unsupported seek origin")
        if not 0 <= candidate <= CAPACITY:
            raise ValueError("Seek outside research device")
        self._position = candidate
        return self._position

    def read(self, size: int = -1) -> bytes:
        self._check()
        if type(size) is not int:
            raise TypeError("Read size must be an integer")
        remaining = CAPACITY - self._position
        if size < 0:
            size = remaining
        size = min(size, remaining)
        result = self._volume.read_at(self._position, size)
        self._position += len(result)
        return result

    def readinto(self, buffer) -> int:
        self._check()
        view = memoryview(buffer)
        if view.readonly:
            raise TypeError("readinto requires writable buffer")
        try:
            view = view.cast("B")
            data = self.read(len(view))
            view[:len(data)] = data
            return len(data)
        finally:
            view.release()

    def write(self, data) -> int:
        self._check()
        try:
            payload = memoryview(data).tobytes()
        except (TypeError, ValueError) as exc:
            raise TypeError("Write requires a binary buffer") from exc
        if not payload:
            return 0
        if self._position + len(payload) > CAPACITY:
            raise ValueError("Write exceeds fixed research-device capacity")
        # write_at performs encrypted multi-sector commit before returning.
        self._volume.write_at(self._position, payload)
        self._position += len(payload)
        return len(payload)

    def truncate(self, size=None):
        raise io.UnsupportedOperation("The research block device has fixed capacity")

    def flush(self) -> None:
        # Commits perform flush/fsync synchronously in ResearchVolume; this
        # cannot promise durability against buggy controllers or firmware.
        if self.closed:
            raise ValueError("Encrypted research device is closed")
        self._volume._check_open()

    def close(self) -> None:
        if not self.closed:
            try:
                if self._owns_volume:
                    self._volume.close()
            finally:
                # io.IOBase.close() invokes flush(); avoid accessing volume
                # after the owned handle is intentionally closed.
                self._owns_volume = False
                super().close()


def open_research_device(path, key: bytes, *, create: bool = False,
                         expected_sequence: int | None = None,
                         expected_receipt: str | None = None) -> VirtualBlockStream:
    """Open an ordinary test-only .kvi image; caller owns returned stream."""
    volume = ResearchVolume(
        path, key, create=create, expected_sequence=expected_sequence,
        expected_receipt=expected_receipt)
    try:
        return VirtualBlockStream(volume, owns_volume=True)
    except BaseException:
        volume.close()
        raise
