"""Synthetic KRYPTA encrypted virtual device exercises on Windows/Linux.

No mounting, no privileged calls, and no access to block devices.
"""
from __future__ import annotations

import io
import os

import pytest

from research.volume_image import BLOCK_BYTES, MAX_BLOCKS, ResearchVolume, VolumeImageError
from research.virtual_device import CAPACITY, VirtualBlockStream, open_research_device


def test_normal_file_like_read_write_and_cross_sector_roundtrip(tmp_path):
    p, key = tmp_path / "scratch.kvi", os.urandom(32)
    with open_research_device(p, key, create=True) as device:
        assert device.seekable() and device.readable() and device.writable()
        assert device.capacity == BLOCK_BYTES * MAX_BLOCKS
        assert device.seek(BLOCK_BYTES-3) == BLOCK_BYTES-3
        assert device.write(b"Hello KRYPTA!") == 13
        assert device.tell() == BLOCK_BYTES+10
        device.seek(BLOCK_BYTES-3)
        assert device.read(13) == b"Hello KRYPTA!"
        assert device.read(4) == bytes(4)
        receipt = device.commit_receipt
    assert device.closed
    with open_research_device(p, key, expected_sequence=1, expected_receipt=receipt) as fresh:
        assert fresh.seek(BLOCK_BYTES-3) == BLOCK_BYTES-3
        assert fresh.read(13) == b"Hello KRYPTA!"


def test_sparse_reads_and_eof_are_exact(tmp_path):
    with open_research_device(tmp_path/"sparse.kvi", os.urandom(32), create=True) as device:
        assert device.read(7) == bytes(7)
        assert device.seek(-5, os.SEEK_END) == CAPACITY-5
        assert device.read() == bytes(5)
        assert device.read() == b""
        assert device.write(b"") == 0
        assert device.seek(0) == 0
        assert len(device.read()) == CAPACITY


def test_readinto_updates_mutable_bytearray(tmp_path):
    with open_research_device(tmp_path/"readinto.kvi", os.urandom(32), create=True) as device:
        device.write(b"one")
        device.seek(0)
        buf = bytearray(6)
        assert device.readinto(buf) == 6
        assert bytes(buf) == b"one" + bytes(3)
        with pytest.raises(TypeError):
            device.readinto(b"immutable")


def test_standard_io_buffered_random_path(tmp_path):
    path, key = tmp_path/"buffered.kvi", os.urandom(32)
    with open_research_device(path, key, create=True) as raw:
        # Clients can use normal buffered Python file I/O; flushing buffers
        # publishes an authenticated encrypted commit via write_at.
        with io.BufferedRandom(raw, buffer_size=BLOCK_BYTES) as buffered:
            buffered.seek(2047)
            buffered.write(b"wrapped test" * 40)
            buffered.flush()
            buffered.seek(2047)
            assert buffered.read(12) == b"wrapped test"
        assert raw.closed
    with open_research_device(path, key, expected_sequence=1) as verify:
        verify.seek(2047)
        assert verify.read(12) == b"wrapped test"


@pytest.mark.parametrize("offset,whence", [
    (-1, os.SEEK_SET), (CAPACITY+1, os.SEEK_SET),
    (1, os.SEEK_END), (-(CAPACITY+1), os.SEEK_END),
    (0, 99),
])
def test_seek_bounds_rejected_without_changing_position(tmp_path, offset, whence):
    with open_research_device(tmp_path/"seek.kvi", os.urandom(32), create=True) as dev:
        dev.seek(100)
        with pytest.raises(ValueError):
            dev.seek(offset, whence)
        assert dev.tell() == 100


def test_failed_write_does_not_advance_cursor_or_modify_image(tmp_path):
    p = tmp_path/"bounds.kvi"
    with open_research_device(p, os.urandom(32), create=True) as dev:
        dev.seek(-3, os.SEEK_END)
        before = p.read_bytes()
        with pytest.raises(ValueError):
            dev.write(b"toolong")
        assert dev.tell() == CAPACITY-3
        assert p.read_bytes() == before
        assert dev.write(b"END") == 3


def test_nonbinary_write_rejected(tmp_path):
    p = tmp_path/"invalid.kvi"
    with open_research_device(p, os.urandom(32), create=True) as dev:
        with pytest.raises(TypeError):
            dev.write("text cannot be accepted")
        assert dev.tell() == 0


def test_owned_handle_closed_and_released(tmp_path):
    p, key = tmp_path/"own.kvi", os.urandom(32)
    device = open_research_device(p, key, create=True)
    assert device.tell() == 0
    device.close()
    assert device.closed
    with pytest.raises(ValueError):
        device.tell()
    with open_research_device(p, key) as other:
        assert other.tell() == 0


def test_nonowned_handle_does_not_close_volume(tmp_path):
    p, key = tmp_path/"borrowed.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as volume:
        with VirtualBlockStream(volume) as stream:
            stream.write(b"abc")
        assert volume.read_at(0, 3) == b"abc"


def test_volume_write_failure_does_not_advance_position(tmp_path, monkeypatch):
    p, key = tmp_path/"failed.kvi", os.urandom(32)
    with open_research_device(p, key, create=True) as dev:
        dev.seek(100)
        def failed(*args, **kwargs):
            raise OSError("simulated filesystem failure")
        monkeypatch.setattr(dev._volume, "write_at", failed)
        with pytest.raises(OSError):
            dev.write(b"will fail")
        assert dev.tell() == 100


def test_truncation_unsupported_and_real_device_unavailable(tmp_path):
    p, key = tmp_path/"virtual.kvi", os.urandom(32)
    with open_research_device(p, key, create=True) as dev:
        with pytest.raises(io.UnsupportedOperation):
            dev.truncate(0)
    with pytest.raises(VolumeImageError):
        open_research_device(tmp_path/"physical-disk.img", key, create=True)
