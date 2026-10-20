"""PVIMG/1 bounded IOBase adapter over disposable authenticated .kpv files."""
from __future__ import annotations

import io
import os

import pytest

from research.paged_stream import (
    CAPACITY, MAX_IO_BYTES, PagedBlockStream, open_paged_research_device,
)
from research.paged_volume import (
    BLOCK_BYTES, MAX_BLOCKS, PagedResearchVolume, PagedVolumeError,
)


def test_cross_radix_seek_read_write_and_authenticated_reopen(tmp_path):
    path, key = tmp_path / "stream.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        with PagedBlockStream(volume) as stream:
            assert stream.capacity == 1024 ** 3
            assert stream.seek(64 * BLOCK_BYTES - 2) == 64 * BLOCK_BYTES - 2
            assert stream.write(b"across radix boundary") == len(b"across radix boundary")
            assert stream.seek(64 * BLOCK_BYTES - 2) == 64 * BLOCK_BYTES - 2
            assert stream.read(21) == b"across radix boundary"
            assert stream.seek(-4, os.SEEK_END) == CAPACITY - 4
            assert stream.write(b"last") == 4
            assert stream.seek(-4, os.SEEK_END) == CAPACITY - 4
            assert stream.read(9) == b"last"
            assert stream.read(1) == b""
            receipt = stream.commit_receipt
        # Non-owning stream close leaves the original volume valid.
        assert volume.read(MAX_BLOCKS - 1)[-4:] == b"last"
    with open_paged_research_device(path, key, expected_receipt=receipt) as stream:
        stream.seek(64 * BLOCK_BYTES - 2)
        assert stream.read(21) == b"across radix boundary"
        assert stream.seek(-4, os.SEEK_END) == CAPACITY - 4
        assert stream.read(4) == b"last"


def test_readinto_and_buffer_protocol_write(tmp_path):
    path, key = tmp_path / "buffers.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        with PagedBlockStream(volume) as stream:
            assert stream.write(memoryview(bytearray(b"ABCD"))) == 4
            stream.seek(0)
            target = bytearray(7)
            assert stream.readinto(target) == 7
            assert target == b"ABCD" + bytes(3)
            stream.seek(0)
            with pytest.raises(TypeError, match="read-only"):
                stream.readinto(bytes(5))
            with pytest.raises(TypeError):
                stream.write("not binary")
            assert stream.tell() == 0


def test_unbounded_read_returns_one_bounded_chunk_not_entire_1gib(tmp_path):
    path, key = tmp_path / "limit.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        with PagedBlockStream(volume) as stream:
            assert stream.seek(1) == 1
            data = stream.read(-1)
            assert len(data) == MAX_IO_BYTES - 1
            assert not any(data)
            assert stream.tell() == MAX_IO_BYTES
            assert len(stream.read(100)) == 100


def test_oversized_unaligned_write_rejected_without_side_effect(tmp_path):
    path, key = tmp_path / "oversized.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        with PagedBlockStream(volume) as stream:
            stream.seek(1)
            receipt = stream.commit_receipt
            before = path.read_bytes()
            with pytest.raises(ValueError, match="256-sector"):
                stream.write(b"x" * MAX_IO_BYTES)
            assert stream.tell() == 1
            assert stream.commit_receipt == receipt
            assert path.read_bytes() == before


def test_write_error_poison_and_position_remains_unchanged(tmp_path, monkeypatch):
    path, key = tmp_path / "fault.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        with PagedBlockStream(volume) as stream:
            original = volume._append

            def cut(kind, data):
                if kind == b"C":
                    raise OSError("synthetic storage crash")
                return original(kind, data)

            monkeypatch.setattr(volume, "_append", cut)
            with pytest.raises(OSError, match="storage crash"):
                stream.write(b"new data")
            assert stream._position == 0
            with pytest.raises(PagedVolumeError, match="Uncertain"):
                stream.read(1)
    with open_paged_research_device(path, key, expected_sequence=0) as recovered:
        assert recovered.read(8) == bytes(8)


@pytest.mark.parametrize("pos", [-1, CAPACITY + 1])
def test_seek_outside_logical_range_fails(tmp_path, pos):
    path = tmp_path / "seek.kpv"
    with open_paged_research_device(path, os.urandom(32), create=True) as stream:
        with pytest.raises(ValueError):
            stream.seek(pos)


def test_bad_offsets_seek_methods_and_truncation(tmp_path):
    path = tmp_path / "bad.kpv"
    with open_paged_research_device(path, os.urandom(32), create=True) as stream:
        initial = stream.tell()
        for offset, whence in [(True, os.SEEK_SET), (3.14, 0), (0, True)]:
            with pytest.raises(TypeError):
                stream.seek(offset, whence)
        with pytest.raises(ValueError):
            stream.seek(1, 999)
        with pytest.raises(io.UnsupportedOperation):
            stream.truncate(0)
        assert stream.tell() == initial


def test_explicit_opener_and_exclusive_lock(tmp_path):
    path, key = tmp_path / "ownership.kpv", os.urandom(32)
    with open_paged_research_device(path, key, create=True) as owned:
        assert owned.write(b"correct") == 7
        with pytest.raises((PagedVolumeError, OSError)):
            open_paged_research_device(path, key)
        receipt = owned.commit_receipt
    with open_paged_research_device(path, key, expected_receipt=receipt) as second:
        assert second.read(7) == b"correct"
        assert second.seekable() and second.readable() and second.writable()
    with pytest.raises(ValueError, match="closed"):
        second.tell()


def test_wrong_file_extension_is_not_an_image(tmp_path):
    bad = tmp_path / "physical.img"
    with pytest.raises(PagedVolumeError):
        open_paged_research_device(bad, os.urandom(32), create=True)
    assert not bad.exists()


def test_io_buffered_random_integration(tmp_path):
    path, key = tmp_path / "buffered.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        raw = PagedBlockStream(volume)
        with io.BufferedRandom(raw, buffer_size=8192) as stream:
            stream.seek(4096)
            assert stream.write(b"buffered payload") == len(b"buffered payload")
            stream.flush()
            stream.seek(4096)
            assert stream.read(len(b"buffered payload")) == b"buffered payload"
        assert volume.read(1).startswith(b"buffered payload")


def test_last_byte_and_closed_stream_behavior(tmp_path):
    path = tmp_path / "last.kpv"
    with open_paged_research_device(path, os.urandom(32), create=True) as stream:
        stream.seek(-1, os.SEEK_END)
        assert stream.write(b"X") == 1
        assert stream.tell() == CAPACITY
        with pytest.raises(ValueError, match="256-sector"):
            stream.write(b"Y")
        stream.seek(-1, os.SEEK_END)
        assert stream.read(1) == b"X"
    with pytest.raises(ValueError):
        stream.read(1)
