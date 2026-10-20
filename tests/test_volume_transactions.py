"""KRYPTA-VIMG/0 multi-sector transaction/receipt research checks only.

Uses ordinary tmp_path files; NEVER opens a block device or uses real user data.
"""
from __future__ import annotations

import os
import pytest

from research.volume_image import BLOCK_BYTES, MAX_BLOCKS, ResearchVolume, VolumeImageError


def _payload(character: bytes) -> bytes:
    return character * BLOCK_BYTES


def test_batch_single_sequence_atomic_reopen(tmp_path):
    p, key = tmp_path / "volume.kvi", os.urandom(32)
    changes = {1: _payload(b"A"), 2: _payload(b"B"), 100: _payload(b"C")}
    with ResearchVolume(p, key, create=True) as image:
        assert image.sequence == 0
        genesis_receipt = image.commit_receipt
        assert len(genesis_receipt) == 64
        assert image.write_many(changes) == 1
        assert image.sequence == 1
        assert image.commit_receipt != genesis_receipt
        for i, data in changes.items():
            assert image.read(i) == data
        receipt = image.commit_receipt
    with ResearchVolume(p, key, expected_sequence=1, expected_receipt=receipt) as reopened:
        for i, data in changes.items():
            assert reopened.read(i) == data


def test_generation_and_receipt_once_per_atomic_batch(tmp_path):
    p, key = tmp_path / "volume.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as image:
        assert image.write_many({7: _payload(b"A"), 8: _payload(b"B")}) == 1
        r1 = image.commit_receipt
        assert image.write_many({7: _payload(b"C"), 8: _payload(b"D")}) == 2
        assert image.entries["7"][0] == image.entries["8"][0] == 2
        assert image.commit_receipt != r1
    with ResearchVolume(p, key, expected_sequence=2) as image:
        assert image.read(7) == _payload(b"C")
        assert image.read(8) == _payload(b"D")


@pytest.mark.parametrize("bad_updates", [
    {},
    {MAX_BLOCKS: _payload(b"A")},
    {-1: _payload(b"A")},
    {True: _payload(b"A")},
    {1: b"short"},
    {1: "wrong type"},
    {1: bytearray(BLOCK_BYTES)},
])
def test_batch_input_prevalidation_has_no_side_effects(tmp_path, bad_updates):
    p, key = tmp_path / "volume.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as image:
        snapshot = p.read_bytes()
        with pytest.raises(VolumeImageError):
            image.write_many(bad_updates)
        assert image.sequence == 0
        assert image.commit_receipt
        assert p.read_bytes() == snapshot
        assert image.write(0, _payload(b"Z")) == 1


def test_failure_before_commit_preserves_entire_previous_batch(tmp_path, monkeypatch):
    p, key = tmp_path / "volume.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as image:
        image.write_many({1: _payload(b"A"), 2: _payload(b"B")})
        old_receipt = image.commit_receipt
        original_frame = image._frame
        def cut(kind, payload):
            if kind == b"C":
                raise OSError("synthetic power loss before commit")
            return original_frame(kind, payload)
        monkeypatch.setattr(image, "_frame", cut)
        with pytest.raises(OSError):
            image.write_many({1: _payload(b"X"), 2: _payload(b"Y"), 3: _payload(b"Z")})
        with pytest.raises(VolumeImageError, match="Uncertain"):
            image.read(1)
        with pytest.raises(VolumeImageError, match="Uncertain"):
            image.write(9, _payload(b"Q"))
    with ResearchVolume(p, key, expected_sequence=1, expected_receipt=old_receipt) as recovered:
        assert recovered.read(1) == _payload(b"A")
        assert recovered.read(2) == _payload(b"B")
        assert recovered.read(3) == bytes(BLOCK_BYTES)


def test_failure_during_second_data_frame_preserves_previous_commit(tmp_path, monkeypatch):
    p, key = tmp_path / "volume.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as image:
        original_frame = image._frame
        count = 0
        def cut(kind, payload):
            nonlocal count
            if kind == b"D":
                count += 1
                if count == 2:
                    raise OSError("synthetic data frame interruption")
            return original_frame(kind, payload)
        monkeypatch.setattr(image, "_frame", cut)
        with pytest.raises(OSError):
            image.write_many({1: _payload(b"A"), 2: _payload(b"B")})
    with ResearchVolume(p, key, expected_sequence=0) as image:
        assert image.read(1) == image.read(2) == bytes(BLOCK_BYTES)


def test_torn_commit_frame_reverts_entire_batch(tmp_path, monkeypatch):
    p, key = tmp_path / "volume.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as image:
        original_frame = image._frame
        def cut(kind, payload):
            if kind == b"C":
                image._f.seek(0, os.SEEK_END)
                # Header advertises a longer commit than was written.
                image._f.write(b"KVF0C" + len(payload).to_bytes(4, "big"))
                image._f.write(payload[:13])
                image._f.flush()
                os.fsync(image._f.fileno())
                raise OSError("interrupted commit frame")
            return original_frame(kind, payload)
        monkeypatch.setattr(image, "_frame", cut)
        with pytest.raises(OSError):
            image.write_many({1: _payload(b"A"), 2: _payload(b"B")})
    with ResearchVolume(p, key, expected_sequence=0) as image:
        assert image.read(1) == bytes(BLOCK_BYTES)
        assert image.read(2) == bytes(BLOCK_BYTES)


def test_external_receipt_detects_old_valid_snapshot_even_same_credential(tmp_path):
    p, key = tmp_path / "volume.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as image:
        image.write(1, _payload(b"A"))
        snapshot = p.read_bytes()
        receipt_one = image.commit_receipt
        image.write(1, _payload(b"B"))
        receipt_two = image.commit_receipt
    assert receipt_one != receipt_two
    p.write_bytes(snapshot)
    with pytest.raises(VolumeImageError, match="receipt mismatch"):
        ResearchVolume(p, key, expected_receipt=receipt_two)
    with ResearchVolume(p, key, expected_receipt=receipt_one) as recovered:
        assert recovered.read(1) == _payload(b"A")
    # External receipt protection/storage is NOT provided by the research code.


def test_reject_untrusted_external_receipt_inputs(tmp_path):
    key = os.urandom(32)
    p = tmp_path / "volume.kvi"
    with ResearchVolume(p, key, create=True):
        pass
    for receipt in ["", "a" * 63, "Z" * 64, "A" * 64, 3, b"x" * 32]:
        with pytest.raises(VolumeImageError):
            ResearchVolume(p, key, expected_receipt=receipt)


@pytest.mark.parametrize("position, payload", [
    (0, b"abc"),
    (BLOCK_BYTES - 2, b"CROSS"),
    (BLOCK_BYTES + 50, b"data"),
    (BLOCK_BYTES * MAX_BLOCKS - 3, b"END"),
])
def test_logical_byte_writes_roundtrip(tmp_path, position, payload):
    p, key = tmp_path / "volume.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as image:
        assert image.write_at(position, payload) == 1
        assert image.read_at(position, len(payload)) == payload
        assert image.read_at(position, 0) == b""
        assert image.read_at(0, 20) == (payload if position == 0 else b"").ljust(20, b"\x00")
        receipt = image.commit_receipt
    with ResearchVolume(p, key, expected_receipt=receipt) as reopened:
        assert reopened.read_at(position, len(payload)) == payload


def test_cross_sector_byte_write_is_single_commit(tmp_path):
    p, key = tmp_path / "volume.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as image:
        image.write(1, _payload(b"X"))
        initial = image.sequence
        assert image.write_at(BLOCK_BYTES * 1 + 4093, b"ABCDEFG") == initial + 1
        assert image.read_at(BLOCK_BYTES * 1 + 4089, 15) == b"XXXXABCDEFG" + bytes(4)
        assert image.entries["1"][0] == 2
        assert image.entries["2"][0] == 1


@pytest.mark.parametrize("position,length", [
    (-1, 1), (0, -1), (MAX_BLOCKS * BLOCK_BYTES + 1, 0),
    (MAX_BLOCKS * BLOCK_BYTES, 1), (True, 1), (0.0, 1),
])
def test_invalid_logical_byte_reads(tmp_path, position, length):
    with ResearchVolume(tmp_path / "v.kvi", os.urandom(32), create=True) as image:
        with pytest.raises(VolumeImageError):
            image.read_at(position, length)


@pytest.mark.parametrize("position,payload", [
    (-1, b"A"), (MAX_BLOCKS * BLOCK_BYTES, b"A"), (0, b""),
    (True, b"A"), (0, "not bytes"),
])
def test_invalid_logical_byte_writes_are_nondestructive(tmp_path, position, payload):
    p = tmp_path / "v.kvi"
    with ResearchVolume(p, os.urandom(32), create=True) as image:
        snapshot = p.read_bytes()
        with pytest.raises(VolumeImageError):
            image.write_at(position, payload)
        assert p.read_bytes() == snapshot


def test_same_sequence_but_different_image_receipt_detects_mismatch(tmp_path):
    key = os.urandom(32)
    a, b = tmp_path / "a.kvi", tmp_path / "b.kvi"
    with ResearchVolume(a, key, create=True) as first:
        first.write(1, _payload(b"A"))
        trusted = first.commit_receipt
    with ResearchVolume(b, key, create=True) as second:
        second.write(1, _payload(b"A"))
        assert second.sequence == 1
    with pytest.raises(VolumeImageError, match="receipt mismatch"):
        ResearchVolume(b, key, expected_sequence=1, expected_receipt=trusted)
