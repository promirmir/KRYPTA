"""Disposable AES-GCM journaled sector tests; no raw physical disk access."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from research.sealed_sector_image import SealedSectorImage, SealedSectorError, SECTOR_BYTES


@pytest.fixture
def opened(tmp_path):
    p, key = tmp_path / "sealed.kdevtest", os.urandom(32)
    with SealedSectorImage.create(p, key, physical_sectors=128, logical_sectors=16) as image:
        yield p, key, image


def test_encrypted_reopen_with_required_external_receipt(opened):
    p, key, image = opened
    first = b"A" * SECTOR_BYTES
    second = b"B" * SECTOR_BYTES
    old = image.receipt
    assert image.write_many({0: first, 15: second}) == 1
    assert image.verify_all()["verified_sectors"] == 2
    assert image.read_sector(0) == first
    assert image.read_sector(15) == second
    receipt = image.receipt
    assert old != receipt
    image.close()  # Windows writer holds an exclusive byte-range lock.
    raw = p.read_bytes()
    assert first not in raw and second not in raw
    image.close()
    with pytest.raises(SealedSectorError, match="receipt"):
        SealedSectorImage.open(p, key, physical_sectors=128, expected_receipt=old)
    with SealedSectorImage.open(p, key, physical_sectors=128, expected_receipt=receipt) as copy:
        assert copy.read_sector(0) == first
        assert copy.read_sector(15) == second
        assert copy.read_sector(1) == bytes(SECTOR_BYTES)
        with pytest.raises(SealedSectorError, match="Read-only"):
            copy.write_sector(2, first)


def test_wrong_master_or_geometry_fails_closed(opened):
    p, key, image = opened
    receipt = image.receipt
    image.close()
    with pytest.raises(SealedSectorError):
        SealedSectorImage.open(p, os.urandom(32), physical_sectors=128,
                               expected_receipt=receipt)
    with pytest.raises(Exception):
        SealedSectorImage.open(p, key, physical_sectors=127, expected_receipt=receipt)
    for invalid in ("", "A" * 64, "f" * 63):
        with pytest.raises(SealedSectorError):
            SealedSectorImage.open(p, key, physical_sectors=128,
                                   expected_receipt=invalid)


def test_cow_updates_leave_original_ciphertext_untouched(opened):
    p, key, image = opened
    image.write_sector(3, b"a" * SECTOR_BYTES)
    anchor = image.receipt
    before = image._io.read_sector(3)  # same locked writer handle
    assert image.write_sector(3, b"b" * SECTOR_BYTES) == 2
    assert image.read_sector(3) == b"b" * SECTOR_BYTES
    assert image._io.read_sector(3) == before
    receipt = image.receipt
    image.close()
    with SealedSectorImage.open(p, key, physical_sectors=128,
                                expected_receipt=receipt) as recovered:
        assert recovered.sequence == 2
        assert recovered.read_sector(3) == b"b" * SECTOR_BYTES
    with pytest.raises(SealedSectorError):
        SealedSectorImage.open(p, key, physical_sectors=128,
                               expected_receipt=anchor)


def test_interrupt_before_root_preserves_old_pinned_state(opened, monkeypatch):
    p, key, image = opened
    image.write_sector(0, b"a" * SECTOR_BYTES)
    old_receipt = image.receipt
    underlying = image._io.write_sector

    def fail_metadata(sector, data):
        if sector in (1, 2):
            raise OSError("simulated interruption before root")
        return underlying(sector, data)

    monkeypatch.setattr(image._io, "write_sector", fail_metadata)
    with pytest.raises(OSError, match="interruption"):
        image.write_many({0: b"b" * SECTOR_BYTES, 1: b"c" * SECTOR_BYTES})
    with pytest.raises(SealedSectorError, match="Uncertain"):
        image.read_sector(0)
    image.close()
    with SealedSectorImage.open(p, key, physical_sectors=128,
                                expected_receipt=old_receipt) as reopened:
        assert reopened.read_sector(0) == b"a" * SECTOR_BYTES
        assert reopened.read_sector(1) == bytes(SECTOR_BYTES)


def test_after_root_flush_ack_failure_never_promotes_old_receipt(opened, monkeypatch):
    p, key, image = opened
    old_receipt = image.receipt
    original = image._io.flush
    calls = 0

    def lost_ack():
        nonlocal calls
        calls += 1
        original()
        if calls == 2:
            raise OSError("ack lost after durable commit")

    monkeypatch.setattr(image._io, "flush", lost_ack)
    with pytest.raises(OSError, match="ack lost"):
        image.write_sector(0, b"x" * SECTOR_BYTES)
    with pytest.raises(SealedSectorError, match="Uncertain"):
        image.read_sector(0)
    image.close()
    with pytest.raises(SealedSectorError, match="receipt"):
        SealedSectorImage.open(p, key, physical_sectors=128,
                               expected_receipt=old_receipt)


def test_ciphertext_tamper_detection_and_quarantine(opened):
    p, key, image = opened
    image.write_sector(7, b"s" * SECTOR_BYTES)
    receipt = image.receipt
    phys = image._state["map"]["7"][0]
    image.close()
    with open(p, "r+b") as f:
        f.seek(phys * SECTOR_BYTES + 17)
        byte = f.read(1)
        f.seek(phys * SECTOR_BYTES + 17)
        f.write(bytes([byte[0] ^ 1]))
    with SealedSectorImage.open(p, key, physical_sectors=128,
                                expected_receipt=receipt) as reopened:
        with pytest.raises(SealedSectorError, match="tampering"):
            reopened.read_sector(7)
        with pytest.raises(SealedSectorError, match="Uncertain"):
            reopened.verify_all()


def test_torn_secondary_metadata_slot_falls_back_only_to_pinned_old(opened):
    p, key, image = opened
    original = image.receipt
    image.close()
    with open(p, "r+b") as f:
        f.seek(SECTOR_BYTES * 2)
        f.write(b"bad" + bytes(40))
    with SealedSectorImage.open(p, key, physical_sectors=128,
                                expected_receipt=original) as reopened:
        assert reopened.sequence == 0
        assert reopened.read_sector(0) == bytes(SECTOR_BYTES)


def test_reject_bad_names_physical_disks_and_missing_receipt(opened):
    p, key, image = opened
    for index in (-1, 16, True, "0"):
        with pytest.raises(SealedSectorError):
            image.read_sector(index)
    with pytest.raises(SealedSectorError):
        image.write_many({0: b"wrong"})
    with pytest.raises(SealedSectorError):
        image.write_many({})
    with pytest.raises(SealedSectorError):
        image.write_many({index: bytes(SECTOR_BYTES) for index in range(9)})
    image.close()  # Allow Windows reader to inspect first sector without writer lock.
    with pytest.raises(SealedSectorError):
        SealedSectorImage.open(p, key, physical_sectors=128,
                               expected_receipt="not a receipt")
    with pytest.raises(Exception):
        SealedSectorImage.create(Path("/dev/sda"), key)


def test_multiple_batches_and_disk_full_no_partial_commit(tmp_path):
    p, key = tmp_path / "tiny.kdevtest", os.urandom(32)
    with SealedSectorImage.create(p, key, physical_sectors=19, logical_sectors=16) as image:
        image.write_many({i: bytes([i + 1]) * SECTOR_BYTES for i in range(8)})
        image.write_many({i: bytes([i + 1]) * SECTOR_BYTES for i in range(8, 16)})
        pinned = image.receipt
        with pytest.raises(SealedSectorError, match="capacity"):
            image.write_sector(0, b"Z" * SECTOR_BYTES)
        assert image.receipt == pinned
        assert image.sequence == 2
        assert image.verify_all()["verified_sectors"] == 16
