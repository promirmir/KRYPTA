"""Paged AEAD metadata v2: encrypted, COW, bounded, isolated file only."""
import os

import pytest

from research.paged_aead_v2 import (
    PagedAEADImage, PagedAEADError, SECTOR_BYTES,
)


def test_exceeds_v1_limit_and_reopens_multi_page_index(tmp_path):
    path, key = tmp_path / "larger.kdevtest", os.urandom(32)
    checks = [0, 31, 32, 63, 64, 511, 991, 1023]
    data = {index: bytes([index % 253 + 1]) * SECTOR_BYTES for index in checks}
    with PagedAEADImage.create(path, key, physical_sectors=128,
                               logical_sectors=1024) as image:
        assert image.write_many(data) == 1
        assert image.logical_sectors == 1024
        assert image.verify_all()["verified_sectors"] == 8
        assert image.read_sector(1000) == bytes(SECTOR_BYTES)
        receipt = image.receipt
    assert all(value not in path.read_bytes() for value in data.values())
    with PagedAEADImage.open(path, key, physical_sectors=128,
                             expected_receipt=receipt) as reopened:
        assert reopened.verify_all()["verified_sectors"] == 8
        for index, value in data.items():
            assert reopened.read_sector(index) == value
        with pytest.raises(PagedAEADError):
            reopened.write_sector(0, data[0])


def test_old_external_receipt_fails_closed_and_no_v1_misinterpretation(tmp_path):
    path, key = tmp_path / "old.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=64,
                               logical_sectors=64) as image:
        old = image.receipt
        image.write_sector(32, b"A" * SECTOR_BYTES)
        receipt = image.receipt
    with pytest.raises(PagedAEADError, match="receipt"):
        PagedAEADImage.open(path, key, physical_sectors=64, expected_receipt=old)
    with pytest.raises(PagedAEADError):
        PagedAEADImage.open(path, os.urandom(32), physical_sectors=64,
                           expected_receipt=receipt)


def test_aborted_root_write_preserves_previous_authenticated_state(tmp_path, monkeypatch):
    path, key = tmp_path / "failed.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=64,
                               logical_sectors=64) as image:
        image.write_many({0: b"A" * SECTOR_BYTES, 32: b"B" * SECTOR_BYTES})
        old = image.receipt
        original = image._io.write_sector

        def reject_root(address, data):
            if address in (1, 2):
                raise OSError("synthetic crash before commit")
            return original(address, data)

        monkeypatch.setattr(image._io, "write_sector", reject_root)
        with pytest.raises(OSError, match="crash"):
            image.write_many({0: b"X" * SECTOR_BYTES, 32: b"Y" * SECTOR_BYTES})
        with pytest.raises(PagedAEADError, match="Uncertain"):
            image.read_sector(0)
    with PagedAEADImage.open(path, key, physical_sectors=64,
                             expected_receipt=old) as recovered:
        assert recovered.read_sector(0) == b"A" * SECTOR_BYTES
        assert recovered.read_sector(32) == b"B" * SECTOR_BYTES


def test_tamper_leaf_is_rejected_and_handle_quarantined(tmp_path):
    path, key = tmp_path / "tamper.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=64) as image:
        image.write_sector(0, b"Q" * SECTOR_BYTES)
        receipt = image.receipt
        physical = image._root["leaves"]["0"][0]
    with open(path, "r+b") as f:
        f.seek(physical * SECTOR_BYTES + 5)
        ch = f.read(1)
        f.seek(physical * SECTOR_BYTES + 5)
        f.write(bytes([ch[0] ^ 1]))
    with PagedAEADImage.open(path, key, physical_sectors=64,
                             expected_receipt=receipt) as image:
        with pytest.raises(PagedAEADError, match="authentication"):
            image.read_sector(0)
        with pytest.raises(PagedAEADError, match="Uncertain"):
            image.verify_all()


def test_reject_overflow_and_preserve_receipt(tmp_path):
    path, key = tmp_path / "limit.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=18) as image:
        anchor = image.receipt
        for invalid in ({}, {0: b"no"}, {1024: bytes(SECTOR_BYTES)},
                        {True: bytes(SECTOR_BYTES)},
                        {i: bytes(SECTOR_BYTES) for i in range(9)}):
            with pytest.raises(PagedAEADError):
                image.write_many(invalid)
            assert image.receipt == anchor
        with pytest.raises(PagedAEADError):
            image.read_sector(-1)


def test_new_v2_does_not_accept_non_scratch_devices(tmp_path):
    with pytest.raises(Exception):
        PagedAEADImage.create("/dev/sda", os.urandom(32))
    with pytest.raises(Exception):
        PagedAEADImage.create(tmp_path / "no.raw", os.urandom(32))


def test_post_root_ack_loss_requires_independent_review(tmp_path, monkeypatch):
    path, key = tmp_path / "uncertain.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=64) as image:
        old = image.receipt
        original = image._io.flush
        count = 0

        def lost_ack():
            nonlocal count
            count += 1
            original()
            if count == 2:
                raise OSError("lost commit ack")

        monkeypatch.setattr(image._io, "flush", lost_ack)
        with pytest.raises(OSError, match="lost commit"):
            image.write_sector(0, b"Z" * SECTOR_BYTES)
        with pytest.raises(PagedAEADError, match="Uncertain"):
            image.read_sector(0)
    with pytest.raises(PagedAEADError, match="receipt"):
        PagedAEADImage.open(path, key, physical_sectors=64,
                           expected_receipt=old)
