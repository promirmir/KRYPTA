"""Systematically fail every COW stage; verify pinned state after reopen.

Only disposable local ordinary .kdevtest files; no physical devices.
"""
from __future__ import annotations

import os

import pytest

from research.paged_aead_v2 import PagedAEADImage, PagedAEADError, SECTOR_BYTES


@pytest.mark.parametrize("write_number", [1, 2, 3, 4, 5])
def test_each_interrupted_sector_write_never_promotes_receipt(
        tmp_path, monkeypatch, write_number):
    path, key = tmp_path / f"failure-{write_number}.kdevtest", os.urandom(32)
    with PagedAEADImage.create(
            path, key, physical_sectors=64, logical_sectors=64) as image:
        image.write_many({0: b"0" * SECTOR_BYTES, 32: b"3" * SECTOR_BYTES})
        pinned = image.receipt
        original = image._io.write_sector
        count = 0

        def fail_at_sector(index, data):
            nonlocal count
            count += 1
            if count == write_number:
                raise OSError("injected sector interruption")
            return original(index, data)

        monkeypatch.setattr(image._io, "write_sector", fail_at_sector)
        with pytest.raises(OSError, match="injected sector"):
            image.write_many({0: b"A" * SECTOR_BYTES, 32: b"B" * SECTOR_BYTES})
        with pytest.raises(PagedAEADError, match="Uncertain"):
            image.read_sector(0)
    # Before publishing the new root, the previous root and data must remain
    # readable under EXACTLY the old independently recorded receipt.
    with PagedAEADImage.open(path, key, physical_sectors=64,
                             expected_receipt=pinned) as reopened:
        assert reopened.sequence == 1
        assert reopened.read_sector(0) == b"0" * SECTOR_BYTES
        assert reopened.read_sector(32) == b"3" * SECTOR_BYTES
        assert reopened.verify_all()["verified_sectors"] == 2


def test_failed_staging_flush_preserves_previous_commit(tmp_path, monkeypatch):
    path, key = tmp_path / "flush-data.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=64) as image:
        image.write_sector(0, b"A" * SECTOR_BYTES)
        anchor = image.receipt

        def failed_flush():
            raise OSError("no durable staging flush")

        # Restore the injected flush before the context manager closes its
        # writer; otherwise Windows retries our fake failure during cleanup.
        with monkeypatch.context() as injected:
            injected.setattr(image._io, "flush", failed_flush)
            with pytest.raises(OSError, match="durable"):
                image.write_sector(0, b"B" * SECTOR_BYTES)
            with pytest.raises(PagedAEADError, match="Uncertain"):
                image.read_sector(0)
    with PagedAEADImage.open(path, key, physical_sectors=64,
                             expected_receipt=anchor) as recovered:
        assert recovered.read_sector(0) == b"A" * SECTOR_BYTES


def test_post_commit_ack_loss_does_not_reuse_stale_receipt(tmp_path, monkeypatch):
    path, key = tmp_path / "flush-root.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=64) as image:
        old = image.receipt
        flush = image._io.flush
        count = 0

        def lost_confirmation():
            nonlocal count
            count += 1
            flush()
            if count == 2:
                raise OSError("root durable; acknowledgement lost")

        monkeypatch.setattr(image._io, "flush", lost_confirmation)
        with pytest.raises(OSError, match="acknowledgement lost"):
            image.write_sector(0, b"N" * SECTOR_BYTES)
        with pytest.raises(PagedAEADError, match="Uncertain"):
            image.read_sector(0)
    with pytest.raises(PagedAEADError, match="receipt"):
        PagedAEADImage.open(path, key, physical_sectors=64, expected_receipt=old)


def test_duplicate_data_indices_and_wrong_types_prevent_any_write(tmp_path):
    path, key = tmp_path / "invalid.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=64) as image:
        anchor = image.receipt
        for invalid in ({"0": b"A" * SECTOR_BYTES},
                        {-1: b"A" * SECTOR_BYTES},
                        {0: bytearray(SECTOR_BYTES)},
                        {0: b"A" * (SECTOR_BYTES - 1)}):
            with pytest.raises(PagedAEADError):
                image.write_many(invalid)
            assert image.receipt == anchor
            assert image.sequence == 0
