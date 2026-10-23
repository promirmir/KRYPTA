"""Authenticated logical sector discard in disposable PAGED-AEAD/2 images.

Never issues filesystem/SSD TRIM, never opens a physical block device.
Root commit failures must preserve the independently pinned old state.
"""
import os

import pytest

from research.paged_aead_v2 import (
    PagedAEADImage, PagedAEADError, SECTOR_BYTES, ZERO,
)

A = b"A" * SECTOR_BYTES
B = b"B" * SECTOR_BYTES
C = b"C" * SECTOR_BYTES


def test_discard_crosses_leaf_boundary_prunes_empty_leaves_and_reopens(tmp_path):
    image_path, key = tmp_path / "trim-cross-page.kdevtest", os.urandom(32)
    with PagedAEADImage.create(image_path, key, physical_sectors=96,
                               logical_sectors=1024) as img:
        img.write_many({0: A, 31: B, 32: C})
        before = img.receipt
        old_cipher_address = img._leaf(1)["0"][0]
        with image_path.open("rb") as physical:
            physical.seek(old_cipher_address * SECTOR_BYTES)
            old_cipher = physical.read(SECTOR_BYTES)
        assert img.trim_many([31, 32]) == 2
        assert img.receipt != before
        assert img.read_sector(31) == ZERO
        assert img.read_sector(32) == ZERO
        assert img.read_sector(0) == A
        assert "1" not in img._root["leaves"]  # leaf 32 was pruned
        assert img.verify_all()["verified_sectors"] == 1
        latest = img.receipt
        # TRIM is logical ONLY; earlier ciphertext is not securely erased.
        with image_path.open("rb") as physical:
            physical.seek(old_cipher_address * SECTOR_BYTES)
            assert physical.read(SECTOR_BYTES) == old_cipher
    with PagedAEADImage.open(
            image_path, key, physical_sectors=96, expected_receipt=latest) as reopened:
        assert reopened.read_sector(0) == A
        assert reopened.read_sector(31) == ZERO
        assert reopened.read_sector(32) == ZERO
        assert reopened.verify_all()["verified_sectors"] == 1
    with pytest.raises(PagedAEADError, match="receipt"):
        PagedAEADImage.open(
            image_path, key, physical_sectors=96, expected_receipt=before)


def test_mixed_write_and_trim_publish_one_root_and_reopen(tmp_path):
    path, key = tmp_path / "mixed.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=80,
                               logical_sectors=1024) as img:
        img.write_many({0: A, 32: B, 64: C})
        assert img.sequence == 1
        assert img.apply_many({0: None, 32: C, 63: A, 64: None}) == 2
        receipt = img.receipt
        assert img.sequence == 2
        assert img.read_sector(0) == ZERO
        assert img.read_sector(32) == C
        assert img.read_sector(63) == A
        assert img.read_sector(64) == ZERO
        assert "0" not in img._root["leaves"]
        assert "2" not in img._root["leaves"]
        assert img.verify_all()["verified_sectors"] == 2
    with PagedAEADImage.open(
            path, key, physical_sectors=80, expected_receipt=receipt) as img:
        assert img.read_sector(0) == ZERO
        assert img.read_at(63 * SECTOR_BYTES, SECTOR_BYTES) == A
        assert img.verify_all()["verified_sectors"] == 2


def test_trim_missing_does_not_consume_quota_or_change_receipt(tmp_path):
    path, key = tmp_path / "no-op.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=32) as img:
        receipt, next_sector = img.receipt, img._root["next"]
        assert img.trim_many([0, 31]) == 0
        assert img.receipt == receipt
        assert img._root["next"] == next_sector
        img.write_sector(0, A)
        updated = img.receipt
        assert img.trim_many([32]) == 1
        assert img.receipt == updated
        assert img.read_sector(0) == A


@pytest.mark.parametrize("bad", [
    [], [0] * 2, [-1], [64], [True], [1.0], ["0"], [0] * 9,
])
def test_invalid_trim_batches_cannot_touch_disk(tmp_path, bad):
    path, key = tmp_path / "invalid-trim.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=32,
                               logical_sectors=64) as img:
        anchor = img.receipt
        source = path.read_bytes()
        with pytest.raises(PagedAEADError):
            img.trim_many(bad)
        assert img.receipt == anchor
        assert path.read_bytes() == source


def test_legacy_write_api_must_not_accept_none(tmp_path):
    path, key = tmp_path / "no-implicit-discard.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=32) as img:
        with pytest.raises(PagedAEADError):
            img.write_many({0: None})
        assert img.sequence == 0
        with pytest.raises(PagedAEADError):
            img.apply_many({0: bytearray(SECTOR_BYTES)})
        assert img.sequence == 0


def test_trim_detects_corruption_before_removing_mapping(tmp_path):
    path, key = tmp_path / "corrupt-trim.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=64) as img:
        img.write_sector(0, A)
        addr = img._leaf(0)["0"][0]
        anchor = img.receipt
    with path.open("r+b") as f:
        f.seek(addr * SECTOR_BYTES)
        original = f.read(1)
        f.seek(addr * SECTOR_BYTES)
        f.write(bytes([original[0] ^ 1]))
    with PagedAEADImage.open(path, key, physical_sectors=64,
                             expected_receipt=anchor, read_only=False) as img:
        with pytest.raises(PagedAEADError, match="authentication"):
            img.trim_many([0])
        with pytest.raises(PagedAEADError, match="Uncertain"):
            img.read_sector(0)
    # Tampering was not hidden by publishing an authenticated trim.
    with PagedAEADImage.open(path, key, physical_sectors=64,
                             expected_receipt=anchor) as img:
        with pytest.raises(PagedAEADError, match="authentication"):
            img.read_sector(0)


def test_trim_root_interruption_preserves_old_receipt_and_data(tmp_path, monkeypatch):
    path, key = tmp_path / "crash-before-root.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=64) as img:
        img.write_many({0: A, 32: B})
        anchor = img.receipt
        native = img._io.write_sector
        def fail_root(index, contents):
            if index in (1, 2):
                raise OSError("injected interrupted root")
            return native(index, contents)
        monkeypatch.setattr(img._io, "write_sector", fail_root)
        with pytest.raises(OSError, match="interrupted root"):
            img.apply_many({0: None, 32: C})
        with pytest.raises(PagedAEADError, match="Uncertain"):
            img.verify_all()
    with PagedAEADImage.open(path, key, physical_sectors=64,
                             expected_receipt=anchor) as recovered:
        assert recovered.read_sector(0) == A
        assert recovered.read_sector(32) == B


def test_trim_root_ack_loss_quarantines_and_rejects_old_receipt(tmp_path, monkeypatch):
    path, key = tmp_path / "crash-after-root.kdevtest", os.urandom(32)
    with PagedAEADImage.create(path, key, physical_sectors=64) as img:
        img.write_sector(0, A)
        anchor = img.receipt
        original_flush = img._io.flush
        flushes = 0
        def lose_second_ack():
            nonlocal flushes
            flushes += 1
            original_flush()
            if flushes == 2:
                raise OSError("synthetic lost root acknowledgment")
        monkeypatch.setattr(img._io, "flush", lose_second_ack)
        with pytest.raises(OSError, match="acknowledgment"):
            img.trim_many([0])
        with pytest.raises(PagedAEADError, match="Uncertain"):
            img.read_sector(0)
    with pytest.raises(PagedAEADError, match="receipt"):
        PagedAEADImage.open(path, key, physical_sectors=64,
                            expected_receipt=anchor)
