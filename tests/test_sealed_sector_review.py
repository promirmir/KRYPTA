"""Read-only forensic checks on disposable AES-GCM scratch images."""
from __future__ import annotations

import os

import pytest

from research.sealed_sector_image import SealedSectorImage, SealedSectorError, SECTOR_BYTES
from research.sealed_sector_review import inspect_untrusted_roots


def test_cow_history_review_reads_both_slots_without_mutation(tmp_path):
    p, key = tmp_path / "forensic.kdevtest", os.urandom(32)
    with SealedSectorImage.create(p, key, physical_sectors=128) as image:
        before = image.receipt
        image.write_sector(0, b"New" * (SECTOR_BYTES // 3) + b"\0")
        after = image.receipt
    raw_before = p.read_bytes()
    review = inspect_untrusted_roots(
        p, key, physical_sectors=128, previously_trusted_receipt=before)
    assert review["review_only"] is True
    assert review["write_authorized"] is False
    assert review["trusted_receipt_changed"] is False
    assert "receipt" not in review
    assert review["candidates"][0]["sequence"] == 1
    assert review["candidates"][0]["candidate_receipt_UNTRUSTED"] == after
    assert review["candidates"][0]["all_live_sectors_authenticated"]
    assert review["candidates"][1]["candidate_receipt_UNTRUSTED"] == before
    assert review["candidates"][1]["matches_prior_external_receipt"]
    assert not review["candidates"][0]["matches_prior_external_receipt"]
    assert p.read_bytes() == raw_before


def test_forged_ciphertext_is_detected_not_promoted(tmp_path):
    p, key = tmp_path / "tamper.kdevtest", os.urandom(32)
    with SealedSectorImage.create(p, key, physical_sectors=128) as image:
        image.write_sector(0, b"X" * SECTOR_BYTES)
        phys = image._state["map"]["0"][0]
    with open(p, "r+b") as writer:
        writer.seek(phys * SECTOR_BYTES + 10)
        original = writer.read(1)
        writer.seek(phys * SECTOR_BYTES + 10)
        writer.write(bytes([original[0] ^ 1]))
    before = p.read_bytes()
    review = inspect_untrusted_roots(p, key, physical_sectors=128)
    assert review["candidates"][0]["all_live_sectors_authenticated"] is False
    assert review["candidates"][0]["verified_sector_count"] == 0
    assert review["write_authorized"] is False
    assert p.read_bytes() == before


def test_prior_receipt_is_context_only_not_authorization(tmp_path):
    p, key = tmp_path / "replay.kdevtest", os.urandom(32)
    with SealedSectorImage.create(p, key, physical_sectors=128) as image:
        old = image.receipt
        image.write_sector(1, b"Z" * SECTOR_BYTES)
    report = inspect_untrusted_roots(p, key, physical_sectors=128,
                                     previously_trusted_receipt=old)
    assert report["observed_highest_sequence_UNTRUSTED"] == 1
    assert report["trusted_receipt_changed"] is False
    with pytest.raises(SealedSectorError):
        SealedSectorImage.open(p, key, physical_sectors=128,
                               expected_receipt=old)


def test_wrong_key_invalid_receipt_or_geometry_is_rejected(tmp_path):
    p, key = tmp_path / "invalid.kdevtest", os.urandom(32)
    with SealedSectorImage.create(p, key, physical_sectors=128):
        pass
    with pytest.raises(SealedSectorError):
        inspect_untrusted_roots(p, os.urandom(32), physical_sectors=128)
    with pytest.raises(SealedSectorError):
        inspect_untrusted_roots(p, key, physical_sectors=128,
                                previously_trusted_receipt="incorrect")
    with pytest.raises(Exception):
        inspect_untrusted_roots(p, key, physical_sectors=127)


def test_only_torn_unused_slot_keeps_previous_root_readable(tmp_path):
    p, key = tmp_path / "torn.kdevtest", os.urandom(32)
    with SealedSectorImage.create(p, key, physical_sectors=128) as image:
        pinned = image.receipt
    with open(p, "r+b") as f:
        f.seek(2 * SECTOR_BYTES)
        f.write(b"broken new slot")
    before = p.read_bytes()
    reviewed = inspect_untrusted_roots(
        p, key, physical_sectors=128, previously_trusted_receipt=pinned)
    assert len(reviewed["candidates"]) == 1
    assert reviewed["candidates"][0]["matches_prior_external_receipt"]
    assert p.read_bytes() == before
