"""Real on-disk test-file capacity reclamation, no physical devices."""
import os
import pytest
from research.paged_aead_v2 import PagedAEADImage, PagedAEADError, SECTOR_BYTES
from research.paged_aead_compaction import compact_verified_copy


def test_reclaims_exhausted_append_only_image_without_touching_old(tmp_path):
    key = os.urandom(32)
    source, target = tmp_path / "full.kdevtest", tmp_path / "new.kdevtest"
    with PagedAEADImage.create(source, key, physical_sectors=48,
                               logical_sectors=64) as image:
        for i in range(22):
            assert image.write_at(7, bytes([i + 1]) * 100) == 100
        anchor = image.receipt
        original = image.read_at(0, 200)
        with pytest.raises(PagedAEADError, match="capacity"):
            image.write_at(7, b"A" * 100)
    original_disk = source.read_bytes()
    output = compact_verified_copy(
        source, target, key, source_physical_sectors=48,
        expected_source_receipt=anchor)
    assert source.read_bytes() == original_disk
    assert output["target_candidate_receipt"] != anchor
    assert output["live_sectors_verified"] == 1
    assert target.stat().st_size < source.stat().st_size
    with PagedAEADImage.open(source, key, physical_sectors=48,
                             expected_receipt=anchor) as old:
        assert old.read_at(0, 200) == original
    with PagedAEADImage.open(
        target, key, physical_sectors=output["target_physical_sectors"],
        expected_receipt=output["target_candidate_receipt"],
        read_only=False,
    ) as newer:
        assert newer.read_at(0, 200) == original
        assert newer.write_at(7, b"NEW") == 3


def test_multi_leaf_ciphertext_reencrypted_on_fresh_volume(tmp_path):
    key = os.urandom(32)
    source, target = tmp_path / "src.kdevtest", tmp_path / "dst.kdevtest"
    values = {0: b"A" * SECTOR_BYTES, 31: b"B" * SECTOR_BYTES,
              32: b"C" * SECTOR_BYTES, 63: b"D" * SECTOR_BYTES,
              1023: b"E" * SECTOR_BYTES}
    with PagedAEADImage.create(source, key, physical_sectors=128,
                               logical_sectors=1024) as image:
        image.write_many(values)
        anchor = image.receipt
        old_id = image._vid
    result = compact_verified_copy(
        source, target, key, source_physical_sectors=128,
        expected_source_receipt=anchor, target_physical_sectors=64)
    assert result["live_sectors_verified"] == 5
    assert result["target_sequence"] == 3
    with PagedAEADImage.open(target, key, physical_sectors=64,
                             expected_receipt=result["target_candidate_receipt"]) as image:
        assert image._vid != old_id
        assert image.verify_all()["verified_sectors"] == 5
        for i, value in values.items():
            assert image.read_sector(i) == value
        assert image.read_sector(1000) == bytes(SECTOR_BYTES)


def test_wrong_key_receipt_existing_destination_alias_and_short_target(tmp_path):
    key = os.urandom(32)
    source, target = tmp_path / "source.kdevtest", tmp_path / "existing.kdevtest"
    with PagedAEADImage.create(source, key, physical_sectors=64,
                               logical_sectors=64) as image:
        image.write_many({i: bytes([i + 1]) * SECTOR_BYTES for i in range(8)})
        image.write_many({i: bytes([i + 9]) * SECTOR_BYTES for i in range(8, 16)})
        anchor = image.receipt
    target.write_bytes(b"do not overwrite")
    old_source, old_target = source.read_bytes(), target.read_bytes()
    with pytest.raises(Exception):
        compact_verified_copy(source, target, key, source_physical_sectors=64,
                              expected_source_receipt=anchor)
    assert target.read_bytes() == old_target
    for key_arg, receipt, path in (
        (os.urandom(32), anchor, tmp_path / "wrong-key.kdevtest"),
        (key, "0" * 64, tmp_path / "wrong-receipt.kdevtest"),
    ):
        with pytest.raises(PagedAEADError):
            compact_verified_copy(source, path, key_arg, source_physical_sectors=64,
                                  expected_source_receipt=receipt)
        assert not path.exists()
    with pytest.raises(PagedAEADError, match="too small"):
        compact_verified_copy(source, tmp_path / "small.kdevtest", key,
                              source_physical_sectors=64,
                              expected_source_receipt=anchor,
                              target_physical_sectors=16)
    with pytest.raises(PagedAEADError, match="separate"):
        compact_verified_copy(source, source, key,
                              source_physical_sectors=64,
                              expected_source_receipt=anchor)
    assert source.read_bytes() == old_source


def test_corrupt_live_ciphertext_is_never_copied(tmp_path):
    key = os.urandom(32)
    source, target = tmp_path / "damage.kdevtest", tmp_path / "copy.kdevtest"
    with PagedAEADImage.create(source, key, physical_sectors=64) as image:
        image.write_sector(0, b"P" * SECTOR_BYTES)
        anchor = image.receipt
        physical = image._leaf(0)["0"][0]
    with open(source, "r+b") as handle:
        handle.seek(physical * SECTOR_BYTES + 17)
        previous = handle.read(1)
        handle.seek(physical * SECTOR_BYTES + 17)
        handle.write(bytes([previous[0] ^ 1]))
    with pytest.raises(PagedAEADError):
        compact_verified_copy(source, target, key, source_physical_sectors=64,
                              expected_source_receipt=anchor)
    assert not target.exists()


def test_empty_source_produces_new_blank_authenticated_image(tmp_path):
    key = os.urandom(32)
    source, target = tmp_path / "empty.kdevtest", tmp_path / "new.kdevtest"
    with PagedAEADImage.create(source, key, physical_sectors=128,
                               logical_sectors=1024) as image:
        anchor = image.receipt
    result = compact_verified_copy(source, target, key,
                                   source_physical_sectors=128,
                                   expected_source_receipt=anchor)
    assert result["live_sectors_verified"] == 0
    assert result["target_sequence"] == 0
    with PagedAEADImage.open(
        target, key, physical_sectors=result["target_physical_sectors"],
        expected_receipt=result["target_candidate_receipt"],
    ) as image:
        assert image.read_sector(1023) == bytes(SECTOR_BYTES)
