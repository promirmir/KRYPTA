"""PVIMG/1 nondestructive compaction and adversarial recovery tests.

Only synthetic .kpv files and ephemeral random test keys. Never physical disks.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from research.paged_volume import (
    BLOCK_BYTES, FANOUT, FRAME, MAX_BLOCKS, MAX_TX_BLOCKS,
    PagedResearchVolume, PagedVolumeError,
)


def payload(value: int) -> bytes:
    return bytes([value]) * BLOCK_BYTES


def test_compaction_preserves_sparse_live_data_and_source_bytes(tmp_path):
    source = tmp_path / "source.kpv"
    destination = tmp_path / "compacted.kpv"
    key = os.urandom(32)
    original = {0: payload(1), 63: payload(2), 64: payload(3),
                4095: payload(4), 4096: payload(5),
                MAX_BLOCKS - 1: payload(6)}
    with PagedResearchVolume(source, key, create=True) as volume:
        volume.write_many(original)
        for n in range(1, 9):
            volume.write(4096, payload(n + 20))
        original[4096] = payload(28)
        before = source.read_bytes()
        source_receipt = volume.receipt
        source_sequence = volume.sequence
        report = volume.export_compacted_copy(destination)
        assert source.read_bytes() == before
        assert volume.receipt == source_receipt
        assert volume.sequence == source_sequence
        assert report["source_receipt"] == source_receipt
        assert report["sectors_verified"] == len(original)
        assert report["source_image_id"] != report["destination_image_id"]
        assert report["source_receipt"] != report["destination_receipt"]
        assert destination.stat().st_size < source.stat().st_size
        # The original has not been closed or mutated by exporting.
        for idx, value in original.items():
            assert volume.read(idx) == value
    with PagedResearchVolume(destination, key,
                             expected_receipt=report["destination_receipt"]) as compact:
        for idx, value in original.items():
            assert compact.read(idx) == value
        assert compact.read(65) == bytes(BLOCK_BYTES)
        assert compact.verify_all()["verified_sectors"] == len(original)
        assert compact.sequence == report["destination_sequence"]
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(destination, key, expected_receipt=source_receipt)


def test_compaction_of_empty_sparse_volume(tmp_path):
    key = os.urandom(32)
    source, target = tmp_path / "empty.kpv", tmp_path / "new.kpv"
    with PagedResearchVolume(source, key, create=True) as volume:
        old = source.read_bytes()
        report = volume.export_compacted_copy(target)
        assert source.read_bytes() == old
        assert report["sectors_verified"] == 0
        assert report["destination_sequence"] == 0
    with PagedResearchVolume(target, key,
                             expected_receipt=report["destination_receipt"]) as reopened:
        assert reopened.verify_all()["verified_sectors"] == 0
        assert reopened.read(MAX_BLOCKS - 1) == bytes(BLOCK_BYTES)


def test_destination_exists_never_overwritten(tmp_path):
    key = os.urandom(32)
    source, target = tmp_path / "src.kpv", tmp_path / "exists.kpv"
    with PagedResearchVolume(source, key, create=True) as volume:
        volume.write(9, payload(9))
        initial_source = source.read_bytes()
        target.write_bytes(b"OWNER-ORIGINAL-DATA")
        with pytest.raises(PagedVolumeError):
            volume.export_compacted_copy(target)
        assert target.read_bytes() == b"OWNER-ORIGINAL-DATA"
        assert source.read_bytes() == initial_source


def test_refuses_same_source_path_without_side_effects(tmp_path):
    key = os.urandom(32)
    source = tmp_path / "same.kpv"
    with PagedResearchVolume(source, key, create=True) as volume:
        before = source.read_bytes()
        with pytest.raises(PagedVolumeError, match="must differ"):
            volume.export_compacted_copy(source)
        assert source.read_bytes() == before


def test_corrupted_source_is_rejected_before_new_file_is_created(tmp_path):
    key = os.urandom(32)
    source, target = tmp_path / "damaged.kpv", tmp_path / "not-created.kpv"
    with PagedResearchVolume(source, key, create=True) as volume:
        volume.write(2, payload(11))
        pos = volume._entry(2)[1] + FRAME.size + 25
        with open(source, "r+b") as handle:
            handle.seek(pos)
            b = handle.read(1)
            handle.seek(pos)
            handle.write(bytes([b[0] ^ 0x40]))
            handle.flush()
            os.fsync(handle.fileno())
        before = source.read_bytes()
        with pytest.raises(PagedVolumeError, match="tampering"):
            volume.export_compacted_copy(target)
        assert not target.exists()
        assert source.read_bytes() == before


def test_failed_destination_write_cleans_only_new_copy(tmp_path, monkeypatch):
    key = os.urandom(32)
    source, target = tmp_path / "source.kpv", tmp_path / "failed.kpv"
    with PagedResearchVolume(source, key, create=True) as volume:
        volume.write_many({5: payload(1), MAX_BLOCKS - 1: payload(2)})
        source_snapshot = source.read_bytes()
        true_write = PagedResearchVolume.write_many

        def fail_only_target(self, changes):
            if self.path == target:
                # Produce a valid first commit, then simulate later failure.
                true_write(self, changes)
                raise OSError("synthetic destination crash after data")
            return true_write(self, changes)

        monkeypatch.setattr(PagedResearchVolume, "write_many", fail_only_target)
        with pytest.raises(OSError, match="synthetic destination crash"):
            volume.export_compacted_copy(target)
        assert not target.exists()
        assert source.read_bytes() == source_snapshot
        assert volume.read(5) == payload(1)


@pytest.mark.skipif(os.name != "posix", reason="Test requires atomic POSIX path swap")
def test_destination_path_swap_is_never_deleted_on_failure(tmp_path, monkeypatch):
    key = os.urandom(32)
    source, target = tmp_path / "source.kpv", tmp_path / "target.kpv"
    moved, outsider = tmp_path / "new-inode.kpv", b"UNRELATED-USER-FILE"
    with PagedResearchVolume(source, key, create=True) as volume:
        volume.write(7, payload(7))
        before = source.read_bytes()
        original_write = PagedResearchVolume.write_many

        def fail_after_target_swap(self, changes):
            if self.path == target:
                original_write(self, changes)
                target.rename(moved)
                target.write_bytes(outsider)
                raise OSError("synthetic replacement during copy")
            return original_write(self, changes)

        monkeypatch.setattr(PagedResearchVolume, "write_many", fail_after_target_swap)
        with pytest.raises(OSError, match="synthetic replacement"):
            volume.export_compacted_copy(target)
        # Never delete a different user's replacement path.
        assert target.read_bytes() == outsider
        assert moved.exists()
        assert source.read_bytes() == before


def test_unaligned_bounded_read_crossing_257_sectors_is_rejected(tmp_path):
    key = os.urandom(32)
    source = tmp_path / "readbounds.kpv"
    with PagedResearchVolume(source, key, create=True) as volume:
        original = source.read_bytes()
        with pytest.raises(PagedVolumeError, match="spans too many"):
            volume.read_at(1, MAX_TX_BLOCKS * BLOCK_BYTES)
        assert source.read_bytes() == original
        assert len(volume.read_at(1, MAX_TX_BLOCKS * BLOCK_BYTES - 1)) == MAX_TX_BLOCKS * BLOCK_BYTES - 1


def test_compaction_fails_closed_with_bad_source_handle(tmp_path):
    key = os.urandom(32)
    source, target = tmp_path / "close.kpv", tmp_path / "unused.kpv"
    volume = PagedResearchVolume(source, key, create=True)
    volume.close()
    with pytest.raises(PagedVolumeError, match="Closed"):
        volume.export_compacted_copy(target)
    assert not target.exists()


def test_compacted_copy_recovers_and_new_writes_use_fresh_sector_generations(tmp_path):
    key = os.urandom(32)
    source, target = tmp_path / "source.kpv", tmp_path / "copy.kpv"
    with PagedResearchVolume(source, key, create=True) as volume:
        for i in range(5):
            volume.write(17, payload(i + 1))
        old_generation = volume._entry(17)[0]
        report = volume.export_compacted_copy(target)
        assert old_generation == 5
    with PagedResearchVolume(target, key,
                             expected_receipt=report["destination_receipt"]) as compact:
        assert compact._entry(17)[0] == 1
        assert compact.write_at(17 * BLOCK_BYTES + 2, b"ok") == 2
        assert compact._entry(17)[0] == 2
        assert compact.read(17)[2:4] == b"ok"


def test_compaction_failure_on_wrong_target_extension_keeps_source(tmp_path):
    key = os.urandom(32)
    source = tmp_path / "vol.kpv"
    with PagedResearchVolume(source, key, create=True) as vol:
        vol.write(1, payload(1))
        before = source.read_bytes()
        with pytest.raises(PagedVolumeError, match="separate"):
            vol.export_compacted_copy(tmp_path / "out.img")
        assert source.read_bytes() == before
