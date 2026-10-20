"""Filesystem-aware PVIMG/PFS migration and failure-injection tests.

No physical disks, keys or user files; all inputs are ephemeral test images.
"""
import os

import pytest

from research.paged_fs import CATALOGUE_SECTORS, PagedFileSystem, PagedFSError
from research.paged_volume import BLOCK_BYTES, PagedResearchVolume, PagedVolumeError


def test_export_keeps_live_files_and_excludes_deleted_sector_records(tmp_path):
    source, target = tmp_path / "source.kpv", tmp_path / "clean.kpv"
    key = os.urandom(32)
    samples = {
        "first": b"A" * (2 * BLOCK_BYTES + 1),
        "unicode-żółty": b"KRYPTA-TEST" * 93,
        "empty": b"",
    }
    with PagedResearchVolume(source, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("first", samples["first"])
        fs.write_file("deleted", b"REMOVED-CONTENT" * 100)
        deleted_sectors = set(fs._files["deleted"]["blocks"])
        fs.delete_file("deleted")
        fs.write_file("unicode-żółty", samples["unicode-żółty"])
        fs.write_file("empty", b"")
        fs.write_file("first", samples["first"][:-1] + b"B", replace=True)
        samples["first"] = samples["first"][:-1] + b"B"
        source_bytes = source.read_bytes()
        receipt = fs.receipt
        result = fs.export_live_files(target)
        assert source.read_bytes() == source_bytes
        assert fs.receipt == receipt
        assert result["source_receipt"] == receipt
        assert result["files_verified"] == len(samples)
        assert result["bytes_verified"] == sum(map(len, samples.values()))
        assert result["source_image_id"] != result["destination_image_id"]
        assert result["source_receipt"] != result["destination_receipt"]
    with PagedResearchVolume(target, key, expected_receipt=result["destination_receipt"]) as new_volume:
        target_fs = PagedFileSystem(new_volume)
        assert target_fs.list_files() == sorted(samples)
        for name, data in samples.items():
            assert target_fs.read_file(name) == data
        assert target_fs.verify_all()["files_verified"] == len(samples)
        used = {index for desc in target_fs._files.values() for index in desc["blocks"]}
        live = set(new_volume._allocated_indices())
        assert live == set(range(CATALOGUE_SECTORS)) | used
        # Deleted records must not be retained merely because the source
        # encrypted-volume index still references the old logical sectors.
        assert len(live) == CATALOGUE_SECTORS + sum(
            (len(data) + BLOCK_BYTES - 1) // BLOCK_BYTES for data in samples.values()
        )
        assert "deleted" not in target_fs.list_files()
    assert target.stat().st_size < source.stat().st_size
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(target, key, expected_receipt=receipt)
    assert deleted_sectors  # The original really had deleted records.


def test_export_of_formatted_empty_filesystem(tmp_path):
    source, target = tmp_path / "zero.kpv", tmp_path / "zero-copy.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(source, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        original = source.read_bytes()
        report = fs.export_live_files(target)
        assert source.read_bytes() == original
        assert report["files_verified"] == 0
    with PagedResearchVolume(target, key, expected_receipt=report["destination_receipt"]) as vol:
        fs = PagedFileSystem(vol)
        assert fs.list_files() == []
        assert vol.sequence == 1


def test_export_refuses_existing_target_or_same_source(tmp_path):
    source, target = tmp_path / "live.kpv", tmp_path / "existing.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(source, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("x", b"not to lose")
        before = source.read_bytes()
        target.write_bytes(b"DO-NOT-OVERWRITE")
        with pytest.raises(PagedVolumeError):
            fs.export_live_files(target)
        assert target.read_bytes() == b"DO-NOT-OVERWRITE"
        with pytest.raises(PagedFSError, match="separate"):
            fs.export_live_files(source)
        assert source.read_bytes() == before


def test_source_corruption_fails_before_creating_target(tmp_path):
    source, target = tmp_path / "corrupted.kpv", tmp_path / "not-created.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(source, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("bad", b"X" * BLOCK_BYTES)
        index = fs._files["bad"]["blocks"][0]
        pos = volume._entry(index)[1] + 30
        with open(source, "r+b") as handle:
            handle.seek(pos)
            value = handle.read(1)
            handle.seek(pos)
            handle.write(bytes([value[0] ^ 1]))
        before = source.read_bytes()
        with pytest.raises(PagedVolumeError):
            fs.export_live_files(target)
        assert not target.exists()
        assert source.read_bytes() == before


def test_destination_failure_removes_only_new_copy(tmp_path, monkeypatch):
    source, target = tmp_path / "source.kpv", tmp_path / "fault.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(source, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("one", b"1" * BLOCK_BYTES)
        fs.write_file("two", b"2" * BLOCK_BYTES)
        source_original = source.read_bytes()
        original = PagedFileSystem.write_file

        def failure(self, name, data, *, replace=False):
            if self._volume.path == target and name == "two":
                raise OSError("synthetic destination failure")
            return original(self, name, data, replace=replace)

        monkeypatch.setattr(PagedFileSystem, "write_file", failure)
        with pytest.raises(OSError, match="synthetic destination"):
            fs.export_live_files(target)
        assert not target.exists()
        assert source.read_bytes() == source_original
        assert fs.read_file("one") == b"1" * BLOCK_BYTES


@pytest.mark.skipif(os.name != "posix", reason="POSIX destination path replacement test")
def test_replaced_destination_inode_is_not_deleted_on_failure(tmp_path, monkeypatch):
    source, target = tmp_path / "source.kpv", tmp_path / "copy.kpv"
    orphan = tmp_path / "moved.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(source, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("one", b"test")
        previous_source = source.read_bytes()
        original = PagedFileSystem.write_file

        def replace_target(self, name, data, *, replace=False):
            if self._volume.path == target:
                original(self, name, data, replace=replace)
                target.rename(orphan)
                target.write_bytes(b"UNRELATED-FILE")
                raise OSError("synthetic destination path replacement")
            return original(self, name, data, replace=replace)

        monkeypatch.setattr(PagedFileSystem, "write_file", replace_target)
        with pytest.raises(OSError, match="synthetic destination"):
            fs.export_live_files(target)
        assert target.read_bytes() == b"UNRELATED-FILE"
        assert orphan.exists()
        assert source.read_bytes() == previous_source


def test_export_wrong_extension_rejected_with_original_intact(tmp_path):
    source, target = tmp_path / "original.kpv", tmp_path / "not-image.img"
    key = os.urandom(32)
    with PagedResearchVolume(source, key, create=True) as vol:
        fs = PagedFileSystem.format(vol)
        before = source.read_bytes()
        with pytest.raises(PagedFSError, match="suffix"):
            fs.export_live_files(target)
        assert source.read_bytes() == before
        assert not target.exists()
