"""Non-destructive compact migration and whole-file integrity checks.

Only synthetic .kvi research images are used. No disk driver, partition or
production recovery policy is installed or tested.
"""
from __future__ import annotations

import os

import pytest

from research.fs_image import ResearchFileSystem, ResearchFSError
from research.volume_image import (
    BLOCK_BYTES, DATA_ADDRESS, FRAME, ResearchVolume, VolumeImageError
)


def _image(tmp_path):
    path = tmp_path / "original.kvi"
    key = os.urandom(32)
    volume = ResearchVolume(path, key, create=True)
    fs = ResearchFileSystem.format(volume)
    return path, key, volume, fs


def test_authenticated_copy_reduces_append_only_history_and_preserves_files(tmp_path):
    path, key, volume, fs = _image(tmp_path)
    try:
        fs.write_file("historia.txt", b"first")
        fs.write_file("note.txt", "Zażółć Привет 你好".encode("utf-8"))
        fs.write_file("unused.txt", b"deleted")
        fs.delete_file("unused.txt")
        for i in range(12):
            fs.write_file("historia.txt", (f"version-{i}".encode() * 777), replace=True)
        expected = {name: fs.read_file(name) for name in fs.list_files()}
        original_bytes = path.read_bytes()
        source_seq = volume.sequence
        source_receipt = volume.commit_receipt
        report = fs.verify_all()
        assert report["files_verified"] == 2
        assert report["bytes_verified"] == sum(map(len, expected.values()))
        assert report["sequence"] == source_seq
        assert report["receipt"] == source_receipt
        assert path.read_bytes() == original_bytes  # verification is read-only

        dest = tmp_path / "compacted.kvi"
        migrated = volume.export_compacted_copy(dest)
        assert migrated["source_sequence"] == source_seq
        assert migrated["source_receipt"] == source_receipt
        assert migrated["new_sequence"] == 1
        assert migrated["new_image_id"] != volume.id.hex()
        assert migrated["new_receipt"] != source_receipt
        assert migrated["live_sectors"] >= 4
        assert path.read_bytes() == original_bytes
        assert dest.stat().st_size < path.stat().st_size
        assert b"historia.txt" not in dest.read_bytes()
        assert b"Za\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87" not in dest.read_bytes()
        with ResearchVolume(dest, key, expected_sequence=1,
                            expected_receipt=migrated["new_receipt"]) as new_volume:
            fs_new = ResearchFileSystem(new_volume)
            assert fs_new.list_files() == sorted(expected)
            assert {name: fs_new.read_file(name) for name in fs_new.list_files()} == expected
            assert fs_new.verify_all()["files_verified"] == 2
    finally:
        volume.close()


def test_export_of_empty_genesis_still_is_valid_and_separate(tmp_path):
    path = tmp_path / "empty.kvi"
    key = os.urandom(32)
    with ResearchVolume(path, key, create=True) as v:
        original = path.read_bytes()
        report = v.export_compacted_copy(tmp_path / "empty-copy.kvi")
        assert report["live_sectors"] == 0
        assert report["new_sequence"] == 0
        assert path.read_bytes() == original
    with ResearchVolume(tmp_path / "empty-copy.kvi", key,
                        expected_receipt=report["new_receipt"]) as copy:
        assert copy.read(0) == bytes(BLOCK_BYTES)


def test_existing_destination_never_overwritten(tmp_path):
    path, key, volume, fs = _image(tmp_path)
    dest = tmp_path / "existing.kvi"
    dest.write_bytes(b"existing user data")
    before = dest.read_bytes()
    try:
        with pytest.raises((VolumeImageError, FileExistsError, OSError)):
            volume.export_compacted_copy(dest)
        assert dest.read_bytes() == before
        assert fs.list_files() == []
    finally:
        volume.close()


def test_same_path_is_rejected_without_changes(tmp_path):
    path, key, volume, _ = _image(tmp_path)
    try:
        before = path.read_bytes()
        with pytest.raises(VolumeImageError, match="separate"):
            volume.export_compacted_copy(path)
        assert path.read_bytes() == before
    finally:
        volume.close()


def test_tampered_live_sector_refuses_migration_and_cleans_new_copy(tmp_path):
    path, key, volume, fs = _image(tmp_path)
    fs.write_file("visible", b"test-data")
    # Open volume currently holds exclusive lock. Synthetic fault injection
    # changes ciphertext while open; this deliberately bypasses the API.
    info = volume.entries[str(4)]
    offset = info[1] + FRAME.size + DATA_ADDRESS.size + 10
    with open(path, "r+b") as out:
        out.seek(offset)
        original = out.read(1)
        out.seek(offset)
        out.write(bytes([original[0] ^ 1]))
        out.flush()
        os.fsync(out.fileno())
    damaged_snapshot = path.read_bytes()
    dest = tmp_path / "not-created.kvi"
    try:
        with pytest.raises((VolumeImageError, ResearchFSError)):
            volume.export_compacted_copy(dest)
        assert not dest.exists()
        assert path.read_bytes() == damaged_snapshot
        with pytest.raises(VolumeImageError):
            fs.verify_all()
    finally:
        volume.close()


def test_failed_destination_write_does_not_remove_source(tmp_path, monkeypatch):
    path, key, volume, fs = _image(tmp_path)
    fs.write_file("saved", b"protected research value")
    source = path.read_bytes()
    dest = tmp_path / "failure.kvi"
    original_method = ResearchVolume.write_many
    def break_destination(self, updates):
        if self.path == dest:
            raise OSError("injected destination failure")
        return original_method(self, updates)
    monkeypatch.setattr(ResearchVolume, "write_many", break_destination)
    try:
        with pytest.raises(OSError, match="injected destination failure"):
            volume.export_compacted_copy(dest)
        assert not dest.exists()
        assert path.read_bytes() == source
        assert fs.read_file("saved") == b"protected research value"
    finally:
        volume.close()


def test_verify_all_detects_mutated_active_catalogue_and_files(tmp_path):
    path, key, volume, fs = _image(tmp_path)
    try:
        fs.write_file("hello", b"KRYPTA example")
        initial = path.read_bytes()
        assert fs.verify_all()["files_verified"] == 1
        assert path.read_bytes() == initial
    finally:
        volume.close()


def test_compacted_copy_requires_same_key_not_old_receipt(tmp_path):
    path, key, volume, fs = _image(tmp_path)
    try:
        fs.write_file("data", b"abc")
        old = fs.receipt
        report = volume.export_compacted_copy(tmp_path / "new.kvi")
    finally:
        volume.close()
    with pytest.raises(VolumeImageError, match="receipt mismatch"):
        ResearchVolume(tmp_path / "new.kvi", key, expected_receipt=old)
    with pytest.raises(VolumeImageError):
        ResearchVolume(tmp_path / "new.kvi", os.urandom(32))
    with ResearchVolume(tmp_path / "new.kvi", key,
                        expected_receipt=report["new_receipt"]) as new_volume:
        assert ResearchFileSystem(new_volume).read_file("data") == b"abc"


def test_failed_genesis_discards_only_new_test_image(tmp_path, monkeypatch):
    dest = tmp_path / "bad-genesis.kvi"
    original = ResearchVolume._commit
    def fail_genesis(self, seq, entries):
        if seq == 0:
            raise OSError("simulated crash before authenticated genesis")
        return original(self, seq, entries)
    monkeypatch.setattr(ResearchVolume, "_commit", fail_genesis)
    with pytest.raises(OSError, match="simulated crash"):
        ResearchVolume(dest, os.urandom(32), create=True)
    assert not dest.exists()


def test_failed_creation_does_not_unlink_preexisting_file(tmp_path, monkeypatch):
    dest = tmp_path / "preexisting.kvi"
    dest.write_bytes(b"existing unique data")
    original = dest.read_bytes()
    monkeypatch.setattr(ResearchVolume, "_commit",
                        lambda *args: (_ for _ in ()).throw(AssertionError("must not run")))
    with pytest.raises(VolumeImageError):
        ResearchVolume(dest, os.urandom(32), create=True)
    assert dest.read_bytes() == original
