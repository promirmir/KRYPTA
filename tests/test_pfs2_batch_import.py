"""PFS/2 multi-file transaction: only disposable ordinary-file images."""
from __future__ import annotations

import os

import pytest

from krypta.volume_lab import create_image, import_files, verify_image
from research.paged_fs2 import PagedFS2, PagedFS2Error, MAX_FILE_BYTES
from research.paged_volume import PagedResearchVolume, PagedVolumeError


def test_two_files_one_commit_and_independent_receipt(tmp_path):
    image = tmp_path / "batch.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as volume:
        fs = PagedFS2.format(volume)
        old_receipt, sequence = fs.receipt, fs.sequence
        content = {"first.txt": b"first" * 101, "second.bin": b"\0" * 4096 + b"end"}
        assert fs.write_files_atomic(content) == sequence + 1
        assert fs.sequence == sequence + 1
        assert fs.list_files() == sorted(content)
        assert all(fs.read_file(name) == data for name, data in content.items())
        new_receipt = fs.receipt
        assert new_receipt != old_receipt
    with pytest.raises(PagedVolumeError):
        with PagedResearchVolume(image, key, expected_receipt=old_receipt):
            pass
    with PagedResearchVolume(image, key, expected_receipt=new_receipt, read_only=True) as reopened:
        restored = PagedFS2(reopened)
        assert restored.verify_all()["files_verified"] == 2


def test_batch_preflight_rejects_duplicates_sizes_and_existing_before_write(tmp_path):
    image = tmp_path / "batch.kpv"
    with PagedResearchVolume(image, os.urandom(32), create=True) as volume:
        fs = PagedFS2.format(volume)
        start_receipt = fs.receipt
        for invalid in ({}, {"huge.bin": bytes(MAX_FILE_BYTES + 1)},
                        {"x": "not bytes"}, {"bad/name": b"x"}):
            with pytest.raises((PagedFS2Error, ValueError)):
                fs.write_files_atomic(invalid)
            assert fs.receipt == start_receipt
        fs.write_file("already", b"original")
        existing_receipt = fs.receipt
        with pytest.raises(FileExistsError):
            fs.write_files_atomic({"new": b"new", "already": b"overwrite"})
        assert fs.receipt == existing_receipt
        assert fs.list_files() == ["already"]


def test_failed_batch_final_commit_preserves_all_previous_names(tmp_path, monkeypatch):
    image = tmp_path / "batch.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as volume:
        fs = PagedFS2.format(volume)
        fs.write_file("old", b"OLD")
        trusted = fs.receipt
        append = volume._append

        def fail_final(kind, payload):
            if kind == b"C":
                raise OSError("simulated loss before commit")
            return append(kind, payload)

        monkeypatch.setattr(volume, "_append", fail_final)
        with pytest.raises(OSError, match="simulated loss"):
            fs.write_files_atomic({"new1": b"A" * 8000, "new2": b"B" * 9000})
        with pytest.raises(PagedVolumeError, match="Uncertain"):
            fs.list_files()
    with PagedResearchVolume(image, key, expected_receipt=trusted, read_only=True) as reopened:
        fs = PagedFS2(reopened)
        assert fs.list_files() == ["old"]
        assert fs.read_file("old") == b"OLD"


def test_volume_lab_multi_select_one_receipt_and_recovery_unlock(tmp_path):
    image = tmp_path / "demo.kpv"
    envelope = tmp_path / "demo.pvkey"
    recovery = tmp_path / "recovery.secret"
    password = "A sufficiently long test-only passphrase 2026"
    before = create_image(image, envelope, recovery, password, password)
    first = tmp_path / "one.txt"
    second = tmp_path / "two.bin"
    first.write_bytes(b"Test content one")
    second.write_bytes(os.urandom(5010))
    result = import_files(image, envelope, before["receipt"],
                          [first, second], password=password)
    assert result["files_imported"] == 2
    assert result["receipt_changed"] is True
    assert result["bytes_verified"] == first.stat().st_size + second.stat().st_size
    assert result["receipt"] != before["receipt"]
    assert first.read_bytes() == b"Test content one"
    verified = verify_image(image, envelope, result["receipt"], recovery=recovery)
    assert [f["name"] for f in verified["files"]] == ["one.txt", "two.bin"]
    with pytest.raises(Exception):
        verify_image(image, envelope, before["receipt"], recovery=recovery)


def test_volume_lab_multi_select_rejects_name_alias_and_too_many_bytes(tmp_path):
    image = tmp_path / "demo.kpv"
    envelope = tmp_path / "demo.pvkey"
    recovery = tmp_path / "recovery.secret"
    password = "A sufficiently long test-only passphrase 2026"
    original = create_image(image, envelope, recovery, password, password)
    folder = tmp_path / "another"
    folder.mkdir()
    a = tmp_path / "same.bin"
    b = folder / "same.bin"
    a.write_bytes(b"A")
    b.write_bytes(b"B")
    with pytest.raises(ValueError, match="basenames"):
        import_files(image, envelope, original["receipt"], [a, b], password=password)
    with pytest.raises(ValueError, match="distinct"):
        import_files(image, envelope, original["receipt"], [image], password=password)
    huge = tmp_path / "huge.bin"
    with open(huge, "wb") as handle:
        handle.truncate(MAX_FILE_BYTES + 1)
    with pytest.raises(ValueError, match="32-MiB"):
        import_files(image, envelope, original["receipt"], [huge], password=password)
    assert verify_image(image, envelope, original["receipt"], password=password)["files_verified"] == 0
