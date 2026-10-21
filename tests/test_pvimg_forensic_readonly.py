"""Disposable-image forensic PVIMG/1 read-only regression suite.

No physical volumes, partitions, actual credentials or system devices.
"""
from __future__ import annotations

import os
import stat

import pytest

from research.paged_volume import (
    BLOCK_BYTES, PagedResearchVolume, PagedVolumeError,
)
from krypta.volume_lab import (
    create_image, verify_image, import_file, export_file, rotate_image,
)

PASS = "A long unique testing passphrase for forensic read-only PVIMG!"
NEW_PASS = "A separate long unique testing passphrase for new PVIMG!"


def _tail(path):
    """Synthetic incomplete record after a fully committed authenticated root."""
    with path.open("ab") as handle:
        handle.write(b"KPG1")  # truncated frame header: not a complete commit
    return path.read_bytes()


def test_read_only_handles_incomplete_tail_without_changing_a_single_byte(tmp_path):
    image, key = tmp_path / "sample.kpv", os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as vol:
        vol.write(5, b"\x19" * BLOCK_BYTES)
        receipt = vol.receipt
    bytes_before = _tail(image)
    with PagedResearchVolume(image, key, expected_receipt=receipt,
                             read_only=True) as reader:
        assert reader.read_only is True
        assert reader._f.readable()
        assert not reader._f.writable()
        assert reader._trim_offset is not None
        assert reader.read(5) == b"\x19" * BLOCK_BYTES
        assert reader.verify_all()["verified_sectors"] == 1
        assert reader.receipt == receipt
        for mutation in (
            lambda: reader.write(5, b"\x01" * BLOCK_BYTES),
            lambda: reader.write_many_atomic_large({3: b"\x07" * BLOCK_BYTES}),
            lambda: reader.write_at(0, b"abc"),
            lambda: reader._flush(),
        ):
            with pytest.raises(PagedVolumeError, match="Read-only"):
                mutation()
    assert image.read_bytes() == bytes_before


def test_read_only_rejects_create_and_non_boolean_flags(tmp_path):
    image, key = tmp_path / "not-created.kpv", os.urandom(32)
    with pytest.raises(PagedVolumeError, match="Read-only"):
        PagedResearchVolume(image, key, create=True, read_only=True)
    assert not image.exists()
    with pytest.raises(PagedVolumeError, match="Read-only"):
        PagedResearchVolume(image, key, read_only=1)
    assert not image.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX advisory lock semantics")
def test_shared_readers_exclude_writer(tmp_path):
    image, key = tmp_path / "concurrent.kpv", os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as writer:
        receipt = writer.receipt
    with PagedResearchVolume(image, key, read_only=True,
                             expected_receipt=receipt) as reader1:
        with PagedResearchVolume(image, key, read_only=True,
                                 expected_receipt=receipt) as reader2:
            assert reader1.receipt == reader2.receipt == receipt
            with pytest.raises((PagedVolumeError, OSError)):
                PagedResearchVolume(image, key, expected_receipt=receipt)


def test_volume_lab_verify_export_and_rotation_preserve_original_crash_tail(tmp_path):
    image = tmp_path / "working.kpv"
    envelope = tmp_path / "password.pvkey"
    recovery = tmp_path / "offline.recovery"
    created = create_image(image, envelope, recovery, PASS, PASS)
    plaintext = tmp_path / "source.txt"
    plaintext.write_bytes(b"forensic-source-content" * 300)
    imported = import_file(image, envelope, created["receipt"],
                           plaintext, password=PASS)
    unchanged = _tail(image)
    check = verify_image(image, envelope, imported["receipt"], password=PASS)
    assert check["files_verified"] == 1
    assert image.read_bytes() == unchanged

    out = tmp_path / "verified-export.txt"
    exported = export_file(image, envelope, imported["receipt"],
                           "source.txt", out, recovery=recovery)
    assert exported["receipt"] == imported["receipt"]
    assert out.read_bytes() == plaintext.read_bytes()
    assert image.read_bytes() == unchanged

    rotated = rotate_image(
        image, envelope, imported["receipt"],
        tmp_path / "migrated.kpv",
        tmp_path / "migrated.pvkey",
        tmp_path / "migrated.recovery",
        NEW_PASS, NEW_PASS, old_recovery=recovery,
    )
    assert rotated["image_id"] != created["image_id"]
    assert image.read_bytes() == unchanged


def test_read_only_posix_file_permission_mode_supported(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX mode bits")
    image, key = tmp_path / "immutable.kpv", os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as vol:
        receipt = vol.receipt
    image.chmod(stat.S_IRUSR)
    try:
        with PagedResearchVolume(image, key, read_only=True,
                                 expected_receipt=receipt) as reader:
            assert reader.verify_all()["sequence"] == 0
            assert not reader._f.writable()
    finally:
        image.chmod(stat.S_IRUSR | stat.S_IWUSR)
