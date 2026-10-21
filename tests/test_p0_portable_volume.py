"""P0 cross-platform regular-file volume compatibility regressions.

This test uses only temporary .kpv images. It never opens a physical device.
Passing on both Windows and Linux verifies format compatibility at the Python
engine boundary, NOT Windows filesystem mounting or safe full-disk encryption.
"""
from __future__ import annotations

import os

import pytest

from research.paged_volume import PagedResearchVolume, PagedVolumeError
from research.paged_fs import PagedFileSystem


@pytest.mark.parametrize("filename,payload", [
    ("portable.txt", b"portable encrypted volume" * 97),
    ("zazolc.txt", bytes(range(256)) * 8),
])
def test_regular_file_volume_reopens_without_data_loss(tmp_path, filename, payload):
    image = tmp_path / "portable.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file(filename, payload)
        receipt = fs.receipt
        assert fs.read_file(filename) == payload
    raw_image = image.read_bytes()
    assert payload[:32] not in raw_image
    assert filename.encode("utf-8") not in raw_image

    with PagedResearchVolume(image, key, expected_receipt=receipt) as volume:
        fs = PagedFileSystem(volume)
        assert fs.read_file(filename) == payload
        assert fs.verify_all()["bytes_verified"] == len(payload)
        assert fs.receipt == receipt


def test_wrong_key_does_not_modify_encrypted_image(tmp_path):
    image = tmp_path / "wrong-key.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("secret", b"preserve this ciphertext" * 40)
    before = image.read_bytes()
    with pytest.raises((PagedVolumeError, ValueError, OSError)):
        with PagedResearchVolume(image, os.urandom(32)) as volume:
            PagedFileSystem(volume)
    assert image.read_bytes() == before
