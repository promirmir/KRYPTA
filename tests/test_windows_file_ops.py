"""Disposable Windows-style file-IO contract on authenticated PFS/2 images.

Does NOT mount WinFsp or access physical disks.
"""
import os
import pytest

from research.paged_volume import PagedResearchVolume
from research.paged_fs2 import PagedFS2, PagedFS2Error
from research.windows_file_ops import WindowsFileOperations


def test_file_io_reopens_with_authenticated_receipt(tmp_path):
    image = tmp_path / "win-io.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as volume:
        ops = WindowsFileOperations(PagedFS2.format(volume))
        ops.create(r"\hello.bin")
        assert ops.write(r"\hello.bin", 0, b"hello") == 5
        assert ops.write(r"\hello.bin", 1, b"X") == 1
        assert ops.read(r"\hello.bin", 0, 5) == b"hXllo"
        assert ops.list_directory() == ["hello.bin"]
        receipt = ops._fs.receipt
    with PagedResearchVolume(image, key, expected_receipt=receipt) as volume:
        ops = WindowsFileOperations(PagedFS2(volume))
        assert ops.read(r"\hello.bin", 0, 5) == b"hXllo"
        ops.truncate(r"\hello.bin", 2)
        assert ops.read(r"\hello.bin", 0, 10) == b"hX"
        ops.delete(r"\hello.bin")
        assert ops.list_directory() == []


@pytest.mark.parametrize("path", ["file", "/", "\\", r"\one\two", r"\one:stream"])
def test_windows_path_rejections(tmp_path, path):
    image = tmp_path / "bad-path.kpv"
    with PagedResearchVolume(image, os.urandom(32), create=True) as volume:
        ops = WindowsFileOperations(PagedFS2.format(volume))
        with pytest.raises(PagedFS2Error):
            ops.create(path)


def test_out_of_bounds_write_preserves_commit(tmp_path):
    image = tmp_path / "oversized.kpv"
    with PagedResearchVolume(image, os.urandom(32), create=True) as volume:
        ops = WindowsFileOperations(PagedFS2.format(volume))
        ops.create(r"\safe")
        ops.write(r"\safe", 0, b"original")
        receipt = ops._fs.receipt
        with pytest.raises(PagedFS2Error):
            ops.write(r"\safe", ops._fs.max_file_bytes, b"x")
        assert ops._fs.receipt == receipt
        assert ops.read(r"\safe", 0, 8) == b"original"


def test_stat_and_rename_preserve_authenticated_content(tmp_path):
    image = tmp_path / "rename.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as volume:
        ops = WindowsFileOperations(PagedFS2.format(volume))
        ops.create(r"\old.bin")
        ops.write(r"\old.bin", 0, b"secure data")
        assert ops.stat(r"\old.bin")["size"] == len(b"secure data")
        ops.rename(r"\old.bin", r"\new.bin")
        assert ops.read(r"\new.bin", 0, 11) == b"secure data"
        receipt = ops._fs.receipt
    with PagedResearchVolume(image, key, expected_receipt=receipt) as volume:
        ops = WindowsFileOperations(PagedFS2(volume))
        assert ops.list_directory() == ["new.bin"]
        assert ops.read(r"\new.bin", 0, 11) == b"secure data"
