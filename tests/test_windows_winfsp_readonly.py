"""Portable mock checks of real WinFsp-shaped read-only callbacks.

This does not substitute for native WinFsp tests on Windows.
"""
from types import SimpleNamespace
import os
import pytest

from research.paged_volume import PagedResearchVolume
from research.paged_fs2 import PagedFS2
from research.windows_file_ops import WindowsFileOperations
from research.windows_winfsp_readonly import make_readonly_winfsp_operations


class NotFound(Exception):
    pass


class AccessDenied(Exception):
    pass


class WriteProtected(Exception):
    pass


class EndOfFile(Exception):
    pass


class Base:
    pass


def fake_api():
    return SimpleNamespace(
        BaseFileSystemOperations=Base,
        FILE_ATTRIBUTE=SimpleNamespace(FILE_ATTRIBUTE_DIRECTORY=16, FILE_ATTRIBUTE_ARCHIVE=32),
        NTStatusObjectNameNotFound=NotFound,
        NTStatusAccessDenied=AccessDenied,
        NTStatusMediaWriteProtected=WriteProtected,
        NTStatusEndOfFile=EndOfFile,
    )


def test_readonly_winfsp_callbacks_use_authenticated_pfs2(tmp_path):
    image = tmp_path / "sample.kpv"
    with PagedResearchVolume(image, os.urandom(32), create=True) as volume:
        fs = PagedFS2.format(volume)
        ops = WindowsFileOperations(fs)
        ops.create(r"\file.txt")
        ops.write(r"\file.txt", 0, b"sample")
        receipt = fs.receipt
        bridge = make_readonly_winfsp_operations(ops, fake_api())
        root = bridge.open("\\", 0, 0)
        assert bridge.read_directory(root, None)[0]["file_name"] == "file.txt"
        assert bridge.read_directory(root, "file.txt") == []
        assert bridge.get_dir_info_by_name(root, "file.txt")["file_size"] == 6
        with pytest.raises(NotFound):
            bridge.get_dir_info_by_name(root, "missing.txt")
        with pytest.raises(NotFound):
            bridge.get_dir_info_by_name(root, r"..\\other.txt")
        handle = bridge.open(r"\file.txt", 0, 0)
        assert bridge.get_file_info(handle)["file_size"] == 6
        assert bridge.read(handle, 0, 6) == b"sample"
        with pytest.raises(EndOfFile):
            bridge.read(handle, 6, 1)
        with pytest.raises(WriteProtected):
            bridge.write(handle, b"bad", 0, False, False)
        with pytest.raises(AccessDenied):
            bridge.get_security_by_name(r"\file.txt")
        assert fs.receipt == receipt


def test_missing_binding_is_rejected_before_callback_creation(tmp_path):
    image = tmp_path / "sample.kpv"
    with PagedResearchVolume(image, os.urandom(32), create=True) as volume:
        ops = WindowsFileOperations(PagedFS2.format(volume))
        with pytest.raises(RuntimeError, match="Missing WinFsp"):
            make_readonly_winfsp_operations(ops, SimpleNamespace())
