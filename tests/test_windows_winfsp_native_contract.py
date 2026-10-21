"""Native Python binding contract test; NOT a kernel mount test.

On Windows this imports real winfspy if available. Missing optional bindings
produce an explicit skip; Linux skips as the driver is Windows-specific.
"""
import os

import pytest

from research.paged_volume import PagedResearchVolume
from research.paged_fs2 import PagedFS2
from research.windows_file_ops import WindowsFileOperations
from research.windows_winfsp_readonly import make_readonly_winfsp_operations


@pytest.mark.skipif(os.name != "nt", reason="WinFsp Windows-only native binding")
def test_real_winfspy_readonly_callback_surface(tmp_path):
    winfspy = pytest.importorskip("winfspy")
    image = tmp_path / "native.kpv"
    with PagedResearchVolume(image, os.urandom(32), create=True) as volume:
        fs = PagedFS2.format(volume)
        ops = WindowsFileOperations(fs)
        ops.create(r"\native.txt")
        ops.write(r"\native.txt", 0, b"test")
        before = fs.receipt
        adapter = make_readonly_winfsp_operations(ops, winfspy)
        handle = adapter.open(r"\native.txt", 0, 0)
        assert adapter.read(handle, 0, 4) == b"test"
        assert adapter.get_file_info(handle)["file_size"] == 4
        assert fs.receipt == before
