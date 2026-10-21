"""Fail-closed Windows callback contract over disposable PFS/2 images."""
import os
import pytest

from research.paged_volume import PagedResearchVolume
from research.paged_fs2 import PagedFS2
from research.windows_file_ops import WindowsFileOperations
from research.windows_callback_contract import WindowsCallbackContract, UnsupportedWindowsRequest


def test_read_only_callbacks_on_authenticated_image(tmp_path):
    image = tmp_path / "callback.kpv"
    with PagedResearchVolume(image, os.urandom(32), create=True) as vol:
        ops = WindowsFileOperations(PagedFS2.format(vol))
        ops.create(r"\sample.txt")
        ops.write(r"\sample.txt", 0, b"data")
        contract = WindowsCallbackContract(ops)
        before = ops._fs.receipt
        assert contract.dispatch("list_directory") == ["sample.txt"]
        assert contract.dispatch("stat", path=r"\sample.txt")["size"] == 4
        assert contract.dispatch("read", path=r"\sample.txt", offset=0, length=4) == b"data"
        for operation, kwargs in [
            ("write", {"path": r"\sample.txt", "offset": 0, "data": b"x"}),
            ("delete", {"path": r"\sample.txt"}),
            ("mount", {}),
            ("read", {"path": r"\sample.txt"}),
            ("stat", {"path": r"\sample.txt", "unknown": 2}),
        ]:
            with pytest.raises(UnsupportedWindowsRequest):
                contract.dispatch(operation, **kwargs)
        assert ops._fs.receipt == before
        assert ops.read(r"\sample.txt", 0, 4) == b"data"
