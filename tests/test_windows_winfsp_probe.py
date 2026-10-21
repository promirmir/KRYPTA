"""Dependency probes never require installed WinFsp or touch a real disk."""
from types import SimpleNamespace

import pytest

from research.windows_winfsp_probe import probe_winfsp, require_winfsp, WinFspUnavailable


def test_non_windows_is_fail_closed():
    result = probe_winfsp(platform="posix", loader=lambda _: pytest.fail("must not import"))
    assert not result.available


def test_missing_binding_fails_closed():
    def missing(_):
        raise ImportError("not installed")
    assert not probe_winfsp(platform="nt", loader=missing).available
    with pytest.raises(WinFspUnavailable):
        require_winfsp(platform="nt", loader=missing)


def test_partial_binding_fails_closed():
    result = probe_winfsp(platform="nt", loader=lambda _: SimpleNamespace(FileSystem=object))
    assert not result.available
    assert "Missing required" in result.reason


def test_present_binding_is_not_claimed_as_mount():
    api = SimpleNamespace(FileSystem=object, BaseFileSystemOperations=object,
                          NTStatusAccessDenied=Exception)
    result = require_winfsp(platform="nt", loader=lambda _: api)
    assert result.available
    assert "unverified" in result.reason
