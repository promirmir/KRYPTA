"""Windows-only non-mounting security-gate tests for disposable images."""
import os
import pytest

from research.windows_mount_preflight import (
    WindowsMountPreflightError, validate_windows_mount_request,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-specific preflight")


def test_disposable_regular_image_with_current_receipt(tmp_path):
    image = tmp_path / "test.kpv"
    image.write_bytes(b"synthetic test image; NOT a valid encrypted container")
    mountpoint = tmp_path / "empty"
    mountpoint.mkdir()
    assert validate_windows_mount_request(image, mountpoint, "a" * 64) == (image, mountpoint)


@pytest.mark.parametrize("receipt", ["", "A" * 64, "0" * 63, "z" * 64])
def test_untrusted_receipt_rejected_without_writes(tmp_path, receipt):
    image = tmp_path / "test.kpv"
    image.write_bytes(b"unchanged")
    mountpoint = tmp_path / "empty"
    mountpoint.mkdir()
    with pytest.raises(WindowsMountPreflightError):
        validate_windows_mount_request(image, mountpoint, receipt)
    assert image.read_bytes() == b"unchanged"


def test_nonempty_mountpoint_and_wrong_extension_rejected(tmp_path):
    image = tmp_path / "test.kpv"
    image.write_bytes(b"unchanged")
    mountpoint = tmp_path / "mount"
    mountpoint.mkdir()
    (mountpoint / "existing").write_bytes(b"keep")
    with pytest.raises(WindowsMountPreflightError):
        validate_windows_mount_request(image, mountpoint, "a" * 64)
    (mountpoint / "existing").unlink()
    with pytest.raises(WindowsMountPreflightError):
        validate_windows_mount_request(tmp_path / "missing.img", mountpoint, "a" * 64)
    assert image.read_bytes() == b"unchanged"


def test_reparse_point_in_mount_ancestor_rejected(tmp_path):
    image = tmp_path / "test.kpv"
    image.write_bytes(b"unchanged")
    actual_parent = tmp_path / "real-parent"
    actual_parent.mkdir()
    mountpoint = actual_parent / "empty"
    mountpoint.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        os.symlink(actual_parent, linked_parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Creating directory links is restricted on this Windows runner")
    with pytest.raises(WindowsMountPreflightError, match="Reparse point"):
        validate_windows_mount_request(image, linked_parent / "empty", "a" * 64)
    assert image.read_bytes() == b"unchanged"


def test_reparse_point_in_image_ancestor_rejected(tmp_path):
    real_parent = tmp_path / "images"
    real_parent.mkdir()
    image = real_parent / "test.kpv"
    image.write_bytes(b"unchanged")
    mountpoint = tmp_path / "empty"
    mountpoint.mkdir()
    linked_parent = tmp_path / "linked-images"
    try:
        os.symlink(real_parent, linked_parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Creating directory links is restricted on this Windows runner")
    with pytest.raises(WindowsMountPreflightError, match="Reparse point"):
        validate_windows_mount_request(linked_parent / "test.kpv", mountpoint, "a" * 64)
    assert image.read_bytes() == b"unchanged"
