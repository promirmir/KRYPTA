"""Read-only Linux PFS/2 mount guards: executable fixtures, no physical drives."""
from __future__ import annotations

import errno
import os

import pytest

from research.linux_fuse import KryptaFuseOps, FuseOSError, mount_paged_image
from research.paged_fs2 import PagedFS2
from research.paged_volume import PagedResearchVolume


def make_image(tmp_path):
    image = tmp_path / "private-test.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as volume:
        fs = PagedFS2.format(volume)
        fs.write_file("stored.txt", b"authenticated content")
        receipt = fs.receipt
    return image, key, receipt


def assert_ro(callback, *args):
    with pytest.raises(FuseOSError) as caught:
        callback(*args)
    assert caught.value.errno == errno.EROFS


def test_readonly_callbacks_cannot_modify_ciphertext_or_advance_receipt(tmp_path):
    image, key, receipt = make_image(tmp_path)
    original = image.read_bytes()
    with PagedResearchVolume(image, key, expected_receipt=receipt,
                             read_only=True) as volume:
        fs = PagedFS2(volume)
        ops = KryptaFuseOps(fs, read_only=True)
        fh = ops.open("/stored.txt", os.O_RDONLY)
        assert ops.read("/stored.txt", 128, 0, fh) == b"authenticated content"
        assert ops.flush("/stored.txt", fh) == 0
        assert_ro(ops.open, "/stored.txt", os.O_WRONLY)
        assert_ro(ops.open, "/stored.txt", os.O_RDWR | os.O_TRUNC)
        assert_ro(ops.open, "/stored.txt", os.O_RDONLY | os.O_CREAT)
        assert_ro(ops.create, "/new.txt", 0o600)
        assert_ro(ops.write, "/stored.txt", b"malicious", 0, fh)
        assert_ro(ops.truncate, "/stored.txt", 0, fh)
        assert_ro(ops.unlink, "/stored.txt")
        assert_ro(ops.rename, "/stored.txt", "/other.txt")
        assert ops.statfs("/")["f_bavail"] == 0
        assert ops.release("/stored.txt", fh) == 0
        assert fs.receipt == receipt
    assert image.read_bytes() == original


def test_readonly_mount_requires_matching_volume_descriptor(tmp_path, monkeypatch):
    from research import linux_fuse
    image, key, receipt = make_image(tmp_path)
    mount_dir = tmp_path / "private-mount"
    mount_dir.mkdir(mode=0o700)
    called = []
    monkeypatch.setattr(linux_fuse, "FUSE",
                        lambda operations, folder, **kw: called.append((operations, kw)) or 1)
    with PagedResearchVolume(image, key, expected_receipt=receipt,
                             read_only=True) as volume:
        assert mount_paged_image(volume, str(mount_dir), read_only=True) == 1
        assert called[0][0]._read_only is True
        assert called[0][1]["ro"] is True
        assert called[0][1]["allow_other"] is False
        with pytest.raises(PermissionError, match="mode"):
            mount_paged_image(volume, str(mount_dir), read_only=False)
    with PagedResearchVolume(image, key, expected_receipt=receipt) as writable:
        with pytest.raises(PermissionError, match="mode"):
            mount_paged_image(writable, str(mount_dir), read_only=True)
        with pytest.raises(PermissionError, match="descriptor"):
            KryptaFuseOps(PagedFS2(writable), read_only=True)
    assert len(called) == 1


def test_readonly_cli_opens_image_readonly_and_never_publishes_receipt(tmp_path, monkeypatch):
    from research import linux_mount_paged
    image, key, receipt = make_image(tmp_path)
    mount_dir = tmp_path / "mount"
    mount_dir.mkdir(mode=0o700)
    monkeypatch.setattr(linux_mount_paged.platform, "system", lambda: "Linux")
    monkeypatch.setattr(linux_mount_paged, "read_test_key_fd", lambda fd: key)
    captures = []
    def mount(volume, folder, *, read_only):
        captures.append((volume.read_only, read_only, volume.receipt, folder))
    monkeypatch.setattr(linux_mount_paged, "mount_paged_image", mount)
    args = ["--image", str(image), "--mountpoint", str(mount_dir),
            "--key-fd", "7", "--expected-receipt", receipt,
            "--accept-development-risk", "--read-only"]
    assert linux_mount_paged.main(args) == 0
    assert captures == [(True, True, receipt, str(mount_dir))]
    with pytest.raises(SystemExit):
        linux_mount_paged.main(args + [
            "--final-receipt-out", str(tmp_path / "forbidden.receipt")])
    assert not (tmp_path / "forbidden.receipt").exists()
