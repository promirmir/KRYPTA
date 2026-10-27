"""Linux FUSE one-shot staged write regressions. No mount or physical disk."""
from __future__ import annotations

import errno
import os
import tempfile
from pathlib import Path

import pytest

from research.linux_fuse import FuseOSError
from research.linux_fuse_staged_test import OneShotStagedFuseOps, MAX_STAGED_BYTES
from research.paged_fs2 import PagedFS2
from research.paged_volume import PagedResearchVolume, PagedVolumeError
from research.receipt_anchor import pin_trusted_image, ReceiptPinError


@pytest.fixture
def harness():
    with (tempfile.TemporaryDirectory(prefix="krypta-one-shot-fuse-") as d,
          tempfile.TemporaryDirectory(prefix="krypta-external-seal-") as p):
        root, external = Path(d), Path(p)
        image = root / "lab.kpv"
        key = os.urandom(32)
        with PagedResearchVolume(image, key, create=True) as vol:
            fs = PagedFS2.format(vol)
            fs.write_file("sample.txt", b"original")
            trusted = fs.receipt
        pin = external / "initial.kpin"
        sealed = pin_trusted_image(image, key, trusted, pin)
        with PagedResearchVolume(image, key, expected_receipt=trusted) as volume:
            fs = PagedFS2(volume)
            ops = OneShotStagedFuseOps(
                fs, test_root=root, trusted_pin_path=pin,
                independently_trusted_seal=sealed["seal_sha256"]
            )
            yield image, key, fs, volume, ops, pin, sealed, root


def fails(number, callback, *args):
    with pytest.raises(FuseOSError) as exc:
        callback(*args)
    assert exc.value.errno == number


def test_stage_then_abort_preserves_exact_encrypted_file_and_receipt(harness):
    image, key, fs, _, ops, pin, sealed, root = harness
    before, receipt = image.read_bytes(), fs.receipt
    writer = ops.open("/sample.txt", os.O_RDWR)
    assert ops.write("/sample.txt", b"CHANGED", 0, writer) == 7
    assert ops.read("/sample.txt", 8, 0, writer) == b"CHANGEDl"
    assert ops.getattr("/sample.txt", writer)["st_size"] == 8
    other = ops.open("/sample.txt", os.O_RDONLY)
    assert ops.read("/sample.txt", 8, 0, other) == b"original"
    assert image.read_bytes() == before
    fails(errno.EBUSY, ops.open, "/sample.txt", os.O_WRONLY)
    fails(errno.EROFS, ops.unlink, "/sample.txt")
    fails(errno.EROFS, ops.create, "/new.txt", 0o600)
    fails(errno.EROFS, ops.rename, "/sample.txt", "/other.txt")
    fails(errno.EBADF, ops.write, "/sample.txt", b"write", 0, other)
    assert ops.release("/sample.txt", writer) == 0
    assert ops.release("/sample.txt", other) == 0
    assert fs.receipt == receipt
    assert image.read_bytes() == before
    assert ops.observed_receipt_UNTRUSTED is None


def test_flush_authenticates_one_root_and_quarantines_until_new_pin(harness):
    image, key, fs, vol, ops, pin, sealed, root = harness
    previous = fs.receipt
    start = fs.sequence
    writer = ops.open("/sample.txt", os.O_RDWR | os.O_TRUNC)
    assert ops.getattr("/sample.txt", writer)["st_size"] == 0
    assert ops.write("/sample.txt", b"persisted", 0, writer) == 9
    assert fs.receipt == previous
    assert ops.fsync("/sample.txt", 0, writer) == 0
    assert fs.sequence == start + 1
    assert fs.read_file("sample.txt") == b"persisted"
    observed = ops.observed_receipt_UNTRUSTED
    assert observed == fs.receipt and observed != previous
    # Even successfully observed receipt is NOT independently trusted.
    fails(errno.EIO, ops.read, "/sample.txt", 9, 0, writer)
    fails(errno.EIO, ops.getattr, "/sample.txt")
    fails(errno.EIO, ops.readdir, "/", None)
    fails(errno.EIO, ops.statfs, "/")
    fails(errno.EIO, ops.open, "/sample.txt", os.O_RDONLY)
    fails(errno.EIO, ops.write, "/sample.txt", b"again", 0, writer)
    assert ops.release("/sample.txt", writer) == 0
    vol.close()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(image, key, expected_receipt=previous, read_only=True)
    with PagedResearchVolume(image, key, expected_receipt=observed,
                             read_only=True) as reopened:
        assert PagedFS2(reopened).read_file("sample.txt") == b"persisted"
    assert pin.exists()


def test_append_sparse_and_bounded_staging_with_no_immediate_disk_write(harness):
    image, key, fs, _, ops, pin, sealed, root = harness
    before = image.read_bytes()
    writer = ops.open("/sample.txt", os.O_RDWR | os.O_APPEND)
    assert ops.write("/sample.txt", b"END", 0, writer) == 3
    assert ops.read("/sample.txt", 99, 0, writer) == b"originalEND"
    # O_APPEND ignores the provided offset by POSIX design; test the absolute
    # quota with an explicitly non-appending descriptor.
    assert ops.release("/sample.txt", writer) == 0
    writer = ops.open("/sample.txt", os.O_RDWR)
    fails(errno.EFBIG, ops.write, "/sample.txt", b"x", MAX_STAGED_BYTES, writer)
    fails(errno.EFBIG, ops.truncate, "/sample.txt", MAX_STAGED_BYTES + 1, writer)
    fails(errno.EINVAL, ops.write, "/sample.txt", "not bytes", 0, writer)
    fails(errno.EROFS, ops.truncate, "/sample.txt", 0)
    assert image.read_bytes() == before
    assert ops.release("/sample.txt", writer) == 0
    assert fs.read_file("sample.txt") == b"original"


def test_stale_pin_wrong_seal_and_non_disposable_path_rejected(harness):
    image, key, fs, vol, ops, pin, sealed, root = harness
    with pytest.raises(ReceiptPinError, match="seal mismatch"):
        OneShotStagedFuseOps(fs, test_root=root, trusted_pin_path=pin,
                             independently_trusted_seal="0" * 64)
    with pytest.raises(ReceiptPinError, match="temp child"):
        OneShotStagedFuseOps(fs, test_root=root.parent, trusted_pin_path=pin,
                             independently_trusted_seal=sealed["seal_sha256"])
    with pytest.raises(ReceiptPinError, match="receipt"):
        fs.write_file("new.txt", b"independently committed")
        OneShotStagedFuseOps(fs, test_root=root, trusted_pin_path=pin,
                             independently_trusted_seal=sealed["seal_sha256"])


def test_failure_before_root_commit_poisoned_mount_and_old_pin_still_reopens(
        harness, monkeypatch):
    image, key, fs, vol, ops, pin, sealed, root = harness
    old_receipt = fs.receipt
    old_content = fs.read_file("sample.txt")
    writer = ops.open("/sample.txt", os.O_RDWR)
    ops.write("/sample.txt", b"newdata", 0, writer)
    saved = vol._append

    def lose_before_commit(kind, payload):
        if kind == b"C":
            raise OSError("simulated power interruption")
        return saved(kind, payload)

    monkeypatch.setattr(vol, "_append", lose_before_commit)
    fails(errno.EIO, ops.flush, "/sample.txt", writer)
    assert ops.observed_receipt_UNTRUSTED is None
    fails(errno.EIO, ops.readdir, "/", None)
    fails(errno.EIO, ops.open, "/sample.txt", os.O_RDWR)
    assert ops.release("/sample.txt", writer) == 0
    vol.close()
    with PagedResearchVolume(image, key, expected_receipt=old_receipt,
                             read_only=True) as reopened:
        assert PagedFS2(reopened).read_file("sample.txt") == old_content


def test_commit_ack_loss_does_not_silently_promote_new_receipt(
        harness, monkeypatch):
    image, key, fs, vol, ops, pin, sealed, root = harness
    old_receipt = fs.receipt
    writer = ops.open("/sample.txt", os.O_RDWR)
    ops.write("/sample.txt", b"changed", 0, writer)
    old_commit = vol._commit

    def lost_ack(*args):
        old_commit(*args)
        raise OSError("simulated lost commit acknowledgment")

    monkeypatch.setattr(vol, "_commit", lost_ack)
    fails(errno.EIO, ops.fsync, "/sample.txt", False, writer)
    assert ops.observed_receipt_UNTRUSTED is None
    fails(errno.EIO, ops.getattr, "/sample.txt")
    assert ops.release("/sample.txt", writer) == 0
    vol.close()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(image, key, expected_receipt=old_receipt,
                             read_only=True)


def test_noop_flush_and_readonly_mount_path_remain_safe(harness):
    image, key, fs, _, ops, pin, sealed, root = harness
    before = image.read_bytes()
    reader = ops.open("/sample.txt", os.O_RDONLY)
    assert ops.flush("/sample.txt", reader) == 0
    assert ops.release("/sample.txt", reader) == 0
    writer = ops.open("/sample.txt", os.O_RDWR)
    assert ops.flush("/sample.txt", writer) == 0
    assert ops.observed_receipt_UNTRUSTED is None
    assert ops.release("/sample.txt", writer) == 0
    assert fs.list_files() == ["sample.txt"]
    assert image.read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="Linux FUSE requires POSIX")
def test_native_mount_wires_sealed_staging_without_changing_legacy_mount(
        harness, monkeypatch):
    from research import linux_fuse
    image, key, fs, volume, ops, pin, sealed, root = harness
    destination = root / "mount"
    destination.mkdir(mode=0o700)
    passed = []

    def fake_fuse(handler, folder, **options):
        passed.append((handler, options))
        return 333

    monkeypatch.setattr(linux_fuse, "FUSE", fake_fuse)
    result, bridge = linux_fuse.mount_paged_image(
        volume, str(destination), staged_one_shot=True,
        test_root=root, trusted_pin_path=pin,
        independently_trusted_seal=sealed["seal_sha256"]
    )
    assert result == 333
    assert bridge is passed[0][0]
    assert isinstance(bridge, OneShotStagedFuseOps)
    assert passed[0][1]["nothreads"] is True
    assert passed[0][1]["allow_other"] is False
    assert passed[0][1]["default_permissions"] is True
    assert "ro" not in passed[0][1]
    with pytest.raises(ValueError, match="mutually exclusive"):
        linux_fuse.mount_paged_image(
            volume, str(destination), read_only=True, staged_one_shot=True,
            test_root=root, trusted_pin_path=pin,
            independently_trusted_seal=sealed["seal_sha256"]
        )
    with pytest.raises(ValueError, match="pin flags"):
        linux_fuse.mount_paged_image(
            volume, str(destination), trusted_pin_path=pin
        )


def test_explicit_cli_does_not_allow_ambiguous_one_shot_options():
    from research.linux_mount_paged import main
    with pytest.raises(SystemExit):
        main(["--image", "unused.kpv", "--mountpoint", "unused",
              "--key-fd", "7", "--expected-receipt", "0" * 64,
              "--accept-development-risk", "--one-shot-staged-write"])
    with pytest.raises(SystemExit):
        main(["--image", "unused.kpv", "--mountpoint", "unused",
              "--key-fd", "7", "--expected-receipt", "0" * 64,
              "--accept-development-risk", "--trusted-seal", "0" * 64])
