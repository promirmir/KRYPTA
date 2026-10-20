"""PVIMG-PFS/1 persistence, atomicity, Linux FUSE callback safety.

All writes target disposable regular .kpv files, never real system devices.
"""
from __future__ import annotations

import errno
import os
import stat
import pytest

from research import linux_fuse
from research.paged_volume import BLOCK_BYTES, PagedResearchVolume, PagedVolumeError
from research.paged_fs import (
    CATALOGUE_SECTORS, MAX_FILE_BYTES, MAX_FILES,
    PagedFileSystem, PagedFSError, FS_MAGIC,
)
from research.linux_fuse import KryptaFuseOps, FuseOSError


@pytest.fixture
def system(tmp_path):
    path, key = tmp_path / "files.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as vol:
        fs = PagedFileSystem.format(vol)
        yield path, key, vol, fs, KryptaFuseOps(fs)


def fails(code, callback, *args):
    with pytest.raises(FuseOSError) as error:
        callback(*args)
    assert error.value.errno == code


def test_formatted_cow_large_file_reopen_and_legacy_separation(tmp_path):
    path, key = tmp_path / "paged.kpv", os.urandom(32)
    large = os.urandom(600 * 1024)  # > 512-KiB older VIMG/0 logical capacity
    with PagedResearchVolume(path, key, create=True) as vol:
        with pytest.raises(PagedFSError, match="not formatted"):
            PagedFileSystem(vol)
        fs = PagedFileSystem.format(vol)
        assert fs.write_file("żółty.bin", large) == 2
        assert fs.read_file("żółty.bin") == large
        assert fs.verify_all()["bytes_verified"] == len(large)
        with pytest.raises(PagedFSError, match="Formatting refused"):
            PagedFileSystem.format(vol)
        receipt = fs.receipt
    assert large[:64] not in path.read_bytes()
    assert b"żółty" not in path.read_bytes()
    assert FS_MAGIC not in path.read_bytes()
    with PagedResearchVolume(path, key, expected_receipt=receipt) as vol:
        fs = PagedFileSystem(vol)
        assert fs.read_file("żółty.bin") == large


def test_fuse_larger_than_old_volume_and_recovery(system):
    path, key, vol, fs, fuse = system
    assert stat.S_ISDIR(fuse.getattr("/")["st_mode"])
    data = b"KRYPTA-DISPOSABLE-" * (35 * 1024)  # > 512 KiB
    fd = fuse.create("/large.dat", 0o600)
    assert fuse.write("/large.dat", data, 0, fd) == len(data)
    assert fuse.read("/large.dat", len(data), 0, fd) == data
    assert fuse.fsync("/large.dat", 0, fd) == 0
    assert fuse.release("/large.dat", fd) == 0
    assert fuse.rename("/large.dat", "/renamed.dat") == 0
    assert fuse.getattr("/renamed.dat")["st_size"] == len(data)
    assert b"large.dat" not in path.read_bytes()
    assert data[:64] not in path.read_bytes()
    receipt = fs.receipt
    # Cannot independently reopen while held (single-writer lock).
    with pytest.raises((PagedVolumeError, OSError)):
        PagedResearchVolume(path, key)
    assert isinstance(receipt, str) and len(receipt) == 64


def test_file_mutations_partial_writes_and_sparse_extension(system):
    _, _, _, fs, fuse = system
    fd = fuse.create("/sparse.txt", 0o600)
    assert fuse.write("/sparse.txt", b"abc", 20, fd) == 3
    assert fuse.read("/sparse.txt", 25, 0, fd) == bytes(20) + b"abc"
    assert fuse.write("/sparse.txt", b"X", 21, fd) == 1
    assert fuse.read("/sparse.txt", 25, 0, fd) == bytes(20) + b"aXc"
    fuse.release("/sparse.txt", fd)
    fh = fuse.open("/sparse.txt", os.O_WRONLY | os.O_APPEND)
    assert fuse.write("/sparse.txt", b"end", 0, fh) == 3
    fuse.release("/sparse.txt", fh)
    assert fs.read_file("sparse.txt") == bytes(20) + b"aXcend"
    assert fuse.unlink("/sparse.txt") == 0
    assert fs.list_files() == []


def test_fuse_permissions_handles_and_unsupported_features(system):
    _, _, _, _, fuse = system
    fh = fuse.create("/handle.txt", 0o600)
    fails(errno.EBADF, fuse.write, "/other.txt", b"oops", 0, fh)
    fails(errno.EBADF, fuse.read, "/handle.txt", 1, 0, fh + 42)
    fails(errno.EBUSY, fuse.unlink, "/handle.txt")
    fails(errno.EBUSY, fuse.rename, "/handle.txt", "/moved.txt")
    fuse.release("/handle.txt", fh)
    for method, args in [
        (fuse.mkdir, ("/subdir", 0o700)),
        (fuse.chmod, ("/handle.txt", 0o777)),
        (fuse.symlink, ("/target", "/link")),
    ]:
        fails(errno.EOPNOTSUPP, method, *args)
    fails(errno.EINVAL, fuse.create, "/CON", 0o600)
    fails(errno.ENOENT, fuse.create, "/nested/file", 0o600)
    assert fuse.getattr("/handle.txt")["st_mode"] & 0o777 == 0o600


def test_no_data_loss_when_invalid_large_write_is_rejected(system):
    image, _, _, fs, fuse = system
    fd = fuse.create("/limited", 0o600)
    fuse.write("/limited", b"preserved", 0, fd)
    before = image.read_bytes()
    receipt = fs.receipt
    fails(errno.EFBIG, fuse.write, "/limited", b"X", MAX_FILE_BYTES, fd)
    assert image.read_bytes() == before
    assert fs.receipt == receipt
    assert fuse.read("/limited", 20, 0, fd) == b"preserved"
    fails(errno.EFBIG, fuse.truncate, "/limited", MAX_FILE_BYTES + 1, fd)
    fuse.release("/limited", fd)


def test_fuse_reports_physical_not_one_gibibyte_space(system):
    _, _, _, _, fuse = system
    stats = fuse.statfs("/")
    assert stats["f_blocks"] < 262144
    assert stats["f_bavail"] <= stats["f_blocks"]
    assert stats["f_files"] == MAX_FILES
    h = fuse.create("/test", 0o600)
    fuse.write("/test", b"Q" * 9000, 0, h)
    assert fuse.statfs("/")["f_bavail"] < stats["f_bavail"]


def test_crash_before_commit_recovers_previous_files(tmp_path, monkeypatch):
    path, key = tmp_path / "crash.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as vol:
        fs = PagedFileSystem.format(vol)
        fs.write_file("stable", b"original")
        receipt = fs.receipt
        raw_append = vol._append
        def fail_commit(kind, payload):
            if kind == b"C":
                raise OSError("synthetic crash before filesystem commit")
            return raw_append(kind, payload)
        monkeypatch.setattr(vol, "_append", fail_commit)
        with pytest.raises(OSError, match="synthetic crash"):
            fs.write_file("stable", b"not committed", replace=True)
        with pytest.raises(PagedVolumeError, match="Uncertain"):
            fs.read_file("stable")
    with PagedResearchVolume(path, key, expected_receipt=receipt) as vol:
        fs = PagedFileSystem(vol)
        assert fs.read_file("stable") == b"original"
        assert fs.verify_all()["files_verified"] == 1


def test_wrong_recovery_receipt_rejected_without_mutation(tmp_path):
    path, key = tmp_path / "rollback.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as vol:
        fs = PagedFileSystem.format(vol)
        fs.write_file("old", b"A")
        old = path.read_bytes()
        fs.write_file("new", b"B")
        later = fs.receipt
    path.write_bytes(old)
    before = path.read_bytes()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(path, key, expected_receipt=later)
    assert path.read_bytes() == before


def test_failed_directory_metadata_quota_no_partial_write(system):
    path, _, _, fs, _ = system
    before = path.read_bytes()
    with pytest.raises(PagedFSError):
        fs.write_file("A" * 97, b"bad")
    assert path.read_bytes() == before


def test_stale_catalogue_does_not_silently_overwrite(system):
    _, _, vol, fs, _ = system
    stale = PagedFileSystem(vol)
    fs.write_file("first", b"one")
    with pytest.raises(PagedFSError, match="Stale"):
        stale.write_file("second", b"two")
    fresh = PagedFileSystem(vol)
    assert fresh.list_files() == ["first"]


def test_empty_file_and_rename_no_plaintext_leak(system):
    path, _, _, fs, _ = system
    assert fs.write_file("empty", b"") == 2
    fs.rename_file("empty", "renamed")
    assert fs.read_file("renamed") == b""
    fs.delete_file("renamed")
    assert fs.list_files() == []
    assert b"renamed" not in path.read_bytes()


@pytest.mark.skipif(os.name != "posix", reason="Linux-only mount policy checks")
def test_opt_in_paged_mount_strict_permissions(system, tmp_path, monkeypatch):
    _, _, vol, _, _ = system
    captures = []
    monkeypatch.setattr(
        linux_fuse, "FUSE",
        lambda ops, folder, **options: captures.append((ops, folder, options)) or 123,
    )
    location = tmp_path / "private"
    location.mkdir(mode=0o700)
    assert linux_fuse.mount_paged_image(vol, str(location)) == 123
    obj, _, opts = captures[0]
    assert isinstance(obj, KryptaFuseOps)
    assert opts["allow_other"] is False and opts["nothreads"] is True
    assert opts["default_permissions"] is True
    original = os.getuid
    monkeypatch.setattr(linux_fuse.os, "getuid", lambda: 0)
    with pytest.raises(PermissionError, match="root"):
        linux_fuse.mount_paged_image(vol, str(location))
    monkeypatch.setattr(linux_fuse.os, "getuid", original)
    location.chmod(0o755)
    with pytest.raises(PermissionError, match="0700"):
        linux_fuse.mount_paged_image(vol, str(location))


def test_unformatted_paged_volume_cannot_be_mounted(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX-only mount policy")
    image, key = tmp_path / "unformatted.kpv", os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as vol:
        folder = tmp_path / "empty"
        folder.mkdir(mode=0o700)
        called = []
        monkeypatch.setattr(linux_fuse, "FUSE",
                            lambda *a, **kw: called.append(kw))
        with pytest.raises(PagedFSError, match="not formatted"):
            linux_fuse.mount_paged_image(vol, str(folder))
        assert not called
