"""Synthetic FUSE operations tests: no mounting, no /dev/fuse, no real disks.

End-to-end file mutations use the actual authenticated KRYPTA-FS/VIMG/HORIZON
stack on disposable .kvi files, with no external FUSE dependency required.
"""
from __future__ import annotations

import errno
import os
import stat

import pytest

from research import linux_fuse
from research.fs_image import ResearchFileSystem, MAX_FILE_BYTES
from research.volume_image import ResearchVolume
from research.linux_fuse import KryptaFuseOps, FuseOSError


@pytest.fixture
def system(tmp_path):
    image, key = tmp_path / "research.kvi", os.urandom(32)
    with ResearchVolume(image, key, create=True) as vol:
        fs = ResearchFileSystem.format(vol)
        yield image, key, vol, fs, KryptaFuseOps(fs)


def bad(code, method, *args):
    with pytest.raises(FuseOSError) as x:
        method(*args)
    assert x.value.errno == code


def test_readdir_getattr_and_owner_only_modes(system):
    _, _, _, _, ops = system
    directory = ops.getattr("/")
    assert stat.S_ISDIR(directory["st_mode"])
    assert stat.S_IMODE(directory["st_mode"]) == 0o700
    assert ops.readdir("/", 0) == [".", ".."]
    bad(errno.ENOENT, ops.getattr, "/absent")
    bad(errno.ENOTDIR, ops.readdir, "/absent", 0)
    bad(errno.ENOENT, ops.getattr, "/nested/filename")


def test_create_write_reopen_with_encrypted_name_and_data(system):
    image, key, _, _, ops = system
    fh = ops.create("/Zażółć.txt", 0o600)
    assert fh > 0
    assert ops.write("/Zażółć.txt", b"private FAKE data", 0, fh) == 17
    assert ops.read("/Zażółć.txt", 50, 0, fh) == b"private FAKE data"
    assert ops.getattr("/Zażółć.txt")["st_size"] == 17
    assert "Zażółć.txt" in ops.readdir("/", 0)
    assert ops.flush("/Zażółć.txt", fh) == 0
    assert ops.fsync("/Zażółć.txt", 0, fh) == 0
    assert ops.release("/Zażółć.txt", fh) == 0
    ciphertext = image.read_bytes()
    assert b"private FAKE data" not in ciphertext
    assert "Zażółć.txt".encode() not in ciphertext
    # Existing locked volume cannot be opened a second time, so actual
    # reopen is tested by the independent volume suite.


def test_partial_random_writes_and_sparse_extension(system):
    _, _, _, fs, ops = system
    fh = ops.create("/sparse.bin", 0o600)
    ops.write("/sparse.bin", b"xyz", 9, fh)
    assert ops.read("/sparse.bin", 100, 0, fh) == bytes(9) + b"xyz"
    ops.write("/sparse.bin", b"A", 10, fh)
    assert fs.read_file("sparse.bin") == bytes(9) + b"xAz"
    ops.write("/sparse.bin", b"!", 0, fh)
    assert fs.read_file("sparse.bin") == b"!" + bytes(8) + b"xAz"


def test_append_mode_ignores_supplied_write_offset(system):
    _, _, _, fs, ops = system
    fh = ops.create("/append", 0o600)
    ops.write("/append", b"one", 0, fh)
    ops.release("/append", fh)
    appender = ops.open("/append", os.O_WRONLY | os.O_APPEND)
    assert ops.write("/append", b"two", 0, appender) == 3
    assert fs.read_file("append") == b"onetwo"
    bad(errno.EBADF, ops.read, "/append", 1, 0, appender)


def test_open_truncate_and_access_modes(system):
    _, _, _, fs, ops = system
    fd = ops.create("/open", 0o600)
    ops.write("/open", b"abcde", 0, fd)
    ops.release("/open", fd)
    read_only = ops.open("/open", os.O_RDONLY)
    bad(errno.EBADF, ops.write, "/open", b"X", 0, read_only)
    bad(errno.EACCES, ops.truncate, "/open", 0, read_only)
    ops.release("/open", read_only)
    wr = ops.open("/open", os.O_WRONLY | os.O_TRUNC)
    assert fs.read_file("open") == b""
    ops.write("/open", b"new", 0, wr)
    ops.release("/open", wr)
    read = ops.open("/open", os.O_RDONLY)
    assert ops.read("/open", 999, 0, read) == b"new"
    assert ops.read("/open", 999, 999, read) == b""
    ops.release("/open", read)


def test_truncation_to_larger_and_smaller_size(system):
    _, _, _, fs, ops = system
    h = ops.create("/resize", 0o600)
    ops.write("/resize", b"abcde", 0, h)
    ops.truncate("/resize", 11, h)
    assert fs.read_file("resize") == b"abcde" + bytes(6)
    ops.truncate("/resize", 2, h)
    assert fs.read_file("resize") == b"ab"
    bad(errno.EFBIG, ops.truncate, "/resize", MAX_FILE_BYTES + 1, h)


def test_unlink_open_file_rejected_then_permitted(system):
    _, _, _, fs, ops = system
    h = ops.create("/remove", 0o600)
    bad(errno.EBUSY, ops.unlink, "/remove")
    assert ops.release("/remove", h) == 0
    assert ops.unlink("/remove") == 0
    assert fs.list_files() == []
    bad(errno.ENOENT, ops.unlink, "/remove")


def test_rename_open_file_rejected_then_permitted(system):
    _, _, _, fs, ops = system
    h = ops.create("/old", 0o600)
    bad(errno.EBUSY, ops.rename, "/old", "/new")
    ops.release("/old", h)
    assert ops.rename("/old", "/new") == 0
    assert fs.list_files() == ["new"]
    bad(errno.ENOENT, ops.getattr, "/old")
    bad(errno.EEXIST, ops.create, "/new", 0o600)


def test_per_file_quota_refuses_without_data_mutation(system):
    _, _, _, fs, ops = system
    h = ops.create("/limit", 0o600)
    initial = fs.receipt
    bad(errno.EFBIG, ops.write, "/limit", b"A", MAX_FILE_BYTES, h)
    assert fs.receipt == initial
    assert fs.read_file("limit") == b""
    bad(errno.EFBIG, ops.write, "/limit", b"A" * (MAX_FILE_BYTES + 1), 0, h)


def test_invalid_names_and_unsupported_nested_directories(system):
    _, _, _, fs, ops = system
    bad(errno.ENOENT, ops.create, "/parent/child", 0o600)
    bad(errno.EINVAL, ops.create, "/CON", 0o600)
    bad(errno.EINVAL, ops.create, "/trail.", 0o600)
    assert fs.list_files() == []


def test_unsupported_posix_features_fail_closed(system):
    _, _, _, _, ops = system
    for callback, args in [
        (ops.mkdir, ("/subdir", 0o700)),
        (ops.chmod, ("/", 0o777)),
        (ops.chown, ("/", 0, 0)),
        (ops.utimens, ("/", None)),
        (ops.symlink, ("/a", "/b")),
        (ops.link, ("/a", "/b")),
        (ops.setxattr, ("/", "user.x", b"v", 0)),
        (ops.rmdir, ("/x",)),
    ]:
        bad(errno.EOPNOTSUPP, callback, *args)


def test_invalid_handles_cannot_access_files(system):
    _, _, _, _, ops = system
    h = ops.create("/valid", 0o600)
    bad(errno.EBADF, ops.read, "/valid", 1, 0, h+900)
    bad(errno.EBADF, ops.write, "/valid", b"X", 0, h+900)
    bad(errno.EBADF, ops.release, "/valid", h+900)


def test_get_statfs_size_and_usage(system):
    _, _, _, _, ops = system
    start = ops.statfs("/")
    assert start["f_blocks"] == 124
    assert start["f_bavail"] == 124
    assert start["f_ffree"] == 48
    fh = ops.create("/data", 0o600)
    ops.write("/data", b"x" * 5000, 0, fh)
    after = ops.statfs("/")
    assert after["f_bavail"] == 122
    assert after["f_ffree"] == 47


def test_direct_engine_write_causes_stale_fs_error(system):
    _, _, vol, _, ops = system
    h = ops.create("/stale", 0o600)
    vol.write(80, b"Q" * 4096)
    bad(errno.EINVAL, ops.read, "/stale", 10, 0, h)


def test_mounted_write_underlying_crash_propagates_as_eio(system, monkeypatch):
    _, _, volume, fs, ops = system
    h = ops.create("/important-test", 0o600)
    original = volume._frame
    def reject_commit(kind, data):
        if kind == b"C":
            raise OSError("simulated write interruption")
        return original(kind, data)
    monkeypatch.setattr(volume, "_frame", reject_commit)
    bad(errno.EIO, ops.write, "/important-test", b"test", 0, h)
    bad(errno.EIO, ops.read, "/important-test", 100, 0, h)


@pytest.mark.skipif(os.name != "posix", reason="Linux-only research mount gate")
def test_opt_in_mount_requires_empty_owned_directory(system, tmp_path, monkeypatch):
    _, _, vol, fs, _ = system
    calls = []
    def mock_fuse(ops, path, **options):
        calls.append((ops, path, options))
        return "MOCK MOUNT ONLY"
    monkeypatch.setattr(linux_fuse, "FUSE", mock_fuse)
    folder = tmp_path / "mount"
    folder.mkdir()
    assert linux_fuse.mount_research_image(vol, str(folder)) == "MOCK MOUNT ONLY"
    obj, directory, opts = calls[0]
    assert isinstance(obj, KryptaFuseOps)
    assert opts["foreground"] and opts["nothreads"]
    assert opts["allow_other"] is False
    assert opts["default_permissions"] is True
    (folder / "existing").write_bytes(b"do-not-touch")
    with pytest.raises(ValueError):
        linux_fuse.mount_research_image(vol, str(folder))


@pytest.mark.skipif(os.name != "posix", reason="Linux-only research mount gate")
def test_mount_rejects_image_within_mountpoint(system, tmp_path, monkeypatch):
    _, _, vol, _, _ = system
    monkeypatch.setattr(linux_fuse, "FUSE", lambda *a, **k: 0)
    # Even when not actually mounting, reject an image below a mountpoint.
    with pytest.raises(ValueError):
        linux_fuse.mount_research_image(vol, str(tmp_path))
