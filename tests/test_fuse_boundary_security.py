"""FUSE boundary regression tests: do not let a handle authorize another file.

Runs purely on disposable KRYPTA research images. Never touches /dev/fuse,
mounts a real filesystem, formats a disk or handles user-secret material.
"""
from __future__ import annotations

import errno
import os
import stat

import pytest

from research.fs_image import ResearchFileSystem
from research.linux_fuse import FuseOSError, KryptaFuseOps
from research.volume_image import ResearchVolume


@pytest.fixture
def fs_fixture(tmp_path):
    image = tmp_path / "adversarial.kvi"
    key = os.urandom(32)
    with ResearchVolume(image, key, create=True) as vol:
        engine = ResearchFileSystem.format(vol)
        ops = KryptaFuseOps(engine)
        yield engine, ops


def expect_err(number, callback, *args):
    with pytest.raises(FuseOSError) as e:
        callback(*args)
    assert e.value.errno == number


def test_handle_cannot_read_or_write_another_existing_path(fs_fixture):
    fs, ops = fs_fixture
    first = ops.create("/alice", 0o600)
    ops.write("/alice", b"AAA", 0, first)
    second = ops.create("/bob", 0o600)
    ops.write("/bob", b"BBB", 0, second)
    old_receipt = fs.receipt

    expect_err(errno.EBADF, ops.read, "/bob", 3, 0, first)
    expect_err(errno.EBADF, ops.read, "/alice", 3, 0, second)
    expect_err(errno.EBADF, ops.write, "/bob", b"ATTACK", 0, first)
    expect_err(errno.EBADF, ops.write, "/alice", b"ATTACK", 0, second)
    expect_err(errno.EBADF, ops.flush, "/bob", first)
    expect_err(errno.EBADF, ops.fsync, "/bob", 0, first)
    expect_err(errno.EBADF, ops.release, "/bob", first)
    expect_err(errno.EBADF, ops.truncate, "/bob", 0, first)

    assert fs.receipt == old_receipt
    assert fs.read_file("alice") == b"AAA"
    assert fs.read_file("bob") == b"BBB"
    assert ops.release("/alice", first) == 0
    assert ops.release("/bob", second) == 0


def test_existing_file_exclusive_open_does_not_truncate(fs_fixture):
    fs, ops = fs_fixture
    handle = ops.create("/existing", 0o600)
    ops.write("/existing", b"do-not-clobber", 0, handle)
    ops.release("/existing", handle)
    receipt = fs.receipt
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_TRUNC
    expect_err(errno.EEXIST, ops.open, "/existing", flags)
    assert fs.receipt == receipt
    assert fs.read_file("existing") == b"do-not-clobber"


def test_unsupported_linux_file_modes_fail_closed(fs_fixture):
    fs, ops = fs_fixture
    h = ops.create("/test", 0o600)
    ops.release("/test", h)
    receipt = fs.receipt
    for flag_name in ("O_PATH", "O_TMPFILE", "O_DIRECTORY"):
        flag = getattr(os, flag_name, None)
        if flag:
            expect_err(errno.EOPNOTSUPP, ops.open, "/test", flag)
    assert fs.receipt == receipt


def test_invalid_creation_filetype_cannot_create(fs_fixture):
    fs, ops = fs_fixture
    old = fs.receipt
    expect_err(errno.EOPNOTSUPP, ops.create, "/named-pipe", stat.S_IFIFO | 0o600)
    expect_err(errno.EOPNOTSUPP, ops.create, "/directory", stat.S_IFDIR | 0o700)
    expect_err(errno.EINVAL, ops.create, "/negative", -1)
    assert fs.receipt == old
    assert fs.list_files() == []


def test_bad_handle_name_mismatch_rejected_without_touching_fs(fs_fixture):
    fs, ops = fs_fixture
    handle = ops.create("/test", 0o600)
    before = fs.receipt
    expect_err(errno.EBADF, ops.read, "/non-existent", 5, 0, handle)
    expect_err(errno.EBADF, ops.write, "/non-existent", b"new", 0, handle)
    expect_err(errno.EBADF, ops.release, "/non-existent", handle)
    assert fs.receipt == before
    assert ops.read("/test", 5, 0, handle) == b""
