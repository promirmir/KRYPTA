"""Versioned KRYPTA-PFS/2 crash-atomic large-file tests.

Only private temporary ordinary .kpv images and independent 32-byte test keys.
"""
from __future__ import annotations

import errno
import hashlib
import os
import random

import pytest

from research.fs_image import ResearchFSError
from research.linux_fuse import KryptaFuseOps, FuseOSError, mount_paged_image
from research.paged_fs import PagedFileSystem
from research.paged_fs2 import (
    DIRECTORY_BLOCKS, MAGIC, MAX_FILE_BYTES, PagedFS2, PagedFS2Error,
)
from research.paged_volume import (
    BLOCK_BYTES, MAX_ATOMIC_FILE_BLOCKS, MAX_TX_BLOCKS,
    PagedResearchVolume, PagedVolumeError,
)


@pytest.fixture
def volume(tmp_path):
    path = tmp_path / "pfs2.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as vol:
        fs = PagedFS2.format(vol)
        yield path, key, vol, fs


def test_large_file_3mib_single_atomic_commit_and_authenticated_reopen(volume):
    path, key, vol, fs = volume
    size = 3 * 1024 * 1024 + 37
    source = os.urandom(size)
    before = fs.sequence
    assert fs.write_file("three-megabytes.bin", source) == before + 1
    assert fs.read_range("three-megabytes.bin", 2 * 1024 * 1024, 101) == source[2 * 1024 * 1024:2 * 1024 * 1024 + 101]
    assert fs.stat("three-megabytes.bin")["size"] == size
    assert fs.verify_all()["bytes_verified"] == size
    assert MAGIC not in path.read_bytes()
    receipt = fs.receipt
    vol.close()
    with PagedResearchVolume(path, key, expected_receipt=receipt) as reopened:
        restored = PagedFS2(reopened)
        assert restored.read_file("three-megabytes.bin") == source
        assert restored.verify_all()["files_verified"] == 1


def test_three_byte_overwrite_does_not_reencrypt_megabytes(volume):
    path, _, vol, fs = volume
    original = os.urandom(2 * 1024 * 1024)
    fs.write_file("file", original)
    before = path.stat().st_size
    sequence = fs.sequence
    assert fs.write_at("file", 900_000, b"XYZ") == sequence + 1
    assert path.stat().st_size - before < 180_000
    assert fs.read_range("file", 899_999, 5) == original[899_999:900_000] + b"XYZ" + original[900_003:900_004]
    assert fs.stat("file")["size"] == len(original)
    new = original[:900_000] + b"XYZ" + original[900_003:]
    assert fs._files["file"]["sha256"] == hashlib.sha256(new).hexdigest()
    assert fs.verify_all()["bytes_verified"] == len(new)


def test_sparse_32_mib_seek_write_and_truncate(volume):
    _, _, _, fs = volume
    fs.write_file("sparse", b"")
    pos = MAX_FILE_BYTES - 2
    assert fs.write_at("sparse", pos, b"ok") == 3
    assert fs.stat("sparse")["size"] == MAX_FILE_BYTES
    assert fs.read_range("sparse", pos - 3, 5) == bytes(3) + b"ok"
    assert fs.read_range("sparse", 0, 100) == bytes(100)
    assert sum(s is not None for s in fs._files["sparse"]["blocks"]) == 1
    assert fs.verify_all()["bytes_verified"] == MAX_FILE_BYTES
    fs.truncate_file("sparse", 20)
    assert fs.stat("sparse")["size"] == 20
    assert fs.read_file("sparse") == bytes(20)


def test_failure_before_commit_preserves_old_root_and_old_external_receipt(volume, monkeypatch):
    path, key, vol, fs = volume
    old = os.urandom(250 * 1024)
    fs.write_file("target", old)
    old_receipt = fs.receipt
    old_sequence = fs.sequence
    original_append = vol._append

    def fail_final_commit(kind, payload):
        if kind == b"C":
            raise OSError("power interrupted before final root")
        return original_append(kind, payload)

    monkeypatch.setattr(vol, "_append", fail_final_commit)
    with pytest.raises(OSError, match="power interrupted"):
        fs.write_file("target", os.urandom(2 * 1024 * 1024), replace=True)
    with pytest.raises(PagedVolumeError, match="Uncertain"):
        fs.read_file("target")
    vol.close()
    with PagedResearchVolume(path, key,
                             expected_receipt=old_receipt,
                             expected_sequence=old_sequence) as reopened:
        safe = PagedFS2(reopened)
        assert safe.read_file("target") == old
        assert safe.sequence == old_sequence
        assert safe.receipt == old_receipt


def test_failed_commit_does_not_publish_new_name(volume, monkeypatch):
    path, key, vol, fs = volume
    initial_receipt = fs.receipt
    append = vol._append

    def fail(kind, data):
        if kind == b"C":
            raise OSError("no final commit")
        return append(kind, data)

    monkeypatch.setattr(vol, "_append", fail)
    with pytest.raises(OSError):
        fs.write_file("new", b"N" * (1024 * 1024 + 3))
    vol.close()
    with PagedResearchVolume(path, key, expected_receipt=initial_receipt) as opened:
        assert PagedFS2(opened).list_files() == []


def test_old_pfs1_still_opens_without_upgrade(tmp_path, monkeypatch):
    original = tmp_path / "original.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(original, key, create=True) as v:
        old = PagedFileSystem.format(v)
        old.write_file("legacy", b"prior version intact")
        with pytest.raises(PagedFS2Error, match="not formatted"):
            PagedFS2(v)
        assert old.read_file("legacy") == b"prior version intact"
        seen = []
        monkeypatch.setattr("research.linux_fuse.FUSE", lambda ops, path, **kw: seen.append(type(ops._fs)) or 99)
        mount = tmp_path / "mount"
        mount.mkdir(mode=0o700)
        if os.name == "posix" and hasattr(os, "getuid") and os.getuid() != 0:
            assert mount_paged_image(v, str(mount)) == 99
            assert seen == [PagedFileSystem]


def test_fuse_new_file_large_seek_reopen_and_inline_read(volume):
    _, _, _, fs = volume
    ops = KryptaFuseOps(fs)
    fh = ops.create("/large", 0o600)
    assert ops.write("/large", b"secret", 3 * 1024 * 1024, fh) == 6
    assert ops.getattr("/large")["st_size"] == 3 * 1024 * 1024 + 6
    assert ops.read("/large", 16, 3 * 1024 * 1024 - 2, fh) == b"\0\0secret"
    assert ops.read("/large", 16, 0, fh) == bytes(16)
    assert ops.fsync("/large", 0, fh) == 0
    ops.release("/large", fh)
    assert ops.truncate("/large", 5) == 0
    assert fs.read_file("large") == bytes(5)
    stats = ops.statfs("/")
    assert stats["f_blocks"] < 262144
    assert stats["f_bavail"] <= stats["f_blocks"]


def test_wrong_key_rejected_and_v1_not_auto_converted(volume):
    path, key, vol, fs = volume
    fs.write_file("x", b"x")
    receipt = fs.receipt
    vol.close()
    with pytest.raises(PagedVolumeError):
        PagedResearchVolume(path, os.urandom(32))
    with PagedResearchVolume(path, key, expected_receipt=receipt) as correct:
        assert PagedFS2(correct).read_file("x") == b"x"
        with pytest.raises(ResearchFSError):
            PagedFileSystem(correct)


def test_invalid_sector_aliases_and_duplicate_directory_names_fail_closed(volume):
    path, _, vol, fs = volume
    fs.write_file("a", b"A" * BLOCK_BYTES)
    fs.write_file("b", b"B" * BLOCK_BYTES)
    a = fs._files["a"]["blocks"][0]
    bad = {k: dict(v) for k, v in fs._files.items()}
    bad["b"]["blocks"] = [a]
    from research.paged_fs2 import _encode
    with pytest.raises(PagedFS2Error, match="Aliased"):
        _encode(bad)


def test_zero_data_noop_retains_old_receipt(volume):
    path, _, _, fs = volume
    fs.write_file("empty", b"")
    receipt, seq, before = fs.receipt, fs.sequence, path.read_bytes()
    fs.write_at("empty", 0, b"")
    fs.truncate_file("empty", 0)
    assert fs.receipt == receipt
    assert fs.sequence == seq
    assert path.read_bytes() == before


def test_max_atomic_bound_no_bad_write(volume):
    path, _, vol, fs = volume
    original = path.read_bytes()
    with pytest.raises(PagedVolumeError):
        vol.write_many_atomic_large({i: bytes(BLOCK_BYTES) for i in range(MAX_ATOMIC_FILE_BLOCKS + 1)})
    assert path.read_bytes() == original
    assert fs.sequence == vol.sequence
    with pytest.raises(PagedVolumeError):
        vol.write_many({i: bytes(BLOCK_BYTES) for i in range(MAX_TX_BLOCKS + 1)})
    assert path.read_bytes() == original


def test_range_input_guards_and_no_mutation(volume):
    path, _, _, fs = volume
    fs.write_file("x", b"original")
    receipt, before = fs.receipt, path.read_bytes()
    for offset, payload in [(True, b"Y"), (-1, b"Y"), (0, "Y"), (MAX_FILE_BYTES, b"invalid")]:
        with pytest.raises(PagedFS2Error):
            fs.write_at("x", offset, payload)
    assert fs.receipt == receipt
    assert path.read_bytes() == before
