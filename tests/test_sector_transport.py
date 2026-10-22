"""Disposable sector-transport contract tests; no physical device is used."""
from __future__ import annotations

import os

import pytest

from research.test_sector_transport import (
    MAX_TEST_SECTORS, SECTOR_BYTES, SectorTransportError,
    TestSectorTransport,
)


def test_boundary_sectors_and_durable_reopen(tmp_path):
    path = tmp_path / "synthetic.kdevtest"
    first, last = b"A" * SECTOR_BYTES, b"Z" * SECTOR_BYTES
    with TestSectorTransport(path, 16, create=True) as io:
        assert io.read_sector(0) == bytes(SECTOR_BYTES)
        io.write_sector(0, first)
        io.write_sector(15, last)
        io.flush()
        assert io.read_sector(0) == first
        assert io.read_sector(15) == last
    with TestSectorTransport(path, 16, read_only=True) as io:
        assert io.read_sector(0) == first
        assert io.read_sector(15) == last
        with pytest.raises(SectorTransportError, match="Read-only"):
            io.write_sector(2, first)


@pytest.mark.parametrize("sector", [-1, 16, 10**100, True, "0"])
def test_outside_address_never_changes_scratch_file(tmp_path, sector):
    path = tmp_path / "limits.kdevtest"
    with TestSectorTransport(path, 16, create=True) as io:
        before = path.stat().st_size
        with pytest.raises(SectorTransportError):
            io.write_sector(sector, bytes(SECTOR_BYTES))
        assert path.stat().st_size == before


@pytest.mark.parametrize("payload", [b"", b"A", bytes(SECTOR_BYTES + 1), "not bytes"])
def test_partial_sector_write_rejected(tmp_path, payload):
    with TestSectorTransport(tmp_path / "payload.kdevtest", 16, create=True) as io:
        with pytest.raises(SectorTransportError, match="4096"):
            io.write_sector(0, payload)
        assert io.read_sector(0) == bytes(SECTOR_BYTES)


def test_no_existing_file_overwrite_or_wrong_geometry(tmp_path):
    path = tmp_path / "created.kdevtest"
    with TestSectorTransport(path, 16, create=True):
        with pytest.raises(FileExistsError):
            TestSectorTransport(path, 16, create=True)
    with pytest.raises(SectorTransportError, match="size"):
        TestSectorTransport(path, 17)


def test_reject_symlink_hardlink_and_nonregular(tmp_path):
    path = tmp_path / "ordinary.kdevtest"
    with TestSectorTransport(path, 16, create=True):
        pass
    alias = tmp_path / "alias.kdevtest"
    try:
        alias.symlink_to(path)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unsupported")
    with pytest.raises(SectorTransportError):
        TestSectorTransport(alias, 16)
    hard = tmp_path / "hard.kdevtest"
    try:
        os.link(path, hard)
    except (OSError, NotImplementedError):
        pytest.skip("Hardlinks unsupported")
    with pytest.raises(SectorTransportError):
        TestSectorTransport(path, 16)
    with pytest.raises(SectorTransportError):
        TestSectorTransport(tmp_path / "dev-null", 16, create=True)


def test_fails_closed_after_unexpected_resize(tmp_path):
    path = tmp_path / "resized.kdevtest"
    with TestSectorTransport(path, 16, create=True) as io:
        os.truncate(path, 17 * SECTOR_BYTES)
        with pytest.raises(SectorTransportError, match="resized"):
            io.read_sector(0)
        with pytest.raises(SectorTransportError, match="Uncertain"):
            io.write_sector(0, bytes(SECTOR_BYTES))


def test_fails_closed_after_failed_fsync(tmp_path, monkeypatch):
    path = tmp_path / "flush.kdevtest"
    with TestSectorTransport(path, 16, create=True) as io:
        io.write_sector(0, b"K" * SECTOR_BYTES)
        original = os.fsync
        def fail(fd):
            if fd == io._fd:
                raise OSError("synthetic fsync failure")
            return original(fd)
        monkeypatch.setattr(os, "fsync", fail)
        with pytest.raises(OSError, match="synthetic"):
            io.flush()
        with pytest.raises(SectorTransportError, match="Uncertain"):
            io.read_sector(0)


def test_unexpected_short_write_poison(tmp_path, monkeypatch):
    with TestSectorTransport(tmp_path / "short.kdevtest", 16, create=True) as io:
        original = os.write
        def fail(fd, data):
            if fd == io._fd:
                return 0
            return original(fd, data)
        monkeypatch.setattr(os, "write", fail)
        with pytest.raises(SectorTransportError, match="Short"):
            io.write_sector(0, bytes(SECTOR_BYTES))
        with pytest.raises(SectorTransportError, match="Uncertain"):
            io.read_sector(0)


def test_fixed_test_capacity_and_no_raw_device_path(tmp_path):
    for invalid in (0, 1, MAX_TEST_SECTORS + 1, True):
        with pytest.raises(SectorTransportError):
            TestSectorTransport(tmp_path / "bad.kdevtest", invalid, create=True)
    with pytest.raises(SectorTransportError):
        TestSectorTransport("/dev/sda", 16)
    with pytest.raises(SectorTransportError):
        TestSectorTransport(r"\\.\PhysicalDrive0", 16)
