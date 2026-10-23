"""Block-level AEAD v2 regression: emulated loop only, never opens a real device."""
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from research.linux_loop_aead import (
    LabLoopSectorTransport, LoopLabError, open_lab_loop_v2,
)
from research.paged_aead_v2 import PagedAEADImage, PagedAEADError

LOOP = "/dev/loop7"
SECTOR = 4096
KEY = bytes(range(32))


class FakeKernelLoop:
    """Native regular-file I/O behind a synthetic BLOCK descriptor identity."""

    def __init__(self, backing):
        self.backing = Path(backing)
        self.handles = {}
        self.opens = []
        self.closes = 0
        self.bad_target = False
        self.short_read = False
        self.short_write = False
        self.fail_flush = False
        self.replaced = False
        self.bad_capacity = False
        self.locked = False
        self.read_offsets = []
        self.write_offsets = []

    @staticmethod
    def _file_meta(info):
        return SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=getattr(info, "st_uid", 0),
            st_nlink=info.st_nlink, st_dev=info.st_dev, st_ino=info.st_ino,
            st_rdev=getattr(info, "st_rdev", 0), st_size=info.st_size,
        )

    def _block_meta(self):
        return SimpleNamespace(
            st_mode=stat.S_IFBLK | 0o600, st_dev=5, st_ino=17,
            st_rdev=120 if not self.replaced else 121,
            st_nlink=1, st_uid=0, st_size=self.backing.stat().st_size,
        )

    def open_backing(self, path):
        self.opens.append(("file", path))
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        self.handles[fd] = "file"
        return fd

    def open_loop(self, path, read_only):
        self.opens.append(("loop", path, read_only))
        flags = os.O_RDONLY if read_only else os.O_RDWR
        fd = os.open(self.backing, flags | getattr(os, "O_BINARY", 0))
        self.handles[fd] = "loop"
        return fd

    def stat(self, path):
        if path == LOOP:
            return self._block_meta()
        return self._file_meta(os.stat(path))

    def fstat(self, fd):
        if self.handles[fd] == "loop":
            return self._block_meta()
        return self._file_meta(os.fstat(fd))

    def lock(self, fd):
        assert not self.locked
        self.locked = True

    def unlock(self, fd):
        assert self.locked
        self.locked = False

    def loop_info(self, fd):
        info = os.stat(self.backing)
        return (info.st_dev, info.st_ino + int(self.bad_target), 0, 0, 7, 0)

    def capacity(self, fd):
        return self.backing.stat().st_size + (4096 if self.bad_capacity else 0)

    def pread(self, fd, size, offset):
        self.read_offsets.append(offset)
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, size - int(self.short_read))

    def pwrite(self, fd, data, offset):
        self.write_offsets.append(offset)
        os.lseek(fd, offset, os.SEEK_SET)
        return os.write(fd, data[:-1] if self.short_write else data)

    def fsync(self, fd):
        os.fsync(fd)
        if self.fail_flush:
            raise OSError("simulated lost fsync acknowledgement")

    def close(self, fd):
        self.closes += 1
        self.handles.pop(fd)
        os.close(fd)


def encrypted_fixture(tmp_path):
    path = tmp_path / "krypta-lab.kdevtest"
    with PagedAEADImage.create(path, KEY, physical_sectors=64,
                               logical_sectors=64) as image:
        receipt = image.receipt
    return path, receipt


def test_real_encrypted_sector_roundtrip_through_emulated_loop(tmp_path):
    path, root0 = encrypted_fixture(tmp_path)
    kernel = FakeKernelLoop(path)
    with open_lab_loop_v2(LOOP, path, KEY, root0, read_only=False,
                          system="Linux", kernel=kernel) as image:
        assert image.sequence == 0
        assert image.read_sector(0) == bytes(SECTOR)
        image.write_sector(0, b"X" * SECTOR)
        image.write_at(4096 - 3, b"physical loop research")
        root1 = image.receipt
        assert image.read_at(4096 - 3, len(b"physical loop research")) == (
            b"physical loop research")
        assert image.verify_all()["verified_sectors"] == 2
    assert not kernel.locked
    assert kernel.closes == 2
    assert kernel.read_offsets and kernel.write_offsets
    assert b"X" * SECTOR not in path.read_bytes()
    with PagedAEADImage.open(path, KEY, physical_sectors=64,
                             expected_receipt=root1) as reopened:
        assert reopened.read_at(0, 1) == b"X"
        assert reopened.read_at(4096 - 3, len(b"physical loop research")) == (
            b"physical loop research")
    with pytest.raises(PagedAEADError, match="receipt"):
        open_lab_loop_v2(LOOP, path, KEY, root0, system="Linux",
                         kernel=FakeKernelLoop(path))


def test_read_only_loop_never_writes(tmp_path):
    path, receipt = encrypted_fixture(tmp_path)
    backend = FakeKernelLoop(path)
    with open_lab_loop_v2(LOOP, path, KEY, receipt, read_only=True,
                          system="Linux", kernel=backend) as image:
        assert image.read_sector(0) == bytes(SECTOR)
        with pytest.raises(PagedAEADError):
            image.write_sector(0, b"Q" * SECTOR)
    assert not backend.write_offsets


@pytest.mark.parametrize("bad_path", [
    "/dev/sda", "/dev/nvme0n1", "/dev/loop7p1", "/dev/mapper/test",
    "/dev/loop07", "/tmp/loop7", "loop7",
])
def test_other_devices_rejected_without_open(tmp_path, bad_path):
    path, receipt = encrypted_fixture(tmp_path)
    backend = FakeKernelLoop(path)
    with pytest.raises(LoopLabError):
        open_lab_loop_v2(bad_path, path, KEY, receipt,
                         system="Linux", kernel=backend)
    assert not backend.opens


def test_invalid_backing_path_and_not_linux_rejected(tmp_path):
    path, root = encrypted_fixture(tmp_path)
    fake = FakeKernelLoop(path)
    with pytest.raises(LoopLabError):
        open_lab_loop_v2(LOOP, path.with_suffix(".bin"), KEY, root,
                         system="Linux", kernel=fake)
    with pytest.raises(LoopLabError):
        open_lab_loop_v2(LOOP, path, KEY, root, system="Windows", kernel=fake)
    assert fake.opens == []


@pytest.mark.parametrize("change", ["bad_target", "bad_capacity"])
def test_loop_wrong_backing_inode_or_geometry_rejected_before_io(tmp_path, change):
    path, root = encrypted_fixture(tmp_path)
    fake = FakeKernelLoop(path)
    setattr(fake, change, True)
    with pytest.raises(LoopLabError):
        open_lab_loop_v2(LOOP, path, KEY, root, system="Linux", kernel=fake)
    assert fake.closes == 2 and not fake.locked
    assert fake.write_offsets == []


def test_emulated_disconnect_poison_and_no_commit(tmp_path):
    path, receipt = encrypted_fixture(tmp_path)
    fake = FakeKernelLoop(path)
    with open_lab_loop_v2(LOOP, path, KEY, receipt, read_only=False,
                          system="Linux", kernel=fake) as image:
        fake.replaced = True
        with pytest.raises(LoopLabError):
            image.write_sector(0, b"T" * SECTOR)
        with pytest.raises(LoopLabError, match="Uncertain"):
            image.read_sector(0)
    with PagedAEADImage.open(path, KEY, physical_sectors=64,
                             expected_receipt=receipt) as image:
        assert image.read_sector(0) == bytes(SECTOR)


def test_short_sector_read_poisoned_and_closed(tmp_path):
    path, receipt = encrypted_fixture(tmp_path)
    fake = FakeKernelLoop(path)
    with open_lab_loop_v2(LOOP, path, KEY, receipt,
                          system="Linux", kernel=fake) as image:
        fake.short_read = True
        # Logical sparse sector 0 returns authenticated zero without block I/O.
        # Read physical header sector 0 to exercise a genuinely short pread.
        with pytest.raises(LoopLabError, match="Uncertain"):
            image._io.read_sector(0)
        with pytest.raises(LoopLabError, match="Uncertain"):
            image._io.read_sector(0)


@pytest.mark.parametrize("fault", ["short_write", "fail_flush"])
def test_partial_write_or_fsync_failure_quarantines_image(tmp_path, fault):
    path, receipt = encrypted_fixture(tmp_path)
    fake = FakeKernelLoop(path)
    with open_lab_loop_v2(LOOP, path, KEY, receipt, read_only=False,
                          system="Linux", kernel=fake) as image:
        setattr(fake, fault, True)
        with pytest.raises((LoopLabError, OSError)):
            image.write_sector(0, b"A" * SECTOR)
        with pytest.raises(PagedAEADError, match="Uncertain"):
            image.read_sector(0)
    assert fake.closes == 2


def test_authenticated_tamper_not_accepted_over_loop(tmp_path):
    path, old = encrypted_fixture(tmp_path)
    with open_lab_loop_v2(LOOP, path, KEY, old, read_only=False,
                          system="Linux", kernel=FakeKernelLoop(path)) as image:
        image.write_sector(0, b"Z" * SECTOR)
        receipt = image.receipt
    with open(path, "r+b") as stream:
        stream.seek(3 * SECTOR + 30)
        first = stream.read(1)
        stream.seek(3 * SECTOR + 30)
        stream.write(bytes([first[0] ^ 0x55]))
    with open_lab_loop_v2(LOOP, path, KEY, receipt,
                          system="Linux", kernel=FakeKernelLoop(path)) as image:
        with pytest.raises(PagedAEADError, match="authentication"):
            image.read_sector(0)
