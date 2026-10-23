"""Synthetic tests of the hardware read-only boundary (no real disks opened)."""
import hashlib
import stat
from types import SimpleNamespace

import pytest

from krypta.physical_read_probe import (
    PhysicalProbeError, probe_linux_usb_readonly, SAMPLE_BYTES,
)

DEVICE = "/dev/sdb"
CAPACITY = 128 * 4096


def inventory(**changes):
    disk = {
        "device": DEVICE, "bytes": CAPACITY, "model": "lab USB",
        "bus": "usb", "inspection_complete": True, "mounted": False,
        "system_or_boot": False, "write_authorized": False,
    }
    disk.update(changes)
    return {"platform": "Linux", "physical_disk_encryption_enabled": False,
            "devices": [disk]}


class FakeBlockIO:
    def __init__(self, *, regular=False, actual_size=CAPACITY, short=False,
                 replace_after_open=False):
        self.flags = []
        self.closed = 0
        self.reads = []
        self.regular = regular
        self.actual_size = actual_size
        self.short = short
        self.replace_after_open = replace_after_open
        self.opened = False

    def stat(self, path):
        assert path == DEVICE
        changed = self.opened and self.replace_after_open
        return SimpleNamespace(st_mode=stat.S_IFREG if self.regular else stat.S_IFBLK,
                               st_dev=1, st_ino=20, st_rdev=8 if not changed else 9)

    def fstat(self, fd):
        assert fd == 19
        return SimpleNamespace(st_mode=stat.S_IFBLK, st_dev=1, st_ino=20, st_rdev=8)

    def open(self, path):
        self.flags.append(path)
        self.opened = True
        return 19

    def capacity(self, fd):
        return self.actual_size

    def pread(self, fd, count, offset):
        self.reads.append((count, offset))
        return bytes([offset // SAMPLE_BYTES % 251]) * (count - int(self.short))

    def close(self, fd):
        self.closed += 1


def test_reads_three_bounded_samples_and_closes_once():
    io = FakeBlockIO()
    report = probe_linux_usb_readonly(
        DEVICE, system="Linux", scanner=inventory, backend=io)
    assert report["write_authorized"] is False
    assert report["encryption_available"] is False
    assert report["capacity_bytes"] == CAPACITY
    assert io.flags == [DEVICE] and io.closed == 1
    expected = sorted({0, (CAPACITY // 2 // 4096) * 4096, CAPACITY - 4096})
    assert io.reads == [(4096, p) for p in expected]
    assert [x["offset_bytes"] for x in report["samples"]] == expected
    assert report["samples"][0]["sha256"] == hashlib.sha256(bytes(4096)).hexdigest()


@pytest.mark.parametrize("fields", [
    {"bus": "sata"},
    {"mounted": True},
    {"mounted": None},
    {"system_or_boot": True},
    {"system_or_boot": None},
    {"inspection_complete": False},
    {"write_authorized": True},
    {"bytes": 0},
])
def test_refuses_unsafe_inventory_before_open(fields):
    io = FakeBlockIO()
    with pytest.raises(PhysicalProbeError):
        probe_linux_usb_readonly(
            DEVICE, system="Linux", scanner=lambda: inventory(**fields), backend=io)
    assert io.flags == [] and io.closed == 0


def test_rejects_other_os_and_partition_path_before_any_io():
    io = FakeBlockIO()
    with pytest.raises(PhysicalProbeError):
        probe_linux_usb_readonly(DEVICE, system="Windows",
                                 scanner=inventory, backend=io)
    with pytest.raises(PhysicalProbeError):
        probe_linux_usb_readonly("/dev/disk/by-id/usb", system="Linux",
                                 scanner=inventory, backend=io)
    assert io.flags == []


@pytest.mark.parametrize("settings", [
    {"regular": True},
    {"actual_size": CAPACITY + 4096},
    {"short": True},
    {"replace_after_open": True},
])
def test_no_success_after_unsafe_kernel_identity_size_or_short_read(settings):
    io = FakeBlockIO(**settings)
    with pytest.raises(PhysicalProbeError):
        probe_linux_usb_readonly(
            DEVICE, system="Linux", scanner=inventory, backend=io)
    assert io.closed == (0 if settings.get("regular") else 1)


def test_rejects_remount_between_inventory_scans():
    io = FakeBlockIO()
    calls = [0]

    def changed():
        calls[0] += 1
        return inventory(mounted=calls[0] > 1)

    with pytest.raises(PhysicalProbeError):
        probe_linux_usb_readonly(DEVICE, system="Linux", scanner=changed, backend=io)
    assert calls[0] == 2
    assert io.closed == 1


def test_refuses_unlisted_device_before_open():
    io = FakeBlockIO()
    with pytest.raises(PhysicalProbeError):
        probe_linux_usb_readonly("/dev/sdc", system="Linux", scanner=inventory, backend=io)
    assert not io.flags

def test_linux_swap_is_treated_as_busy_not_safe():
    import json
    from krypta.physical_disks import parse_linux_inventory
    item = {
        "type": "disk", "path": DEVICE, "size": CAPACITY,
        "tran": "usb", "rm": False, "ro": False, "mountpoints": [None],
        "children": [{"type": "part", "fstype": "swap", "mountpoints": [None]}],
    }
    disks = parse_linux_inventory(json.dumps({"blockdevices": [item]}))
    assert disks[0]["mounted"] is True
    with pytest.raises(PhysicalProbeError):
        probe_linux_usb_readonly(
            DEVICE, system="Linux",
            scanner=lambda: {"platform": "Linux",
                "physical_disk_encryption_enabled": False, "devices": disks},
            backend=FakeBlockIO())
