"""Pure parser tests; only synthetic disk metadata is inspected."""
from __future__ import annotations

import json

import pytest

from krypta.physical_disks import (
    DeviceInspectionError, inspect_physical_disks,
    parse_linux_inventory, parse_windows_inventory,
)

LINUX = {"blockdevices": [
    {"name": "sda", "path": "/dev/sda", "type": "disk", "size": 500000000000,
     "model": "internal", "tran": "sata", "rm": False, "ro": False,
     "mountpoints": [None], "children": [
         {"type": "part", "mountpoints": ["/boot"]},
         {"type": "part", "mountpoints": [None], "children": [
             {"type": "crypt", "mountpoints": ["/"]}]}]},
    {"name": "sdb", "path": "/dev/sdb", "type": "disk", "size": "64000000000",
     "model": "usb", "tran": "usb", "rm": True, "ro": False,
     "mountpoints": [None], "children": [
         {"type": "part", "mountpoints": ["/media/user/usb"]}]},
]}

WINDOWS = [
    {"number": 0, "size_bytes": 500000000000, "model": "internal",
     "bus_type": "NVMe", "is_system": True, "is_boot": True, "is_read_only": False,
     "is_offline": False, "partition_count": 3, "inspected_partitions": 3,
     "mounted": True},
    {"number": 2, "size_bytes": 64000000000, "model": "usb",
     "bus_type": "USB", "is_system": False, "is_boot": False, "is_read_only": False,
     "is_offline": False, "partition_count": 1, "inspected_partitions": 0,
     "mounted": False},
]


def test_linux_system_disk_and_usb_have_no_write_permission():
    devices = parse_linux_inventory(json.dumps(LINUX))
    assert [d["device"] for d in devices] == ["/dev/sda", "/dev/sdb"]
    assert devices[0]["system_or_boot"] and devices[0]["mounted"]
    assert devices[1]["removable_hint"] and devices[1]["mounted"]
    assert all(not d["write_authorized"] for d in devices)


def test_windows_incomplete_partition_inspection_does_not_guess_unmounted():
    devices = parse_windows_inventory(json.dumps(WINDOWS))
    assert devices[0]["device"] == "PhysicalDrive0"
    assert devices[0]["system_or_boot"]
    assert devices[1]["mounted"] is None
    assert not devices[1]["inspection_complete"]
    assert all(d["write_authorized"] is False for d in devices)


@pytest.mark.parametrize("disk", [
    {"type": "disk", "path": "/dev/sda/path", "size": 123, "rm": False, "ro": False},
    {"type": "disk", "path": "/dev/sdb", "size": 0, "rm": False, "ro": False},
    {"type": "disk", "path": "/dev/sdc", "size": 123, "rm": "?", "ro": False},
    {"type": "disk", "path": "/dev/sdd", "size": 123, "rm": False, "ro": False,
     "children": "corrupt"},
])
def test_linux_rejects_ambiguous_metadata(disk):
    with pytest.raises(DeviceInspectionError):
        parse_linux_inventory(json.dumps({"blockdevices": [disk]}))


def test_windows_rejects_duplicate_drive_numbers():
    with pytest.raises(DeviceInspectionError, match="Duplicate"):
        parse_windows_inventory(json.dumps([WINDOWS[0], WINDOWS[0]]))


@pytest.mark.parametrize("system,sample,executable", [
    ("Linux", LINUX, "lsblk"),
    ("Windows", WINDOWS, "powershell.exe"),
])
def test_only_static_readonly_inventory_queries(system, sample, executable):
    calls = []

    def runner(argv, **opts):
        calls.append((argv, opts))
        class Result:
            returncode = 0
            stdout = json.dumps(sample)
        return Result()

    result = inspect_physical_disks(system=system, runner=runner)
    assert result["device_count"] == 2
    assert result["physical_disk_encryption_enabled"] is False
    assert all(d["write_authorized"] is False for d in result["devices"])
    assert calls[0][0][0] == executable
    assert calls[0][1]["check"] is False
    assert "shell" not in calls[0][1]


def test_query_failure_never_returns_synthetic_drives():
    class Bad:
        returncode = 1
        stdout = "{}"
    with pytest.raises(DeviceInspectionError):
        inspect_physical_disks(system="Linux", runner=lambda *a, **k: Bad())


def test_unsupported_platform_fails():
    with pytest.raises(DeviceInspectionError):
        inspect_physical_disks(system="Android")


def test_windows_slow_inventory_is_bounded_and_never_authorizes_writes():
    from subprocess import TimeoutExpired
    observed = []

    def slow_runner(argv, **kwargs):
        observed.append(kwargs["timeout"])
        raise TimeoutExpired(argv, kwargs["timeout"])

    with pytest.raises(DeviceInspectionError, match="OS device query failed"):
        inspect_physical_disks(system="Windows", runner=slow_runner)
    assert observed == [60]

    observed.clear()
    with pytest.raises(DeviceInspectionError, match="OS device query failed"):
        inspect_physical_disks(system="Linux", runner=slow_runner)
    assert observed == [18]
