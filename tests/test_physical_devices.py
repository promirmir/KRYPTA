"""Fixture-based physical disk discovery: no device writes."""
from __future__ import annotations

import json
from types import SimpleNamespace

from krypta.physical_devices import (
    inspect_physical_disks, parse_linux_physical, parse_windows_physical,
)


def test_linux_root_disk_detects_mount_deep_in_partitions():
    payload = {"blockdevices": [{
        "path": "/dev/nvme0n1", "type": "disk", "size": 1073741824,
        "rm": False, "hotplug": False, "ro": False, "mountpoints": [None],
        "children": [{
            "type": "part", "fstype": "ext4", "mountpoints": ["/"],
        }],
    }]}
    found = parse_linux_physical(json.dumps(payload))
    assert found["read_only"] and not found["any_device_authorized_for_writes"]
    assert found["devices"][0]["status"] == "system_or_boot_disk"
    assert found["devices"][0]["write_authorized"] is False


def test_linux_usb_with_mounted_data_is_not_available():
    payload = {"blockdevices": [{
        "path": "/dev/sdc", "type": "disk", "size": 2000000000,
        "rm": True, "hotplug": True, "ro": False, "mountpoints": [None],
        "children": [{"type": "part", "mountpoints": ["/media/usb"]}],
    }]}
    assert parse_linux_physical(json.dumps(payload))["devices"][0]["status"] == (
        "disk_with_mounted_filesystems"
    )


def test_linux_unmounted_usb_is_inspection_candidate_only():
    payload = {"blockdevices": [{
        "path": "/dev/sdc", "type": "disk", "size": "2000000000",
        "rm": 1, "hotplug": 1, "ro": 0, "mountpoints": [None],
        "children": [{"type": "part", "mountpoints": [None]}],
    }]}
    record = parse_linux_physical(json.dumps(payload))["devices"][0]
    assert record["status"] == "external_candidate_inspection_only"
    assert not record["write_authorized"]


def test_linux_missing_mount_metadata_and_malformed_payload_fail_closed():
    payload = {"blockdevices": [{
        "path": "/dev/sda", "type": "disk", "size": 4096,
        "rm": False, "hotplug": False, "ro": False,
    }]}
    assert parse_linux_physical(json.dumps(payload))["devices"][0]["status"] == (
        "unknown_requires_independent_review"
    )
    assert parse_linux_physical('{"blockdevices":{}}')["status"] == "unknown"


def test_windows_system_and_unverified_usb_never_approved():
    payload = {"disks": [
        {"number": 0, "name": "System", "bus": "NVMe", "size": 1000000,
         "boot": True, "system": True, "offline": False, "read_only": False},
        {"number": 3, "name": "USB", "bus": "USB", "size": "4000000",
         "boot": False, "system": False, "offline": False, "read_only": False},
    ]}
    first, second = parse_windows_physical(json.dumps(payload))["devices"]
    assert first["status"] == "system_or_boot_disk"
    assert second["status"] == "unknown_requires_independent_review"
    assert first["write_authorized"] is False
    assert second["write_authorized"] is False


def test_windows_truthy_string_is_not_accepted_as_boolean():
    payload = {"disks": [{
        "number": 2, "size": 50000, "bus": "USB", "boot": "False",
        "system": "False", "offline": False, "read_only": False,
    }]}
    assert parse_windows_physical(json.dumps(payload))["devices"][0]["status"] == (
        "unknown_requires_independent_review"
    )


def test_inventory_commands_are_read_only_and_fail_closed():
    captured = []

    def runner(argv, **kwargs):
        captured.append(argv)
        if argv[0] == "lsblk":
            return SimpleNamespace(returncode=0, stdout='{"blockdevices":[]}')
        return SimpleNamespace(returncode=0, stdout='{"disks":[]}')

    for system in ("Linux", "Windows"):
        report = inspect_physical_disks(system, runner)
        assert report["status"] == "inspected"
        assert report["physical_disk_encryption_available"] is False
    assert captured[0][0] == "lsblk"
    assert "Get-Disk" in captured[1][-1]
    assert "Format-" not in captured[1][-1]
    assert "Clear-Disk" not in captured[1][-1]

    def broken(*_, **__):
        raise OSError("missing command")
    assert inspect_physical_disks("Linux", broken)["status"] == "unknown"
    assert inspect_physical_disks("Android", broken)["status"] == "unsupported"
