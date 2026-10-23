"""USB backup GUI regression without access to physical drives."""
from __future__ import annotations

from krypta.usb_backup_gui import usb_backup_candidates


def report(*devices):
    return {"platform": "Linux", "physical_disk_encryption_enabled": False,
            "devices": list(devices)}


def eligible(device="/dev/sdz"):
    return {"device": device, "bus": "usb", "bytes": 2 * 1024 * 1024,
            "mounted": False, "system_or_boot": False,
            "inspection_complete": True, "write_authorized": False}


def test_linux_ui_offers_only_eligible_explicit_readonly_sources():
    assert usb_backup_candidates(report(
        eligible("/dev/sdz"), eligible("/dev/sdb"), eligible("/dev/sdz")
    )) == ["/dev/sdb", "/dev/sdz"]
    assert usb_backup_candidates(report()) == []
    assert usb_backup_candidates({"platform": "Windows", "devices": [
        eligible()]}) == []


def test_ui_never_offers_mounted_system_non_usb_or_incomplete_candidates():
    for change in (
        {"mounted": True}, {"system_or_boot": True}, {"bus": "nvme"},
        {"bus": "sata"}, {"inspection_complete": False},
        {"write_authorized": True}, {"bytes": None},
        {"bytes": 512}, {"device": "C:/fake"}, {"device": "/tmp/not-block"},
    ):
        assert not usb_backup_candidates(report({**eligible(), **change})), change


def test_dependent_inventory_fails_closed():
    assert usb_backup_candidates({"platform": "Linux", "devices": [
        eligible()], "physical_disk_encryption_enabled": True}) == []
    assert usb_backup_candidates({"platform": "Linux", "devices": "bogus",
                                  "physical_disk_encryption_enabled": False}) == []


def test_packaged_usb_test_performs_authenticated_recovery_without_hardware():
    from krypta.desktop_entry import run_usb_backup_self_test
    assert run_usb_backup_self_test() == 0
