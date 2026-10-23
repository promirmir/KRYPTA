"""No hardware access: synthetic Linux USB backup and authenticated recovery."""
import hashlib
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from krypta.core import CryptoError, decrypt_file, file_info, generate_keyfile
from krypta.physical_backup import backup_linux_usb_encrypted
from krypta.physical_read_probe import PhysicalProbeError

DEVICE = "/dev/sdb"
CAPACITY = 2 * 1024 * 1024


def inventory(**changes):
    info = {
        "device": DEVICE, "bytes": CAPACITY, "bus": "usb",
        "mounted": False, "system_or_boot": False,
        "inspection_complete": True, "write_authorized": False,
    }
    info.update(changes)
    return {"platform": "Linux", "physical_disk_encryption_enabled": False,
            "devices": [info]}


class FakeReadOnlyDevice:
    def __init__(self, *, short=False, changed=False, actual_capacity=CAPACITY):
        self.reads = []
        self.opens = []
        self.closes = 0
        self.short = short
        self.changed = changed
        self.actual_capacity = actual_capacity

    def stat(self, path):
        assert path == DEVICE
        return SimpleNamespace(st_mode=stat.S_IFBLK, st_dev=3, st_ino=8,
                               st_rdev=9 if self.changed else 8)

    def fstat(self, fd):
        assert fd == 91
        return SimpleNamespace(st_mode=stat.S_IFBLK, st_dev=3, st_ino=8,
                               st_rdev=8)

    def open(self, path):
        self.opens.append(path)
        return 91

    def capacity(self, fd):
        return self.actual_capacity

    def pread(self, fd, count, offset):
        self.reads.append((count, offset))
        return bytes([(offset // 4096) % 251]) * (count - int(self.short))

    def close(self, fd):
        assert fd == 91
        self.closes += 1


def keyfile(tmp_path):
    key = tmp_path / "independent.secret"
    generate_keyfile(key)
    return key


def output(tmp_path):
    return tmp_path / "usb-backup.krypta"


def run(tmp_path, device, **kwargs):
    return backup_linux_usb_encrypted(
        DEVICE, output(tmp_path), "long strong password sample", keyfile(tmp_path),
        system="Linux", scanner=kwargs.pop("scanner", inventory),
        backend=device, **kwargs,
    )


def test_whole_disk_encrypted_readonly_and_decryptable(tmp_path):
    device = FakeReadOnlyDevice()
    result = run(tmp_path, device)
    assert result["source_write_authorized"] is False
    assert result["physical_disk_encrypted"] is False
    assert result["format"] == "KRYPTA-FILE/2"
    assert device.opens == [DEVICE] and device.closes == 1
    assert device.reads == [(1024 * 1024, 0), (1024 * 1024, 1024 * 1024)]
    assert file_info(output(tmp_path))["version"] == 2
    assert output(tmp_path).stat().st_size > CAPACITY
    recovered = tmp_path / "recovered-USB.img"
    decrypt_file(output(tmp_path), recovered, "long strong password sample",
                 tmp_path / "independent.secret")
    assert recovered.stat().st_size == CAPACITY
    expected = (bytes([0]) * (1024 * 1024) +
                bytes([(1024 * 1024 // 4096) % 251]) * (1024 * 1024))
    assert hashlib.sha256(recovered.read_bytes()).digest() == hashlib.sha256(expected).digest()


@pytest.mark.parametrize("change", [
    {"mounted": True}, {"system_or_boot": True}, {"bus": "sata"},
    {"inspection_complete": False}, {"write_authorized": True},
])
def test_unsafe_usb_denied_before_fd_open(tmp_path, change):
    device = FakeReadOnlyDevice()
    with pytest.raises(PhysicalProbeError):
        run(tmp_path, device, scanner=lambda: inventory(**change))
    assert device.opens == [] and not output(tmp_path).exists()


@pytest.mark.parametrize("flags", [
    {"short": True}, {"changed": True}, {"actual_capacity": CAPACITY + 512},
])
def test_io_error_identity_or_geometry_does_not_publish(tmp_path, flags):
    device = FakeReadOnlyDevice(**flags)
    with pytest.raises(PhysicalProbeError):
        run(tmp_path, device)
    assert device.closes == 1
    assert not output(tmp_path).exists()


def test_mount_event_after_full_stream_prevents_publish(tmp_path):
    calls = [0]
    device = FakeReadOnlyDevice()

    def changing_inventory():
        calls[0] += 1
        return inventory(mounted=(calls[0] >= 3))

    with pytest.raises(PhysicalProbeError):
        run(tmp_path, device, scanner=changing_inventory)
    assert len(device.reads) == 2 and device.closes == 1
    assert not output(tmp_path).exists()


def test_existing_output_is_never_overwritten(tmp_path):
    target = output(tmp_path)
    target.write_bytes(b"precious data")
    device = FakeReadOnlyDevice()
    with pytest.raises(PhysicalProbeError):
        run(tmp_path, device)
    assert target.read_bytes() == b"precious data"
    assert not device.opens


def test_cannot_use_password_only_without_external_secret(tmp_path):
    device = FakeReadOnlyDevice()
    with pytest.raises(PhysicalProbeError):
        backup_linux_usb_encrypted(DEVICE, output(tmp_path), "long password", None,
                                   system="Linux", scanner=inventory, backend=device)
    assert not device.opens


def test_non_linux_cannot_touch_device(tmp_path):
    device = FakeReadOnlyDevice()
    with pytest.raises(PhysicalProbeError):
        backup_linux_usb_encrypted(DEVICE, output(tmp_path), "long password",
                                   keyfile(tmp_path), system="Windows",
                                   scanner=inventory, backend=device)
    assert not device.opens


def test_archive_tampering_rejected_before_plaintext_export(tmp_path):
    device = FakeReadOnlyDevice()
    run(tmp_path, device)
    blob = output(tmp_path).read_bytes()
    output(tmp_path).write_bytes(blob[:-1] + bytes([blob[-1] ^ 0x80]))
    target = tmp_path / "never-created.img"
    with pytest.raises(CryptoError):
        decrypt_file(output(tmp_path), target, "long strong password sample",
                     tmp_path / "independent.secret")
    assert not target.exists()
