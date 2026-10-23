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
    assert result["backup_verified"] is True
    assert result["verified_plaintext_bytes"] == CAPACITY
    assert result["verification_plaintext_written"] is False
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


def test_postwrite_archive_verification_failure_never_claims_success(tmp_path, monkeypatch):
    """A failed authenticated second read must not return a success report."""
    from krypta import physical_backup
    device = FakeReadOnlyDevice()

    def verification_failure(*_args):
        raise CryptoError("simulated post-publication archive corruption")

    monkeypatch.setattr(physical_backup, "verify_file", verification_failure)
    with pytest.raises(PhysicalProbeError, match="verification failed"):
        run(tmp_path, device)
    assert device.closes == 1
    # No unverified file may exist at the ordinary backup destination.
    assert not output(tmp_path).exists()
    assert not list(tmp_path.glob(".krypta-pending-*"))



def test_visible_name_is_absent_during_post_write_authentication(tmp_path, monkeypatch):
    """A normal file name only appears after source bytes and AEAD are verified."""
    from krypta import physical_backup
    original_verify = physical_backup.verify_file
    target = output(tmp_path)
    observed = []

    def observe_pending(pending, password, key):
        assert not target.exists()
        assert pending.exists() and pending.name.startswith(".krypta-pending-")
        assert pending.parent == target.parent
        observed.append(pending.name)
        return original_verify(pending, password, key)

    monkeypatch.setattr(physical_backup, "verify_file", observe_pending)
    result = run(tmp_path, FakeReadOnlyDevice())
    assert result["backup_verified"] is True
    assert len(observed) == 1
    assert target.is_file()
    assert not list(tmp_path.glob(".krypta-pending-*"))


def test_wrong_decrypted_digest_cannot_publish_misleading_backup(tmp_path, monkeypatch):
    """A valid AEAD archive containing unexpected source bytes is not a success."""
    from krypta import physical_backup
    real_verify = physical_backup.verify_file

    def lie_about_size(pending, password, key):
        valid = real_verify(pending, password, key)
        return {**valid, "plaintext_bytes": valid["plaintext_bytes"] + 1}

    monkeypatch.setattr(physical_backup, "verify_file", lie_about_size)
    with pytest.raises(PhysicalProbeError, match="verification failed"):
        run(tmp_path, FakeReadOnlyDevice())
    assert not output(tmp_path).exists()
    assert not list(tmp_path.glob(".krypta-pending-*"))


def test_no_clobber_if_output_appears_during_publication(tmp_path, monkeypatch):
    """Attack/race simulation: another process creates target after preflight."""
    from krypta import physical_backup
    native_link = physical_backup.os.link
    target = output(tmp_path)
    seen = []

    def conflicting_link(src, dst, **kwargs):
        if Path(dst) == target:
            assert not target.exists()
            seen.append(True)
            target.write_bytes(b"EXISTING DATA MUST SURVIVE")
        return native_link(src, dst, **kwargs)

    monkeypatch.setattr(physical_backup.os, "link", conflicting_link)
    with pytest.raises(PhysicalProbeError, match="already exists"):
        run(tmp_path, FakeReadOnlyDevice())
    assert seen == [True]
    assert target.read_bytes() == b"EXISTING DATA MUST SURVIVE"
    assert not list(tmp_path.glob(".krypta-pending-*"))


@pytest.mark.skipif(os.name != "posix", reason="Directory fsync is POSIX-specific")
def test_directory_fsync_failure_reports_uncertain_publication(tmp_path, monkeypatch):
    """Never claim backup durability if the filesystem rejects directory sync."""
    from krypta import physical_backup
    native_fsync = physical_backup.os.fsync

    def deny_directory_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("Injected directory sync failure")
        return native_fsync(fd)

    monkeypatch.setattr(physical_backup.os, "fsync", deny_directory_sync)
    with pytest.raises(PhysicalProbeError, match="persistence is uncertain"):
        run(tmp_path, FakeReadOnlyDevice())
    assert output(tmp_path).is_file()
    assert not list(tmp_path.glob(".krypta-pending-*"))
