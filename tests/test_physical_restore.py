"""P0 recovery drill: only disposable .img files, never real block devices."""
import hashlib
import os
from pathlib import Path

import pytest

from krypta.core import CryptoError, encrypt_file, generate_keyfile
from krypta.physical_read_probe import PhysicalProbeError
from krypta.physical_restore import restore_usb_archive_to_image


PASSWORD = "strong recovery test password"
PAYLOAD = bytes(range(256)) * 48


@pytest.fixture
def bundle(tmp_path):
    original = tmp_path / "usb-original.img"
    original.write_bytes(PAYLOAD)
    secret = tmp_path / "independent.key"
    generate_keyfile(secret)
    archive = tmp_path / "backup.krypta"
    encrypt_file(original, archive, PASSWORD, secret)
    return archive, secret, tmp_path / "restored.img"


def restore(bundle, password=PASSWORD, keyfile=None):
    archive, secret, destination = bundle
    return restore_usb_archive_to_image(
        archive, destination, password, secret if keyfile is None else keyfile
    )


def test_complete_recovery_verified_before_publication(bundle):
    report = restore(bundle)
    target = bundle[2]
    assert target.read_bytes() == PAYLOAD
    assert report["restored_bytes"] == len(PAYLOAD)
    assert report["restored_sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert report["independent_readback_verified"] is True
    assert report["physical_disk_written"] is False
    assert report["plaintext_image_written"] is True
    assert not list(target.parent.glob(".krypta-restore-pending-*"))


def test_wrong_password_does_not_publish_plaintext(bundle):
    with pytest.raises(CryptoError):
        restore(bundle, password="incorrect")
    assert not bundle[2].exists()
    assert not list(bundle[2].parent.glob(".krypta-restore-pending-*"))


def test_tampered_final_tag_refuses_any_plaintext(bundle):
    archive, _, output = bundle
    value = archive.read_bytes()
    archive.write_bytes(value[:-1] + bytes([value[-1] ^ 0x20]))
    with pytest.raises(CryptoError):
        restore(bundle)
    assert not output.exists()


def test_existing_image_not_overwritten(bundle):
    dest = bundle[2]
    dest.write_bytes(b"irreplaceable")
    with pytest.raises(PhysicalProbeError, match="NEW"):
        restore(bundle)
    assert dest.read_bytes() == b"irreplaceable"


def test_independent_readback_mismatch_prevents_publication(bundle, monkeypatch):
    from krypta import physical_restore
    normal = physical_restore._readback_image

    def simulate_staging_damage(path):
        amount, digest, identity = normal(path)
        return amount, "0" * 64, identity

    monkeypatch.setattr(physical_restore, "_readback_image", simulate_staging_damage)
    with pytest.raises(PhysicalProbeError, match="differ"):
        restore(bundle)
    assert not bundle[2].exists()
    assert not list(bundle[2].parent.glob(".krypta-restore-pending-*"))


def test_no_physical_device_paths_and_no_symlink_output(bundle, tmp_path):
    archive, secret, _ = bundle
    with pytest.raises(PhysicalProbeError):
        restore_usb_archive_to_image(archive, "/dev/forbidden.img", PASSWORD, secret)
    link = tmp_path / "linked.img"
    link.symlink_to(tmp_path / "other.img")
    with pytest.raises(PhysicalProbeError):
        restore_usb_archive_to_image(archive, link, PASSWORD, secret)
    assert not (tmp_path / "other.img").exists()


def test_reject_missing_external_secret_and_unaligned_source(tmp_path):
    source = tmp_path / "tiny.raw"
    source.write_bytes(b"plain data")
    secret = tmp_path / "keyfile"
    generate_keyfile(secret)
    archive = tmp_path / "tiny.krypta"
    encrypt_file(source, archive, PASSWORD, secret)
    dest = tmp_path / "tiny.img"
    with pytest.raises(PhysicalProbeError, match="block-aligned"):
        restore_usb_archive_to_image(archive, dest, PASSWORD, secret)
    with pytest.raises(PhysicalProbeError, match="keyfile"):
        restore_usb_archive_to_image(archive, dest, PASSWORD, None)
    assert not dest.exists()


def test_final_destination_creation_race_does_not_clobber(bundle, monkeypatch):
    from krypta import physical_restore
    original_link = physical_restore.os.link
    target = bundle[2]

    def race_link(src, dst, *args, **kwargs):
        if Path(src).name.startswith(".krypta-restore-pending-"):
            target.write_bytes(b"another user's file")
        return original_link(src, dst, *args, **kwargs)

    monkeypatch.setattr(physical_restore.os, "link", race_link)
    with pytest.raises(PhysicalProbeError, match="publication failed"):
        restore(bundle)
    assert target.read_bytes() == b"another user's file"
    assert not list(target.parent.glob(".krypta-restore-pending-*"))
