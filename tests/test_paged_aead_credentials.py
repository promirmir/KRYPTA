"""End-to-end password and recovery for paged AEAD v2 scratch images."""
import json
import os
from pathlib import Path

import pytest

from research.paged_aead_v2 import PagedAEADImage, SECTOR_BYTES
from research.paged_aead_credentials import (
    V2CredentialsError, open_v2_with_password, open_v2_with_recovery,
    provision_v2_credentials, unlock_v2_password, unlock_v2_recovery,
)


@pytest.fixture
def provisioned(tmp_path):
    key = os.urandom(32)
    image_path = tmp_path / "volume.kdevtest"
    bundle, recovery = tmp_path / "vol.pv2key", tmp_path / "secret.bin"
    password = "Long offline credential for KRYPTA v2"
    with PagedAEADImage.create(image_path, key, physical_sectors=128,
                               logical_sectors=64) as image:
        image.write_at(SECTOR_BYTES - 4, b"SecretByCrossSector")
        receipt = image.receipt
    before = image_path.read_bytes()
    result = provision_v2_credentials(
        image_path, key, password, bundle, recovery,
        physical_sectors=128, expected_receipt=receipt)
    assert image_path.read_bytes() == before
    return image_path, bundle, recovery, key, password, receipt, result


def test_password_and_recovery_unlock_same_encrypted_image(provisioned):
    image, bundle, recovery, key, password, receipt, result = provisioned
    assert result["image_modified"] is False
    assert result["physical_disk_write_authorized"] is False
    assert key not in bundle.read_bytes()
    assert recovery.read_bytes() not in bundle.read_bytes()
    assert unlock_v2_password(bundle, password) == (
        key, bytes.fromhex(result["volume_id"]))
    assert unlock_v2_recovery(bundle, recovery) == (
        key, bytes.fromhex(result["volume_id"]))
    with open_v2_with_password(image, bundle, password,
                               physical_sectors=128,
                               expected_receipt=receipt) as vol:
        assert vol.read_at(SECTOR_BYTES - 4, 19) == b"SecretByCrossSector"
        with pytest.raises(Exception):
            vol.write_sector(0, bytes(SECTOR_BYTES))
    with open_v2_with_recovery(image, bundle, recovery,
                               physical_sectors=128,
                               expected_receipt=receipt) as vol:
        assert vol.verify_all()["verified_sectors"] == 2
        assert vol.read_at(SECTOR_BYTES - 4, 19) == b"SecretByCrossSector"


def test_password_writer_requires_correct_receipt_and_updates_sectors(provisioned):
    image, bundle, _, _, password, receipt, _ = provisioned
    with open_v2_with_password(image, bundle, password,
                               physical_sectors=128,
                               expected_receipt=receipt, read_only=False) as vol:
        assert vol.write_at(0, b"OPENED") == 6
        current = vol.receipt
    assert current != receipt
    with pytest.raises(V2CredentialsError):
        open_v2_with_password(image, bundle, password,
                              physical_sectors=128,
                              expected_receipt=receipt)
    with open_v2_with_password(image, bundle, password,
                               physical_sectors=128,
                               expected_receipt=current) as vol:
        assert vol.read_at(0, 6) == b"OPENED"


def test_wrong_password_or_recovery_rejected(provisioned, tmp_path):
    image, bundle, recovery, key, password, receipt, result = provisioned
    with pytest.raises(V2CredentialsError, match="authentication"):
        open_v2_with_password(image, bundle, "incorrect but long enough",
                              physical_sectors=128, expected_receipt=receipt)
    forged = tmp_path / "incorrect-recovery.bin"
    forged.write_bytes(os.urandom(32))
    with pytest.raises(V2CredentialsError, match="authentication"):
        open_v2_with_recovery(image, bundle, forged,
                              physical_sectors=128, expected_receipt=receipt)
    with pytest.raises(Exception):
        open_v2_with_password(image, bundle, password,
                              physical_sectors=127, expected_receipt=receipt)


def test_existing_paths_and_wrong_source_receipt_are_non_destructive(tmp_path):
    key = os.urandom(32)
    image, bundle, recovery = (
        tmp_path / "source.kdevtest",
        tmp_path / "existing.pv2key",
        tmp_path / "new-secret.bin",
    )
    with PagedAEADImage.create(image, key, physical_sectors=64) as vol:
        receipt = vol.receipt
    before = image.read_bytes()
    bundle.write_bytes(b"DO NOT OVERWRITE")
    with pytest.raises(Exception):
        provision_v2_credentials(image, key, "long safe passphrase",
                                 bundle, recovery, physical_sectors=64,
                                 expected_receipt=receipt)
    assert image.read_bytes() == before
    assert bundle.read_bytes() == b"DO NOT OVERWRITE"
    assert not recovery.exists()
    with pytest.raises(Exception):
        provision_v2_credentials(image, key, "long safe passphrase",
                                 tmp_path / "fresh.pv2key",
                                 tmp_path / "fresh-secret.bin",
                                 physical_sectors=64,
                                 expected_receipt="0" * 64)
    assert not (tmp_path / "fresh.pv2key").exists()


def test_short_pin_and_aliases_refused_before_any_changes(tmp_path):
    key = os.urandom(32)
    image = tmp_path / "test.kdevtest"
    bundle, recovery = tmp_path / "keys.pv2key", tmp_path / "recovery.bin"
    with PagedAEADImage.create(image, key, physical_sectors=64) as vol:
        receipt = vol.receipt
    with pytest.raises(V2CredentialsError):
        provision_v2_credentials(image, key, "1234", bundle, recovery,
                                 physical_sectors=64, expected_receipt=receipt)
    assert not bundle.exists() and not recovery.exists()
    with pytest.raises(V2CredentialsError, match="differ"):
        provision_v2_credentials(image, key, "Valid long passphrase",
                                 image, recovery,
                                 physical_sectors=64, expected_receipt=receipt)


def test_tamper_envelope_and_different_volume_identity_rejected(provisioned, tmp_path):
    image, bundle, recovery, key, password, receipt, _ = provisioned
    other = tmp_path / "other.kdevtest"
    with PagedAEADImage.create(other, key, physical_sectors=128) as created:
        other_receipt = created.receipt
    with pytest.raises(V2CredentialsError, match="different image"):
        open_v2_with_password(other, bundle, password,
                              physical_sectors=128,
                              expected_receipt=other_receipt)
    altered = tmp_path / "altered.pv2key"
    doc = json.loads(bundle.read_text())
    doc["kdf"]["memory_kib"] = 2**30
    altered.write_text(json.dumps(doc))
    with pytest.raises(V2CredentialsError):
        unlock_v2_password(altered, password)
