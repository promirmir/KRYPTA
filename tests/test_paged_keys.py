"""Adversarial PVKEY/1 password and independent recovery key tests.

All files are synthetic temporary regular images. No real disks, user keys,
operating-system accounts or Android/TPM hardware are modified.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from research.paged_fs2 import PagedFS2
from research.paged_keys import (
    PagedKeyError, provision_keys, unlock_password, unlock_recovery,
    rewrap_password_with_recovery, MAX_ENVELOPE_BYTES,
)
from research.paged_volume import PagedResearchVolume, PagedVolumeError

PASSWORD = "Niezależne mocne hasło testowe 2026"
NEW_PASSWORD = "Inne całkiem długie hasło odzyskiwania"


@pytest.fixture
def case(tmp_path):
    image = tmp_path / "vault.kpv"
    envelope = tmp_path / "vault.pvkey"
    recovery = tmp_path / "backup.recovery"
    key = os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as volume:
        fs = PagedFS2.format(volume)
        fs.write_file("inside", b"never-in-key-envelope" * 155)
        receipt = fs.receipt
        report = provision_keys(volume, PASSWORD, envelope, recovery)
        identity = volume.id
    return {
        "image": image, "envelope": envelope, "recovery": recovery,
        "key": key, "id": identity, "receipt": receipt, "report": report,
    }


def _check_reopen(image, key, receipt):
    with PagedResearchVolume(image, key, expected_receipt=receipt) as v:
        return PagedFS2(v).read_file("inside")


def test_password_unlock_to_mountable_actual_pfs2(case):
    key, identity = unlock_password(case["envelope"], PASSWORD)
    assert key == case["key"]
    assert identity == case["id"]
    assert _check_reopen(case["image"], key, case["receipt"]) == b"never-in-key-envelope" * 155
    assert case["envelope"].read_bytes().find(key) == -1
    assert case["envelope"].read_bytes().find(PASSWORD.encode("utf-8")) == -1
    assert len(case["recovery"].read_bytes()) == 32
    assert case["recovery"].read_bytes() != key
    if os.name == "posix":
        for p in (case["envelope"], case["recovery"]):
            assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_independent_recovery_without_password(case):
    key, image_id = unlock_recovery(case["envelope"], case["recovery"])
    assert (key, image_id) == (case["key"], case["id"])
    assert _check_reopen(case["image"], key, case["receipt"]) == b"never-in-key-envelope" * 155
    with pytest.raises(PagedKeyError, match="authentication failed"):
        unlock_password(case["envelope"], "incorrect-long-passphrase-2026")


def test_new_password_envelope_recovery_no_old_overwrite(case, tmp_path):
    replacement = tmp_path / "second.pvkey"
    before_original = case["envelope"].read_bytes()
    before_recovery = case["recovery"].read_bytes()
    report = rewrap_password_with_recovery(
        case["envelope"], case["recovery"], NEW_PASSWORD, replacement
    )
    assert report["image_id"] == case["id"].hex()
    assert case["envelope"].read_bytes() == before_original
    assert case["recovery"].read_bytes() == before_recovery
    assert replacement.read_bytes() != before_original
    assert unlock_password(replacement, NEW_PASSWORD)[0] == case["key"]
    assert unlock_recovery(replacement, case["recovery"])[0] == case["key"]
    # This is recovery, NOT revocation: the old envelope still works.
    assert unlock_password(case["envelope"], PASSWORD)[0] == case["key"]
    with pytest.raises(PagedKeyError):
        unlock_password(replacement, PASSWORD)


def test_no_existing_output_replacement(case, tmp_path):
    with PagedResearchVolume(case["image"], case["key"],
                             expected_receipt=case["receipt"]) as vol:
        original = case["envelope"].read_bytes()
        occupied = tmp_path / "occupied"
        occupied.write_bytes(b"CANARY")
        with pytest.raises(PagedKeyError, match="overwrite"):
            provision_keys(vol, PASSWORD, case["envelope"], tmp_path / "new.recovery")
        assert not (tmp_path / "new.recovery").exists()
        assert case["envelope"].read_bytes() == original
        with pytest.raises(PagedKeyError, match="overwrite"):
            provision_keys(vol, PASSWORD, occupied, tmp_path / "not-there.recovery")
        assert occupied.read_bytes() == b"CANARY"
        assert not (tmp_path / "not-there.recovery").exists()
        with pytest.raises(PagedKeyError, match="differ"):
            provision_keys(vol, PASSWORD, case["image"], tmp_path / "x")
        assert case["image"].exists()


def test_short_pin_must_not_be_advertised_as_offline_safe(case, tmp_path):
    with PagedResearchVolume(case["image"], case["key"]) as v:
        for bad in ["1", "1234", "12345678901", "", "é" * 11]:
            with pytest.raises(PagedKeyError, match="12"):
                provision_keys(v, bad, tmp_path / "short.pvkey", tmp_path / "short.recovery")
        assert not (tmp_path / "short.pvkey").exists()
        assert not (tmp_path / "short.recovery").exists()


def test_wrong_recovery_secret_and_missing_file_do_not_unlock(case, tmp_path):
    wrong = tmp_path / "wrong.recovery"
    wrong.write_bytes(os.urandom(32))
    if os.name == "posix":
        wrong.chmod(0o600)
    with pytest.raises(PagedKeyError, match="authentication failed"):
        unlock_recovery(case["envelope"], wrong)
    with pytest.raises(PagedKeyError):
        unlock_recovery(case["envelope"], tmp_path / "does-not-exist")


def test_envelope_byte_tamper_and_duplicate_keys_rejected(case, tmp_path):
    payload = json.loads(case["envelope"].read_text())
    payload["password_nonce"] = "AAAAAAAAAAAAAAAA"
    altered = tmp_path / "altered.pvkey"
    altered.write_text(json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n")
    if os.name == "posix":
        altered.chmod(0o600)
    with pytest.raises(PagedKeyError, match="authentication failed"):
        unlock_password(altered, PASSWORD)
    duplicate = tmp_path / "duplicate.pvkey"
    original = case["envelope"].read_bytes()
    duplicate.write_bytes(original.replace(b'"format":', b'"format":"DUP","format":', 1))
    if os.name == "posix":
        duplicate.chmod(0o600)
    with pytest.raises(PagedKeyError):
        unlock_password(duplicate, PASSWORD)


def test_prohibit_wrong_image_and_incorrect_receipt(case, tmp_path):
    other = tmp_path / "different.kpv"
    with PagedResearchVolume(other, case["key"], create=True) as v:
        PagedFS2.format(v)
        new_id = v.id
    recovered_key, bound_id = unlock_password(case["envelope"], PASSWORD)
    assert bound_id != new_id
    with PagedResearchVolume(other, recovered_key) as v:
        assert v.id != bound_id  # caller MUST check image identity
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(case["image"], recovered_key,
                           expected_receipt="0" * 64)


def test_symlink_private_credential_is_rejected(case, tmp_path):
    alias = tmp_path / "symlink.pvkey"
    try:
        alias.symlink_to(case["envelope"])
    except (OSError, NotImplementedError):
        pytest.skip("Symlink privilege not available on this platform")
    with pytest.raises(PagedKeyError, match="Symlink"):
        unlock_password(alias, PASSWORD)


@pytest.mark.skipif(os.name != "posix", reason="Unix POSIX mode enforcement")
def test_world_readable_recovery_and_bundle_blocked(case):
    case["envelope"].chmod(0o644)
    with pytest.raises(PagedKeyError, match="private"):
        unlock_password(case["envelope"], PASSWORD)
    case["envelope"].chmod(0o600)
    case["recovery"].chmod(0o644)
    with pytest.raises(PagedKeyError, match="private"):
        unlock_recovery(case["envelope"], case["recovery"])


def test_truncated_and_huge_envelopes_bounded(case, tmp_path):
    original = case["envelope"].read_bytes()
    for name, data in [("truncated", original[:-1]), ("huge", b"X" * (MAX_ENVELOPE_BYTES + 1))]:
        p = tmp_path / f"{name}.pvkey"
        p.write_bytes(data)
        if os.name == "posix":
            p.chmod(0o600)
        with pytest.raises(PagedKeyError):
            unlock_password(p, PASSWORD)


def test_corrupted_image_remains_locked_even_with_correct_bundle(case, tmp_path):
    copy = tmp_path / "copy.kpv"
    content = bytearray(case["image"].read_bytes())
    content[0] ^= 0x80
    copy.write_bytes(content)
    key, image_id = unlock_password(case["envelope"], PASSWORD)
    with pytest.raises(PagedVolumeError):
        PagedResearchVolume(copy, key, expected_receipt=case["receipt"])


def test_case_does_not_leak_secret_in_source_image(case):
    raw = case["image"].read_bytes()
    assert PASSWORD.encode("utf-8") not in raw
    assert case["recovery"].read_bytes() not in raw
    assert case["envelope"].read_bytes() not in raw
