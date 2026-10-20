"""PFS/2 real data-encryption-key rotation and no-overwrite failure tests."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from research.paged_fs2 import PagedFS2
from research.paged_keys import (
    PagedKeyError, provision_keys, unlock_password, unlock_recovery,
)
from research.paged_rekey import rotate_pfs2_data_key
from research.paged_volume import PagedResearchVolume, PagedVolumeError

OLD = "Long original high entropy passphrase 2026"
NEW = "An independent replacement passphrase 2026"


@pytest.fixture
def example(tmp_path):
    old_img = tmp_path / "original.kpv"
    old_bundle = tmp_path / "original.pvkey"
    old_recovery = tmp_path / "original.recovery"
    key = os.urandom(32)
    files = {
        "report": os.urandom(1024 * 1024 + 77),
        "zero": b"",
        "name-żółty": b"UNICODE-PRESERVED" * 29,
    }
    with PagedResearchVolume(old_img, key, create=True) as v:
        fs = PagedFS2.format(v)
        for name, content in files.items():
            fs.write_file(name, content)
        fs.write_file("deleted", b"ORPHANED-SOURCE-CIPHERTEXT" * 91)
        fs.delete_file("deleted")
        receipt = fs.receipt
        provision_keys(v, OLD, old_bundle, old_recovery)
        image_id = v.id
    return dict(
        img=old_img, bundle=old_bundle, recovery=old_recovery,
        key=key, receipt=receipt, old_id=image_id, files=files,
        target=tmp_path / "rekeyed.kpv", new_bundle=tmp_path / "new.pvkey",
        new_recovery=tmp_path / "new.recovery",
    )


def rotate(e, *, recovery=False):
    common = (
        e["img"], e["bundle"], e["receipt"], e["target"],
        e["new_bundle"], e["new_recovery"], NEW,
    )
    return rotate_pfs2_data_key(
        *common, old_recovery=e["recovery"] if recovery else None,
        old_password=None if recovery else OLD,
    )


def test_actual_new_dek_and_image_id_with_independent_recovery(example):
    e = example
    before = {name: content for name, content in e["files"].items()}
    source_image = e["img"].read_bytes()
    old_bundle_bytes = e["bundle"].read_bytes()
    old_recovery_bytes = e["recovery"].read_bytes()
    result = rotate(e)
    assert result["files_verified"] == len(before)
    assert result["bytes_verified"] == sum(map(len, before.values()))
    assert result["source_receipt"] == e["receipt"]
    assert result["destination_receipt"] != e["receipt"]
    assert result["destination_image_id"] != e["old_id"].hex()
    assert e["img"].read_bytes() == source_image
    assert e["bundle"].read_bytes() == old_bundle_bytes
    assert e["recovery"].read_bytes() == old_recovery_bytes
    new_key, new_id = unlock_password(e["new_bundle"], NEW)
    recovered_key, recovered_id = unlock_recovery(
        e["new_bundle"], e["new_recovery"]
    )
    assert new_key != e["key"] and new_id != e["old_id"]
    assert (recovered_key, recovered_id) == (new_key, new_id)
    with PagedResearchVolume(e["target"], new_key,
                             expected_receipt=result["destination_receipt"]) as v:
        new_fs = PagedFS2(v)
        assert new_fs.list_files() == sorted(before)
        for name, content in before.items():
            assert new_fs.read_file(name) == content
        assert "deleted" not in new_fs.list_files()
        assert b"ORPHANED-SOURCE-CIPHERTEXT" not in e["target"].read_bytes()
    with pytest.raises(PagedVolumeError):
        PagedResearchVolume(e["target"], e["key"])
    with PagedResearchVolume(e["img"], e["key"], expected_receipt=e["receipt"]) as v:
        assert PagedFS2(v).list_files() == sorted(before)


def test_recovery_based_rekey_after_losing_old_password(example):
    e = example
    result = rotate(e, recovery=True)
    assert result["files_verified"] == len(e["files"])
    assert unlock_password(e["new_bundle"], NEW)[0] != e["key"]
    assert unlock_password(e["bundle"], OLD)[0] == e["key"]


def test_existing_destination_is_never_overwritten_or_deleted(example):
    e = example
    e["new_bundle"].write_bytes(b"NEVER-REPLACE-ME")
    old_ciphertext = e["img"].read_bytes()
    with pytest.raises(PagedKeyError, match="overwrite"):
        rotate(e)
    assert e["new_bundle"].read_bytes() == b"NEVER-REPLACE-ME"
    assert not e["target"].exists() and not e["new_recovery"].exists()
    assert e["img"].read_bytes() == old_ciphertext


def test_old_wrong_password_fails_without_output(example):
    e = example
    with pytest.raises(PagedKeyError, match="authentication failed"):
        rotate_pfs2_data_key(
            e["img"], e["bundle"], e["receipt"], e["target"],
            e["new_bundle"], e["new_recovery"], NEW,
            old_password="Not the correct original password",
        )
    assert not e["target"].exists()


def test_wrong_trusted_receipt_fails_without_output(example):
    e = example
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        rotate_pfs2_data_key(
            e["img"], e["bundle"], "0" * 64,
            e["target"], e["new_bundle"], e["new_recovery"],
            NEW, old_password=OLD,
        )
    assert not e["target"].exists()


def test_source_corruption_fails_before_creating_target(example):
    e = example
    with PagedResearchVolume(e["img"], e["key"]) as v:
        fs = PagedFS2(v)
        sector = fs._files["report"]["blocks"][1]
        frame = v._entry(sector)[1] + 40
    with open(e["img"], "r+b") as handle:
        handle.seek(frame)
        prior = handle.read(1)
        handle.seek(frame)
        handle.write(bytes([prior[0] ^ 1]))
    before = e["img"].read_bytes()
    with pytest.raises(PagedVolumeError):
        rotate(e)
    assert not e["target"].exists()
    assert e["img"].read_bytes() == before


def test_midcopy_failure_cleans_new_only_and_preserves_original(example, monkeypatch):
    e = example
    old_image_bytes = e["img"].read_bytes()
    original = PagedFS2.write_file

    def fault(self, filename, data, *, replace=False):
        if self._volume.path == e["target"] and filename == "report":
            raise OSError("synthetic fault while rekeying")
        return original(self, filename, data, replace=replace)

    monkeypatch.setattr(PagedFS2, "write_file", fault)
    with pytest.raises(OSError, match="synthetic fault"):
        rotate(e)
    assert not e["target"].exists()
    assert not e["new_bundle"].exists()
    assert not e["new_recovery"].exists()
    assert e["img"].read_bytes() == old_image_bytes
    assert unlock_password(e["bundle"], OLD)[0] == e["key"]


def test_failed_output_provisioning_does_not_leave_partial_target(example, monkeypatch):
    e = example
    import research.paged_rekey as rekey
    real = rekey.provision_keys

    def fail(*args, **kwargs):
        raise OSError("synthetic credential failure")

    monkeypatch.setattr(rekey, "provision_keys", fail)
    with pytest.raises(OSError, match="synthetic credential"):
        rotate(e)
    assert not e["target"].exists()
    assert not e["new_bundle"].exists()
    assert not e["new_recovery"].exists()


def test_aliases_rejected_before_any_new_file(example):
    e = example
    with pytest.raises(PagedKeyError, match="distinct"):
        rotate_pfs2_data_key(
            e["img"], e["bundle"], e["receipt"],
            e["img"], e["new_bundle"], e["new_recovery"],
            NEW, old_password=OLD,
        )
    with pytest.raises(PagedKeyError, match="distinct"):
        rotate_pfs2_data_key(
            e["img"], e["bundle"], e["receipt"],
            e["target"], e["new_bundle"], e["new_bundle"],
            NEW, old_password=OLD,
        )
    assert not e["target"].exists()


def test_requires_exactly_one_source_credential(example):
    e = example
    args = (
        e["img"], e["bundle"], e["receipt"],
        e["target"], e["new_bundle"], e["new_recovery"], NEW,
    )
    with pytest.raises(PagedKeyError, match="exactly one"):
        rotate_pfs2_data_key(*args)
    with pytest.raises(PagedKeyError, match="exactly one"):
        rotate_pfs2_data_key(
            *args, old_password=OLD, old_recovery=e["recovery"]
        )


def test_rotate_cli_with_old_recovery_and_piped_new_password(example, capsys):
    from research.paged_key_cli import main
    e = example
    reader, writer = os.pipe()
    try:
        os.write(writer, NEW.encode("utf-8"))
        os.close(writer)
        writer = -1
        assert main([
            "rotate-volume-key",
            "--image", str(e["img"]),
            "--envelope", str(e["bundle"]),
            "--expected-receipt", e["receipt"],
            "--new-image", str(e["target"]),
            "--new-envelope", str(e["new_bundle"]),
            "--new-recovery", str(e["new_recovery"]),
            "--old-recovery", str(e["recovery"]),
            "--password-fd", str(reader),
            "--acknowledge-test-only",
        ]) == 0
    finally:
        os.close(reader)
        if writer >= 0:
            os.close(writer)
    printed = capsys.readouterr().out
    assert "NEW EXTERNAL RECEIPT" in printed
    assert NEW not in printed and OLD not in printed
    key, ident = unlock_password(e["new_bundle"], NEW)
    with PagedResearchVolume(e["target"], key) as v:
        assert v.id == ident
        assert PagedFS2(v).read_file("report") == e["files"]["report"]


def test_rekey_rejects_unchanged_password_even_with_new_random_dek(example):
    e = example
    with pytest.raises(PagedKeyError, match="DIFFERENT"):
        rotate_pfs2_data_key(
            e["img"], e["bundle"], e["receipt"],
            e["target"], e["new_bundle"], e["new_recovery"], OLD,
            old_password=OLD,
        )
    assert not e["target"].exists()
