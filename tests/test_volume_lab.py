"""Volume Lab regression tests: only temporary, disposable encrypted images.

No physical disk, partition, OS volume, or other user files are touched.
"""
from __future__ import annotations

import os

import pytest

from krypta.volume_lab import (
    create_image, verify_image, import_file, export_file, rotate_image,
    recover_password,
)
from research.paged_keys import PagedKeyError
from research.paged_fs2 import MAX_FILE_BYTES

PASSWORD = "This is a long development passphrase 2026"
NEW_PASSWORD = "Another independent very long passphrase 2026"


@pytest.fixture
def lab(tmp_path):
    img = tmp_path / "synthetic.kpv"
    envelope = tmp_path / "synthetic.pvkey"
    recovery = tmp_path / "recovery.secret"
    first = create_image(img, envelope, recovery, PASSWORD, PASSWORD)
    return {
        "image": img, "envelope": envelope, "recovery": recovery,
        "receipt": first["receipt"], "image_id": first["image_id"],
        "tmp": tmp_path,
    }


def test_create_verify_and_password_or_recovery_unlock(lab):
    params = (lab["image"], lab["envelope"], lab["receipt"])
    a = verify_image(*params, password=PASSWORD)
    b = verify_image(*params, recovery=lab["recovery"])
    assert a == b
    assert a["files_verified"] == 0
    assert a["image_id"] == lab["image_id"]


def test_add_and_export_authenticated_file_with_updated_external_receipt(lab):
    source = lab["tmp"] / "message.bin"
    payload = os.urandom(33333) + b"hello KRYPTA"
    source.write_bytes(payload)
    imported = import_file(
        lab["image"], lab["envelope"], lab["receipt"], source,
        password=PASSWORD,
    )
    assert imported["receipt"] != lab["receipt"]
    assert source.read_bytes() == payload  # plaintext source never altered
    with pytest.raises(Exception):
        verify_image(lab["image"], lab["envelope"], lab["receipt"], password=PASSWORD)
    report = verify_image(
        lab["image"], lab["envelope"], imported["receipt"],
        recovery=lab["recovery"],
    )
    assert report["files"] == [{"name": "message.bin", "size": len(payload)}]
    target = lab["tmp"] / "restored.bin"
    result = export_file(
        lab["image"], lab["envelope"], imported["receipt"],
        "message.bin", target, recovery=lab["recovery"],
    )
    assert result["receipt"] == imported["receipt"]
    assert target.read_bytes() == payload
    with pytest.raises(PagedKeyError, match="overwrite"):
        export_file(
            lab["image"], lab["envelope"], imported["receipt"],
            "message.bin", target, password=PASSWORD,
        )
    assert target.read_bytes() == payload


def test_never_auto_accept_receipt_or_wrong_password(lab):
    with pytest.raises(PagedKeyError, match="trusted"):
        verify_image(lab["image"], lab["envelope"], "", password=PASSWORD)
    with pytest.raises(PagedKeyError):
        verify_image(lab["image"], lab["envelope"], lab["receipt"],
                     password="wrong-but-sufficiently-long-password")
    with pytest.raises(PagedKeyError, match="exactly one"):
        verify_image(lab["image"], lab["envelope"], lab["receipt"],
                     password=PASSWORD, recovery=lab["recovery"])
    with pytest.raises(PagedKeyError, match="exactly one"):
        verify_image(lab["image"], lab["envelope"], lab["receipt"])


def test_create_never_overwrites_any_existing_output(lab):
    source_ciphertext = lab["image"].read_bytes()
    with pytest.raises(Exception):
        create_image(lab["image"], lab["tmp"] / "new.pvkey",
                     lab["tmp"] / "fresh.secret", PASSWORD, PASSWORD)
    assert source_ciphertext == lab["image"].read_bytes()
    assert not (lab["tmp"] / "new.pvkey").exists()
    assert not (lab["tmp"] / "fresh.secret").exists()


def test_bad_confirmation_does_not_create_image(lab):
    image = lab["tmp"] / "notcreated.kpv"
    with pytest.raises(PagedKeyError, match="match"):
        create_image(image, lab["tmp"] / "notcreated.pvkey",
                     lab["tmp"] / "notcreated.recovery",
                     PASSWORD, NEW_PASSWORD)
    assert not image.exists()


def test_existing_encrypted_file_is_never_replaced(lab):
    source = lab["tmp"] / "duplicate.bin"
    source.write_bytes(b"original")
    first = import_file(
        lab["image"], lab["envelope"], lab["receipt"], source,
        recovery=lab["recovery"],
    )
    source.write_bytes(b"replacement")
    with pytest.raises(FileExistsError):
        import_file(
            lab["image"], lab["envelope"], first["receipt"], source,
            password=PASSWORD,
        )
    result = export_file(
        lab["image"], lab["envelope"], first["receipt"],
        "duplicate.bin", lab["tmp"] / "plain.bin", password=PASSWORD,
    )
    assert result["bytes_verified"] == len(b"original")
    assert (lab["tmp"] / "plain.bin").read_bytes() == b"original"


def test_refuse_oversized_plaintext_before_any_volume_commit(lab):
    huge = lab["tmp"] / "large.bin"
    with huge.open("wb") as stream:
        stream.truncate(MAX_FILE_BYTES + 1)
    with pytest.raises(ValueError, match="32-MiB"):
        import_file(lab["image"], lab["envelope"], lab["receipt"], huge,
                    password=PASSWORD)
    assert verify_image(lab["image"], lab["envelope"], lab["receipt"],
                        password=PASSWORD)["files_verified"] == 0


def test_recover_password_creates_new_envelope_without_revocation(lab):
    new = lab["tmp"] / "replacement.pvkey"
    original = lab["envelope"].read_bytes()
    report = recover_password(
        lab["envelope"], lab["recovery"], new,
        NEW_PASSWORD, NEW_PASSWORD,
    )
    assert report["image_id"] == lab["image_id"]
    assert lab["envelope"].read_bytes() == original
    assert verify_image(lab["image"], new, lab["receipt"],
                        password=NEW_PASSWORD)["image_id"] == lab["image_id"]
    assert verify_image(lab["image"], lab["envelope"], lab["receipt"],
                        password=PASSWORD)["image_id"] == lab["image_id"]


def test_rotate_new_data_key_and_keep_old_image_valid(lab):
    original = lab["image"].read_bytes()
    new_img, new_bundle, new_recovery = (
        lab["tmp"] / "migrated.kpv", lab["tmp"] / "migrated.pvkey",
        lab["tmp"] / "migrated.recovery",
    )
    report = rotate_image(
        lab["image"], lab["envelope"], lab["receipt"],
        new_img, new_bundle, new_recovery, NEW_PASSWORD, NEW_PASSWORD,
        old_recovery=lab["recovery"],
    )
    assert report["image_id"] != lab["image_id"]
    assert report["receipt"] != lab["receipt"]
    assert lab["image"].read_bytes() == original
    assert verify_image(new_img, new_bundle, report["receipt"],
                        password=NEW_PASSWORD)["files_verified"] == 0
    assert verify_image(lab["image"], lab["envelope"], lab["receipt"],
                        password=PASSWORD)["files_verified"] == 0


def test_refuse_alias_paths_and_symlink_input(lab):
    with pytest.raises(ValueError, match="distinct"):
        import_file(lab["image"], lab["envelope"], lab["receipt"],
                    lab["image"], password=PASSWORD)
    with pytest.raises(ValueError, match="distinct"):
        export_file(lab["image"], lab["envelope"], lab["receipt"],
                    "anything", lab["image"], password=PASSWORD)
    symlink = lab["tmp"] / "linked.kpv"
    try:
        symlink.symlink_to(lab["image"])
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unsupported by test host")
    with pytest.raises(ValueError, match="ordinary"):
        verify_image(symlink, lab["envelope"], lab["receipt"],
                     password=PASSWORD)


def test_source_image_is_rejected_when_not_kpv(lab):
    with pytest.raises(ValueError, match="kpv"):
        verify_image(lab["tmp"] / "not-a-volume.txt", lab["envelope"],
                     lab["receipt"], password=PASSWORD)


def test_gui_forms_have_separate_required_secret_fields():
    from krypta.volume_lab_gui import FORMS
    assert {command for _, _, command in FORMS} == {
        "create", "verify", "import", "export", "rotate", "recover",
    }
    for _, fields, _ in FORMS:
        assert len([key for key, *_ in fields]) == len(set(key for key, *_ in fields))



def test_hardlink_alias_is_not_treated_as_separate_plaintext(lab):
    alias = lab["tmp"] / "alias.kpv"
    try:
        os.link(lab["image"], alias)
    except (OSError, NotImplementedError):
        pytest.skip("Hardlinks unavailable on this filesystem")
    with pytest.raises(ValueError, match="Hardlinked"):
        import_file(
            lab["image"], lab["envelope"], lab["receipt"],
            alias, password=PASSWORD,
        )
    assert verify_image(lab["image"], lab["envelope"], lab["receipt"],
                        password=PASSWORD)["files_verified"] == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO support required")
def test_never_open_fifo_instead_of_regular_plaintext(lab):
    fifo = lab["tmp"] / "named-pipe"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular files"):
        import_file(
            lab["image"], lab["envelope"], lab["receipt"],
            fifo, password=PASSWORD,
        )
    assert verify_image(lab["image"], lab["envelope"], lab["receipt"],
                        password=PASSWORD)["files_verified"] == 0



def test_import_denies_new_commit_when_existing_file_ciphertext_is_corrupted(lab):
    """Authenticated directory metadata is NOT enough: verify old plaintext."""
    from research.paged_keys import unlock_password
    from research.paged_volume import PagedResearchVolume, PagedVolumeError
    from research.paged_fs2 import PagedFS2

    earlier = lab["tmp"] / "previous.bin"
    earlier.write_bytes(os.urandom(9000))
    first = import_file(
        lab["image"], lab["envelope"], lab["receipt"], earlier,
        password=PASSWORD,
    )
    key, _ = unlock_password(lab["envelope"], PASSWORD)
    with PagedResearchVolume(lab["image"], key,
                             expected_receipt=first["receipt"]) as volume:
        fs = PagedFS2(volume)
        sector = fs._files["previous.bin"]["blocks"][0]
        offset = volume._entry(sector)[1] + 40
    with lab["image"].open("r+b") as handle:
        handle.seek(offset)
        prior = handle.read(1)
        handle.seek(offset)
        handle.write(bytes([prior[0] ^ 0x80]))
    before = lab["image"].read_bytes()
    new_file = lab["tmp"] / "fresh.bin"
    new_file.write_bytes(b"never-import-with-damaged-ciphertext")
    with pytest.raises((PagedVolumeError, ValueError)):
        import_file(
            lab["image"], lab["envelope"], first["receipt"], new_file,
            recovery=lab["recovery"],
        )
    assert lab["image"].read_bytes() == before
    # Source ciphertext already damaged, but absolutely NO new root/commit.
    assert new_file.read_bytes() == b"never-import-with-damaged-ciphertext"


def test_committed_write_with_failed_followup_verification_exposes_untrusted_receipt(
        lab, monkeypatch):
    """Do not strand a user with only the old rollback-failing receipt."""
    from research.paged_fs2 import PagedFS2
    from research.paged_volume import PagedVolumeError
    from krypta.volume_lab import PostCommitVerificationError
    src = lab["tmp"] / "postcommit.bin"
    src.write_bytes(b"test-post-commit-authenticated-recovery")
    original = PagedFS2.read_file

    def fake_io_failure(self, name):
        if name == src.name:
            raise OSError("injected read error AFTER successful root commit")
        return original(self, name)

    monkeypatch.setattr(PagedFS2, "read_file", fake_io_failure)
    with pytest.raises(PostCommitVerificationError) as error:
        import_file(lab["image"], lab["envelope"], lab["receipt"], src,
                    password=PASSWORD)
    receipt = error.value.unverified_receipt
    assert len(receipt) == 64 and receipt != lab["receipt"]
    monkeypatch.setattr(PagedFS2, "read_file", original)
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        verify_image(lab["image"], lab["envelope"], lab["receipt"],
                     password=PASSWORD)
    verified = verify_image(
        lab["image"], lab["envelope"], receipt,
        recovery=lab["recovery"],
    )
    assert verified["files_verified"] == 1


def test_key_provision_success_then_report_failure_cleans_entire_new_bundle(
        lab, monkeypatch):
    from research.paged_fs2 import PagedFS2
    target = lab["tmp"] / "unreported.kpv"
    envelope = lab["tmp"] / "unreported.pvkey"
    recovery = lab["tmp"] / "unreported.recovery"
    # Simulate an error AFTER provision_keys has successfully written BOTH
    # credentials, when the newly formatted filesystem reports its receipt.
    def fail_receipt(self):
        raise OSError("simulated receipt retrieval fault")
    monkeypatch.setattr(PagedFS2, "receipt", property(fail_receipt))
    with pytest.raises(OSError, match="receipt retrieval"):
        create_image(target, envelope, recovery, NEW_PASSWORD, NEW_PASSWORD)
    assert not target.exists()
    assert not envelope.exists()
    assert not recovery.exists()
