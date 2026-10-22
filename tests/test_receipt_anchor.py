"""Adversarial sealed receipt pin tests: disposable encrypted PFS/2 files ONLY."""
from __future__ import annotations

import json
import os

import pytest

from research.paged_fs2 import PagedFS2
from research.paged_volume import PagedResearchVolume, PagedVolumeError
from research.receipt_anchor import (
    PIN_FORMAT, ReceiptPinError, load_sealed_pin, pin_trusted_image,
    verify_image_with_sealed_pin,
)


@pytest.fixture
def state(tmp_path):
    image = tmp_path / "disposable.kpv"
    pin_dir = tmp_path / "offline-pins"
    pin_dir.mkdir(mode=0o700)
    key = os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as volume:
        fs = PagedFS2.format(volume)
        fs.write_file("confidential", b"original bytes")
        trusted = fs.receipt
        image_id = volume.id
    return image, key, trusted, image_id, pin_dir


def _pin(state, name="baseline.kpin"):
    image, key, receipt, image_id, pin_dir = state
    return pin_trusted_image(
        image, key, receipt, pin_dir / name, expected_image_id=image_id
    )


def test_enroll_with_trusted_receipt_then_verify_without_image_mutation(state):
    image, key, receipt, image_id, pin_dir = state
    initial_image = image.read_bytes()
    report = _pin(state)
    assert report["trust_promoted"] is False
    assert report["read_only_verified"] is True
    assert report["image_id"] == image_id.hex()
    pin = pin_dir / "baseline.kpin"
    original_pin = pin.read_bytes()
    read = load_sealed_pin(pin, report["seal_sha256"])
    assert read == {
        "format": PIN_FORMAT,
        "image_id": image_id.hex(),
        "sequence": report["sequence"],
        "receipt": receipt,
    }
    verified = verify_image_with_sealed_pin(
        image, key, pin, report["seal_sha256"]
    )
    assert verified["status"] == "SEALED_PIN_MATCH"
    assert verified["files_verified"] == 1
    assert verified["bytes_verified"] == len(b"original bytes")
    assert verified["trust_promoted"] is False
    assert image.read_bytes() == initial_image
    assert pin.read_bytes() == original_pin
    if os.name == "posix":
        assert pin.stat().st_mode & 0o077 == 0


def test_rolled_back_valid_image_rejected_by_current_pin(state):
    image, key, previous, _image_id, pin_dir = state
    older_image = image.read_bytes()
    with PagedResearchVolume(
        image, key, expected_receipt=previous
    ) as volume:
        PagedFS2(volume).write_file("confidential", b"newer bytes", replace=True)
        latest = volume.receipt
    pinned = pin_trusted_image(image, key, latest, pin_dir / "latest.kpin")
    image.write_bytes(older_image)
    before = image.read_bytes()
    with pytest.raises(PagedVolumeError, match="possible rollback"):
        verify_image_with_sealed_pin(
            image, key, pin_dir / "latest.kpin", pinned["seal_sha256"]
        )
    assert image.read_bytes() == before


def test_newer_candidate_is_not_silently_promoted(state):
    image, key, previous, image_id, pin_dir = state
    original = _pin(state)
    with PagedResearchVolume(
        image, key, expected_receipt=previous
    ) as volume:
        PagedFS2(volume).write_file("new", b"unreviewed")
    after = image.read_bytes()
    with pytest.raises(PagedVolumeError, match="receipt mismatch|sequence mismatch"):
        verify_image_with_sealed_pin(
            image, key, pin_dir / "baseline.kpin", original["seal_sha256"]
        )
    assert image.read_bytes() == after
    # Enrollment always needs the externally known current receipt. Never
    # take the new observation as an implicit trusted baseline.
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        pin_trusted_image(image, key, previous, pin_dir / "forbidden.kpin",
                          expected_image_id=image_id)
    assert not (pin_dir / "forbidden.kpin").exists()


def test_older_pin_copy_with_newer_out_of_band_seal_fails(state):
    image, key, receipt, _image_id, pin_dir = state
    first = _pin(state, "v1.kpin")
    old_pin = (pin_dir / "v1.kpin").read_bytes()
    with PagedResearchVolume(image, key, expected_receipt=receipt) as v:
        PagedFS2(v).write_file("second", b"fresh")
        later = v.receipt
    second = pin_trusted_image(image, key, later, pin_dir / "v2.kpin")
    (pin_dir / "v2.kpin").write_bytes(old_pin)  # Synthetic pin rollback
    with pytest.raises(ReceiptPinError, match="seal mismatch"):
        verify_image_with_sealed_pin(
            image, key, pin_dir / "v2.kpin", second["seal_sha256"]
        )
    assert first["seal_sha256"] != second["seal_sha256"]


def test_existing_pin_is_never_replaced_even_when_contents_bad(state):
    image, key, receipt, _image_id, pin_dir = state
    report = _pin(state)
    before = (pin_dir / "baseline.kpin").read_bytes()
    with pytest.raises(ReceiptPinError, match="Refusing to overwrite"):
        _pin(state)
    assert (pin_dir / "baseline.kpin").read_bytes() == before
    assert load_sealed_pin(pin_dir / "baseline.kpin", report["seal_sha256"])["receipt"] == receipt


@pytest.mark.parametrize("untrusted", ["", "0" * 63, "A" * 64, None, 123, True])
def test_external_seal_is_mandatory_and_strict(state, untrusted):
    image, key, _, _, pin_dir = state
    _pin(state)
    before = image.read_bytes()
    with pytest.raises(ReceiptPinError, match="independently trusted pin seal"):
        verify_image_with_sealed_pin(image, key, pin_dir / "baseline.kpin", untrusted)
    assert image.read_bytes() == before


def test_wrong_key_wrong_image_id_and_symlink_denied(state, tmp_path):
    image, key, _, _, pin_dir = state
    report = _pin(state)
    pin = pin_dir / "baseline.kpin"
    other = tmp_path / "different.kpv"
    with PagedResearchVolume(other, key, create=True) as volume:
        PagedFS2.format(volume)
    with pytest.raises(PagedVolumeError):
        verify_image_with_sealed_pin(other, key, pin, report["seal_sha256"])
    with pytest.raises(PagedVolumeError):
        verify_image_with_sealed_pin(image, os.urandom(32), pin, report["seal_sha256"])
    symlink = pin_dir / "alias.kpin"
    try:
        symlink.symlink_to(pin)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not available")
    with pytest.raises(ReceiptPinError, match="Symlink"):
        load_sealed_pin(symlink, report["seal_sha256"])


def test_untrusted_mutations_are_rejected_without_image_touch(state):
    image, key, _, _, pin_dir = state
    report = _pin(state)
    pin = pin_dir / "baseline.kpin"
    original_image = image.read_bytes()
    pin.write_bytes(pin.read_bytes().replace(b'"sequence":', b'"sequence":999, "sequence":'))
    with pytest.raises(ReceiptPinError, match="seal mismatch"):
        verify_image_with_sealed_pin(image, key, pin, report["seal_sha256"])
    assert image.read_bytes() == original_image


def test_untrusted_pin_in_image_directory_and_nonprivate_directory_rejected(state):
    image, key, receipt, _image_id, pin_dir = state
    with pytest.raises(ReceiptPinError, match="must not share"):
        pin_trusted_image(image, key, receipt, image.with_suffix(".kpin"))
    if os.name == "posix":
        pin_dir.chmod(0o777)
        with pytest.raises(ReceiptPinError, match="not group/world writable"):
            pin_trusted_image(image, key, receipt, pin_dir / "unsafe.kpin")
        pin_dir.chmod(0o700)


def test_parent_fsync_failure_is_not_reported_as_success(state, monkeypatch):
    import research.receipt_anchor as pins
    image, key, receipt, _image_id, pin_dir = state

    def fail_fsync(_path):
        raise OSError("injected directory durability failure")

    monkeypatch.setattr(pins, "_flush_parent", fail_fsync)
    with pytest.raises(OSError, match="durability failure"):
        pin_trusted_image(image, key, receipt, pin_dir / "failed.kpin")
    # An uncertain result leaves its exclusive-created name occupied, rather
    # than silently overwriting it on a retry.
    assert (pin_dir / "failed.kpin").exists()
    with pytest.raises(ReceiptPinError, match="Refusing to overwrite"):
        pin_trusted_image(image, key, receipt, pin_dir / "failed.kpin")


def test_reject_malformed_sealed_document_even_if_digest_is_known(state):
    import research.receipt_anchor as pins
    image, key, _, _, pin_dir = state
    _pin(state)
    path = pin_dir / "baseline.kpin"
    doc = json.loads(path.read_text())
    doc["sequence"] = True
    modified = pins._canonical(doc)
    path.write_bytes(modified)
    with pytest.raises(ReceiptPinError, match="Noncanonical or invalid"):
        verify_image_with_sealed_pin(image, key, path, pins._seal(modified))
