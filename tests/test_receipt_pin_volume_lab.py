"""Desktop service receipt-pin integration, using only throwaway credentials."""
from __future__ import annotations

import pytest

from krypta.volume_lab import (
    create_image, import_file, seal_existing_trusted_receipt,
    verify_sealed_receipt_image,
)
from research.paged_volume import PagedVolumeError
from research.receipt_anchor import ReceiptPinError

PASSWORD = "A completely independent test passphrase 2026"


def test_desktop_service_pins_trusted_state_and_reads_with_recovery(tmp_path):
    image = tmp_path / "only-test.kpv"
    envelope = tmp_path / "keys.pvkey"
    recovery = tmp_path / "recovery.key"
    pins = tmp_path / "out-of-band-test-only"
    pins.mkdir(mode=0o700)
    pin = pins / "first.kpin"
    result = create_image(image, envelope, recovery, PASSWORD, PASSWORD)
    before = image.read_bytes()
    written = seal_existing_trusted_receipt(
        image, envelope, result["receipt"], pin, password=PASSWORD,
    )
    assert written["receipt_changed"] is False
    assert written["trust_promoted"] is False
    assert written["seal_sha256"]
    examined = verify_sealed_receipt_image(
        image, envelope, pin, written["seal_sha256"], recovery=recovery
    )
    assert examined["status"] == "SEALED_PIN_MATCH"
    assert examined["image_id"] == result["image_id"]
    assert examined["receipt_changed"] is False
    assert image.read_bytes() == before

    src = tmp_path / "next.bin"
    src.write_bytes(b"unapproved for automatic trust promotion")
    # This explicit, existing Volume Lab write requires old known receipt.
    imported = import_file(
        image, envelope, result["receipt"], src, password=PASSWORD
    )
    with pytest.raises(PagedVolumeError, match="possible rollback"):
        verify_sealed_receipt_image(
            image, envelope, pin, written["seal_sha256"], password=PASSWORD
        )
    with pytest.raises(PagedVolumeError, match="possible rollback"):
        seal_existing_trusted_receipt(
            image, envelope, result["receipt"], pins / "invalid.kpin",
            recovery=recovery,
        )
    assert not (pins / "invalid.kpin").exists()
    assert imported["receipt"] != result["receipt"]


def test_service_rejects_wrong_seal_before_image_access(tmp_path):
    image = tmp_path / "only-test.kpv"
    envelope = tmp_path / "keys.pvkey"
    recovery = tmp_path / "recovery.key"
    pins = tmp_path / "pins"
    pins.mkdir(mode=0o700)
    pin = pins / "anchor.kpin"
    created = create_image(image, envelope, recovery, PASSWORD, PASSWORD)
    sealed = seal_existing_trusted_receipt(
        image, envelope, created["receipt"], pin, recovery=recovery
    )
    before = image.read_bytes()
    with pytest.raises(ReceiptPinError, match="seal mismatch"):
        verify_sealed_receipt_image(
            image, envelope, pin, "0" * 64, password=PASSWORD
        )
    with pytest.raises(ReceiptPinError, match="independently trusted pin seal"):
        verify_sealed_receipt_image(image, envelope, pin, "", password=PASSWORD)
    with pytest.raises(ReceiptPinError, match="Refusing to overwrite"):
        seal_existing_trusted_receipt(
            image, envelope, created["receipt"], pin, password=PASSWORD
        )
    assert image.read_bytes() == before
    assert pin.is_file()
    assert sealed["seal_sha256"] != "0" * 64
