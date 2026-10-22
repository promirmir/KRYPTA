"""Portable adversarial WinFsp-shaped one-shot write callback tests.

No device mounts. Everything uses random keys and disposable temp .kpv files.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from research.paged_fs2 import PagedFS2
from research.paged_volume import PagedResearchVolume, PagedVolumeError
from research.receipt_anchor import ReceiptPinError, pin_trusted_image
from research.windows_file_ops import WindowsFileOperations
from research.windows_winfsp_staged_test import make_one_shot_test_winfsp_operations


class AccessDenied(Exception):
    pass


class WriteProtected(Exception):
    pass


class NotFound(Exception):
    pass


class EndOfFile(Exception):
    pass


class Base:
    pass


def api():
    return SimpleNamespace(
        BaseFileSystemOperations=Base,
        FILE_ATTRIBUTE=SimpleNamespace(FILE_ATTRIBUTE_DIRECTORY=16, FILE_ATTRIBUTE_ARCHIVE=32),
        NTStatusObjectNameNotFound=NotFound,
        NTStatusAccessDenied=AccessDenied,
        NTStatusMediaWriteProtected=WriteProtected,
        NTStatusEndOfFile=EndOfFile,
    )


@pytest.fixture
def harness():
    with (tempfile.TemporaryDirectory(prefix="krypta-staged-winfsp-") as d,
          tempfile.TemporaryDirectory(prefix="krypta-sealed-pin-") as p):
        root, pin_dir = Path(d), Path(p)
        image = root / "only-test.kpv"
        key = os.urandom(32)
        with PagedResearchVolume(image, key, create=True) as volume:
            fs = PagedFS2.format(volume)
            fs.write_file("sample.txt", b"original")
            receipt = fs.receipt
        pin = pin_dir / "v1.kpin"
        result = pin_trusted_image(image, key, receipt, pin)
        with PagedResearchVolume(
            image, key, expected_receipt=receipt
        ) as writer:
            fs = PagedFS2(writer)
            bridge = make_one_shot_test_winfsp_operations(
                WindowsFileOperations(fs), api(), test_root=root,
                trusted_pin_path=pin,
                independently_trusted_seal=result["seal_sha256"]
            )
            yield image, key, pin, result, writer, fs, bridge, root


def test_unflushed_write_is_private_and_unmount_abort_is_safe(harness):
    image, key, pin, result, writer, fs, bridge, root = harness
    before = image.read_bytes()
    h = bridge.open(r"\sample.txt", 0, 0x0002)
    assert bridge.write(h, b"CHANGED", 0, False, False) == 7
    assert bridge.read(h, 0, 8) == b"CHANGEDl"
    assert bridge.get_file_info(h)["file_size"] == 8
    assert fs.read_file("sample.txt") == b"original"
    assert image.read_bytes() == before
    with pytest.raises(WriteProtected):
        bridge.open(r"\sample.txt", 0, 0x0002)
    bridge.close(h)
    assert image.read_bytes() == before
    assert bridge.observed_receipt_UNTRUSTED is None



def test_buffer_protocol_payload_is_accepted_and_invalid_buffer_rejected(harness):
    # winfspy's native binding uses CFFI buffers, not necessarily 'bytes'.
    # A standard non-bytes Python exporter proves this adapter does not
    # rely on a concrete bytes type, while retaining its bounded write gate.
    from array import array

    image, key, pin, result, writer, fs, bridge, root = harness
    before = image.read_bytes()
    h = bridge.open(r"\\sample.txt", 0, 0x0002)
    try:
        assert bridge.write(h, array("B", b"ADAPTED!"), 0, False, False) == 8
        assert bridge.read(h, 0, 8) == b"ADAPTED!"
        with pytest.raises(AccessDenied):
            bridge.write(h, object(), 0, False, False)
        assert image.read_bytes() == before
    finally:
        bridge.close(h)


def test_one_flush_commits_single_root_and_blocks_more_writes(harness):
    image, key, pin, result, volume, fs, bridge, root = harness
    prior = fs.receipt
    start_seq = fs.sequence
    h = bridge.open(r"\sample.txt", 0, 0x0002)
    assert bridge.write(h, b"UPDATED", 0, False, False) == 7
    assert fs.receipt == prior
    bridge.flush(h)
    assert fs.sequence == start_seq + 1
    assert fs.read_file("sample.txt") == b"UPDATEDl"
    assert bridge.observed_receipt_UNTRUSTED == fs.receipt
    with pytest.raises(WriteProtected):
        bridge.write(h, b"again", 0, False, False)
    with pytest.raises(WriteProtected):
        bridge.open(r"\sample.txt", 0, 0x0002)
    with pytest.raises(WriteProtected):
        bridge.flush(h)
    bridge.close(h)
    volume.close()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(image, key, expected_receipt=prior, read_only=True)
    with PagedResearchVolume(image, key, expected_receipt=fs._volume.receipt,
                             read_only=True) as reopened:
        assert PagedFS2(reopened).read_file("sample.txt") == b"UPDATEDl"


def test_mutating_callbacks_are_fail_closed(harness):
    image, key, pin, result, volume, fs, bridge, root = harness
    first = image.read_bytes()
    h = bridge.open(r"\sample.txt", 0, 0x0002)
    for name, args in (
        ("create", ("new",)), ("rename", (h, "new")), ("can_delete", (h, "sample")),
        ("overwrite", (h,)), ("set_basic_info", (h,)), ("set_security", (h,)),
    ):
        with pytest.raises(WriteProtected):
            getattr(bridge, name)(*args)
    # WinFsp sends these optional metadata hints after a successful
    # native write. They are harmless only in the synthetic test adapter.
    assert bridge.cleanup(h, r"\sample.txt", 0xF0) is None
    with pytest.raises(WriteProtected):
        bridge.cleanup(h, r"\sample.txt", 0x01)
    with pytest.raises(WriteProtected):
        bridge.cleanup(h, r"\sample.txt", 0x02)
    with pytest.raises(WriteProtected):
        bridge.set_file_size(h, 9, True)
    with pytest.raises(AccessDenied):
        bridge.write(h, b"x", -1, False, False)
    with pytest.raises(AccessDenied):
        bridge.set_file_size(h, -1, False)
    with pytest.raises(NotFound):
        bridge.open(r"\missing.txt", 0, 0x0002)
    bridge.close(h)
    assert image.read_bytes() == first


def test_stale_pin_refused_before_write_adapter_creation(harness):
    image, key, pin, result, volume, fs, bridge, root = harness
    with pytest.raises(ReceiptPinError, match="seal mismatch"):
        make_one_shot_test_winfsp_operations(
            WindowsFileOperations(fs), api(), test_root=root,
            trusted_pin_path=pin, independently_trusted_seal="0" * 64
        )
    old = pin.read_bytes()
    pin.write_bytes(old.replace(b'"sequence":', b'"sequence":0,"sequence":'))
    with pytest.raises(ReceiptPinError, match="seal mismatch"):
        make_one_shot_test_winfsp_operations(
            WindowsFileOperations(fs), api(), test_root=root,
            trusted_pin_path=pin, independently_trusted_seal=result["seal_sha256"]
        )


def test_reject_real_or_unspecific_paths_even_with_valid_pin(harness):
    image, key, pin, result, volume, fs, bridge, root = harness
    with pytest.raises(ReceiptPinError, match="dedicated temp"):
        make_one_shot_test_winfsp_operations(
            WindowsFileOperations(fs), api(), test_root=root.parent,
            trusted_pin_path=pin, independently_trusted_seal=result["seal_sha256"]
        )
    with pytest.raises(ReceiptPinError, match="dedicated temp"):
        make_one_shot_test_winfsp_operations(
            WindowsFileOperations(fs), api(), test_root=root / "nonexistent",
            trusted_pin_path=pin, independently_trusted_seal=result["seal_sha256"]
        )


def test_two_threads_cannot_share_writer(harness):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    image, key, pin, result, volume, fs, bridge, root = harness
    before = image.read_bytes()
    trusted = fs.receipt
    gate = Barrier(3)

    def open_writer():
        gate.wait()
        try:
            return bridge.open(r"\sample.txt", 0, 0x0002)
        except WriteProtected:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(open_writer)
        two = pool.submit(open_writer)
        gate.wait()
        contexts = [one.result(), two.result()]
    assert sum(c is not None for c in contexts) == 1
    assert image.read_bytes() == before
    for ctx in contexts:
        if ctx is not None:
            bridge.close(ctx)
    assert fs.receipt == trusted


def test_commit_acknowledgement_lost_freezes_write_session(harness, monkeypatch):
    image, key, pin, result, volume, fs, bridge, root = harness
    before = fs.receipt
    h = bridge.open(r"\sample.txt", 0, 0x0002)
    bridge.write(h, b"changed", 0, False, False)
    original_commit = volume._commit

    def lost_ack(*args):
        original_commit(*args)
        raise OSError("simulated lost acknowledgment AFTER persisted commit")

    monkeypatch.setattr(volume, "_commit", lost_ack)
    with pytest.raises(AccessDenied):
        bridge.flush(h)
    assert bridge.observed_receipt_UNTRUSTED is None
    with pytest.raises(WriteProtected):
        bridge.write(h, b"another", 0, False, False)
    with pytest.raises(WriteProtected):
        bridge.open(r"\sample.txt", 0, 0x0002)
    bridge.close(h)
    volume.close()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(image, key, expected_receipt=before, read_only=True)
    # The post-crash newer receipt must NOT be trusted by the driver.
    assert pin.exists()
