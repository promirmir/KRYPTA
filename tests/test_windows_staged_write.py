"""Crash/rollback gates for one-file staged Windows PFS/2 writes.

No WinFsp or live drives; disposable .kpv files and ephemeral keys only.
"""
import os

import pytest

from research.paged_fs2 import PagedFS2, PagedFS2Error
from research.paged_volume import PagedResearchVolume, PagedVolumeError
from research.windows_file_ops import WindowsFileOperations
from research.windows_staged_write import (
    MAX_STAGED_FILE_BYTES, StagedWindowsFileWrite, UncertainStagedCommit,
)


@pytest.fixture
def image(tmp_path):
    path, key = tmp_path / "staged.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        fs = PagedFS2.format(volume)
        fs.write_file("one.txt", b"original")
        yield path, key, volume, fs, WindowsFileOperations(fs)


def test_staging_does_not_mutate_image_and_abort_preserves_receipt(image):
    path, _, _, fs, ops = image
    old = fs.receipt
    original_bytes = path.read_bytes()
    with StagedWindowsFileWrite(ops, r"\one.txt", old) as session:
        assert session.write(2, b"NEW") == 3
        session.truncate(11)
        assert session.read(0, 11) == b"orNEWnal" + bytes(3)
        assert ops.read(r"\one.txt", 0, 20) == b"original"
        assert fs.receipt == old
        assert path.read_bytes() == original_bytes
    assert fs.receipt == old
    assert path.read_bytes() == original_bytes
    with pytest.raises(PagedFS2Error, match="ended"):
        session.commit()


def test_single_atomic_commit_and_reopen_against_new_external_receipt(image):
    path, key, volume, fs, ops = image
    initial = fs.receipt
    initial_sequence = fs.sequence
    stage = StagedWindowsFileWrite(ops, r"\one.txt", initial)
    stage.write(2, b"NEW")
    stage.truncate(12)
    stage.write(11, b"!")
    assert fs.receipt == initial
    report = stage.commit()
    assert report["receipt_changed"] is True
    assert report["receipt"] != initial
    assert report["sequence"] == initial_sequence + 1
    expected = b"orNEWnal" + bytes(3) + b"!"
    assert fs.read_file("one.txt") == expected
    assert fs.verify_all()["receipt"] == report["receipt"]
    with pytest.raises(PagedFS2Error, match="ended"):
        stage.write(0, b"x")
    volume.close()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(path, key, expected_receipt=initial)
    with PagedResearchVolume(path, key, expected_receipt=report["receipt"],
                             read_only=True) as reopened:
        assert PagedFS2(reopened).read_file("one.txt") == expected


def test_noop_commit_does_not_advance_receipt(image):
    _, _, _, fs, ops = image
    initial = fs.receipt
    with StagedWindowsFileWrite(ops, r"\one.txt", initial) as stage:
        out = stage.commit()
    assert out == {"receipt": initial, "receipt_changed": False,
                   "sequence": fs.sequence}


def test_staged_edits_restored_to_empty_do_not_fake_receipt_change(image):
    path, _, _, fs, ops = image
    fs.write_file("empty.txt", b"")
    receipt = fs.receipt
    sequence = fs.sequence
    snapshot = path.read_bytes()
    stage = StagedWindowsFileWrite(ops, r"\empty.txt", receipt)
    stage.write(0, b"not-persisted")
    stage.truncate(0)
    result = stage.commit()
    assert result["receipt"] == receipt
    assert result["receipt_changed"] is False
    assert result["sequence"] == sequence
    assert path.read_bytes() == snapshot


def test_stale_base_detected_before_commit_without_overwriting(image):
    _, _, _, fs, ops = image
    initial = fs.receipt
    stage = StagedWindowsFileWrite(ops, r"\one.txt", initial)
    stage.write(0, b"staged")
    ops.write(r"\one.txt", 0, b"direct")
    current = fs.receipt
    with pytest.raises(PagedFS2Error, match="Stale staged base"):
        stage.commit()
    assert fs.receipt == current
    assert fs.read_file("one.txt") == b"directal"
    with pytest.raises(PagedFS2Error, match="ended"):
        stage.commit()


def test_wrong_or_missing_receipt_and_read_only_are_refused(image):
    path, key, volume, fs, ops = image
    for bad in ("", "z" * 64, "a" * 63, "X" * 64, None):
        with pytest.raises((ValueError, PagedFS2Error)):
            StagedWindowsFileWrite(ops, r"\one.txt", bad)
    receipt = fs.receipt
    volume.close()
    with PagedResearchVolume(path, key, expected_receipt=receipt,
                             read_only=True) as reopened:
        with pytest.raises(PagedFS2Error, match="Read-only"):
            StagedWindowsFileWrite(
                WindowsFileOperations(PagedFS2(reopened)), r"\one.txt", receipt
            )


@pytest.mark.parametrize("offset,data", [
    (-1, b"x"), (True, b"x"), (0, bytearray(b"x")),
    (MAX_STAGED_FILE_BYTES, b"x"), (0, "not bytes"),
])
def test_bad_write_does_not_change_staging_or_ciphertext(image, offset, data):
    path, _, _, fs, ops = image
    previous = path.read_bytes()
    receipt = fs.receipt
    with StagedWindowsFileWrite(ops, r"\one.txt", receipt) as stage:
        with pytest.raises(PagedFS2Error):
            stage.write(offset, data)
        assert stage.read(0, 8) == b"original"
        with pytest.raises(PagedFS2Error):
            stage.truncate(MAX_STAGED_FILE_BYTES + 1)
    assert fs.receipt == receipt
    assert path.read_bytes() == previous


def test_casefold_ambiguous_catalogue_rejected(image):
    _, _, _, fs, ops = image
    fs.write_file("ONE.TXT", b"other")
    with pytest.raises(PagedFS2Error, match="ambiguous"):
        StagedWindowsFileWrite(ops, r"\one.txt", fs.receipt)


def test_corrupt_existing_file_refuses_to_stage_before_side_effects(image, monkeypatch):
    path, _, _, fs, ops = image
    snapshot = path.read_bytes()
    monkeypatch.setattr(fs, "verify_all", lambda: (_ for _ in ()).throw(
        PagedFS2Error("Synthetic authenticated content corruption")))
    with pytest.raises(PagedFS2Error, match="corruption"):
        StagedWindowsFileWrite(ops, r"\one.txt", fs.receipt)
    assert path.read_bytes() == snapshot


def test_interruption_before_final_root_keeps_old_snapshot(image, monkeypatch):
    path, key, volume, fs, ops = image
    original = fs.receipt
    stage = StagedWindowsFileWrite(ops, r"\one.txt", original)
    stage.write(0, b"candidate")
    append = volume._append

    def interrupted(kind, payload):
        if kind == b"C":
            raise OSError("synthetic power interruption before commit record")
        return append(kind, payload)

    monkeypatch.setattr(volume, "_append", interrupted)
    with pytest.raises(UncertainStagedCommit) as error:
        stage.commit()
    assert error.value.unverified_receipt is None
    with pytest.raises(PagedVolumeError, match="Uncertain"):
        fs.read_file("one.txt")
    volume.close()
    with PagedResearchVolume(path, key, expected_receipt=original,
                             read_only=True) as recovered:
        assert PagedFS2(recovered).read_file("one.txt") == b"original"


def test_lost_commit_ack_is_not_misreported_as_rollback(image, monkeypatch):
    path, key, volume, fs, ops = image
    old_receipt = fs.receipt
    stage = StagedWindowsFileWrite(ops, r"\one.txt", old_receipt)
    stage.write(0, b"changed")
    original_commit = volume._commit

    def lose_ack(*args):
        original_commit(*args)
        raise OSError("synthetic lost durable commit acknowledgement")

    monkeypatch.setattr(volume, "_commit", lose_ack)
    with pytest.raises(UncertainStagedCommit) as error:
        stage.commit()
    assert error.value.unverified_receipt is None
    volume.close()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(path, key, expected_receipt=old_receipt,
                            read_only=True)
    # Diagnostic scan WITHOUT a trusted receipt is NOT rollback protection.
    with PagedResearchVolume(path, key, read_only=True) as diagnostic:
        assert PagedFS2(diagnostic).read_file("one.txt") == b"changedl"


def test_postcommit_authentication_failure_returns_only_untrusted_candidate(
        image, monkeypatch):
    path, key, volume, fs, ops = image
    old_receipt = fs.receipt
    stage = StagedWindowsFileWrite(ops, r"\one.txt", old_receipt)
    stage.write(0, b"updated")
    original_verify = fs.verify_all
    calls = 0

    def fail_readback():
        nonlocal calls
        calls += 1
        if calls == 2:  # precommit full sweep passed, postcommit fails
            raise PagedFS2Error("synthetic postcommit verification failed")
        return original_verify()

    monkeypatch.setattr(fs, "verify_all", fail_readback)
    with pytest.raises(UncertainStagedCommit) as error:
        stage.commit()
    candidate = error.value.unverified_receipt
    assert isinstance(candidate, str) and len(candidate) == 64
    assert candidate != old_receipt
    volume.close()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(path, key, expected_receipt=old_receipt)
    # A receipt from the failed check is only forensic, NEVER auto-trusted.
    with PagedResearchVolume(path, key, expected_receipt=candidate,
                             read_only=True) as diagnostic:
        assert PagedFS2(diagnostic).read_file("one.txt") == b"updatedl"
