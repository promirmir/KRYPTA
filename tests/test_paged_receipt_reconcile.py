"""Non-mutating uncertain-commit receipt lineage and CLI regression tests.

Only disposable PFS/2 .kpv files, random keys and fault injection are used.
"""
from __future__ import annotations

import json
import os

import pytest

from research.paged_fs2 import PagedFS2
from research.paged_volume import FRAME, PagedResearchVolume, PagedVolumeError
from research.paged_receipt_reconcile import review_uncertain_commit
from tools import review_uncertain_kpv as cli


@pytest.fixture
def lab(tmp_path):
    image = tmp_path / "review.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(image, key, create=True) as volume:
        fs = PagedFS2.format(volume)
        fs.write_file("example", b"original")
        yield image, key, volume, fs


def review(lab, anchor):
    image, key, vol, _ = lab
    return review_uncertain_commit(
        image, key, anchor, expected_image_id=vol.id
    )


def test_exact_prior_receipt_is_read_only_and_never_promoted(lab):
    image, key, vol, fs = lab
    receipt = fs.receipt
    initial = image.read_bytes()
    vol.close()
    result = review_uncertain_commit(
        image, key, receipt, expected_image_id=vol.id
    )
    assert result["review_only"] is True
    assert result["status"] == "CURRENT_RECEIPT_MATCHES_PRIOR"
    assert result["trusted_prior_receipt"] == receipt
    assert result["observed_receipt_UNTRUSTED"] == receipt
    assert result["commits_since_prior"] == 0
    assert result["files_verified"] == 1
    assert result["bytes_verified"] == len(b"original")
    assert result["uncommitted_tail_present"] is False
    assert image.read_bytes() == initial


def test_one_and_two_descendant_commits_need_manual_review(lab):
    image, key, vol, fs = lab
    prior = fs.receipt
    baseline = fs.sequence
    fs.write_at("example", 0, b"changed")
    fs.write_file("second", b"more")
    new_receipt = fs.receipt
    snapshot = image.read_bytes()
    vol.close()
    outcome = review_uncertain_commit(
        image, key, prior, expected_image_id=vol.id
    )
    assert outcome["status"] == "DESCENDANT_FOUND_MANUAL_REVIEW_REQUIRED"
    assert outcome["trusted_prior_sequence"] == baseline
    assert outcome["commits_since_prior"] == 2
    assert outcome["observed_sequence"] == baseline + 2
    assert outcome["observed_receipt_UNTRUSTED"] == new_receipt
    assert outcome["files_verified"] == 2
    assert image.read_bytes() == snapshot
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(image, key, expected_receipt=prior, read_only=True)


def test_missing_anchor_refuses_valid_but_rolled_back_image(lab):
    image, key, vol, fs = lab
    snapshot = image.read_bytes()
    fs.write_at("example", 0, b"later")
    trusted_newer = fs.receipt
    vol.close()
    image.write_bytes(snapshot)  # Synthetic rollback on throwaway image.
    before = image.read_bytes()
    with pytest.raises(PagedVolumeError, match="not in authenticated chain"):
        review_uncertain_commit(image, key, trusted_newer)
    assert image.read_bytes() == before


def test_anchor_for_different_same_key_image_fails(lab, tmp_path):
    image, key, vol, fs = lab
    previous_image_receipt = fs.receipt
    vol.close()
    other = tmp_path / "other.kpv"
    with PagedResearchVolume(other, key, create=True) as fresh:
        PagedFS2.format(fresh)
        other_id = fresh.id
    before = other.read_bytes()
    with pytest.raises(PagedVolumeError, match="not in authenticated chain"):
        review_uncertain_commit(other, key, previous_image_receipt)
    with pytest.raises(PagedVolumeError, match="binding image ID mismatch"):
        review_uncertain_commit(other, key, previous_image_receipt,
                                expected_image_id=vol.id)
    assert other_id != vol.id
    assert other.read_bytes() == before


def test_corrupted_live_ciphertext_blocks_any_reconciliation(lab):
    image, key, vol, fs = lab
    prior = fs.receipt
    data_frame = vol._entry(fs._files["example"]["blocks"][0])[1]
    vol.close()
    with open(image, "r+b") as handle:
        handle.seek(data_frame + FRAME.size + 27)
        current = handle.read(1)
        handle.seek(data_frame + FRAME.size + 27)
        handle.write(bytes([current[0] ^ 1]))
    corrupted = image.read_bytes()
    with pytest.raises(PagedVolumeError, match="tampering|authentication"):
        review_uncertain_commit(image, key, prior)
    assert image.read_bytes() == corrupted


def test_torn_uncommitted_tail_is_reported_not_trimmed(lab):
    image, key, vol, fs = lab
    trusted = fs.receipt
    vol.close()
    with open(image, "ab") as handle:
        handle.write(FRAME.pack(b"KPG1", b"D", 300))
        handle.write(b"torn-test-data")
    entire = image.read_bytes()
    result = review_uncertain_commit(image, key, trusted)
    assert result["uncommitted_tail_present"] is True
    assert result["status"] == "CURRENT_RECEIPT_MATCHES_PRIOR"
    assert image.read_bytes() == entire


def test_lost_ack_after_commit_is_detected_as_descendant(lab, monkeypatch):
    image, key, vol, fs = lab
    trusted_prior = fs.receipt
    previous = vol._commit

    def lose_ack(*args):
        previous(*args)
        raise OSError("simulated lost acknowledgment AFTER durable commit")

    monkeypatch.setattr(vol, "_commit", lose_ack)
    with pytest.raises(OSError, match="lost acknowledgment"):
        fs.write_at("example", 0, b"UPDATED")
    vol.close()
    snapshot = image.read_bytes()
    report = review_uncertain_commit(image, key, trusted_prior)
    assert report["status"] == "DESCENDANT_FOUND_MANUAL_REVIEW_REQUIRED"
    assert report["commits_since_prior"] == 1
    assert report["observed_receipt_UNTRUSTED"] != trusted_prior
    assert image.read_bytes() == snapshot


@pytest.mark.parametrize("invalid", ["", "b" * 63, "B" * 64, None, 2, True])
def test_invalid_external_anchor_refused_before_open(lab, invalid):
    image, key, vol, _ = lab
    before = image.read_bytes()
    vol.close()
    with pytest.raises(PagedVolumeError, match="trusted prior receipt"):
        review_uncertain_commit(image, key, invalid)
    assert image.read_bytes() == before


@pytest.mark.parametrize("invalid", [b"short", "bad", None if False else b"long" * 8])
def test_malformed_expected_image_identity_refused(lab, invalid):
    image, key, vol, fs = lab
    anchor = fs.receipt
    vol.close()
    with pytest.raises(PagedVolumeError, match="image ID"):
        review_uncertain_commit(image, key, anchor, expected_image_id=invalid)


def test_cli_never_accepts_password_argument():
    common = [
        "--image", "test.kpv", "--envelope", "test.pvkey",
        "--trusted-prior-receipt", "a" * 64,
        "--acknowledge-review-only",
    ]
    with pytest.raises(SystemExit):
        cli._arguments(common + ["--password", "insecure"])
    with pytest.raises(SystemExit):
        cli._arguments(common[:-1])
    with pytest.raises(SystemExit):
        cli._arguments(common[:5] + ["--trusted-prior-receipt", "wrong",
                                      "--acknowledge-review-only"])


def test_cli_requires_prompted_password_and_does_not_mutate_image(
        lab, tmp_path, capsys, monkeypatch):
    image, key, vol, fs = lab
    trusted_prior = fs.receipt
    image_id = vol.id
    vol.close()
    envelope = tmp_path / "test.pvkey"
    envelope.write_bytes(b"synthetic credential file only")
    monkeypatch.setattr(cli, "_get_key", lambda *a, **kw: (key, image_id))
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a: "secret-not-in-report")
    before = image.read_bytes()
    exit_code = cli.main([
        "--image", str(image), "--envelope", str(envelope),
        "--trusted-prior-receipt", trusted_prior,
        "--acknowledge-review-only",
    ])
    out = capsys.readouterr()
    assert exit_code == 0
    assert "secret-not-in-report" not in out.out + out.err
    assert json.loads(out.out)["status"] == "CURRENT_RECEIPT_MATCHES_PRIOR"
    assert image.read_bytes() == before


def test_cli_fail_closed_on_wrong_image_id(lab, tmp_path, capsys, monkeypatch):
    image, key, vol, fs = lab
    receipt = fs.receipt
    vol.close()
    envelope = tmp_path / "outside.pvkey"
    envelope.write_bytes(b"not a credential")
    monkeypatch.setattr(cli, "_get_key", lambda *a, **kw: (key, b"x" * 16))
    monkeypatch.setattr(cli.getpass, "getpass", lambda *a: "fake")
    original = image.read_bytes()
    rc = cli.main([
        "--image", str(image), "--envelope", str(envelope),
        "--trusted-prior-receipt", receipt,
        "--acknowledge-review-only",
    ])
    assert rc == 1
    assert "FAILED" in capsys.readouterr().err
    assert image.read_bytes() == original


def test_real_cli_self_test_exercises_disposable_encrypted_image(capsys):
    """No inputs from the user, no image mutation outside a private temp dir."""
    assert cli.main(["--self-test"]) == 0
    assert "synthetic self-test PASS" in capsys.readouterr().out
