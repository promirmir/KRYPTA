"""Deterministic model-based tests for KRYPTA's experimental encrypted image.

These tests do not establish physical disk crash durability or audit crypto.
They test API consistency under random overlapping byte writes and ambiguous
success/failure near the authenticated commit boundary.
"""
from __future__ import annotations

import os
import random

import pytest

from research.volume_image import BLOCK_BYTES, MAX_BLOCKS, ResearchVolume, VolumeImageError


def test_randomized_logical_writes_match_plaintext_oracle(tmp_path):
    rng = random.Random(0x4B5259505441)
    p = tmp_path / "model.kvi"
    key = os.urandom(32)
    expected = bytearray(MAX_BLOCKS * BLOCK_BYTES)
    with ResearchVolume(p, key, create=True) as image:
        for step in range(150):
            offset = rng.randrange(0, len(expected))
            count = rng.randrange(1, min(4500, len(expected) - offset) + 1)
            data = rng.randbytes(count)
            current_seq = image.write_at(offset, data)
            expected[offset:offset+count] = data
            assert current_seq == step + 1
            assert image.read_at(offset, count) == data
            start = rng.randrange(len(expected))
            length = rng.randrange(0, min(3000, len(expected) - start) + 1)
            assert image.read_at(start, length) == expected[start:start+length]
        receipt = image.commit_receipt
    with ResearchVolume(p, key, expected_sequence=150, expected_receipt=receipt) as reopened:
        for i in range(MAX_BLOCKS):
            assert reopened.read(i) == expected[i*BLOCK_BYTES:(i+1)*BLOCK_BYTES]


def test_complete_commit_with_failed_ack_is_detected_as_uncertain(tmp_path, monkeypatch):
    p = tmp_path / "ambiguous.kvi"
    key = os.urandom(32)
    with ResearchVolume(p, key, create=True) as image:
        first_receipt = image.commit_receipt
        saved_frame = image._frame
        def lost_ack(kind, payload):
            result = saved_frame(kind, payload)
            if kind == b"C":
                raise OSError("simulated crash after durable append and before ACK")
            return result
        monkeypatch.setattr(image, "_frame", lost_ack)
        with pytest.raises(OSError, match="simulated crash"):
            image.write_many({1: b"A" * BLOCK_BYTES, 2: b"B" * BLOCK_BYTES})
        assert image.sequence == 0  # handle may not assume committed result
        with pytest.raises(VolumeImageError, match="Uncertain"):
            image.read(1)
    # Commit is present on disk even though the caller saw a failed operation.
    with ResearchVolume(p, key) as recovered:
        assert recovered.sequence == 1
        assert recovered.commit_receipt != first_receipt
        assert recovered.read(1) == b"A" * BLOCK_BYTES
        assert recovered.read(2) == b"B" * BLOCK_BYTES
    # A stale protected receipt FAILS CLOSED instead of silently approving it.
    with pytest.raises(VolumeImageError, match="receipt mismatch"):
        ResearchVolume(p, key, expected_receipt=first_receipt)


def test_adversarial_reopen_random_transaction_points(tmp_path, monkeypatch):
    p, key = tmp_path / "cut.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as volume:
        assert volume.write_many({2: b"2"*BLOCK_BYTES, 3: b"3"*BLOCK_BYTES}) == 1
        baseline = p.read_bytes()
        trusted_receipt = volume.commit_receipt
    # Each synthetic power cut is run from the same baseline image, using the
    # same external receipt. Partial data writes must never become valid state.
    for fail_after in (0, 1, 2):
        p.write_bytes(baseline)
        with ResearchVolume(p, key, expected_sequence=1, expected_receipt=trusted_receipt) as image:
            true_frame = image._frame
            seen = 0
            def maybe_cut(kind, payload):
                nonlocal seen
                if seen == fail_after:
                    raise OSError("injected pre-frame failure")
                seen += 1
                return true_frame(kind, payload)
            monkeypatch.setattr(image, "_frame", maybe_cut)
            with pytest.raises(OSError):
                image.write_many({2: b"X"*BLOCK_BYTES, 3: b"Y"*BLOCK_BYTES})
        with ResearchVolume(p, key, expected_sequence=1, expected_receipt=trusted_receipt) as restored:
            assert restored.read(2) == b"2"*BLOCK_BYTES
            assert restored.read(3) == b"3"*BLOCK_BYTES


def test_external_receipt_cannot_be_claimed_secure_when_stored_in_image(tmp_path):
    p, key = tmp_path / "untrusted.kvi", os.urandom(32)
    with ResearchVolume(p, key, create=True) as volume:
        original = volume.commit_receipt
        assert len(original) == 64
        assert volume.write_at(0, b"secret test value") == 1
        current = volume.commit_receipt
    assert current != original
    # The image itself must not embed the external trusted receipt as its
    # authority. A caller must store/authenticate it in an independent trust
    # boundary (not implemented by this module).
    assert current.encode("ascii") not in p.read_bytes()
