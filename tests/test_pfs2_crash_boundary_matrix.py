"""Exhaustive *sampled framing* crash-cut matrix for PVIMG/1 + PFS/2.

Only disposable ordinary .kpv files in pytest tmp_path. These tests model a
file truncated at an I/O boundary; they do NOT prove physical-media durability
or authorized receipt promotion. No mounts and no device I/O occur.
"""
from __future__ import annotations

import os

import pytest

from research.paged_fs2 import PagedFS2
from research.paged_volume import (
    FRAME, HEADER_BYTES, PagedResearchVolume, PagedVolumeError,
)


def _frames(data: bytes, start: int):
    """Parse the *known-good* newly appended frame region into byte boundaries."""
    records = []
    cursor = start
    while cursor < len(data):
        magic, kind, length = FRAME.unpack_from(data, cursor)
        assert magic == b"KPG1"
        assert kind in (b"D", b"N", b"C")
        after = cursor + FRAME.size + length
        assert after <= len(data)
        records.append((cursor, cursor + FRAME.size, after, kind))
        cursor = after
    assert cursor == len(data)
    assert records and records[-1][3] == b"C"
    assert sum(kind == b"C" for *_, kind in records) == 1
    assert any(kind == b"D" for *_, kind in records)
    assert any(kind == b"N" for *_, kind in records)
    return records


def _cuts(records, complete_length):
    """Cut before, inside and after each frame, including EVERY commit byte."""
    cuts = set()
    for start, payload_start, end, kind in records:
        candidates = (
            start, start + 1, payload_start - 1, payload_start,
            payload_start + (end - payload_start) // 2,
            end - 1, end,
        )
        cuts.update(candidates)
        if kind == b"C":
            cuts.update(range(start, end + 1))
    assert all(records[0][0] <= i <= complete_length for i in cuts)
    return sorted(cuts)


def _fixture_image(tmp_path):
    path = tmp_path / "source.kpv"
    key = os.urandom(32)
    old_file = b"ORIGINAL-" + os.urandom(9000)
    new_file = b"UPDATED-" + os.urandom(11000)
    with PagedResearchVolume(path, key, create=True) as volume:
        fs = PagedFS2.format(volume)
        fs.write_file("important.bin", old_file)
        fs.write_file("unmodified.bin", b"other data retained")
        old_receipt = fs.receipt
        old_sequence = fs.sequence
        old_bytes = path.read_bytes()
        fs.write_file("important.bin", new_file, replace=True)
        assert fs.sequence == old_sequence + 1
        newest_receipt = fs.receipt
        newest_bytes = path.read_bytes()
        assert newest_receipt != old_receipt
    return (key, old_bytes, newest_bytes, old_receipt, newest_receipt,
            old_sequence, old_file, new_file)


def test_pfs2_all_commit_record_bytes_and_sampled_data_node_boundaries(tmp_path):
    (key, previous_image, next_image, previous_receipt, next_receipt,
     previous_seq, previous_file, updated_file) = _fixture_image(tmp_path)

    frames = _frames(next_image, len(previous_image))
    points = _cuts(frames, len(next_image))
    assert len(points) > 50
    # Crash outcome is unambiguous in this software model: a complete final
    # commit may be accepted ONLY at its final byte; all shorter prefixes
    # recover the independently trusted previous root, never half-updated.
    final_commit_end = frames[-1][2]
    assert final_commit_end == len(next_image)
    cut_path = tmp_path / "interrupted.kpv"
    for point in points:
        contents = next_image[:point]
        cut_path.write_bytes(contents)
        anchor = next_receipt if point == final_commit_end else previous_receipt
        target = updated_file if point == final_commit_end else previous_file
        target_seq = previous_seq + (point == final_commit_end)
        with PagedResearchVolume(
            cut_path, key, expected_receipt=anchor,
            expected_sequence=target_seq, read_only=True,
        ) as recovery:
            filesystem = PagedFS2(recovery)
            assert filesystem.sequence == target_seq
            assert filesystem.receipt == anchor
            assert filesystem.read_file("important.bin") == target
            assert filesystem.read_file("unmodified.bin") == b"other data retained"
            assert filesystem.verify_all()["files_verified"] == 2
            if point in (len(previous_image), final_commit_end):
                # Exactly on a committed boundary, there is no trailing tail.
                assert recovery._trim_offset is None
            else:
                assert recovery._trim_offset is not None
        # Read-only investigation must not trim a damaged tail, or alter data.
        assert cut_path.read_bytes() == contents


def test_complete_commit_never_accepts_stale_prior_receipt(tmp_path):
    key, previous, current, prior, latest, *_ = _fixture_image(tmp_path)
    path = tmp_path / "complete.kpv"
    path.write_bytes(current)
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(path, key, expected_receipt=prior, read_only=True)
    assert path.read_bytes() == current
    with PagedResearchVolume(path, key, expected_receipt=latest,
                             read_only=True) as fs:
        assert PagedFS2(fs).verify_all()["files_verified"] == 2


def test_corrupted_fully_present_commit_fails_closed_not_recovered_as_prior(tmp_path):
    key, previous, current, prior, _, *_ = _fixture_image(tmp_path)
    frames = _frames(current, len(previous))
    commit_offset, payload_offset, _, _ = frames[-1]
    path = tmp_path / "corrupt-commit.kpv"
    corrupt = bytearray(current)
    corrupt[payload_offset + 5] ^= 1
    path.write_bytes(corrupt)
    with pytest.raises(PagedVolumeError, match="MAC"):
        PagedResearchVolume(path, key, read_only=True)
    assert path.read_bytes() == corrupt


def test_committed_metadata_tamper_not_downgraded_to_previous_root(tmp_path):
    key, previous, current, prior, _, *_ = _fixture_image(tmp_path)
    frames = _frames(current, len(previous))
    nodes = [(start, payload, end) for start, payload, end, kind in frames
             if kind == b"N"]
    assert nodes
    path = tmp_path / "tampered-node.kpv"
    corrupt = bytearray(current)
    corrupt[nodes[-1][1] + 3] ^= 1
    path.write_bytes(corrupt)
    with pytest.raises(PagedVolumeError, match="digest mismatch|Noncanonical"):
        PagedResearchVolume(path, key, read_only=True)
    assert path.read_bytes() == corrupt
