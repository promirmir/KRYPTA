"""Forensic read-only review of PVIMG/1 commits after an uncertain write.

An authenticated descendant of an independent old receipt is evidence of
history continuity ONLY. It is not proof of freshness, authorized mutation,
or a new trusted anti-rollback anchor. This API never writes or mounts media.
"""
from __future__ import annotations

import hmac
import json
import re
from pathlib import Path

from .paged_fs2 import PagedFS2
from .paged_volume import (
    FRAME, HEADER_BYTES, MAGIC, MAX_COMMIT_BYTES, MAX_RECORD_BYTES,
    PagedResearchVolume, PagedVolumeError, _json,
)


def _authenticated_lineage(volume: PagedResearchVolume, anchor: str) -> tuple[int | None, int]:
    """Scan the *already authenticated* committed chain under its read lock.

    Independently recheck canonical commit content, HMAC and previous receipt.
    Ignore records after the final authenticated commit: the forensic opener
    must never truncate, delete, salvage or promote a trailing partial write.
    """
    volume._check()
    if not volume.read_only:
        raise PagedVolumeError("Forensic lineage requires a read-only volume")
    position = HEADER_BYTES
    last_receipt = None
    last_sequence = -1
    anchor_sequence = None
    commits = 0
    last_commit_offset = volume._commit_offset
    while position <= last_commit_offset:
        volume._f.seek(position)
        header = volume._f.read(FRAME.size)
        if len(header) != FRAME.size:
            raise PagedVolumeError("Truncated committed frame header")
        magic, kind, length = FRAME.unpack(header)
        if (magic != b"KPG1" or kind not in (b"D", b"N", b"C")
                or length > MAX_RECORD_BYTES):
            raise PagedVolumeError("Invalid committed journal record")
        next_position = position + FRAME.size + length
        if next_position > last_commit_offset and position != last_commit_offset:
            raise PagedVolumeError("Overlapping authenticated commit boundary")
        if kind == b"C":
            if not 32 <= length <= MAX_COMMIT_BYTES:
                raise PagedVolumeError("Invalid authenticated commit record")
            signed = volume._f.read(length)
            if len(signed) != length:
                raise PagedVolumeError("Truncated authenticated commit")
            body_bytes, tag = signed[:-32], signed[-32:]
            expected_mac = hmac.digest(
                volume._mac_key, MAGIC + volume.id + body_bytes, "sha256"
            )
            if not hmac.compare_digest(tag, expected_mac):
                raise PagedVolumeError("Commit authentication failed")
            try:
                body = json.loads(body_bytes)
            except (UnicodeError, ValueError, TypeError) as exc:
                raise PagedVolumeError("Malformed authenticated commit") from exc
            if (not isinstance(body, dict) or set(body) != {"seq", "prev", "root"}
                    or _json(body) != body_bytes
                    or type(body["seq"]) is not int
                    or body["seq"] != last_sequence + 1
                    or body["prev"] != last_receipt):
                raise PagedVolumeError("Commit lineage continuity failed")
            receipt = volume._receipt(signed)
            last_sequence = body["seq"]
            last_receipt = receipt
            commits += 1
            if hmac.compare_digest(anchor, receipt):
                anchor_sequence = last_sequence
        position = next_position
    if (commits == 0 or position <= last_commit_offset
            or last_sequence != volume.sequence
            or not hmac.compare_digest(last_receipt, volume.receipt)):
        raise PagedVolumeError("Authenticated commit lineage mismatch")
    return anchor_sequence, commits


def review_uncertain_commit(
    image: str | Path,
    key: bytes,
    trusted_prior_receipt: str,
    *,
    expected_image_id: bytes | None = None,
) -> dict:
    """Reconcile one externally held prior receipt with a PFS/2 image.

    No trust is automatically promoted. A descendant is reported only after
    authentication of the complete reachable PFS/2 filesystem, but recovery
    still requires independent operator authorization / protected new anchor.
    """
    if (type(trusted_prior_receipt) is not str
            or re.fullmatch(r"[0-9a-f]{64}", trusted_prior_receipt) is None):
        raise PagedVolumeError("An independently trusted prior receipt is required")
    if expected_image_id is not None and (
            type(expected_image_id) is not bytes or len(expected_image_id) != 16):
        raise PagedVolumeError("Expected image ID must be exactly 16 bytes")
    with PagedResearchVolume(image, key, read_only=True) as volume:
        if (expected_image_id is not None
                and not hmac.compare_digest(expected_image_id, volume.id)):
            raise PagedVolumeError("Credential binding image ID mismatch")
        fs = PagedFS2(volume)
        verified = fs.verify_all()
        anchor_sequence, commits = _authenticated_lineage(
            volume, trusted_prior_receipt
        )
        if anchor_sequence is None:
            raise PagedVolumeError(
                "Trusted prior receipt not in authenticated chain; "
                "possible rollback, different image or broken trust. "
                "Do not accept the observed receipt."
            )
        delta = volume.sequence - anchor_sequence
        if delta < 0 or commits != volume.sequence + 1:
            raise PagedVolumeError("Authenticated sequence accounting failed")
        return {
            "review_only": True,
            "status": (
                "CURRENT_RECEIPT_MATCHES_PRIOR" if delta == 0
                else "DESCENDANT_FOUND_MANUAL_REVIEW_REQUIRED"
            ),
            "trusted_prior_receipt": trusted_prior_receipt,
            "trusted_prior_sequence": anchor_sequence,
            "observed_receipt_UNTRUSTED": volume.receipt,
            "observed_sequence": volume.sequence,
            "commits_since_prior": delta,
            "uncommitted_tail_present": volume._trim_offset is not None,
            "image_id": volume.id.hex(),
            "files_verified": verified["files_verified"],
            "bytes_verified": verified["bytes_verified"],
            "warning": (
                "Read-only evidence, NOT proof of latest state or safe "
                "authorization. No receipt promotion or write permitted."
            ),
        }
