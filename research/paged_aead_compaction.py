"""Out-of-place capacity reclamation for KRYPTA test-only .kdevtest images.

Requires the independently trusted source receipt, authenticates all live
data, creates a NEW volume identity, copies and re-encrypts live sectors,
reopens and verifies target. Never mutates or deletes the source.
"""
from __future__ import annotations

from pathlib import Path
import hmac

from .paged_aead_v2 import (
    FIRST_FREE, LEAF_ENTRIES, MAX_BATCH_SECTORS,
    PagedAEADImage, PagedAEADError, SECTOR_BYTES,
)
from .test_sector_transport import MIN_SECTORS, MAX_TEST_SECTORS


def compact_verified_copy(
    source_path: str | Path, target_path: str | Path, master_key: bytes,
    *, source_physical_sectors: int, expected_source_receipt: str,
    target_physical_sectors: int | None = None,
) -> dict:
    """Copy live authenticated sectors into a new independent scratch volume.

    NEVER automatically trusts the destination receipt. If interrupted,
    preserves the old image and any partial destination for inspection.
    """
    source_path, target_path = Path(source_path), Path(target_path)
    if source_path.resolve(strict=False) == target_path.resolve(strict=False):
        raise PagedAEADError("Source and target must be separate scratch files")
    with PagedAEADImage.open(
        source_path, master_key, physical_sectors=source_physical_sectors,
        expected_receipt=expected_source_receipt, read_only=True,
    ) as source:
        verified = source.verify_all()  # Mandatory BEFORE creating destination
        groups = []
        for page in sorted(int(k) for k in source._root["leaves"]):
            live = sorted(page * LEAF_ENTRIES + int(offset)
                          for offset in source._leaf(page))
            for start in range(0, len(live), MAX_BATCH_SECTORS):
                groups.append(live[start:start + MAX_BATCH_SECTORS])
        indexes = [i for group in groups for i in group]
        if len(indexes) != verified["verified_sectors"] or len(indexes) != len(set(indexes)):
            raise PagedAEADError("Inconsistent authenticated live allocation")

        # Each atomic batch allocates one COW leaf plus its live data sectors.
        required = FIRST_FREE + len(indexes) + len(groups)
        if required > MAX_TEST_SECTORS:
            raise PagedAEADError("Scratch-only target cannot fit live sectors")
        if target_physical_sectors is None:
            capacity = min(MAX_TEST_SECTORS,
                           max(MIN_SECTORS, required + max(8, required // 4)))
        elif (type(target_physical_sectors) is int and
              MIN_SECTORS <= target_physical_sectors <= MAX_TEST_SECTORS):
            capacity = target_physical_sectors
        else:
            raise PagedAEADError("Invalid destination test geometry")
        if capacity < required:
            raise PagedAEADError("Target too small for authenticated live sectors")

        with PagedAEADImage.create(
            target_path, master_key, physical_sectors=capacity,
            logical_sectors=source.logical_sectors,
        ) as target:
            for group in groups:
                target.write_many({i: source.read_sector(i) for i in group})
            if target.verify_all()["verified_sectors"] != len(indexes):
                raise PagedAEADError("New image authentication failed")
            candidate = target.receipt
            commits = target.sequence

        # Separate real reopening, not trusting an in-memory target object.
        with PagedAEADImage.open(
            target_path, master_key, physical_sectors=capacity,
            expected_receipt=candidate, read_only=True,
        ) as reopened:
            if (reopened.logical_sectors != source.logical_sectors or
                    reopened.verify_all()["verified_sectors"] != len(indexes)):
                raise PagedAEADError("Reopened candidate did not verify")
            for i in indexes:
                if not hmac.compare_digest(source.read_sector(i),
                                           reopened.read_sector(i)):
                    raise PagedAEADError("Source/target plaintext mismatch")
            if source.receipt != expected_source_receipt:
                raise PagedAEADError("Source receipt changed during inspection")

        return {
            "operation": "VERIFIED TEST-ONLY OUT-OF-PLACE COMPACTION",
            "source_modified": False,
            "source_receipt": expected_source_receipt,
            "target_candidate_receipt": candidate,
            "target_physical_sectors": capacity,
            "logical_sectors": source.logical_sectors,
            "live_sectors_verified": len(indexes),
            "bytes_verified": len(indexes) * SECTOR_BYTES,
            "target_sequence": commits,
            "physical_disk_write_authorized": False,
            "warning": "Keep the original. Independently store/pin the new "
                       "receipt before switching. No automatic trust promotion.",
        }
