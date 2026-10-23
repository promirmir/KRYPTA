"""Read-only forensic inspection of KRYPTA authenticated scratch sector roots.

NO write access, NO automatic receipt trust promotion, NO plaintext exports.
This diagnostic can establish internal AEAD authenticity but CANNOT establish
historical freshness after an attacker replaces the whole disk image.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .sealed_sector_image import (
    SealedSectorImage, SealedSectorError, _keys, _master,
    _read_header, _receipt, SECTOR_BYTES,
)
from .test_sector_transport import TestSectorTransport


def inspect_untrusted_roots(
    path: str | Path, master_key: bytes, *,
    physical_sectors: int, previously_trusted_receipt: str | None = None,
) -> dict:
    """Authenticate every candidate metadata slot without approving any writes.

    \`previously_trusted_receipt\` is optional external context, not an unlock
    override. A higher valid sequence is only an untrusted forensic candidate,
    never a reason to promote an anchor or resume writes automatically.
    """
    master = _master(master_key)
    if previously_trusted_receipt is not None and (
            type(previously_trusted_receipt) is not str or
            len(previously_trusted_receipt) != 64 or any(
                c not in "0123456789abcdef" for c in previously_trusted_receipt)):
        raise SealedSectorError("Prior independent receipt must be 64 lower-case hex")

    with TestSectorTransport(path, physical_sectors, read_only=True) as source:
        header = source.read_sector(0)
        volume_id, logical = _read_header(header, master, physical_sectors)
        _, meta_key, data_key = _keys(master, volume_id)

        # Construct a *decoder only*, not a writable/unlocked image.
        inspector = object.__new__(SealedSectorImage)
        inspector._io = source
        inspector._header = header
        inspector._id = volume_id
        inspector.logical_sectors = logical
        inspector._meta_key = meta_key
        inspector._data_key = data_key
        candidates: list[dict] = []
        for slot in (1, 2):
            raw = source.read_sector(slot)
            state = inspector._decode_slot(slot, raw)
            if state is None:
                continue
            verified = 0
            contents_valid = True
            for logical_index, entry in state["map"].items():
                address, nonce, tag = entry
                try:
                    encrypted = source.read_sector(address)
                    aad = (b"KRYPTA-DATA/1" + volume_id +
                           struct.pack(">II", int(logical_index), address))
                    plaintext = AESGCM(data_key).decrypt(
                        bytes.fromhex(nonce), encrypted + bytes.fromhex(tag), aad)
                    if len(plaintext) != SECTOR_BYTES:
                        contents_valid = False
                        break
                    verified += 1
                except (OSError, ValueError, InvalidTag):
                    contents_valid = False
                    break
            receipt = _receipt(header, raw)
            candidates.append({
                "metadata_slot": slot,
                "sequence": state["sequence"],
                "authenticated_metadata": True,
                "all_live_sectors_authenticated": contents_valid,
                "verified_sector_count": verified,
                "candidate_receipt_UNTRUSTED": receipt,
                "matches_prior_external_receipt": (
                    previously_trusted_receipt is not None and
                    receipt == previously_trusted_receipt
                ),
            })

        if not candidates:
            raise SealedSectorError("No authentic metadata candidate to inspect")
        candidates.sort(key=lambda c: c["sequence"], reverse=True)
        duplicate_sequences = (len(candidates) == 2 and
                               candidates[0]["sequence"] == candidates[1]["sequence"])
        return {
            "operation": "READ-ONLY FORENSIC REVIEW — NO TRUST PROMOTION",
            "review_only": True,
            "write_authorized": False,
            "trusted_receipt_changed": False,
            "volume_id": volume_id.hex(),
            "logical_sectors": logical,
            "candidates": candidates,
            "ambiguous_root_sequence": duplicate_sequences,
            "observed_highest_sequence_UNTRUSTED": candidates[0]["sequence"],
            "warning": (
                "AEAD proves internal authenticity, NOT that a candidate is the "
                "latest historical state. No receipt is automatically trusted. "
                "Preserve the image and independent prior receipt; manual "
                "offline reconciliation is required after interrupted commits."
            ),
        }
