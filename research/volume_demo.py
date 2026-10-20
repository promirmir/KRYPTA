"""Offline KRYPTA experimental-volume smoke test. No persistent keys or user disks.

Run from the source tree: python -m research.volume_demo
"""
from __future__ import annotations

import json
import secrets
import tempfile
from pathlib import Path

from .volume_image import BLOCK_BYTES, ResearchVolume


def run_demo() -> dict:
    """Write, overwrite, reopen and verify only a temporary disposable image."""
    key = secrets.token_bytes(32)
    first = secrets.token_bytes(BLOCK_BYTES)
    second = secrets.token_bytes(BLOCK_BYTES)
    with tempfile.TemporaryDirectory(prefix="krypta-vimg-research-") as td:
        image = Path(td) / "temporary.kvi"
        with ResearchVolume(image, key, create=True) as volume:
            assert volume.read(11) == bytes(BLOCK_BYTES)
            assert volume.write(11, first) == 1
            assert volume.write(11, second) == 2
            assert volume.read(11) == second
        with ResearchVolume(image, key, expected_sequence=2) as volume:
            if volume.read(11) != second:
                raise RuntimeError("Test image did not round-trip")
            if volume.read(12) != bytes(BLOCK_BYTES):
                raise RuntimeError("An unwritten sector was altered")
    return {
        "format": "KRYPTA-VIMG/0",
        "result": "PASS",
        "blocks_overwritten": 1,
        "commit_sequence": 2,
        "persistent_key_or_test_data": False,
        "physical_disk_modified": False,
        "production_volume_encryption": False,
        "hardware_pin_protection": False,
    }


def main() -> int:
    print(json.dumps(run_demo(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())