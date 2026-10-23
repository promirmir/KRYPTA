"""CI-only AES-GCM scratch-image interchange: never use real data or devices."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from research.sealed_sector_image import SealedSectorImage, SECTOR_BYTES

PHYSICAL = 128
IMAGE = "portable.kdevtest"
META = "ci-only-public-test-key.json"


def payload(label: str) -> bytes:
    chunks = []
    for i in range(SECTOR_BYTES // 32):
        chunks.append(hashlib.sha256(
            ("KRYPTA/SECTOR-CROSS-OS/" + label + "/" + str(i)).encode("ascii")
        ).digest())
    return b"".join(chunks)


def save(root: Path, doc: dict) -> None:
    (root / META).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")


def load(root: Path) -> dict:
    doc = json.loads((root / META).read_text(encoding="utf-8"))
    if (not isinstance(doc, dict) or doc.get("synthetic_only") is not True or
            type(doc.get("sequence")) is not int or
            type(doc.get("receipt")) is not str or
            type(doc.get("key")) is not str or
            not isinstance(doc.get("hashes"), dict)):
        raise RuntimeError("Invalid CI-only synthetic test manifest")
    return doc


def verify(image: SealedSectorImage, doc: dict) -> None:
    assert image.sequence == doc["sequence"]
    assert image.receipt == doc["receipt"]
    for idx, digest in doc["hashes"].items():
        assert hashlib.sha256(image.read_sector(int(idx))).hexdigest() == digest
    assert image.verify_all()["verified_sectors"] == len(doc["hashes"])


def run(phase: str, root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("Existing disposable CI test directory required")
    root = root.resolve(strict=True)
    path = root / IMAGE
    if phase == "create":
        key = os.urandom(32)
        with SealedSectorImage.create(path, key, physical_sectors=PHYSICAL,
                                      logical_sectors=16) as volume:
            a, b = payload("A"), payload("B")
            assert volume.write_many({0: a, 15: b}) == 1
            manifest = {
                "synthetic_only": True, "key": key.hex(),
                "sequence": 1, "receipt": volume.receipt,
                "hashes": {
                    "0": hashlib.sha256(a).hexdigest(),
                    "15": hashlib.sha256(b).hexdigest(),
                },
            }
            verify(volume, manifest)
        save(root, manifest)
    elif phase == "update":
        manifest = load(root)
        key = bytes.fromhex(manifest["key"])
        prior = manifest["receipt"]
        with SealedSectorImage.open(path, key, physical_sectors=PHYSICAL,
                                    expected_receipt=prior, read_only=False) as volume:
            verify(volume, manifest)
            content = payload("OTHER-OS")
            assert volume.write_sector(1, content) == 2
            manifest["hashes"]["1"] = hashlib.sha256(content).hexdigest()
            manifest["sequence"] = 2
            manifest["receipt"] = volume.receipt
            verify(volume, manifest)
        assert manifest["receipt"] != prior
        save(root, manifest)
    elif phase == "verify":
        manifest = load(root)
        assert manifest["sequence"] == 2
        assert set(manifest["hashes"]) == {"0", "1", "15"}
        with SealedSectorImage.open(
                path, bytes.fromhex(manifest["key"]),
                physical_sectors=PHYSICAL, expected_receipt=manifest["receipt"]
        ) as volume:
            verify(volume, manifest)
    else:
        raise ValueError("Invalid test phase")
    print("KRYPTA sealed sector actual cross-OS interchange PASS:", phase)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=("create", "update", "verify"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--public-synthetic-ci-key", action="store_true")
    opts = parser.parse_args()
    if not opts.public_synthetic_ci_key:
        parser.error("CI artifacts contain a PUBLIC throwaway key; acknowledge explicitly")
    run(opts.phase, opts.root)


if __name__ == "__main__":
    main()
