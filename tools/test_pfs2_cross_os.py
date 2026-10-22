"""Real cross-runner PFS/2 file-format interoperability on SYNTHETIC .kpv data.

CI: create on OS A -> authenticate and modify on OS B -> authenticate on A.
The test key and 'receipts' travel in the same public test artifact. This
proves interoperability only; it is NOT secure receipt custody/anti-rollback.
Nothing touches physical devices, user profiles or existing image files.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
from pathlib import Path

from research.paged_fs2 import PagedFS2
from research.paged_volume import PagedResearchVolume, PagedVolumeError

FILENAME = "synthetic-cross-platform.kpv"
INITIAL = "synthetic-initial.json"
UPDATED = "synthetic-updated.json"
ORIGINAL = bytes((index * 17 + 11) % 256 for index in range(13_321))
UNCHANGED = b"KRYPTA cross-platform test only: unmodified"
PATCH_AT = 4091
PATCH = b"WINDOWS-LINUX-INTEROPERABILITY"


def _manifest(directory: Path, name: str) -> dict:
    target = directory / name
    if target.is_symlink() or not target.is_file() or target.stat().st_size > 4096:
        raise ValueError("Missing or invalid synthetic test manifest")
    doc = json.loads(target.read_text(encoding="ascii"))
    if (not isinstance(doc, dict)
            or set(doc) != {"test_only", "key", "image_id", "receipt", "sequence", "origin"}
            or doc["test_only"] is not True
            or type(doc["sequence"]) is not int or doc["sequence"] < 0
            or doc["origin"] not in ("initial", "updated")):
        raise ValueError("Noncanonical test-only manifest")
    key = bytes.fromhex(doc["key"])
    if len(key) != 32 or len(bytes.fromhex(doc["image_id"])) != 16:
        raise ValueError("Invalid synthetic key/image identity")
    receipt = doc["receipt"]
    if (not isinstance(receipt, str) or len(receipt) != 64
            or any(c not in "0123456789abcdef" for c in receipt)):
        raise ValueError("Invalid test receipt")
    return doc


def _new_manifest(directory: Path, name: str, key: bytes, volume, origin: str):
    doc = {"test_only": True, "key": key.hex(),
           "image_id": volume.id.hex(), "receipt": volume.receipt,
           "sequence": volume.sequence, "origin": origin}
    # Exclusive creation: the test cannot overwrite a trusted manifest.
    with (directory / name).open("x", encoding="ascii") as destination:
        json.dump(doc, destination, sort_keys=True, separators=(",", ":"))
        destination.write("\n")


def _assert_initial(fs: PagedFS2):
    if (fs.read_file("origin.bin") != ORIGINAL
            or fs.read_file("untouched.txt") != UNCHANGED):
        raise AssertionError("Cross-platform initial plaintext differs")
    if fs.verify_all()["files_verified"] not in (2, 3):
        raise AssertionError("Cross-platform PFS/2 file count mismatch")


def _root(root: str) -> Path:
    p = Path(root)
    if p.is_symlink() or not p.is_dir():
        raise ValueError("Existing ordinary synthetic test directory required")
    return p.resolve(strict=True)


def create(root: str) -> None:
    directory = _root(root)
    key = secrets.token_bytes(32)
    with PagedResearchVolume(directory / FILENAME, key, create=True) as vol:
        fs = PagedFS2.format(vol)
        fs.write_file("origin.bin", ORIGINAL)
        fs.write_file("untouched.txt", UNCHANGED)
        _assert_initial(fs)
        _new_manifest(directory, INITIAL, key, vol, "initial")
    print("KRYPTA CROSS-OS CREATE synthetic image PASS")


def update(root: str) -> None:
    directory = _root(root)
    doc = _manifest(directory, INITIAL)
    if doc["origin"] != "initial":
        raise ValueError("Expected initial test manifest")
    key = bytes.fromhex(doc["key"])
    with PagedResearchVolume(directory / FILENAME, key,
                             expected_receipt=doc["receipt"],
                             expected_sequence=doc["sequence"]) as vol:
        if vol.id.hex() != doc["image_id"]:
            raise PagedVolumeError("Wrong test image identity")
        fs = PagedFS2(vol)
        _assert_initial(fs)
        fs.write_at("origin.bin", PATCH_AT, PATCH)
        fs.write_file("peer.txt", b"written on the independent middle OS")
        expected = ORIGINAL[:PATCH_AT] + PATCH + ORIGINAL[PATCH_AT + len(PATCH):]
        if fs.read_file("origin.bin") != expected:
            raise AssertionError("Cross-OS sector-boundary update differs")
        if fs.read_file("peer.txt") != b"written on the independent middle OS":
            raise AssertionError("Cross-OS additional file differs")
        if fs.verify_all()["files_verified"] != 3:
            raise AssertionError("Cross-OS post-write verification failed")
        if vol.sequence != doc["sequence"] + 2:
            raise AssertionError("Cross-OS unexpected commit count")
        if hmac.compare_digest(vol.receipt, doc["receipt"]):
            raise AssertionError("Cross-OS receipt did not advance")
        _new_manifest(directory, UPDATED, key, vol, "updated")
    print("KRYPTA CROSS-OS UPDATE synthetic image PASS")


def verify(root: str) -> None:
    directory = _root(root)
    prior = _manifest(directory, INITIAL)
    newer = _manifest(directory, UPDATED)
    if (prior["origin"] != "initial" or newer["origin"] != "updated"
            or prior["key"] != newer["key"]
            or prior["image_id"] != newer["image_id"]
            or newer["sequence"] != prior["sequence"] + 2
            or hmac.compare_digest(prior["receipt"], newer["receipt"])):
        raise ValueError("Unlinked cross-platform test manifests")
    path = directory / FILENAME
    if path.is_symlink():
        raise ValueError("Symlink is not a test image")
    before = hashlib.sha256(path.read_bytes()).digest()
    with PagedResearchVolume(path, bytes.fromhex(prior["key"]),
                             expected_receipt=newer["receipt"],
                             expected_sequence=newer["sequence"],
                             read_only=True) as vol:
        if vol.id.hex() != prior["image_id"]:
            raise PagedVolumeError("Unexpected test image identity")
        fs = PagedFS2(vol)
        expected = ORIGINAL[:PATCH_AT] + PATCH + ORIGINAL[PATCH_AT + len(PATCH):]
        if (fs.read_file("origin.bin") != expected
                or fs.read_file("untouched.txt") != UNCHANGED
                or fs.read_file("peer.txt") != b"written on the independent middle OS"):
            raise AssertionError("Incompatible cross-platform PFS/2 contents")
        if fs.verify_all()["files_verified"] != 3:
            raise AssertionError("Cross-platform authentication failed")
    if hashlib.sha256(path.read_bytes()).digest() != before:
        raise AssertionError("Read-only cross-platform check mutated image")
    # The old separately supplied receipt MUST NOT unlock an advanced image.
    try:
        with PagedResearchVolume(path, bytes.fromhex(prior["key"]),
                                 expected_receipt=prior["receipt"],
                                 read_only=True):
            pass
    except PagedVolumeError as exc:
        if "receipt mismatch" not in str(exc):
            raise
    else:
        raise AssertionError("Stale independent receipt was accepted")
    print("KRYPTA CROSS-OS VERIFY synthetic image PASS")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="KRYPTA synthetic-only cross-OS CI contract")
    parser.add_argument("--phase", required=True, choices=("create", "update", "verify"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--acknowledge-public-synthetic-key", action="store_true")
    args = parser.parse_args(argv)
    if not args.acknowledge_public_synthetic_key:
        parser.error("Explicit public synthetic test key acknowledgement required")
    {"create": create, "update": update, "verify": verify}[args.phase](args.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
