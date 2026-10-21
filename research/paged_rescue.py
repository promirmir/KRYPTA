"""KRYPTA PFS/2 independent offline disaster-recovery export.

Reads ONLY a disposable ordinary .kpv image and existing PVKEY/1 credentials.
Uses an independent 256-bit offline recovery key, never a GUI, OS disk,
mountpoint, account, password argument, internet service, or private key dump.

Output is P-L-A-I-N-T-E-X-T. A NEW directory is required. Source is opened
forensic read-only and all files are verified BEFORE any plaintext is created.

This is development/research recovery, not secure filesystem or full disk.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys

from .paged_fs2 import PagedFS2
from .paged_keys import (
    PagedKeyError, unlock_recovery,
)
from .paged_volume import PagedResearchVolume
from .rescue_output import RescueError, private_output


MANIFEST_NAME = "KRYPTA_RESCUE_COMPLETE.json"


def _regular_input(path: Path, *, suffix: str | None = None) -> None:
    if suffix is not None and path.suffix.lower() != suffix:
        raise RescueError("Unexpected encrypted source file extension")
    if path.is_symlink():
        raise RescueError("Symbolic link inputs are forbidden")
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise RescueError("Recovery inputs must be ordinary files")


def _external_receipt(receipt: str) -> None:
    if (type(receipt) is not str or len(receipt) != 64
            or any(c not in "0123456789abcdef" for c in receipt)):
        raise RescueError("Supply 64-lowercase-hex trusted external receipt")


def _same_inode(a: Path, b: Path) -> bool:
    ia, ib = os.stat(a, follow_symlinks=False), os.stat(b, follow_symlinks=False)
    return (ia.st_dev, ia.st_ino) == (ib.st_dev, ib.st_ino)


def rescue_export_all(
    image: str | Path,
    envelope: str | Path,
    recovery: str | Path,
    trusted_receipt: str,
    new_directory: str | Path,
) -> dict:
    """Recover every file to a NEW private directory after full verification.

    Exclusive create for directory, files and final completion manifest.
    Normal failures clean owned entries through pinned directories/handles,
    never pre-existing files. Cleanup may leave output if identity is uncertain.
    A process crash may leave a PARTIAL directory or incomplete manifest:
    treat these as INCOMPLETE, not a finished backup.

    The completion manifest includes non-secret hashes/metadata, but is
    NOT signed, authenticated or protected against malicious modification.
    Preserve the trusted external receipt independently from the image.
    """
    image, envelope, recovery, destination = (
        Path(image), Path(envelope), Path(recovery), Path(new_directory)
    )
    _external_receipt(trusted_receipt)
    for p, suffix in ((image, ".kpv"), (envelope, ".pvkey"),
                      (recovery, None)):
        _regular_input(p, suffix=suffix)
    # Alias protections even when different pathnames are hardlinks.
    sources = [image, envelope, recovery]
    if len(set(p.resolve(strict=True) for p in sources)) != 3:
        raise RescueError("Input image, credentials and recovery must differ")
    if any(_same_inode(a, b) for i, a in enumerate(sources)
           for b in sources[i + 1:]):
        raise RescueError("Hardlinked recovery inputs are forbidden")
    if destination.is_symlink() or destination.exists():
        raise RescueError("Recovery output directory must not already exist")
    if not destination.name or destination.name in (".", ".."):
        raise RescueError("Invalid recovery destination directory")
    volume_key, image_id = unlock_recovery(envelope, recovery)
    with PagedResearchVolume(
        image, volume_key, expected_receipt=trusted_receipt, read_only=True
    ) as volume:
        if not hmac.compare_digest(volume.id, image_id):
            raise RescueError("Recovery credentials belong to a different image")
        fs = PagedFS2(volume)
        authenticated = fs.verify_all()
        names = fs.list_files()
        if MANIFEST_NAME.casefold() in {name.casefold() for name in names}:
            raise RescueError("Encrypted file name collides with rescue manifest")
        if len({name.casefold() for name in names}) != len(names):
            raise RescueError("Case-insensitive filename collision forbids safe export")

        # Do not create any output until every source file has passed
        # AEAD and SHA-256 integrity checks.
        with private_output(destination) as output:
            files: list[dict] = []
            for name in names:
                plaintext = fs.read_file(name)
                digest = hashlib.sha256(plaintext).hexdigest()
                if not hmac.compare_digest(digest, fs.stat(name)["sha256"]):
                    raise RescueError("Authenticated file digest mismatch")
                output.write(name, plaintext)
                files.append({"name": name, "bytes": len(plaintext), "sha256": digest})

            manifest = {
                "format": "KRYPTA-OFFLINE-RESCUE/1",
                "complete": True,
                "image_id": image_id.hex(),
                "trusted_external_receipt": trusted_receipt,
                "file_count": authenticated["files_verified"],
                "bytes_verified": authenticated["bytes_verified"],
                "files": files,
                "warning": "UNENCRYPTED recovered files. Manifest is not signed. "
                           "Preserve external receipt separately.",
            }
            if len(files) != authenticated["files_verified"] or (
                sum(x["bytes"] for x in files) != authenticated["bytes_verified"]
            ):
                raise RescueError("Recovery source file count or size changed")
            report = json.dumps(
                manifest, sort_keys=True, ensure_ascii=True, indent=2
            ).encode("utf-8") + b"\n"
            # Flush payloads before creating the completion marker. Windows
            # directory persistence has no power-loss guarantee here.
            output.sync()
            mpath = destination / MANIFEST_NAME
            output.write(MANIFEST_NAME, report)
            output.sync()
            return {
                "destination": str(destination),
                "image_id": image_id.hex(),
                "receipt": trusted_receipt,
                "files_verified": len(files),
                "bytes_verified": sum(x["bytes"] for x in files),
                "manifest": str(mpath),
                "warning": "RECOVERED FILES ARE UNENCRYPTED. Preserve receipt independently.",
            }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline PFS/2 disaster-recovery export of ALL files (PLAINTEXT)"
    )
    parser.add_argument("--image", required=True, help="Existing ordinary .kpv file")
    parser.add_argument("--envelope", required=True, help="Existing PVKEY/1 .pvkey")
    parser.add_argument("--recovery", required=True, help="Independent 32-byte offline recovery file")
    parser.add_argument("--trusted-receipt", required=True,
                        help="64-hex receipt from separately trusted storage")
    parser.add_argument("--new-directory", required=True,
                        help="NEW output directory for recovered UNENCRYPTED files")
    parser.add_argument("--acknowledge-plaintext-test-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.acknowledge_plaintext_test_only:
        parser.error("Explicit --acknowledge-plaintext-test-only is required")
    try:
        summary = rescue_export_all(
            args.image, args.envelope, args.recovery,
            args.trusted_receipt, args.new_directory,
        )
    except (RescueError, PagedKeyError, OSError, ValueError) as exc:
        print("KRYPTA RECOVERY FAILED: no result is authenticated or complete. "
              "Inspect the input, recovery key, receipt, disk space and permissions.",
              file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
