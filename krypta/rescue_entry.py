"""Independent KRYPTA offline rescue console executable; NO Tk / no OS disks.

This is a separate binary from the encrypted-volume desktop GUI. Recovery
requires BOTH the offline recovery secret and an independently trusted receipt.
All recovered files are plaintext and must be stored on a safe private drive.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def self_test() -> int:
    """Real PFS/2 recovery smoke using only isolated throwaway .kpv files."""
    from krypta.volume_lab import create_image, import_file
    from research.paged_rescue import MANIFEST_NAME, rescue_export_all
    with tempfile.TemporaryDirectory(prefix="krypta-rescue-smoke-") as directory:
        root = Path(directory)
        image = root / "test.kpv"
        envelope = root / "credential.pvkey"
        recovery = root / "offline.recovery"
        passphrase = "Disposable long password for KRYPTA recovery self test!"
        initial = create_image(image, envelope, recovery, passphrase, passphrase)
        source = root / "unique-source.bin"
        payload = b"FULL-INDEPENDENT-KRYPTA-RESCUE-TEST" * 403
        source.write_bytes(payload)
        added = import_file(image, envelope, initial["receipt"], source,
                            password=passphrase)
        # Simulate a torn unfinished frame that forensic read-only must retain.
        with image.open("ab") as f:
            f.write(b"KPG1")
        before = image.read_bytes()
        out = root / "new-recovery-folder"
        result = rescue_export_all(image, envelope, recovery,
                                   added["receipt"], out)
        if result["files_verified"] != 1 or result["bytes_verified"] != len(payload):
            raise RuntimeError("Offline rescue verified count/size mismatch")
        if (out / source.name).read_bytes() != payload:
            raise RuntimeError("Offline rescue exported plaintext mismatch")
        if not (out / MANIFEST_NAME).is_file():
            raise RuntimeError("Offline rescue missing completion marker")
        if image.read_bytes() != before:
            raise RuntimeError("Forensic rescue modified original image")
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return self_test()
    from research.paged_rescue import main as rescue_main
    return rescue_main()


if __name__ == "__main__":
    raise SystemExit(main())
