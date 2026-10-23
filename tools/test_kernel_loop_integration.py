"""Strict REAL Linux kernel-loop write/read integration (isolated scratch only).

Executed as root in a disposable GitHub runner. It creates a new .kdevtest
file, attaches only that file to a free /dev/loopN, writes AES-GCM ciphertext
through the block device and verifies receipt-gated recovery. Cannot attach
physical USB/SSD/HDD devices. Failure to access kernel loop is a TEST FAILURE,
not a skipped or simulated pass.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from research.paged_aead_v2 import PagedAEADImage, PagedAEADError
from research.linux_loop_aead import open_lab_loop_v2

LOOP_PATTERN = re.compile(r"/dev/loop(0|[1-9][0-9]*)\Z")


def _cmd(*args):
    completed = subprocess.run(
        args, capture_output=True, text=True, check=False, timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Kernel-loop command failed ({args[0]}): " +
            (completed.stderr or completed.stdout).strip()[:600]
        )
    return completed.stdout.strip()


def run() -> int:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("Real loop test requires Linux root on a dedicated runner")
    with tempfile.TemporaryDirectory(prefix="krypta-real-kernel-loop-") as work:
        path = Path(work) / "single-use-research.kdevtest"
        key = secrets.token_bytes(32)
        with PagedAEADImage.create(path, key, physical_sectors=128,
                                   logical_sectors=64) as original:
            first = original.receipt
        if path.stat().st_mode & 0o077:
            raise RuntimeError("Scratch file is not private")
        loop = None
        try:
            loop = _cmd("losetup", "--find", "--show", str(path))
            if LOOP_PATTERN.fullmatch(loop) is None:
                raise RuntimeError("Kernel returned unexpected loop device path")
            with open_lab_loop_v2(loop, path, key, first, read_only=False) as disk:
                if disk.read_sector(9) != bytes(4096):
                    raise RuntimeError("Initial logical sector is not zero")
                disk.write_sector(9, b"K" * 4096)
                disk.write_at(4096 * 31 + 4094, b"cross-sector write")
                latest = disk.receipt
                if latest == first or disk.sequence != 2:
                    raise RuntimeError("COW commit/receipt not advanced")
                if disk.read_at(4096 * 31 + 4094, 18) != b"cross-sector write":
                    raise RuntimeError("Authenticated unaligned write failed")
            with open_lab_loop_v2(loop, path, key, latest) as reopened:
                if reopened.read_sector(9) != b"K" * 4096:
                    raise RuntimeError("Read-only reopen lost committed data")
                if reopened.verify_all()["verified_sectors"] != 3:
                    raise RuntimeError("Incomplete authenticated sector catalogue")
            try:
                with open_lab_loop_v2(loop, path, key, first):
                    raise RuntimeError("Stale trusted receipt was accepted")
            except PagedAEADError:
                pass
            print("REAL_KERNEL_LOOP_AEAD=PASS", loop, "receipts=verified", flush=True)
        finally:
            if loop and LOOP_PATTERN.fullmatch(loop):
                _cmd("losetup", "--detach", loop)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
