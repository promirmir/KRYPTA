"""Explicit Linux-only opt-in entrypoint for KRYPTA-FS/0 FUSE research mount.

Never mounts a disk/partition: opens an existing regular .kvi test file only.
NEVER put a volume key in argv, an environment variable or a command history.
No setup/format; no automatic mount; no background service.
"""
from __future__ import annotations

import argparse
import os
import platform
import stat
import sys

from .linux_fuse import mount_research_image
from .volume_image import ResearchVolume


def read_test_key_fd(fd: int) -> bytes:
    """Read exactly 32 opaque bytes from an anonymous pipe/socket descriptor."""
    if type(fd) is not int or fd < 0:
        raise ValueError("Invalid key descriptor")
    if os.isatty(fd):
        raise ValueError("Interactive terminal cannot supply volume key bytes")
    st = os.fstat(fd)
    if not (stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode)):
        raise ValueError("Only a pipe/socket descriptor can supply the test key")
    raw = bytearray()
    try:
        while len(raw) < 32:
            fragment = os.read(fd, 32 - len(raw))
            if not fragment:
                raise ValueError("Expected exactly 32 bytes from test key pipe")
            raw.extend(fragment)
        return bytes(raw)
    finally:
        raw[:] = b"\0" * len(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="KRYPTA-FS/0 RESEARCH-ONLY FUSE adapter for disposable test images"
    )
    parser.add_argument("--image", required=True, help="Existing .kvi research file, NEVER a disk")
    parser.add_argument("--mountpoint", required=True, help="Existing empty private directory")
    parser.add_argument("--key-fd", type=int, required=True, help="Pipe/socket FD with 32 raw key bytes")
    parser.add_argument("--accept-research-risk", action="store_true",
                        help="Confirm no important files or system drives are involved")
    args = parser.parse_args(argv)
    if not args.accept_research_risk:
        parser.error("Explicit --accept-research-risk required: disposable test images only")
    if platform.system() != "Linux":
        parser.error("Real FUSE research mount supported on Linux only")
    key = read_test_key_fd(args.key_fd)
    # Existing ResearchVolume enforces regular *.kvi, single process owner,
    # authenticated commits and does not format/create a physical disk.
    with ResearchVolume(args.image, key, create=False) as volume:
        mount_research_image(volume, args.mountpoint)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError) as exc:
        # No URI, key, ciphertext or file contents in the error message.
        print("KRYPTA mount refused or failed: disposable research image only", file=sys.stderr)
        raise SystemExit(1) from None
