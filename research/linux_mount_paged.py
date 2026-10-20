"""Opt-in Linux FUSE entrypoint for an EXISTING KRYPTA-PFS/1 .kpv test file.

No image formatting, disk enumeration, root privilege, key in argv/env or
automatic trusted-receipt creation. Ordinary file only, private mountpoint.
"""
from __future__ import annotations

import argparse
import platform
import sys

from .linux_mount import read_test_key_fd
from .linux_fuse import mount_paged_image
from .paged_volume import PagedResearchVolume


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="KRYPTA-PFS/1 development filesystem on a disposable .kpv file"
    )
    parser.add_argument("--image", required=True, help="Existing formatted .kpv file")
    parser.add_argument("--mountpoint", required=True, help="Empty private directory (0700)")
    parser.add_argument("--key-fd", type=int, required=True,
                        help="Pipe/socket descriptor containing a 32-byte key")
    parser.add_argument("--expected-receipt", required=True,
                        help="Latest trusted 64-hex receipt held OUTSIDE the image")
    parser.add_argument("--accept-development-risk", action="store_true",
                        help="Acknowledge this is NOT a production filesystem")
    args = parser.parse_args(argv)

    if not args.accept_development_risk:
        parser.error("Explicit risk acknowledgement is required")
    if platform.system() != "Linux":
        parser.error("The FUSE adapter runs only on Linux")
    key = read_test_key_fd(args.key_fd)
    with PagedResearchVolume(
        args.image, key, create=False, expected_receipt=args.expected_receipt
    ) as volume:
        mount_paged_image(volume, args.mountpoint)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError, TypeError):
        # Never print key, ciphertext, volume ID, mount path, or user content.
        print("KRYPTA-PFS mount refused or failed; development files only",
              file=sys.stderr)
        raise SystemExit(1) from None
