"""Opt-in Linux FUSE entrypoint for an EXISTING KRYPTA PFS/1 or PFS/2 test image.

No image formatting, disk enumeration, root privilege, key in argv/env or
automatic trusted-receipt creation. Ordinary file only, private mountpoint.
"""
from __future__ import annotations

import argparse
import platform
import sys

from .linux_mount import read_test_key_fd
from .paged_key_cli import read_password_fd
from .paged_keys import unlock_password, unlock_recovery, PagedKeyError
from .linux_fuse import mount_paged_image
from .paged_volume import PagedResearchVolume


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="KRYPTA-PFS/1 or PFS/2 encrypted development filesystem"
    )
    parser.add_argument("--image", required=True, help="Existing formatted .kpv file")
    parser.add_argument("--mountpoint", required=True, help="Empty private directory (0700)")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--key-fd", type=int,
                        help="Legacy pipe/socket containing raw 32-byte volume key")
    source.add_argument("--envelope",
                        help="Encrypted password/recovery bundle (.pvkey)")
    parser.add_argument("--password-fd", type=int,
                        help="Pipe/socket supplying long passphrase without argv/env")
    parser.add_argument("--recovery", help="Independent 32-byte recovery file, instead of password")
    parser.add_argument("--expected-receipt", required=True,
                        help="Latest trusted 64-hex receipt held OUTSIDE the image")
    parser.add_argument("--accept-development-risk", action="store_true",
                        help="Acknowledge this is NOT a production filesystem")
    args = parser.parse_args(argv)

    if not args.accept_development_risk:
        parser.error("Explicit risk acknowledgement is required")
    if platform.system() != "Linux":
        parser.error("The FUSE adapter runs only on Linux")
    if args.key_fd is not None:
        if args.password_fd is not None or args.recovery is not None:
            parser.error("Raw key descriptor cannot be mixed with password/recovery")
        key, expected_image_id = read_test_key_fd(args.key_fd), None
    else:
        if args.recovery is not None and args.password_fd is not None:
            parser.error("Choose either recovery file or password descriptor")
        if args.recovery is not None:
            key, expected_image_id = unlock_recovery(args.envelope, args.recovery)
        else:
            if args.password_fd is None:
                parser.error("Encrypted envelope requires --password-fd or --recovery")
            key, expected_image_id = unlock_password(
                args.envelope, read_password_fd(args.password_fd)
            )
    with PagedResearchVolume(
        args.image, key, create=False, expected_receipt=args.expected_receipt
    ) as volume:
        if expected_image_id is not None and volume.id != expected_image_id:
            raise PagedKeyError("Encrypted credential belongs to a different volume")
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
