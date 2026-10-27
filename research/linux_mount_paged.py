"""Opt-in Linux FUSE entrypoint for an EXISTING KRYPTA PFS/1 or PFS/2 test image.

No image formatting, disk enumeration, root privilege, key in argv/env or
automatic trusted-receipt creation. Ordinary file only, private mountpoint.
"""
from __future__ import annotations

import argparse
import platform
import sys
from pathlib import Path

from .linux_mount import read_test_key_fd
from .paged_key_cli import read_password_fd
from .paged_keys import unlock_password, unlock_recovery, PagedKeyError, _new_private_file
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
    parser.add_argument("--final-receipt-out",
                        help="Optional NEW no-overwrite file for receipt AFTER successful unmount")
    parser.add_argument("--read-only", action="store_true",
                        help="Strict read-only kernel FUSE mount (no encrypted data writes)")
    parser.add_argument("--one-shot-staged-write", action="store_true",
                        help="TEST-ONLY: one bounded staged PFS/2 writer, exactly one flush commit")
    parser.add_argument("--test-root", help="Dedicated private direct child of system temp dir")
    parser.add_argument("--trusted-pin", help="Independent .kpin in another directory")
    parser.add_argument("--trusted-seal", help="Externally held SHA-256 seal of .kpin")
    parser.add_argument("--accept-development-risk", action="store_true",
                        help="Acknowledge this is NOT a production filesystem")
    args = parser.parse_args(argv)

    if not args.accept_development_risk:
        parser.error("Explicit risk acknowledgement is required")
    if platform.system() != "Linux":
        parser.error("The FUSE adapter runs only on Linux")
    if args.read_only and args.final_receipt_out:
        parser.error("Read-only mount must not publish an advanced receipt")
    if args.one_shot_staged_write:
        if (args.read_only or args.final_receipt_out or not args.test_root
                or not args.trusted_pin or not args.trusted_seal):
            parser.error("One-shot lab mount requires separate test root, trusted pin and seal, no auto-receipt")
    elif args.test_root or args.trusted_pin or args.trusted_seal:
        parser.error("One-shot pin/test-root flags require --one-shot-staged-write")
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
        args.image, key, create=False, expected_receipt=args.expected_receipt,
        read_only=args.read_only
    ) as volume:
        if expected_image_id is not None and volume.id != expected_image_id:
            raise PagedKeyError("Encrypted credential belongs to a different volume")
        if args.one_shot_staged_write:
            _, staged = mount_paged_image(
                volume, args.mountpoint, read_only=False, staged_one_shot=True,
                test_root=args.test_root, trusted_pin_path=args.trusted_pin,
                independently_trusted_seal=args.trusted_seal
            )
            candidate = staged.observed_receipt_UNTRUSTED
            if candidate is not None:
                print("OBSERVED RECEIPT — UNTRUSTED:", candidate)
                print("Un-mount completed. Independently authenticate and seal before next mount.")
            elif staged._ever_attempted:
                print("UNCERTAIN COMMIT: no receipt trusted. Preserve image and prior pin.")
            else:
                print("NO COMMIT: externally trusted receipt unchanged.")
        else:
            mount_paged_image(volume, args.mountpoint, read_only=args.read_only)
        # A fresh receipt is mandatory for the NEXT trusted open after writes.
        # The selected location is not automatically a trusted anti-rollback
        # store. Users must transfer it to independent protected storage.
        final_receipt = volume.receipt
        if args.final_receipt_out is not None:
            dest = Path(args.final_receipt_out)
            resolved = dest.resolve(strict=False)
            image = Path(args.image).resolve(strict=False)
            mountroot = Path(args.mountpoint).resolve(strict=False)
            if (resolved == image or resolved == mountroot or
                    mountroot in resolved.parents or
                    (args.envelope and resolved == Path(args.envelope).resolve(strict=False)) or
                    (args.recovery and resolved == Path(args.recovery).resolve(strict=False))):
                raise PagedKeyError("Unsafe external receipt destination")
            _new_private_file(dest, (final_receipt + "\n").encode("ascii"))
        if not args.one_shot_staged_write:
            print("FINAL RECEIPT:", final_receipt)
        if args.one_shot_staged_write:
            print("One-shot mount never promotes an observed receipt into trust.")
        elif args.read_only:
            print("READ ONLY: ciphertext and receipt were not advanced.")
        else:
            print("Store the latest receipt in independently trusted storage before the next mount.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError, TypeError):
        # Never print key, ciphertext, volume ID, mount path, or user content.
        print("KRYPTA-PFS mount refused or failed; development files only",
              file=sys.stderr)
        raise SystemExit(1) from None
