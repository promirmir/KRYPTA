"""Non-destructive PVIMG/PFS2 development volume setup and credential recovery.

A separate command-line tool, NOT system or physical-disk encryption.
Passphrases never arrive in command-line arguments or environment variables.
"""
from __future__ import annotations

import argparse
import getpass
import os
import stat
import sys

from .paged_keys import (
    PagedKeyError, unlock_password, unlock_recovery,
    rewrap_password_with_recovery,
)
from .paged_volume import PagedResearchVolume, PagedVolumeError
from .paged_fs2 import PagedFS2
from .paged_rekey import rotate_pfs2_data_key


def read_password_fd(fd: int) -> str:
    """Receive a UTF-8 passphrase from anonymous pipe/socket, not terminal."""
    if type(fd) is not int or fd < 0 or os.isatty(fd):
        raise PagedKeyError("Passphrase must come from a nonterminal pipe/socket")
    desc = os.fstat(fd)
    if not (stat.S_ISFIFO(desc.st_mode) or stat.S_ISSOCK(desc.st_mode)):
        raise PagedKeyError("No files or terminals accepted for passphrase input")
    raw = bytearray()
    try:
        while len(raw) <= 4096:
            part = os.read(fd, min(512, 4097 - len(raw)))
            if not part:
                break
            raw.extend(part)
        if len(raw) > 4096:
            raise PagedKeyError("Passphrase bytes exceed maximum length")
        try:
            result = raw.decode("utf-8")
        except UnicodeError as exc:
            raise PagedKeyError("Passphrase pipe is not valid UTF-8") from exc
        if not result:
            raise PagedKeyError("Empty passphrase is not accepted")
        return result
    finally:
        raw[:] = bytes(len(raw))


def _password(args) -> str:
    if args.password_fd is not None:
        return read_password_fd(args.password_fd)
    if not sys.stdin.isatty() and not sys.stderr.isatty():
        raise PagedKeyError("Interactive password prompt requires a terminal or --password-fd")
    return getpass.getpass("KRYPTA password (input hidden): ")


def _new(args) -> None:
    """Create using the same verified dual-unlock service as desktop."""
    from krypta.volume_lab import create_image

    password = _password(args)
    report = create_image(args.image, args.envelope, args.recovery,
                          password, password)
    print("CREATED: KRYPTA-PFS/2 development image, password bundle and separate recovery file")
    print("IMAGE ID:", report["image_id"])
    print("EXTERNAL RECEIPT:", report["receipt"])
    print("Store the current RECEIPT in independently trusted storage; update it after every filesystem change.")
    print("Back up the recovery file OFF this machine and separately from the encrypted image.")


def _check(args) -> None:
    if args.recovery:
        key, expected_id = unlock_recovery(args.envelope, args.recovery)
    else:
        key, expected_id = unlock_password(args.envelope, _password(args))
    with PagedResearchVolume(args.image, key,
                             expected_receipt=args.expected_receipt,
                             read_only=True) as vol:
        if vol.id != expected_id:
            raise PagedKeyError("Unlocked key bundle belongs to a DIFFERENT encrypted image")
        fs = PagedFS2(vol)
        report = fs.verify_all()
        print("VERIFIED:", report["files_verified"], "encrypted files,",
              report["bytes_verified"], "authenticated plaintext bytes")
        print("IMAGE ID:", vol.id.hex())
        print("EXTERNAL RECEIPT:", report["receipt"])


def _offline_list_files(args) -> None:
    """List file names only after authenticating all live data using recovery."""
    from krypta.volume_lab import verify_image

    report = verify_image(args.image, args.envelope, args.expected_receipt,
                          recovery=args.recovery)
    print("VERIFIED RECOVERY IMAGE:", report["image_id"])
    print("AUTHENTICATED FILES:", report["files_verified"])
    for item in report["files"]:
        print("FILE:", repr(item["name"]), "BYTES:", item["size"])
    print("NO FILES EXPORTED. Trusted external receipt remains unchanged.")


def _offline_export_file(args) -> None:
    """Restore exactly one verified file with exclusive-create plaintext output."""
    from krypta.volume_lab import export_file

    report = export_file(args.image, args.envelope, args.expected_receipt,
                         args.name, args.output, recovery=args.recovery)
    print("EXPORTED VERIFIED PLAINTEXT:", repr(report["file"]))
    print("BYTES:", report["bytes_verified"])
    print("WARNING: Output is UNENCRYPTED. Protect its location and permissions.")
    print("EXTERNAL RECEIPT UNCHANGED:", report["receipt"])


def _recover(args) -> None:
    new_password = _password(args)
    info = rewrap_password_with_recovery(
        args.envelope, args.recovery, new_password, args.new_envelope
    )
    print("CREATED: new separately named encrypted password envelope")
    print("IMAGE ID:", info["image_id"])
    print("WARNING: The old envelope/password remain valid until data key rotation.")


def _rotate(args) -> None:
    new_password = _password(args)
    if args.old_password_fd is not None:
        if args.password_fd is not None and args.old_password_fd == args.password_fd:
            raise PagedKeyError("Old/new password pipes must be different")
        old_password = read_password_fd(args.old_password_fd)
        old_recovery = None
    else:
        old_password = None
        old_recovery = args.old_recovery
    result = rotate_pfs2_data_key(
        args.image, args.envelope, args.expected_receipt,
        args.new_image, args.new_envelope, args.new_recovery, new_password,
        old_password=old_password, old_recovery=old_recovery,
    )
    print("CREATED: independent re-encrypted PVIMG/PFS2 image and NEW credentials")
    print("NEW IMAGE ID:", result["destination_image_id"])
    print("NEW EXTERNAL RECEIPT:", result["destination_receipt"])
    print("VERIFIED FILES:", result["files_verified"])
    print("WARNING: old image snapshots with old credentials REMAIN decryptable.")
    print("Store new receipt externally and back up the NEW recovery key separately.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="KRYPTA independent encrypted development image key management"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    new = sub.add_parser("create", help="Create a NEW PFS/2 .kpv plus credential files")
    new.add_argument("--image", required=True)
    new.add_argument("--envelope", required=True)
    new.add_argument("--recovery", required=True)
    new.add_argument("--password-fd", type=int)
    new.add_argument("--acknowledge-test-only", action="store_true")

    verify = sub.add_parser("verify", help="Read an existing volume using password or recovery")
    verify.add_argument("--image", required=True)
    verify.add_argument("--envelope", required=True)
    verify.add_argument("--recovery", help="Separate 32-byte secret file instead of password")
    verify.add_argument("--password-fd", type=int)
    verify.add_argument("--expected-receipt", required=True)
    verify.add_argument("--acknowledge-test-only", action="store_true")

    # Offline recovery does not require the desktop GUI or a password.
    offline_list = sub.add_parser("list-files",
                                  help="Verify and list files using offline recovery key")
    offline_export = sub.add_parser("export-file",
                                    help="Restore ONE authenticated file to NEW plaintext")
    for action in (offline_list, offline_export):
        action.add_argument("--image", required=True)
        action.add_argument("--envelope", required=True)
        action.add_argument("--recovery", required=True)
        action.add_argument("--expected-receipt", required=True,
                            help="Trusted current image receipt from separate storage")
        action.add_argument("--acknowledge-test-only", action="store_true")
    offline_export.add_argument("--name", required=True,
                                help="Exact name from list-files")
    offline_export.add_argument("--output", required=True,
                                help="NEW output path; never overwrite existing files")

    recovery = sub.add_parser("recover-password", help="Create a new password envelope using recovery")
    recovery.add_argument("--envelope", required=True)
    recovery.add_argument("--recovery", required=True)
    recovery.add_argument("--new-envelope", required=True)
    recovery.add_argument("--password-fd", type=int)
    recovery.add_argument("--acknowledge-test-only", action="store_true")

    rotation = sub.add_parser(
        "rotate-volume-key", help="Create a NEW image with a truly independent data key"
    )
    rotation.add_argument("--image", required=True, help="EXISTING source .kpv")
    rotation.add_argument("--envelope", required=True, help="Old .pvkey envelope")
    rotation.add_argument("--expected-receipt", required=True,
                          help="Independently trusted current SOURCE commit receipt")
    rotation.add_argument("--new-image", required=True)
    rotation.add_argument("--new-envelope", required=True)
    rotation.add_argument("--new-recovery", required=True)
    rotation.add_argument("--password-fd", type=int, help="NEW long password from pipe")
    old_factor = rotation.add_mutually_exclusive_group(required=True)
    old_factor.add_argument("--old-password-fd", type=int,
                            help="Old passphrase via a different anonymous pipe")
    old_factor.add_argument("--old-recovery",
                            help="Independent OLD recovery file instead of old passphrase")
    rotation.add_argument("--acknowledge-test-only", action="store_true")

    args = parser.parse_args(argv)
    if not args.acknowledge_test_only:
        parser.error("Explicit --acknowledge-test-only is required")
    if args.command == "create":
        _new(args)
    elif args.command == "verify":
        if args.recovery is not None and args.password_fd is not None:
            parser.error("Select either recovery file or password pipe, not both")
        _check(args)
    elif args.command == "list-files":
        _offline_list_files(args)
    elif args.command == "export-file":
        _offline_export_file(args)
    elif args.command == "recover-password":
        _recover(args)
    elif args.command == "rotate-volume-key":
        _rotate(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PagedKeyError, PagedVolumeError, OSError, ValueError):
        print("KRYPTA test key operation failed; no secret details disclosed",
              file=sys.stderr)
        raise SystemExit(1) from None
