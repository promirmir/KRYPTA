"""Experimental owner-only Windows mount of a verified PFS/2 .kpv file.

This mounts a REGULAR encrypted test image, not a device or system partition.
It is deliberately read-only. A trusted current receipt is mandatory.
Requires Windows, WinFsp and winfspy; not included in release executables.
"""
from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
from pathlib import Path


def _drive_letter(value: str) -> str:
    """Validate a disposable mount drive; never accept C: or a path."""
    if not isinstance(value, str) or not re.fullmatch(r"[D-Zd-z]:", value):
        raise ValueError("Choose an unused drive letter from D: through Z:")
    return value.upper()


def _drive_is_free(drive: str, occupied_mask: int) -> bool:
    letter = _drive_letter(drive)
    return not bool(occupied_mask & (1 << (ord(letter[0]) - ord("A"))))


def _arguments(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        description="KRYPTA experimental read-only WinFsp mount; test images only"
    )
    parser.add_argument("--image", required=True, help="Existing ordinary .kpv image")
    parser.add_argument("--envelope", required=True, help="Matching .pvkey envelope")
    parser.add_argument("--expected-receipt", required=True,
                        help="Trusted CURRENT receipt kept independently of the image")
    parser.add_argument("--drive", required=True, help="Unused drive letter, e.g. Z:")
    parser.add_argument("--recovery", help="Separate recovery secret file; otherwise prompt for password")
    parser.add_argument("--acknowledge-test-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.acknowledge_test_only:
        parser.error("--acknowledge-test-only is required; this is NOT a production mount")
    try:
        args.drive = _drive_letter(args.drive)
    except ValueError as exc:
        parser.error(str(exc))
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_receipt):
        parser.error("--expected-receipt must be the exact 64-character lowercase hex receipt")
    return args


def _owner_read_security_descriptor():
    import win32api
    import win32con
    import win32security
    from winfspy.plumbing.security_descriptor import SecurityDescriptor

    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )
    try:
        sid = win32security.ConvertSidToStringSid(
            win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        )
    finally:
        token.Close()
    return SecurityDescriptor.from_string(
        f"O:{sid}G:{sid}D:P(A;;FRFX;;;SY)(A;;FRFX;;;{sid})"
    )


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    if os.name != "nt":
        raise RuntimeError("This native mount requires Windows")
    if not sys.stdin.isatty():
        raise RuntimeError("Interactive terminal required to control mount lifetime")
    import win32api
    import winfspy
    from research.paged_keys import unlock_password, unlock_recovery, PagedKeyError
    from research.paged_volume import PagedResearchVolume
    from research.paged_fs2 import PagedFS2
    from research.windows_file_ops import WindowsFileOperations
    from research.windows_winfsp_readonly import make_readonly_winfsp_operations

    # Never mount on top of an existing physical, mapped or network drive.
    if not _drive_is_free(args.drive, win32api.GetLogicalDrives()):
        raise RuntimeError("Drive letter already in use; refusing to mount")
    mount_root = Path(args.drive + "\\")
    if mount_root.exists():
        raise RuntimeError("Drive path already exists; refusing to mount")

    if args.recovery:
        key, expected_image_id = unlock_recovery(args.envelope, args.recovery)
    else:
        password = getpass.getpass("KRYPTA volume password: ")
        try:
            key, expected_image_id = unlock_password(args.envelope, password)
        finally:
            password = None  # Python cannot guarantee memory erasure.

    with PagedResearchVolume(
        args.image, key, expected_receipt=args.expected_receipt, read_only=True
    ) as volume:
        if volume.id != expected_image_id:
            raise PagedKeyError("Credential bundle belongs to a different image")
        fs = PagedFS2(volume)
        fs.verify_all()  # Authenticate all files before any plaintext is exposed.
        operations = make_readonly_winfsp_operations(
            WindowsFileOperations(fs), winfspy,
            security_descriptor=_owner_read_security_descriptor(),
        )
        native = winfspy.FileSystem(
            args.drive, operations, sector_size=512,
            sectors_per_allocation_unit=1, read_only_volume=True,
            persistent_acls=True, case_sensitive_search=True,
            case_preserved_names=True, unicode_on_disk=True,
            um_file_context_is_user_context2=True, file_info_timeout=1000,
            post_cleanup_when_modified_only=True,
            reject_irp_prior_to_transact0=False,
            file_system_name=args.drive,
        )
        started = False
        try:
            native.start()
            started = True
            print(f"KRYPTA TEST IMAGE mounted at {args.drive}\\ (READ ONLY).")
            print("Plaintext is accessible to this Windows user and SYSTEM while mounted.")
            print("No physical disk encryption. Press Enter or Ctrl+C to unmount.")
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                pass
        finally:
            if started or native.started:
                native.stop()
                print("KRYPTA experimental drive unmounted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
