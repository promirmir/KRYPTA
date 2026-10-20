"""Non-destructive PVIMG/PFS2 development volume setup and credential recovery.

A separate command-line tool, NOT system or physical-disk encryption.
Passphrases never arrive in command-line arguments or environment variables.
"""
from __future__ import annotations

import argparse
import getpass
import os
import secrets
import stat
import sys
from pathlib import Path

from .paged_keys import (
    PagedKeyError, provision_keys, unlock_password, unlock_recovery,
    rewrap_password_with_recovery,
)
from .paged_volume import PagedResearchVolume, PagedVolumeError
from .paged_fs2 import PagedFS2


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


def _delete_only_created_image(path: Path, identity: tuple[int, int]) -> None:
    try:
        info = os.stat(path, follow_symlinks=False)
        if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == identity:
            path.unlink()
    except OSError:
        pass


def _new(args) -> None:
    """Create only a fresh exclusive-create PVIMG test image and key envelope."""
    if Path(args.image).suffix.lower() != ".kpv":
        raise PagedKeyError("Only disposable .kpv filenames are allowed")
    password = _password(args)
    key = secrets.token_bytes(32)
    img = Path(args.image)
    created = None
    try:
        with PagedResearchVolume(img, key, create=True) as vol:
            info = os.fstat(vol._f.fileno())
            created = (info.st_dev, info.st_ino)
            fs = PagedFS2.format(vol)
            provision_keys(vol, password, args.envelope, args.recovery)
            receipt = fs.receipt
            identity = vol.id.hex()
        print("CREATED: KRYPTA-PFS/2 development image, password bundle and separate recovery file")
        print("IMAGE ID:", identity)
        print("EXTERNAL RECEIPT:", receipt)
        print("Store the current RECEIPT in independently trusted storage; update it after every filesystem change.")
        print("Back up the recovery file OFF this machine and separately from the encrypted image.")
    except BaseException:
        if created is not None:
            _delete_only_created_image(img, created)
        raise


def _check(args) -> None:
    if args.recovery:
        key, expected_id = unlock_recovery(args.envelope, args.recovery)
    else:
        key, expected_id = unlock_password(args.envelope, _password(args))
    with PagedResearchVolume(args.image, key,
                             expected_receipt=args.expected_receipt) as vol:
        if vol.id != expected_id:
            raise PagedKeyError("Unlocked key bundle belongs to a DIFFERENT encrypted image")
        fs = PagedFS2(vol)
        report = fs.verify_all()
        print("VERIFIED:", report["files_verified"], "encrypted files,",
              report["bytes_verified"], "authenticated plaintext bytes")
        print("IMAGE ID:", vol.id.hex())
        print("EXTERNAL RECEIPT:", report["receipt"])


def _recover(args) -> None:
    new_password = _password(args)
    info = rewrap_password_with_recovery(
        args.envelope, args.recovery, new_password, args.new_envelope
    )
    print("CREATED: new separately named encrypted password envelope")
    print("IMAGE ID:", info["image_id"])
    print("WARNING: The old envelope/password remain valid until data key rotation.")


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

    recovery = sub.add_parser("recover-password", help="Create a new password envelope using recovery")
    recovery.add_argument("--envelope", required=True)
    recovery.add_argument("--recovery", required=True)
    recovery.add_argument("--new-envelope", required=True)
    recovery.add_argument("--password-fd", type=int)
    recovery.add_argument("--acknowledge-test-only", action="store_true")

    args = parser.parse_args(argv)
    if not args.acknowledge_test_only:
        parser.error("Explicit --acknowledge-test-only is required")
    if args.command == "create":
        _new(args)
    elif args.command == "verify":
        if args.recovery is not None and args.password_fd is not None:
            parser.error("Select either recovery file or password pipe, not both")
        _check(args)
    elif args.command == "recover-password":
        _recover(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PagedKeyError, PagedVolumeError, OSError, ValueError):
        print("KRYPTA test key operation failed; no secret details disclosed",
              file=sys.stderr)
        raise SystemExit(1) from None
