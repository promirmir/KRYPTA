"""Isolated, strictly read-only PVIMG/1 uncertain-commit review.

Use an independently saved PRIOR receipt. Passwords are prompted in the
console, never accepted in process arguments or stored in output reports.
This tool NEVER promotes an observed receipt into a trusted anchor.
"""
from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
import secrets
import tempfile
from pathlib import Path

from krypta.volume_lab import _distinct, _get_key, _image_path
from research.paged_keys import PagedKeyError
from research.paged_fs2 import PagedFS2Error
from research.paged_volume import PagedVolumeError
from research.paged_receipt_reconcile import review_uncertain_commit


def _arguments(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        description="KRYPTA read-only forensic receipt review; TEST .kpv images only"
    )
    parser.add_argument("--image", required=True)
    parser.add_argument("--envelope", required=True)
    parser.add_argument("--trusted-prior-receipt", required=True)
    parser.add_argument("--recovery", help="Offline recovery key file, otherwise password prompt")
    parser.add_argument("--acknowledge-review-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.acknowledge_review_only:
        parser.error("Explicit --acknowledge-review-only required")
    if re.fullmatch(r"[0-9a-f]{64}", args.trusted_prior_receipt) is None:
        parser.error("Trusted prior receipt must be exactly 64 lowercase hex characters")
    return args


def _self_test() -> int:
    """Packaged binary regression check: synthetic PFS/2 and lost-receipt review.

    No user input, real device, mounted filesystem or plaintext export.
    Use only temporary files and an ephemeral test key.
    """
    from research.paged_fs2 import PagedFS2
    from research.paged_volume import PagedResearchVolume

    with tempfile.TemporaryDirectory(prefix="krypta-review-self-test-") as directory:
        image = Path(directory) / "synthetic.kpv"
        key = secrets.token_bytes(32)
        with PagedResearchVolume(image, key, create=True) as volume:
            fs = PagedFS2.format(volume)
            fs.write_file("check.txt", b"ORIGINAL-SYNTHETIC")
            trusted_prior = fs.receipt
            fs.write_at("check.txt", 0, b"UPDATED-")
            current = fs.receipt
            image_id = volume.id
        snapshot = image.read_bytes()
        report = review_uncertain_commit(
            image, key, trusted_prior, expected_image_id=image_id
        )
        if (report["status"] != "DESCENDANT_FOUND_MANUAL_REVIEW_REQUIRED"
                or report["commits_since_prior"] != 1
                or report["observed_receipt_UNTRUSTED"] != current
                or report["review_only"] is not True
                or report["files_verified"] != 1
                or image.read_bytes() != snapshot):
            raise RuntimeError("Packaged receipt review self-test failed")
    print("KRYPTA READ-ONLY RECEIPT REVIEW: synthetic self-test PASS.")
    return 0


def main(argv: list[str] | None = None) -> int:
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    if actual_argv == ["--self-test"]:
        return _self_test()
    args = _arguments(actual_argv)
    try:
        image = _image_path(args.image)
        if args.recovery is not None:
            _distinct(image, args.envelope, args.recovery)
            key, image_id = _get_key(args.envelope, recovery=args.recovery)
        else:
            _distinct(image, args.envelope)
            password = getpass.getpass("KRYPTA volume password (not echoed): ")
            try:
                key, image_id = _get_key(args.envelope, password=password)
            finally:
                password = None  # No reliable Python memory clearing guarantee.
        result = review_uncertain_commit(
            image, key, args.trusted_prior_receipt,
            expected_image_id=image_id,
        )
    except (PagedKeyError, PagedFS2Error, PagedVolumeError,
            ValueError, OSError):
        print("KRYPTA READ-ONLY REVIEW FAILED. Keep original image and "
              "independently trusted receipt; do not resume writes.",
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
