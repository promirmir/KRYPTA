"""Source-only, strictly read-only PVIMG/1 uncertain-commit review.

Use an independently saved PRIOR receipt. Passwords are prompted in the
console, never accepted in process arguments or stored in output reports.
This tool NEVER promotes an observed receipt into a trusted anchor.
"""
from __future__ import annotations

import argparse
import getpass
import hmac
import json
import re
import sys

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


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
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
            ValueError, OSError) as exc:
        print("KRYPTA READ-ONLY REVIEW FAILED. Keep original image and "
              "independently trusted receipt; do not resume writes.",
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
