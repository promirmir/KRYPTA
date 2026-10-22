# PVIMG/1 — read-only receipt lineage review after an uncertain commit

**Development-only recovery investigation (2026-10-22).** Operates on ordinary
test `.kpv` file images, not drives/partitions. This tool cannot promote a
receipt to a trusted anchor, undo an interrupted transaction, repair corruption
or determine whether an authenticated descendant is the latest possible copy.

## Purpose

An interrupted PFS/2 write can have two important outcomes:

1. Failure **before** the final authenticated commit: the old externally
   trusted receipt still names the last committed state.
2. Failure **after** the final commit is durable but **before acknowledgment**:
   the image may have a newer authenticated state, and demanding the old
   receipt at open correctly rejects it as a possible rollback.

Simply opening the image without a receipt and accepting its new reported
value **is not a safe recovery procedure**. An attacker could replace the
image with an otherwise valid older snapshot. A receipt stored next to an
attacker-controlled image is not an independent anchor.

The new `research.paged_receipt_reconcile.review_uncertain_commit()`
requires the independently held old receipt (64 lowercase hex chars), the
32-byte test key and optionally the 16-byte expected image identity from
the authenticated key envelope. It opens the ordinary file
`PagedResearchVolume(read_only=True)`, verifies the live PFS/2 filesystem,
then checks each signed/canonical commit and its receipt chain. It returns:

- `CURRENT_RECEIPT_MATCHES_PRIOR` if the old receipt is the latest
  authenticated record in this copy.
- `DESCENDANT_FOUND_MANUAL_REVIEW_REQUIRED` if the current image contains
  one or more authenticated commits chained after the old trusted receipt.
- **Failure**, not a "new trust" action, if that prior receipt cannot be found
  in the image's authenticated history; a plausible cause is a rolled-back
  image, a different key/image or corrupted storage.

It separately reports `uncommitted_tail_present`; a damaged trailing
partial frame is **never truncated** by this forensic tool. The value
`observed_receipt_UNTRUSTED` is for diagnosis **only**. The tool checks the
reachable latest state, not every historical plaintext snapshot. The old
receipt is not evidence that older data is still recoverable.

## Console usage (source checkout, Windows and Linux)

Use Python and installed project requirements. Protect the original image
and store the trusted prior receipt **outside** the potentially compromised
storage before starting. With password entry in the console:

```sh
python -m tools.review_uncertain_kpv \
  --image "disposable.kpv" \
  --envelope "disposable.pvkey" \
  --trusted-prior-receipt "REPLACE_WITH_64_LOWERCASE_HEX" \
  --acknowledge-review-only
```

Alternatively, for an independent recovery key file, add
`--recovery "offline.key"`; then no password prompt is used. The image,
envelope and recovery paths cannot alias one another. The program rejects
password arguments and avoids printing credentials. JSON output includes
only hashes, counters and explicit **UNTRUSTED** candidate fields.

There is **no update/save receipt option**. It is unsafe to silently save a
candidate over a trusted receipt. If a descendant is found, freeze writes,
preserve both original image and external trusted anchor, and perform an
operator-controlled offline recovery and comparison against separately
backed-up expected data. Any future receipt promotion must involve an
independently protected and durable trust mechanism and explicit review.

## Assurance limitations

- A chain extending the trusted receipt demonstrates continuity through
  authenticated records in **this particular copy**, not that it is the
  most recent existing copy, that the writer was authorized, or that the
  underlying storage physically persisted the entire image.
- An unauthorized writer with the secret key can produce valid descendant
  records; HMACs do not provide writer authorization.
- The tool does not perform physical crash tests, alter Windows WinFsp mounts,
  claim TPM monotonic anti-rollback protection or enable mounted writes.
- No data is modified: no journal truncation, automatic repair, conversion,
  rekeying, rewriting of receipts or automatic cleanup.
- This is still experimental HORIZON/PVIMG/PFS2 code, not audited crypto.

Relevant checks: `python -m pytest -q tests/test_paged_receipt_reconcile.py`.
Only disposable files with synthetic keys and deliberate corruption are used.
