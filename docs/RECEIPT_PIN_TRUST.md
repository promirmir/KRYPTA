# Externally sealed PFS/2 receipt pins (development, disposable files only)

The PFS/2 journal authenticates commits and previous-receipt links. It does
**not** by itself establish whether an otherwise valid image has been rolled
back. Reading the newest receipt from that same image and trusting it is
unsafe. This milestone introduces an explicit **write-once receipt pin**
(`.kpin`) and a **separately held SHA-256 seal**.

## Precise boundary

- `pin_trusted_image(image, key, trusted_receipt, destination,
  expected_image_id=...)` requires a previously, **independently known**
  current receipt. It opens a normal `.kpv` read-only, checks the exact
  expected receipt and fully authenticates PFS/2 contents before creating a
  separate `.kpin` file using exclusive creation, mode 0600 and
  `fsync(file)`. On POSIX, the parent directory is also `fsync`ed.
  The pin is never replaced or automatically updated.
- `verify_image_with_sealed_pin(image, key, pin_path, trusted_seal)`
  requires the SHA-256 seal supplied independently. It checks the canonical
  pin and verifies the authenticated image ID, exact sequence, exact
  receipt, and complete PFS/2 contents using read-only file access. Any
  other sequence/receipt — **older or newer** — is rejected, not promoted.
- `load_sealed_pin` cannot be invoked successfully without the expected
  seal. Pin, receipt and seal are not cryptographic secrets, but seal
  **integrity and freshness** depend on being protected against replay.
- A SHA-256 seal produced in the same session is just a checksum until the
  operator has independently secured it. The API explicitly reports
  `trust_promoted=False` throughout.

## Example (only a synthetic disposable image)

```python
from research.receipt_anchor import pin_trusted_image, verify_image_with_sealed_pin

# image, volume_key, bound_image_id, and independently trusted latest_receipt
# must already be available from a verified and authorized prior operation.
result = pin_trusted_image(
    image, volume_key, latest_receipt, "/private/separate-pins/baseline.kpin",
    expected_image_id=bound_image_id,
)
# STOP: write down / transmit result["seal_sha256"] through a separately
# protected channel. Do NOT read it back from the same image or pin directory.

report = verify_image_with_sealed_pin(
    image, volume_key, "/private/separate-pins/baseline.kpin",
    independently_retained_seal,
)
assert report["status"] == "SEALED_PIN_MATCH"
```

The `krypta.volume_lab` service exposes password or independent recovery-key
wrappers for these functions, so the desktop application can integrate them
without ever accepting a receipt observed during a failed review. The desktop Volume Lab GUI now explicitly exposes **Utwórz pin .kpin**
and **Sprawdź pin (R/O)** using these wrappers. The UI requires operators
to enter a separately trusted prior receipt for pin creation and an
independently retained seal for read-only verification. After success, the
GUI displays the seal for independent storage, but does not silently save or
protect that seal. It never enables generic receipt export for pin verification
results (trust_promoted=False). This is an operator-managed development-only
trust workflow, **not automatic anti-rollback protection**. The installed
WinFsp mount remains read-only.

## Required external trust assumptions

A file or filesystem **cannot defend its own historical freshness** against
an attacker who can replace or roll back all copies. You MUST store the
**latest** expected seal in an independently protected, replay-resistant place
(for example, a separate controlled device with an operator-controlled
version record). Reading it from the same pin directory, image, GitHub
release, or unattended application output is **not** independent trust.

This implementation does not install a TPM monotonic counter, provide remote
witnessing, secure the operator's separate seal storage, atomically synchronize
image writes with independent pin updates, solve concurrent multi-writer
publication, or recover a lost acknowledgment. A pin cannot resolve an
uncertain later commit: stop writes and use the existing read-only lineage
review. If the image is ahead of the pin, it is **not safe** to adopt the
observed newer receipt automatically.

The pin path must be absolute, end in `.kpin`, have no symlink ancestors,
and reside in a different directory from the test `.kpv` image. On POSIX
the target directory must be owned by the caller and not group/world
writable; the pin itself must be a private single-link regular file. These
checks do not prove the directory is on a separate physical device and
cannot defend against privileged OS or directory-handle races. On Windows
there is no portable Python parent-directory fsync and these checks **do
not establish crash-proof directory-entry durability**. Even on POSIX,
fsync success depends on filesystem/hardware behavior.

Development-only, not audited and not intended for unique data or physical
partitions. **Never delete the previous independently trusted pin or its
seal until the subsequent authorized and independently secured checkpoint
has been verified.** No test writes to real media.

## Regression coverage

```sh
python -m pytest -q tests/test_receipt_anchor.py
```

Coverage includes actual authenticated encrypted images, exact read-only
reopen, full valid image rollback, newer-untrusted image refusal, pin replay
against a different externally retained seal, different image/key,
symlink rejection, wrong/missing seals, noncanonical documents,
exclusive-create and injected parent-fsync failure.
