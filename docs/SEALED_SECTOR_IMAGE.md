# KRYPTA / P0: authenticated sector image (disposable test backend)

Source: research/sealed_sector_image.py. This is **executable encryption code**,
not an empty adapter or a UI mock. It uses the scratch-only test sector transport
on a newly created ordinary \`.kdevtest\` file. It **does not** yet encrypt
physical USB/HDD/SSD media, raw partitions, mounted filesystems or boot drives.

## Cryptographic contract

- Data: AES-256-GCM. Each 4096-byte plaintext sector produces 4096-byte
  ciphertext in a physical scratch sector plus a 16-byte authentication tag
  stored in authenticated metadata.
- Independent HKDF-SHA256 domain-separated 256-bit header-MAC, metadata-AEAD
  and data-AEAD keys, from a caller-provided uniform random 32-byte master key.
- Each data write uses a fresh 96-bit CSPRNG-generated nonce. It binds logical
  and physical sector addresses as AEAD associated data. Each metadata commit
  uses its own randomly generated 96-bit nonce and authenticates an exact,
  canonical catalogue, sector mapping, sequence number, allocation cursor
  and immutable authenticated geometry.
- The header's public fields (magic/version, random volume ID and capacity)
  are authenticated using a separate HMAC-SHA256. Neither the header nor
  the receipt is a secret.
- Current limit: max 32 logical sectors, at most 8 sectors per commit. Sparse
  all-zero sectors need not allocate physical storage. This is intentionally
  small for deterministic crash fault tests and cannot hold full physical media.

## Crash ordering and trust

Write: validate and authenticate all live data; allocate unused COW sectors;
encrypt and write data; **fsync**; construct new authenticated alternate
metadata slot; write and **fsync** it; then return new external \`receipt\`.
Existing live ciphertext is never overwritten in the data phase. On any
ambiguous I/O failure, the open handle is quarantined and must not retry.

When reopening, both AEAD metadata slots are checked and the highest valid
sequence is chosen; reopening **requires the latest separately stored trusted
receipt**. A mismatched or older receipt is rejected, not automatically
upgraded. Following a partial commit the previous trusted state can be
recovered only if it remains the highest authenticated valid root. A
crash after a durable commit but before acknowledgement requires independent
forensic handling; no automatic trust promotion is implemented.

The rollback problem is **not solved by the image alone**. Restoring a
complete valid old image together with an old receipt is undetectable without
external trusted state. User-secret key storage, password KDF integration,
true crash/power-cut device testing, metadata compaction/reclamation, physical
block alignment, concurrent readers/writers, mount adapter and forensic
reconciliation are still unfinished. Do not use this format for real data.

## Acceptance tests

\`tests/test_sealed_sector_image.py\` exercises AES-GCM round-trip, cross-session
reopen, authentication failures, COW, torn metadata, failure before commit,
lost acknowledgement after durable commit, wrong key, wrong geometry, invalid
receipts and bounded atomic batch capacity on Windows/Linux CI.

Next integration gates: compactable fixed-layout encrypted block format,
realistic crash state machine / disk emulator, portable backup keys,
trusted receipt management, and a separate safe physical-device I/O backend.
