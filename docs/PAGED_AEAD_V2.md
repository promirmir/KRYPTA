# KRYPTA paged AEAD metadata v2 — implementation status

Source: research/paged_aead_v2.py. This is a SEPARATE, versioned format from
KRYPTA-AEAD-SECTOR/1. The v1 header and existing images are NOT migrated or
modified. Code still exclusively uses newly created .kdevtest ordinary files,
never real physical disk handles.

- Increases logical-sector addressability from 32 to 1,024 authenticated
  4096-byte sectors (4 MiB logical range) with sparse first-write allocation.
- Each 32-sector index group has its own AEAD-authenticated COW metadata leaf.
  The two alternate 4096-byte root slots authenticate all leaf references.
  A modified group writes new ciphertext sectors and a new metadata leaf, then
  fsyncs, publishes the alternate authenticated root and fsyncs again.
- Independent HKDF-SHA256 key domains for header HMAC, roots, leaves and
  data sectors. Associated data binds group addresses and physical/logical IDs.
  Source key MUST be 32 uniformly random bytes, handled by test harness only.
- On opening, the highest authenticated root must match the external trusted
  latest receipt. An old receipt is never promoted. Lost-ack cases require
  explicit offline analysis; the new v2 version has no automatic rescue tool.
- Current limit: 1,024 logical sectors, at most eight updated data sectors per
  atomic commit, max 256-MiB sparse physical scratch. Metadata append-only.
  NO compaction, full-disk support, hot-unplug safety, physical partition
  backend, mount integration, user credential/key custody or independent audit.

Implementation tests ensure multi-page writes and reads, stale receipts,
crash before root commit, corrupted leaf, capacity rejection, and poisoned
handles. Green tests on synthetic files do NOT satisfy whole-disk acceptance.
The next milestone is a second-tier authenticated directory and fixed-layout
garbage collection, followed by isolated real-device failure testing.
