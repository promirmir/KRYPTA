# Windows staged writes — PFS/2 transaction research

**Research boundary (2026-10-22):** This Python module is **not** connected to the
read-only Windows WinFsp mount or any GUI write button. It never enumerates
physical drives, partitions or phones. Test only disposable ordinary
`.kpv` images and independently backed-up material.

## Contract

`research.windows_staged_write.StagedWindowsFileWrite` requires an already
authenticated **write-open** PFS/2 instance, one *existing* unambiguous flat
Windows name and the **independently trusted current receipt** (exactly 64
lowercase hex characters). It refuses a stale receipt, a read-only backing
image, ambiguous case-folding names and files larger than 4 MiB.

For an existing file, the module authenticates **all live files** before
copying plaintext into at most 4 MiB of RAM. `write(offset, bytes)`,
`truncate(size)` and `read(offset, length)` affect only that in-memory
staging buffer. No disk write is attempted until explicit `commit()`.
`abort()` discards staged changes; a second commit/write after commit or
abort is rejected.

On commit, the module again checks the volume's sequence, receipt and all
live authenticated files while holding the Windows file-operation lock.
A changed volume cannot receive an outdated staged overwrite. One complete
staged file is published by the **existing** PFS/2 copy-on-write mechanism,
with one final authenticated root publication. The module then authenticates
the filesystem and reads the committed file back before returning the *new*
receipt. A no-op session does not advance the receipt.

A reported success is **not** durable trusted-receipt storage. The caller
must safely advance its independently protected receipt *before any later
writes*. Such protected receipt storage, crash durability on physical media,
power-loss tests and filesystem callback sequencing are not implemented.
A receipt saved beside the image is insufficient to detect malicious rollback.

## Failure semantics

- A rejected argument, mismatched receipt, changed sequence or failed
  **precommit** integrity sweep prevents the new write before any commit.
- After publication starts, **any** exception produces
  `UncertainStagedCommit`, even if the final root could have been written.
  The session is closed and cannot be retried on the same handle.
- `unverified_receipt`, when present, comes from a completed commit whose
  later verification failed. It is **forensic recovery information only**,
  not an independently trusted anti-rollback token.
- Without a verified commit acknowledgement, **do not blindly continue
  from either the old or a newly discovered image receipt**. Preserve both
  the old external trust anchor and the image; require separate offline
  recovery and operator confirmation.

There is no promise of reliable Python memory erasure, per-process isolation,
ACL correctness or safety in the presence of a hostile privileged process.
Staging holds plaintext in RAM and duplicates it during encryption. This is
a single-file experiment, not a Windows kernel filesystem transaction: OS
handle sharing, rename/delete atomicity, flush/close semantics, directory
durability, concurrent mounted writers and write-through behavior remain
separate release blockers.

## Verification

`python -m pytest -q tests/test_windows_staged_write.py` runs only against
temporary, synthetic `.kpv` images. Coverage includes: no side effects
before commit/abort, single-commit roundtrip with external receipt,
stale-writer rejection, bounds and casefold checks, write-open enforcement,
pre-existing corruption, simulated failure before root publication, lost
acknowledgment **after** publication, and postcommit verification failure.

All tests are **software fault injection**. They do not prove power-loss
durability or physical-device compatibility. Release/use of a write-enabled
mount must remain blocked until independent security review and additional
Windows/Linux crash-recovery tests are complete.

Related acceptance issue: [#27](https://github.com/promirmir/KRYPTA/issues/27).
