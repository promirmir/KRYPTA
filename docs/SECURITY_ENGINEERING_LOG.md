# KRYPTA security engineering log

The KRYPTA File Vault is an **unaudited research prototype** and must not be used to protect irreplaceable data. This log records narrowly scoped improvements, not certification.

## Ciphertext pre-verification before plaintext writes (2026-10-20)

### Prior behavior

The first ciphertext tag was checked as chunks were decrypted into a temporary plaintext file on the destination volume. A damaged final tag or appended data triggered removal of that temporary file, but could leave recoverable plaintext remnants on journaled filesystems or in snapshots. Deletion is not secure erasure.

### Hardening

`decrypt_file` now performs a complete authenticated verification pass before opening a temporary plaintext output. After the first pass succeeds, the input is rewound and each chunk and final marker are authenticated a **second** time while streaming plaintext to the destination. The actual output is published only after final authentication and is not allowed to overwrite an existing destination.

- Rejects tampering with the last authentication tag without creating a plaintext temp file.
- Rejects appended data without creating a plaintext temp file.
- Preserves the existing KRYPTA-FILE/1 and KRYPTA-FILE/2 reader and does not change the encrypted format.
- Adds regression tests for multi-chunk round trips and no-plaintext-on-known-corruption behavior.

### Limitations and risks

- Two full authenticated passes require additional I/O and decryption CPU time.
- A malicious actor with write access to the ciphertext may change it between the verification pass and the writing pass. Every chunk is independently re-authenticated, but partial plaintext may still be written temporarily before a late second-pass failure. Avoid concurrent modification of encrypted files during decryption.
- **Successful** decryption still creates a plaintext temporary file on the destination volume before atomic publication. Snapshots, filesystem journals and SSD behavior may retain data after deletion. Use an encrypted destination and understand its security model.
- No TPM-backed brute-force throttling or secure-element binding is implemented. A 4-digit PIN alone remains offline guessable.
- Cryptographic primitives have not had independent third-party review, formal verification or security certification.

### Validation

The CI suite runs on Python 3.11 and 3.13. Build checks package the Windows/Linux desktop binaries and exercise an end-to-end encryption/decryption smoke test. Additional targeted tests exercise corrupted terminal tags and appended bytes without creating a plaintext temp file. Hardware security and production readiness require separate evaluation.

## File-descriptor and keyfile lifecycle hardening (2026-10-20)

- File Vault input and keyfile reads now open the file with descriptor-level checks, including `O_NOFOLLOW` and `O_NONBLOCK` where supported (POSIX), then verify a regular file using `fstat` **on that descriptor**. This closes the ordinary POSIX check/open symlink-swap window and avoids blocking on a substituted FIFO. Windows reparse-point and directory-traversal behavior **requires separate native review**; this is not a Windows filesystem isolation guarantee.
- Keyfile reads have a byte-count bound and reject a size change observed during reading. The keyfile hash remains SHA-256 and the file format remains unchanged.
- Random 32-byte keyfiles are created with `O_EXCL` and POSIX mode `0600` at creation time instead of applying `chmod` after creating a possibly readable file. On Windows `0600` is **not** a substitute for auditing NTFS ACL inheritance and access control.
- CI is extended to run tests on **Windows and Linux**. Security CI checks code with Bandit and installed dependencies with `pip-audit`. Passing these checks cannot demonstrate cryptographic correctness or absence of vulnerabilities.

### Still unresolved / do not make stronger claims

Destination-directory symlinks, Windows reparse points, concurrent modifications by an adversary, plaintext-at-rest after successful decryption, secure erasure, memory forensic exposure, and hardware-enforced PIN authorization all require further independent review. The keyfile can still be copied if its storage is compromised.