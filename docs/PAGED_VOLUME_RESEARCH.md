# KRYPTA-PVIMG/1 — paged sparse research image

**Status (2026-10-20): experimental format in a private development branch. Not production disk encryption, not a safe place for unique data.** This is a separate \`.kpv\` image format; **it does not replace KRYPTA-VIMG/0** or alter Windows, Linux or Android storage.

## Objective and scope

The older experimental VIMG/0 keeps a complete flat sector directory inside each commit and is limited to 128 logical sectors (512 KiB). PVIMG/1 instead stores **authenticated copy-on-write radix-tree nodes**, each with at most 64 children, three levels deep. Only nodes on modified paths need new copies; the commit publishes a constant-size authenticated root pointer, rather than serializing the entire sector map on every change.

The sparse logical address space covers **262,144 x 4096-byte sectors = 1 GiB**. This is not guaranteed usable capacity: the physical encrypted append-only journal is explicitly capped at **512 MiB**, includes encryption/metadata overhead, and has no compactor. Only **256 sectors can be modified per research transaction**. Sparse reads return all-zero sectors for unwritten addresses.

## Format sketch (not a stable interoperability standard)

- **Header:** ASCII \`KRYPTA-PVIMG/1\n\` followed by a random 16-byte image ID.
- **Framing:** \`KPG1\` + one-byte record type + unsigned big-endian 32-bit payload length.
- **D — encrypted data:** unsigned 64-bit sector index and 64-bit generation, followed by a HORIZON/0 research authenticated encrypted sector bound to the image ID, sector index and generation.
- **N — metadata node:** canonical ASCII JSON \`{"level":int,"prefix":int,"slots":{...}}\`. Nodes map radix slots to either child references or leaf sector records. References consist of physical frame offset and SHA-256 digest; data references also contain their generation. A child node is validated against the exact parent-provided digest and tree position.
- **C — commit:** canonical ASCII JSON containing increasing sequence, prior authenticated receipt and the latest root reference, followed by HMAC-SHA-256. The per-image commit MAC key is derived with HKDF-SHA-512 and a separate domain. Each resulting commit receipt binds its signed contents and the prior receipt.
- **Durability attempt:** encrypted data and newly written index nodes are flushed/synced before appending and syncing the one root commit. If a write fails, the active handle refuses all additional operations until closed and recovered.

On reopen, the reader scans framed records, authenticates the commit chain and the entire **reachable metadata tree**, then checks any externally provided sequence/receipt **before** truncating an incomplete tail. It validates encrypted sector AEAD tags **when sectors are read**, or with the explicitly requested \`verify_all()\` sweep. A failure never produces unauthenticated plaintext.

## Security boundaries and missing features

1. **NO anti-rollback guarantee:** a copied older valid complete image opens without a separately trusted expected receipt. A receipt saved next to the attacker-controlled image is not a secure anchor. No TPM/TEE trust anchor has been implemented.
2. **NO physical crash-consistency proof:** \`flush/fsync\` and injected process failures do not model storage cache deception, controller firmware bugs, torn-media writes, real power loss, or malicious filesystem behavior.
3. **NO secure PIN:** the caller must already hold an independent random 32-byte test key. The code does not implement password-derived recovery, hardware rate limiting or hardware-backed key custody.
4. **NO mounted volume or physical disks:** only newly created/existing ordinary \`.kpv\` files, never system devices, partitions, boot volumes or OS-transparent writes. Windows reparse/ACL semantics need separate evaluation.
5. **NO production-ready scaling:** log scans remain linear in historical file length; metadata validation and optional full-data verification grow with allocation. The journal retains superseded ciphertext and has **no compaction or secure erasure**.
6. **NO stable format or audited construction:** the HORIZON/0 layered AES-GCM + ChaCha20-Poly1305 research primitive has not been independently cryptanalyzed. This phase measures file/index correctness, not security superiority.

## Evidence and regression gate

\`tests/test_paged_volume.py\` exercises sparse low/high/partition-boundary sector addressing, randomized cross-page batches, concurrent-writer refusal, wrong keys, changed metadata/ciphertext, malicious noncanonical signed commit, missing external receipt, an old snapshot with new external receipt, incomplete trailing frames, interrupted commit and lost commit acknowledgment. All tests use **disposable ordinary files** and RAM-generated test keys.

Reproducible command: \`python -m pytest -q tests/test_paged_volume.py\`.

**Gate before further work:** CI success on Windows/Linux; format parser fuzzing and sustained I/O stress; authenticated filesystem catalogue above this block layer; image crash/recovery testing on disposable VMs; independent review. Do not merge this into any real-disk/boot code until separate explicit authorization.
