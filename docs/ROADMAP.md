# KRYPTA / product engineering roadmap

**Binding product goals:** [PROJECT_CHARTER](PROJECT_CHARTER.md). **Own cryptographic research:** [HORIZON_CRYPTO_RFC](HORIZON_CRYPTO_RFC.md). Existing OS encryption diagnostics are not a substitute for KRYPTA's own engine.

Status on 2026-10-20: **research alpha, not complete full-disk encryption**. Working research components include desktop single-file File Vault, experimental HORIZON/VIMG/FS image and virtual-stream modules (not mountable operating-system drives), and Android 0.5 selected-file encryption (not whole-phone encryption). Full transparent disk encryption, production recovery and trustworthy short-PIN anti-brute-force protection remain unimplemented.

## First-priority completion sequence — OWN encryption engine

1. Harden independent KRYPTA-HORIZON/VIMG/FS on disposable images: authentication of metadata, state consistency, large capacities, compaction and crash/rollback recovery.
2. Connect that engine to an actual **mountable KRYPTA volume** with automatically encrypted reads/writes on Windows and Linux, initially only on disposable virtual machines.
3. Develop protected key lifecycle, recovery and hardware-supported short-PIN security; the PIN must not be the only offline-guessable secret.
4. Add tested system-boot and removable-drive support; ensure safe recovery and backwards-compatible migrations.
5. Expand Android from selected-file vault to the strongest independently implemented protection that platform privileges actually allow; a normal APK cannot replace the OS-wide encryption subsystem.
6. Compare documented guarantees and benchmark real attacks/recovery/performance against existing products. Seek independent evaluation for defense/government adoption, but no unproven superiority claim.

**Other UI features, badges and secondary integrations must not take priority over this independent volume engine.**

## Stage A: file-format research — in progress

- [x] Authenticated encrypted file format v2 with honest, human-readable KRYPTA notice.
- [x] Random 256-bit DEKs, Argon2id KDF, optional separate random keyfile, no-clobber output.
- [x] Terminal Matrix-inspired UI with locally executed file actions and security warnings.
- [x] Negative tests: incorrect PIN, keyfile, tampering, truncation, append, overwrite.
- [ ] Parser fuzz testing, adversarial size/CPU benchmarks, differential crypto test vectors.
- [ ] Robust crash/recovery tests, memory handling review, and cross-OS compatibility.
- [ ] Replace temporary plaintext decryption workflow with reviewed handling suitable for the proposed threat model.

## Stage B: platform key security

- [ ] Evaluate TPM 2.0 / Windows CNG sealed keys and platform policies on real test hardware.
- [ ] Create non-exportable-key prototype with backed-up recovery model, anti-rollback, and device-loss tests.
- [ ] Verify hardware attempt throttling cannot be bypassed by cloning/restoring only ciphertext metadata.
- [ ] Cryptographically bind release integrity, policies and trusted boot measurements where appropriate.

## Stage C: original KRYPTA volumes, Windows and Linux

- [x] Define original experimental HORIZON/0 authenticated block format and independent data-key research path (not production).
- [x] Begin standalone in-memory/file-free block test implementation under `research/` and adversarial regression tests.
- [x] **KRYPTA-VIMG/0 initial research prototype:** standalone authenticated append-only `.kvi` test image, sector map, write generation and recovery of last complete commit. [Implementation](../research/volume_image.py) · [design / limitations](VOLUME_IMAGE_V0.md) · [fault-injection tests](../tests/test_volume_image.py).
- [x] Research-only multi-sector write transactions with one authenticated commit, byte-range I/O, and an optional externally verified commit receipt. Verified with synthetic power-cut and randomized oracle tests ([notes](VIMG_TRANSACTION_RESEARCH.md)).
- [x] Research-only **live-sector migration into a separate authenticated compact image**, new image ID and receipt, old source preserved. Read-only KRYPTA-FS full file sweep. [Research limits](VIMG_LIVE_MIGRATION.md); [negative tests](../tests/test_compacted_migration.py).
- [ ] Production-quality transactional virtual volume with **real online/in-place compaction, hardware-independent recovery, trusted anti-rollback migration, scalable addressing and validated durable crash recovery**. Current prototype is not a mountable disk or production-grade COW filesystem.
- [x] Research Python `io.RawIOBase` virtual block stream (`seek/read/write/readinto`) over original KRYPTA encrypted test images; native packaging includes a disposable `--volume-self-test` ([architecture](VIRTUAL_BLOCK_DEVICE.md)). **No OS interception or mountable virtual drive yet.**
- [ ] Actual transparent Windows/Linux **OS-level** virtual-volume/block-device integration using an independently built KRYPTA backend (not BitLocker/LUKS); disposable VM and recovery testing required.
- [ ] Add robust metadata/root rollback protection and hardware-bound key release with independent secret for short PINs.
- [ ] Add independent removable-drive support, portability and recovery without assuming a local software retry timer is secure.
- [ ] Develop Windows system-volume preboot component and Linux system-volume stack only after disk-image / VM recovery tests.
- [ ] Driver signing, power-loss, restore, firmware update, bad sectors, storage hardware failures, large-files and interrupted writes.

### Standalone experimental cipher research

- [x] HORIZON/0 RFC: original scheme composition (AES-256-GCM + ChaCha20-Poly1305) for independently authenticated sectors; **not a new mathematical cipher**.
- [ ] Test nonces, key/domain separation, misuse, corruption and rollback; no claims that layering is proven stronger.
- [ ] Research separate original primitive only as a laboratory experiment; never silently replace battle-tested production primitives.

## Stage D: password and mobile

- [ ] Password Shield with per-use authentication, secure storage, and explicit authorized integrations.
- [x] Android **research selected-file vault**: local native KRYPTA-MOBILE/1 format with authenticated 64-KiB AES-GCM records, Keystore-wrapped per-file key, system credential confirmation and 11 localized action/warning strings. [Android instructions](../android/README.md). Built and JUnit-tested in private CI.
- [ ] Android **production-grade recoverable encrypted vault**: recovery/backup, real-device hardware-bound tests, safer output/temporary-file handling, signed APK, compatibility and performance.
- [ ] Transparent whole-device custom Android encryption requires appropriately privileged/custom-OS integration — NOT possible through a normal APK.

## Stage E: independent validation and public release

- [ ] Audit of cryptography, boot integrity, key recovery, API boundaries and UI safety.
- [ ] Independent penetration tests, reproducible builds, signed installers/releases and transparent vulnerability response.
- [ ] Publish a responsibly scoped technical whitepaper and externally verified security claims.
- [ ] Public GitHub visibility **only following explicit owner decision**.

No absolute “unbreakable” promise. Every release must describe the real threat model and verified guarantees.

## Platform packaging (2026-10-20)

- [x] Add private CI recipe for Windows `.exe` desktop alpha.
- [x] Add private CI recipe for Linux ELF desktop alpha.
- [x] Add Android-native Matrix-styled UI skeleton and debug-APK CI recipe.
- [x] Confirm successful GitHub Actions research builds for all three platforms.
- [ ] Independently verify binaries on Windows hardware, at least two Linux distributions and the supported Android devices.
- [x] Implement Android selected-file authenticated encryption and OS Keystore wrapping (research only).
- [ ] Secure Android key recovery/portability and whole-device encryption architecture after validation.
- [ ] Sign release artifacts with protected release keys (debug APK and unsigned EXE are not releases).