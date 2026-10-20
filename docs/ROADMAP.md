# KRYPTA / product engineering roadmap

**Binding product goals:** [PROJECT_CHARTER](PROJECT_CHARTER.md). **Own cryptographic research:** [HORIZON_CRYPTO_RFC](HORIZON_CRYPTO_RFC.md). Existing OS encryption diagnostics are not a substitute for KRYPTA's own engine.

Status on 2026-10-20: v0.4.0-alpha. **Only the File Vault research prototype is functional.** Other modules appear in the Matrix-inspired desktop shell to make the architecture tangible without pretending to provide protection.

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
- [ ] Production-quality **transactional** virtual volume with multi-sector atomic commits, durable rollback anchor, compaction and validated crash recovery. Current prototype is not a mountable disk or production-grade COW filesystem.
- [ ] Verify write-through transparent encryption with independent Windows/Linux virtual-volume interface prototypes. No BitLocker/LUKS backend as the main product.
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
- [ ] Android application-controlled encrypted vault and Keystore-backed keys, independent code path; whole-device custom encryption only through appropriately privileged/custom-OS integration, not a regular APK.

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
- [ ] Confirm successful GitHub Actions builds for all three platforms.
- [ ] Independently verify binaries on Windows hardware, at least two Linux distributions and the supported Android devices.
- [ ] Implement actual Android file protection, OS-backed protection and recovery after security architecture review.
- [ ] Sign release artifacts with protected release keys (debug APK and unsigned EXE are not releases).