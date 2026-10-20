# KRYPTA / product engineering roadmap

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

## Stage C: removable volumes and Windows

- [ ] Drive Shield via carefully reviewed disk-volume backend (e.g. integration with proven OS FDE instead of inventing a kernel driver).
- [ ] System Shield TPM/Secure Boot pre-boot integration, recovery and rollback tested using disposable machines only.
- [ ] Power-loss scenarios, Windows updates, driver signing, backup policy and migration tests.

## Stage D: password and mobile

- [ ] Password Shield with per-use authentication, secure storage, and explicit authorized integrations.
- [ ] Android Shield based on native Android FBE and hardware Keystore/Gatekeeper/Weaver, per-device security evaluation.

## Stage E: independent validation and public release

- [ ] Audit of cryptography, boot integrity, key recovery, API boundaries and UI safety.
- [ ] Independent penetration tests, reproducible builds, signed installers/releases and transparent vulnerability response.
- [ ] Publish a responsibly scoped technical whitepaper and externally verified security claims.
- [ ] Public GitHub visibility **only following explicit owner decision**.

No absolute “unbreakable” promise. Every release must describe the real threat model and verified guarantees.