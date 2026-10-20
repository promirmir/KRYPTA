# KRYPTA / product engineering roadmap

**Kryterium zamknięcia prac:** [PRODUCT_ACCEPTANCE.md](PRODUCT_ACCEPTANCE.md). Każdy moduł ma zostać ukończony i sprawdzony na rzeczywistej platformie; pośrednie obrazy plikowe oraz badania kryptograficzne są etapami wdrożenia, nie docelową funkcją produktu.

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

## Działający adapter systemu plików PVIMG-PFS/1 — etap integracji Linux

- [x] Własny, wersjonowany zaszyfrowany katalog PFS/1 na PVIMG/1; atomowy zapis pliku i katalogu w jednej transakcji.
- [x] Adapter FUSE i oddzielne, jawnie autoryzowane montowanie istniejących obrazów .kpv bez uprawnień root i bez dostępu do fizycznych dysków.
- [x] Rozszerzona obsługa plików: maksimum 960 KiB na plik, do 128 plików, nazwy Unicode, zapis/odczyt/rename/delete.
- [ ] Ukończenie zgodności POSIX, wielomegabajtowe pliki, hierarchia katalogów, trwalsze odzyskiwanie po awarii i audyt bezpieczeństwa.
- [ ] Stabilna implementacja Windows na zaszyfrowanym woluminie oraz produkcyjna ochrona systemowa.

[Architektura, wymagania i dowody](PVIMG_LINUX_FUSE.md). Nie przedstawiać logicznego adresowania 1 GiB jako gwarantowanej pojemności zapisu.

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
- [x] **Separate KRYPTA-PVIMG/1 research spike (non-mountable):** copy-on-write, authenticated three-level radix index and single authenticated commit root over a sparse 1-GiB logical address range; 512-MiB append-log quota, no **online/in-place** compactor, no hardware rollback anchor. See [research limitations](PAGED_VOLUME_RESEARCH.md) and [source](../research/paged_volume.py). This is NOT a production-ready larger disk format.
- [x] **PVIMG/1 safe compact-export implementation:** authenticate and copy current sparse sectors to a separate no-overwrite image with fresh identity and receipt, bounded streaming, full read-back, and failure cleanup. Original remains untouched, and the external rollback trust anchor must be migrated independently. Source: [paged_volume.py](../research/paged_volume.py); negative tests: [test_paged_compaction.py](../tests/test_paged_compaction.py). This is **not online compaction**, secure erasure, physical crash certification, or production recovery.
- [x] **PVIMG/1 Python RawIOBase block stream:** bounded, seekable byte-range I/O with authenticated writes, explicit lock ownership and buffered-file compatibility on ordinary test images. This is an intermediary for real OS adapters, **not** an OS mount, kernel driver or completed disk encryption. [Source](../research/paged_stream.py) · [specification](PVIMG_BLOCK_STREAM.md) · [tests](../tests/test_paged_stream.py).
- [ ] Production-quality transactional virtual volume with **real online/in-place compaction, hardware-independent recovery, trusted anti-rollback migration, scalable addressing and validated durable crash recovery**. Current prototype is not a mountable disk or production-grade COW filesystem.
- [x] Research Python `io.RawIOBase` virtual block stream (`seek/read/write/readinto`) over original KRYPTA encrypted test images; native packaging includes a disposable `--volume-self-test` ([architecture](VIRTUAL_BLOCK_DEVICE.md)). **No OS interception or mountable virtual drive yet.**
- [x] **Linux FUSE adapter source** for disposable original KRYPTA-FS/0 encrypted images — callbacks for file read/write/truncate/create/rename/unlink, tested on Windows/Linux without a kernel mount. [Source](../research/linux_fuse.py) · [Linux risk-gated mount entrypoint](../research/linux_mount.py) · [limits](LINUX_FUSE_RESEARCH.md).
- [x] Actual Linux FUSE test-volume mount/write/read/rename/overwrite/unlink/unmount/reopen on disposable Ubuntu 22.04 GitHub VM — verified [CI PASS](https://github.com/promirmir/KRYPTA/actions/runs/39460873238). Not production or a system-volume test.
- [ ] Verify kernel FUSE real mount in additional Linux distributions, multiple OS/kernel versions and simulated sudden power loss; one smoke test does not validate recovery under true outages.
- [ ] Actual production-grade transparent Windows/Linux **OS-level** virtual-volume/block-device integration using independent KRYPTA backend (not BitLocker/LUKS); large-volume, security and recovery tests required.
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