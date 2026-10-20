# KRYPTA Security Status — research checkpoint (2026-10-20)

**Private pre-release research. No independent security audit. No hardware PIN anti-hammering. No system-disk or removable-volume encryption is implemented.**

This page is evidence-based; a passing test is not a proof of confidentiality under every threat model.

## Product completion and verified capability reporting (2026-10-20)

KRYPTA is being developed as a **fully working independent encryption product**, not a permanent technology demonstration. Completion requirements are now explicitly defined in [PRODUCT_ACCEPTANCE.md](PRODUCT_ACCEPTANCE.md). A successful unit test is evidence for a specific component, not proof of production security; unreleased or nonfunctional modules must remain clearly identified.

The Android selected-file implementation exists. Older locale strings misleadingly stated that the APK never encrypted any files. The source translations and 11 generated Android resource sets were corrected to accurately describe **actual selected-file AES-256-GCM encryption** and to explicitly state that whole-phone encryption and portable Keystore recovery are not provided. New regression checks guard this distinction.

### Paged-volume progress

[PR #9](https://github.com/promirmir/KRYPTA/pull/9) merged isolated `research/paged_volume.py`: a 3-level authenticated copy-on-write radix tree with bounded 1-GiB sparse logical addressing and 512-MiB on-disk log quota. [Cross-platform regression CI](https://github.com/promirmir/KRYPTA/actions/runs/39470286063) passed on four Windows/Linux Python combinations. The subsequent byte-range `read_at` / `write_at` methods are an integration building block, not an OS mount. **No production-ready whole-disk encryption or certified security result is claimed.**

## Sparse PVIMG/1 verified compact-copy (2026-10-20)

The `PagedResearchVolume.export_compacted_copy()` API authenticates the live source state, streams allocated sectors to a separate exclusive-create image with a new image ID, and verifies the complete destination against the source. Failure injection covers corrupt source data, interrupted destination writes, existing destination files, output-path replacement and preservation of source bytes. `read_at()` now rejects unaligned ranges that touch more than the allowed number of sectors. See [PVIMG design and limits](PAGED_VOLUME_RESEARCH.md) and `tests/test_paged_compaction.py`.

This is a **file-image development component**, not an online disk compactor or physical storage guarantee. The original file remains intact, old ciphertext is not erased, and no independent trusted rollback receipt store exists.

## Android selected-file research vault (2026-10-20)

The Android **0.5.0 research APK** now implements actual selected-file encryption/decryption through `android/app/src/main/java/io/krypta/research/VaultFormat.java` and an Android Keystore wrapping key (`AndroidVaultKey.java`). Each file uses a random 256-bit DEK; encrypted 64-KiB chunks and an authenticated terminal record use AES-256-GCM. The code is separate from both desktop `.kry` and experimental HORIZON `.kvi` formats.

**Evidence:** `android/app/src/test/java/io/krypta/research/VaultFormatTest.java` passes pure-JVM tests; the Android 35 debug APK builds and passes lint and permission checks in [CI](https://github.com/promirmir/KRYPTA/actions/runs/39436106810). No INTERNET/broad-storage permission was added. The new warning/action labels are localized for 11 languages.

**Limitations:** No Android physical-device Keystore test, no secure/portable recovery key, no proof of hardware-enforced guess throttling, no complete file-write atomicity, no tested OEM compatibility, no actual Android whole-device encryption. Decrypts to an app-private disposable cache file before exporting verified plaintext; deleting an app cache file does not guarantee flash secure erasure. Data may become permanently inaccessible after device loss/Keystore reset. Do not use the debug APK for irreplaceable files.

## Linux FUSE adapter research (2026-10-20)

The original KRYPTA-FS/VIMG/HORIZON stack has an **opt-in Linux FUSE I/O adapter** (`research/linux_fuse.py`) and a Linux-only explicit-risk CLI (`research/linux_mount.py`). Simulated Linux FUSE callbacks are exercised on synthetic `.kvi` images across Windows/Linux CI. Actual Linux FUSE kernel mounting/unmounting, filesystem recovery after VM crash, driver integration and production OS transparent disk encryption remain **UNTESTED/NOT IMPLEMENTED**. Source is independent of BitLocker/LUKS. [Scope and limitations](LINUX_FUSE_RESEARCH.md).

## Independent KRYPTA-FS real Linux FUSE mount — one disposable VM result

The experimental `research/linux_fuse.py` uses **KRYPTA's own** HORIZON/VIMG/FS authentication/encryption and Linux FUSE only as a system I/O interface. It does not delegate any encryption to BitLocker, LUKS or VeraCrypt.

**Evidence:** [GitHub Actions run 39460873238](https://github.com/promirmir/KRYPTA/actions/runs/39460873238) explicitly passed a **genuine kernel FUSE** mount of an ephemeral test `.kvi` image under Ubuntu 22.04, ordinary file write/read, rename, overwriting, unlink, unmount and authenticated reopen. Cross-platform synthetic regression testing verifies path-to-file-handle identity and fail-closed errors.

**Limitations:** at most 512 KiB logical image and a flat catalogue; no directories/ACL/POSIX permissions persistence, device-bound recovery, trusted anti-rollback store, crash test with real power interruption, Windows filesystem mount, whole system disk protection or comparable military assurance. Successful kernel FUSE operation in one CI VM is NOT evidence of these properties. [Linux scope and reproduction notes](LINUX_FUSE_RESEARCH.md).

## VIMG authenticated-manifest canonicalization (2026-10-20)

KRYPTA-VIMG/0 now compares each MAC-verified manifest's exact JSON bytes against its canonical serializer. Authenticated-but-noncanonical records (duplicate keys, reordered properties, noncanonical whitespace) are rejected without modifying the input image. These are **defense-in-depth parser and cross-implementation consistency checks**, not proof against key compromise, ciphertext rollback, unknown cryptographic vulnerabilities or physical power loss.

**Evidence:** [private PR #8](https://github.com/promirmir/KRYPTA/pull/8), [Windows/Linux Python 3.11/3.13 CI success](https://github.com/promirmir/KRYPTA/actions/runs/39467698648); tests in `tests/test_vimg_manifest_canonical.py`. Current VIMG remains research-only.

## Research live-sector migration and file integrity sweep

`ResearchVolume.export_compacted_copy()` creates a NEW no-overwrite authenticated image from currently live sectors, retaining the original and reporting a different image ID/receipt. `ResearchFileSystem.verify_all()` reads/verifies all currently listed files. Negative tests check corrupted source, existing destination, failures during migration and incomplete genesis cleanup. **This is not in-place compaction, secure deletion or anti-rollback migration.** [Limits and test instructions](VIMG_LIVE_MIGRATION.md).

## Experimental encrypted volume image — KRYPTA-VIMG/0

Source: `research/volume_image.py`; [design, limitations and safety](VOLUME_IMAGE_V0.md); `research/volume_demo.py`; tests in `tests/test_volume_image.py`.

Research-only regular `.kvi` image, 128 test sectors at 4096 bytes each. The `write()` API automatically encrypts every full sector through HORIZON/0 and updates a HMAC-authenticated append-only metadata map, separated by durable flush attempts. Synthetic crash tests exercise truncation and recovery of the last complete commit; tampering with an authenticated record is rejected. No system disk, mountable virtual block device, Android storage or physical TPM is changed.

**Not achieved:** OS-level transparent filesystem writes, durable production-grade multi-sector crash atomicity, independent anti-rollback anchor, physical drive recovery validation, secure key persistence/recovery, hardware PIN attempt limit, or independent evaluation. The research image implements logical multi-sector commits and process-level single-writer exclusion for Windows/POSIX; these do not guarantee safety on real disks.

## Original engine research — HORIZON/0 (2026-10-20)

Product direction is defined by [PROJECT_CHARTER.md](PROJECT_CHARTER.md): KRYPTA's eventual transparent disk encryption **must be an independent system, not a BitLocker or LUKS wrapper**. Existing OS encryption inspection code is an optional read-only diagnostic only.

Experimental research files: [HORIZON_CRYPTO_RFC.md](HORIZON_CRYPTO_RFC.md), `research/horizon_lab.py`, `tests/test_horizon_lab.py`. The research construction uses independently derived per-record keys, AES-256-GCM and ChaCha20-Poly1305, plus authenticated block identity and version. It **does not** implement transparent disk I/O, authenticated transaction roots, anti-rollback, secure key release, full-disk encryption, or anything protecting the user's actual computer/phone.

Current tests validate selected correctness and tamper-rejection cases on research input only. The scheme is NOT independently cryptanalyzed; neither its superiority over AES-256/BitLocker nor resistance to unknown quantum/AI attacks has been established. There is no guarantee that layering primitives increases security.


## Implemented and tested

| Area | Evidence | What it establishes |
| --- | --- | --- |
| File Vault authenticated streaming encryption | `tests/test_vault.py`, `tests/test_decrypt_safety.py` | Selected encrypt/decrypt round-trips, incorrect-password and tamper rejection |
| File handling hardening | `krypta/core.py`, `tests/test_file_descriptor_safety.py` | POSIX no-follow/descriptor validation for source/keyfile; exclusive keyfile creation; Windows test coverage |
| Windows/Linux builds | `.github/workflows/build-desktop.yml` | PyInstaller builds and packaged smoke test on hosted runners; hashes included with artifacts |
| Android research UI | `.github/workflows/build-android.yml` | Debug APK builds, permission check, Android Lint, language resource synchronization |
| Languages | `krypta/i18n.py`, `tools/sync_android_strings.py` | Shared 11-locale interface catalogue and automated format checks |
| TPM readiness | `windows/Get-KryptaTpmReadiness.ps1` | Read-only diagnostics; DOES NOT verify rate limiting |
| TPM key-wrap design | `windows/Test-KryptaTpmWrap.ps1` | Explicit opt-in experiment prepared; *not* exercised on physical TPM |
| CNG correctness | `windows/Test-KryptaSoftwareCngOaep.ps1` | RSA-OAEP-SHA256 test using a disposable software key, not a TPM-backed key |
| Static/dependency scanning | `.github/workflows/security-analysis.yml` | Bandit and pip-audit, weekly and on relevant code changes; catches known issues, not unknown ones |

## Confirmed dependency remediation

An initial audit identified advisories affecting the previous declared range `cryptography>=43,<48`. The dependency floor is now **`cryptography>=50.0.2,<51`**, which includes releases patched for the reported advisories, subject to a successful new dependency audit. File-format structure is unchanged. This is not evidence that all future cryptographic bugs are impossible.

## Blocking work before any protection claim or public release

1. **Four-digit PIN protection:** high-entropy, nonexportable key + enforceable authorization rate limit resistant to copying encrypted data and rollback. This is NOT implemented; a PIN alone remains vulnerable to offline guessing.
2. **Physical TPM tests:** use a disposable hardware device, validate provider key behavior and clean failure/recovery on firmware updates and board loss.
3. **Windows full disk and USB backend:** no kernel/boot changes without separate review, power-loss/resume and recovery exercises.
4. **Android:** the 0.5.0 APK encrypts/decrypts explicitly selected test files using KRYPTA-MOBILE/1; it does **not** provide phone-wide encryption, installed-app password protection, secure portable recovery, or independent hardware assurance.
5. **Filesystem and memory:** Windows reparse points/ACLs, race between two-pass verification and plaintext output, encrypted destination handling, key erasure, crash consistency and memory forensics remain unresolved.
6. **Formal testing:** independent crypto review, parser fuzzing on supported OSes, restoration test vectors and expert penetration testing.
7. **Distribution:** signed packages and attestable provenance, independent reproduction, change policy and vulnerability-response procedures.

**No statement of military certification, unconditional future-proof security, or impossibility of decryption may be made.** Device and file headers may identify the actual encryption suite, but cannot prove trust on their own.
