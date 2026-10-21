# KRYPTA Security Status — public development checkpoint (2026-10-21)

**Public source and PUBLIC development binaries (prerelease). No independent security audit. No hardware PIN anti-hammering. No system-disk or removable-volume encryption is implemented.**

This page is evidence-based; a passing test is not a proof of confidentiality under every threat model.

## Verified independent bulk recovery checkpoint — dev-10-1

[PR #22](https://github.com/promirmir/KRYPTA/pull/22) merged to main
`8c8181436d58f8f0d63b4ec42e43e8bf308cb40c` after all four
Windows/Linux Python test configurations and security analysis passed. The
[three-platform workflow](https://github.com/promirmir/KRYPTA/actions/runs/39673702715)
then passed ALL required jobs and published separate console
`KRYPTA-Windows-x64-Rescue.exe` and `KRYPTA-Linux-x64-Rescue` alongside
the preexisting GUI/Android builds, each with a SHA-256 checksum.

The independent console rescue decrypts ALL existing authenticated PFS/2
files using an offline 256-bit recovery secret plus a matching PVKEY/1 envelope
and separately trusted current receipt. It first fully authenticates source
data and only then creates an exclusive new output directory. Source reads
are forensic read-only; normal failures clean only newly created output.
The final completion manifest is **not cryptographically signed**, and an
abrupt process crash can leave incomplete **UNENCRYPTED PLAINTEXT** files.

This is NOT a production recovery certification, full-disk recovery or
Android Keystore recovery. No independent audit, hardware fault-injection
campaign, Windows ACL red-team review or migration on a new physical
machine has yet been demonstrated. [Usage](OFFLINE_RESCUE_ALL.md).

## Product completion and verified capability reporting (2026-10-20)

KRYPTA is being developed as a **fully working independent encryption product**, not a permanent technology demonstration. Completion requirements are now explicitly defined in [PRODUCT_ACCEPTANCE.md](PRODUCT_ACCEPTANCE.md). A successful unit test is evidence for a specific component, not proof of production security; unreleased or nonfunctional modules must remain clearly identified.

The Android selected-file implementation exists. Older locale strings misleadingly stated that the APK never encrypted any files. The source translations and 11 generated Android resource sets were corrected to accurately describe **actual selected-file AES-256-GCM encryption** and to explicitly state that whole-phone encryption and portable Keystore recovery are not provided. New regression checks guard this distinction.

### Paged-volume progress

[PR #9](https://github.com/promirmir/KRYPTA/pull/9) merged isolated `research/paged_volume.py`: a 3-level authenticated copy-on-write radix tree with bounded 1-GiB sparse logical addressing and 512-MiB on-disk log quota. [Cross-platform regression CI](https://github.com/promirmir/KRYPTA/actions/runs/39470286063) passed on four Windows/Linux Python combinations. The subsequent byte-range `read_at` / `write_at` methods are an integration building block, not an OS mount. **No production-ready whole-disk encryption or certified security result is claimed.**

## Offline independent recovery / verified provisioning (development)

A new recovery-key-only command-line path `list-files` / `export-file` operates without Tk GUI. It requires the independently trusted current external receipt and an independently generated 256-bit recovery secret. The source image is opened readonly and fully authenticated before listing; single-file export is exclusive-create and deliberately produces plaintext. Newly provisioned PFS/2 images must also reopen and verify using both password and recovery methods before reporting success. These changes require executable CI confirmation and a separate review, are source-based (Python dependencies needed), and do not yet provide stable whole-device recovery or a certified offline rescue binary. [Procedure](OFFLINE_RECOVERY_CLI.md).

## Desktop PFS/2 Volume Lab (2026-10-21, public development EXE/ELF)

A separately labeled opt-in Tkinter GUI now exposes authenticated operations on disposable ordinary `.kpv` images: create, verify, import/export, password recovery and full-volume key rotation. All existing-image calls **require a caller-supplied externally trusted receipt**, rather than auto-accepting an image's own receipt. Existing output files refuse overwrite; the plaintext import source is not deleted. The desktop PyInstaller release workflow is configured to test the newly packaged backend end-to-end using disposable data.

**Build verification complete, NOT a production-security approval:** [PR #19](https://github.com/promirmir/KRYPTA/pull/19) merged after successful cross-platform unit tests, security analysis and virtual-display GUI tests. [Three-platform build workflow](https://github.com/promirmir/KRYPTA/actions/runs/39661949384) compiled and exercised packaged EXE/ELF smoke tests and compiled/tested/linted Android. Public [dev-7-1 download](https://github.com/promirmir/KRYPTA/releases/tag/krypta-dev-7-1) was published from commit `cafca79fc438a3dfbed0fd6c1224a057c84c8973`. No independent audit, real-device acceptance, Windows full-disk encryption, Linux system partition encryption or Android full-device encryption is offered. [Full limitations](VOLUME_LAB_GUI.md).

## PVIMG true read-only forensic inspection (2026-10-21, dev-8-1)

[PR #21](https://github.com/promirmir/KRYPTA/pull/21) added an explicit `read_only=True` PVIMG open mode, using an OS read-only descriptor and platform locking. Verification and authenticated export no longer truncate uncommitted crash-recovery tails; the source image of a volume-key migration is read-only as well. Test coverage includes byte-for-byte preservation of an interrupted image, write refusal, lock contention and real Linux FUSE integration. Cross-platform tests and production of the *development* EXE/ELF/APK passed in [GitHub Actions](https://github.com/promirmir/KRYPTA/actions/runs/39665972976), published as [dev-8-1](https://github.com/promirmir/KRYPTA/releases/tag/krypta-dev-8-1).

This is **not** a guarantee that host filesystem metadata, access timestamps or forensic disk evidence are preserved, nor a substitute for a trusted external rollback anchor or a third-party audit. The Android APK remains selected-file only.

## PFS/2 actual volume-key rotation and live-file re-encryption (2026-10-20)

`research/paged_rekey.py` now creates an independently keyed NEW PVIMG/PFS2 encrypted image after verifying all currently live files of a source image against the latest externally trusted receipt. Fresh random 256-bit DEK, new image ID and independent password/recovery slots are created, with source unchanged. Source corruption, wrong old credentials/receipt and partial destination failures cause refusal without overwriting any source. New target is reopened for authenticated final verification. The `research/paged_key_cli.py rotate-volume-key` subcommand keeps passwords out of argv/env.

**Not revocation of copied old snapshots:** any party already possessing the original image and original key may still read the historical data. New credentials alone do not retroactively erase stolen copies. No secure erasure, TPM-backed PIN, guaranteed host-filesystem multi-file atomicity or independently audited physical crash protection is implemented. [Technical details](PFS2_DATA_KEY_ROTATION.md).

## PVKEY/1 — Argon2id-protected volume keys and independent recovery (2026-10-20)

The new `research/paged_keys.py` versioned envelope protects a randomly generated PVIMG volume key with an Argon2id-derived AES-256-GCM wrapping key (64 MiB, 3 iterations) and independently encrypts the same key for a randomly generated 256-bit recovery secret. It binds both authenticated slots to the volume image ID. `research/paged_key_cli.py` supports safe exclusive-creation setup, integrity verification with an external receipt, and non-overwrite password recovery. The optional Linux FUSE mount path now supports password or recovery envelope unlock without raw key bytes on argv.

**Crucial limits:** a copied envelope still allows offline password guesses; this is NOT TPM-protected PIN authentication. Rewrapping a password does not revoke the original password or old copies of its envelope. The independent receipt must still be held in genuinely trusted external storage and updated on changes. Hardware key custody, real-world recovery across OS devices, Windows protected ACL testing and an independent audit remain incomplete. [Architecture / limitations](PVKEY_PASSWORD_RECOVERY.md).

## KRYPTA-PFS/2 — 32-MiB encrypted files and single-commit publication (2026-10-20)

New distinct on-disk catalogue `research/paged_fs2.py` supports sparse individual files up to **32 MiB**, with 64-KiB encrypted directory metadata, bounded per-sector AEAD reads, authenticated SHA-256 and data operations usable by the Linux FUSE adapter. PVIMG/1 now offers a separately named `write_many_atomic_large()` covering 8,208 sectors (32-MiB data plus 16 directory sectors) in **one** authenticated root commit.

This is not a series of independently committed batches: failure before final root publication must recover the previous directory AND previous external receipt. Adversarial tests include injected commit failure on multi-megabyte writes and authenticated reopening with the old receipt. Existing PFS/1 remains version-separated; no implicit conversion is performed.

Hard limits remain: **512 MiB physical append log, 1-GiB sparse logical addressing, flat directory, no POSIX ACLs, no physical power-cut validation, no external hardware anti-rollback, no production keys or Windows system volume**. [Implementation and test scope](PFS2_LARGE_ATOMIC_FILES.md).

## PVIMG-PFS/1 selective encrypted-sector writes and logical recovery export (2026-10-20)

`research/paged_fs.py` now verifies a replaced file's original encrypted data and digest, preserves unchanged authenticated data-sector references and encrypts only changed sectors in a single atomic PVIMG catalogue/data transaction. An identical replacement performs no filesystem commit. Both changes are regression-tested without altering VIMG/0 or the on-disk PFS/1 format.

The new `PagedFileSystem.export_live_files()` creates a **separate no-overwrite encrypted image** containing only the currently listed and verified files. Unlike lower-level sector-copy migration, it excludes unlinked file records and orphaned filesystem sectors. It verifies new copies, reports independent image identity and receipt, leaves the source intact, and checks destination inode before cleanup on a failed copy.

**Not secure erasure or independent anti-rollback:** deleted ciphertext remains in the original image and potentially in flash wear-leveling/history; the new image has no trusted receipt anchor automatically provisioned. No real power-loss durability, Windows disk mount or full-system protection claim is made. [Design](PVIMG_LINUX_FUSE.md).

## Linux PVIMG-PFS/1 filesystem integration (2026-10-20)

The implementation adds `research/paged_fs.py` (authenticated flat file catalogue) and `research/linux_mount_paged.py` on top of existing PVIMG/1 and the Linux FUSE adapter. The transaction limit currently restricts **individual files to 960 KiB** with up to 128 flat entries. A separate CI workflow distinguishes genuine Linux kernel FUSE mount PASS from infrastructure SKIP, while cross-platform unit tests verify byte writes, integrity, no-overwrite and failure recovery.

The system remains in development, and its 1-GiB virtual address range is NOT assured usable storage. No Windows system-volume encryption, secure deletion, trusted rollback anchor, independent audit or physical power-cut durability is claimed. [Architecture and limits](PVIMG_LINUX_FUSE.md).

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
