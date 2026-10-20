# KRYPTA Security Status — research checkpoint (2026-10-20)

**Private pre-release research. No independent security audit. No hardware PIN anti-hammering. No system-disk or removable-volume encryption is implemented.**

This page is evidence-based; a passing test is not a proof of confidentiality under every threat model.

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
4. **Android:** the APK currently shows a multilingual research interface; it does not encrypt files, phone storage or installed-app passwords.
5. **Filesystem and memory:** Windows reparse points/ACLs, race between two-pass verification and plaintext output, encrypted destination handling, key erasure, crash consistency and memory forensics remain unresolved.
6. **Formal testing:** independent crypto review, parser fuzzing on supported OSes, restoration test vectors and expert penetration testing.
7. **Distribution:** signed packages and attestable provenance, independent reproduction, change policy and vulnerability-response procedures.

**No statement of military certification, unconditional future-proof security, or impossibility of decryption may be made.** Device and file headers may identify the actual encryption suite, but cannot prove trust on their own.
