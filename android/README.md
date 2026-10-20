# KRYPTA Android — File Vault 0.5 (development build, private APK)

**Actual local file encryption implemented for selected test documents.** This is not whole-phone encryption, transparent OS storage protection, a PIN password vault or certified secure storage. **Do not use unique or irreplaceable data.**

## What works

- Pick a test input file with Android's Storage Access Framework (SAF), confirm Android's **device credential**, and pick a new destination document.
- **Encrypt or decrypt the chosen file** with a native Java AES-256-GCM streaming format `KRYPTA-MOBILE/1`. Every record has authentication and there is an authenticated end marker so most truncation/append/corruption attempts fail closed.
- A random 256-bit per-file data key is encrypted (wrapped) with a device-specific AES-256-GCM key in **Android Keystore** configured for device-credential authentication. No broad storage or INTERNET permission.
- During decryption the full ciphertext is authenticated into an app-private temporary file **before any plaintext is copied to the selected destination**. The application attempts to delete the private temporary file after finishing. Android flash storage does not provide guaranteed secure deletion.
- 11-language user interface. Android Keystore implementation is separate from the experimental Windows/Linux KRYPTA/HORIZON volume formats.

## Fundamental restrictions

- **No recovery.** Losing or replacing the device, resetting its keys, changing the secure lock or uninstalling the application may permanently prevent decryption. No cross-device export of the KeyStore secret is available.
- The user-selected output can remain incomplete after a failed copy/operation. Delete the failed new output and keep the original. Never operate on your only copy.
- The fixed Android device-credential authorization period is **NOT a proven KRYPTA 1-digit/4-digit anti-brute-force protocol**. The Android Keystore API may be hardware-backed or software-enforced depending on the device, and **hardware properties were not verified**.
- Normal APKs cannot transparently replace Android's existing File-Based Encryption for the entire OS or other applications. This is a **selected-file vault only**, with manual import/export.
- No backwards compatibility with desktop `.kry`. The KRYPTA-MOBILE/1 format and key management remain experimental; security auditing and real-device installation are pending.
- The downloaded APK is debug-signed, not a production update. No signed/reproducible public release has been issued.

## Validation

CI: `.github/workflows/build-android.yml` runs pure JVM encryption/validation tests, Android APK assembly, Android Lint and permission inspection. It cannot test the Android Keystore on physical devices, system credential behavior, SAF providers or key-recovery failure modes.

**Independent encryption engine:** the Android selected-file vault uses KRYPTA's own authenticated chunk format with vetted AES-GCM primitives; it does not call BitLocker, LUKS, VeraCrypt or a remote service. See [docs/PROJECT_CHARTER.md](../docs/PROJECT_CHARTER.md).

## Next steps

Stable signed releases, backup/recovery approach, Android emulator instrumented Keystore tests, physical device and OS-version matrix, transaction-safe output cleanup and a wider independently implemented mobile/desktop compatibility layer, before relying on this app for important data.
