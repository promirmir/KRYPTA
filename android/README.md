# KRYPTA Android — File Vault 0.5 (development build, private APK)

**Actual local file encryption implemented for selected test documents.** This is not whole-phone encryption, transparent OS storage protection, a PIN password vault or certified secure storage. **Do not use unique or irreplaceable data.**

## What works

- Pick a test input file with Android's Storage Access Framework (SAF), confirm Android's **device credential**, and pick a new destination document.
- **Encrypt or decrypt the chosen file** with a native Java AES-256-GCM streaming format `KRYPTA-MOBILE/1`. Every record has authentication and there is an authenticated end marker so most truncation/append/corruption attempts fail closed.
- A random 256-bit per-file data key is encrypted (wrapped) with a device-specific AES-256-GCM key in **Android Keystore** configured for device-credential authentication. No broad storage or INTERNET permission.
- During decryption the full ciphertext is authenticated into an app-private temporary file **before any plaintext is copied to the selected destination**. The application attempts to delete the private temporary file after finishing. Android flash storage does not provide guaranteed secure deletion.
- 11-language user interface. Android Keystore implementation is separate from the experimental Windows/Linux KRYPTA/HORIZON volume formats.

## KRYPTA-MOBILE/2 independent recovery (new, development)

New encryptions are written in `KRYPTA-MOBILE/2`. This is **not** the
Windows/Linux `.kry` file format; it is a separately specified KRYPTA format
with portable recovery. The existing `KRYPTA-MOBILE/1` decryption path remains
intact for old Android files, but old v1 files still have **no independent
recovery** if Android Keystore is lost.

The application now requires selecting a NEW 32-byte recovery-secret output
through Storage Access Framework. It writes and reads back the secret **before**
creating any MOBILE/2 ciphertext; inability to verify that secret stops new
encryption. **Move the recovery secret to a separate secure device** and keep
independent backups: anyone possessing it can unlock the corresponding mobile
archive without Android Keystore. A recovery secret stored only on the phone
does not protect against loss, theft, factory reset or storage failure. The app
still uses Android device-credential authentication to unlock files normally.

On Windows or Linux with the source checkout, the same encrypted Android file
can be authenticated or recovered independently using the 32-byte recovery
secret, without exporting the hardware-bound Android Keystore key:

```console
python -m krypta mobile-verify encrypted.km2 --recovery-keyfile external.krc
python -m krypta mobile-recover encrypted.km2 restored-test.bin --recovery-keyfile external.krc
```

The recovery tool validates the whole archive before creating plaintext and
authenticates again while writing a new no-overwrite output. A successful
verification does not prove crash consistency, device-wide encryption, safe
deletion, or independent security certification. CLI recovery currently requires
a Python source installation; it is not yet exposed inside the desktop EXE.
A malicious or failed Android document provider can still leave an incomplete
keyfile or ciphertext. Do not use irreplaceable data. CI checks JVM and Python
against a common pinned AES-GCM vector; physical Android device/SAF export
tests remain required.

## Fundamental restrictions

- **Legacy v1:** no recovery after loss of Android Keystore. **New v2:** 32-byte independent key can recover the file on desktop; if that key is lost together with Android Keystore, recovery is still impossible. Android Keystore itself remains nonexportable.
- The user-selected output can remain incomplete after a failed copy/operation. Delete the failed new output and keep the original. Never operate on your only copy.
- The fixed Android device-credential authorization period is **NOT a proven KRYPTA 1-digit/4-digit anti-brute-force protocol**. The Android Keystore API may be hardware-backed or software-enforced depending on the device, and **hardware properties were not verified**.
- Normal APKs cannot transparently replace Android's existing File-Based Encryption for the entire OS or other applications. This is a **selected-file vault only**, with manual import/export.
- The Android MOBILE/1 and MOBILE/2 formats are intentionally distinct from desktop `.kry`; MOBILE/2 recovery is implemented separately on desktop. Security auditing and real-device installation are pending.
- The downloaded APK is debug-signed, not a production update. No signed/reproducible public release has been issued.

## Validation

CI: `.github/workflows/build-android.yml` runs pure JVM encryption/validation tests, Android APK assembly, Android Lint and permission inspection. It cannot test the Android Keystore on physical devices, system credential behavior, SAF providers or key-recovery failure modes.

**Independent encryption engine:** the Android selected-file vault uses KRYPTA's own authenticated chunk format with vetted AES-GCM primitives; it does not call BitLocker, LUKS, VeraCrypt or a remote service. See [docs/PROJECT_CHARTER.md](../docs/PROJECT_CHARTER.md).

## Next steps

Stable signed releases, backup/recovery approach, Android emulator instrumented Keystore tests, physical device and OS-version matrix, transaction-safe output cleanup and a wider independently implemented mobile/desktop compatibility layer, before relying on this app for important data.
