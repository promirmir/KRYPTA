# Building KRYPTA on Windows, Linux and Android

**2026-10-20 · INTERNAL / RESEARCH ALPHA**

## Current functionality

| Target | Artifact | What it can actually do |
|---|---|---|
| Windows x64 | `KRYPTA.exe` (unsigned alpha, PyInstaller) | Desktop GUI; research file vault for disposable individual files only |
| Linux x64 | `KRYPTA` ELF executable (runner-compatible, not universal) | Same desktop research file-vault GUI |
| Android | `app-debug.apk` (Android-native Java) | Navigation/status interface ONLY; no encryption or device locking |

**None of the three is approved for production protection.** Whole-system encryption, external-volume encryption, TPM anti-brute-force, password manager and Android system-FBE control are NOT implemented.

## Private CI builds

Go to **Actions** inside the private `promirmir/KRYPTA` repository:

- `KRYPTA / Desktop alpha builds` builds on `windows-2022` and `ubuntu-22.04`. Workflows run on source changes or manually via **Run workflow**. Windows artifact contains an `.exe`; Linux artifact contains a compiled ELF binary. Results are uploaded to Actions artifacts with 14-day retention.
- `KRYPTA / Android UI research APK` runs on source changes under `android/**`, or manually; compiles a **debug** APK with Gradle / Android SDK. Obtain the APK from Actions artifacts only after a successful run.

The workflows do not publish a GitHub Release or make a repository public. GitHub artifact access still follows repository permissions. Do not distribute APK debug signing keys.

## Local development

```sh
python -m pip install -e '.[test]' pyinstaller==6.16.0
python -m pytest -q
python -m PyInstaller --noconfirm --clean --onefile --windowed --name KRYPTA krypta/desktop_entry.py
```

Windows: `dist/KRYPTA.exe`. Linux: `dist/KRYPTA` (build on Linux; do not cross-compile via PyInstaller). Linux binaries are tied to runner libc dependencies: test across intended distributions before shipping. On Linux ensure Tk runtime packages are installed. Windows binaries are unsigned: SmartScreen may warn. Do not bypass security prompts to run untrusted binaries.

APK source lives in `android/` and uses the Android Gradle Plugin 8.7.3, JDK 17 and Android SDK 35. The workflow uses a fixed Gradle version 8.9; CI build success is required before treating it as built.

## Release gates (not met)

Security audit; reproducible/attested dependency chain; FDE-specific tests; recovery and fault injection; code signing with protected publisher keys; independent testing on real devices. Public releases only after owner authorization.