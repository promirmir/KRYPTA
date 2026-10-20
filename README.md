# KRYPTA

**SECURITY WORKSTATION · v0.4.0-alpha · PRIVATE DEVELOPMENT BUILD**

> **RESEARCH ONLY. NOT AUDITED. NOT APPROVED FOR PROTECTING IMPORTANT DATA.**
>
> The only implemented cryptographic operation is authenticated encryption of **individual ordinary test files**.
> No disk, boot or system volume is ever modified. The interface contains clearly marked planned modules.

KRYPTA is a separate, independent security project. Its long-term goal is robust encryption for Windows system volumes, removable drives, a password vault, and Android integration. It uses public, established cryptographic primitives and aims to minimize attack surface. Project identity and an unmistakable readable security notice are part of the file format, but branding cannot replace cryptographic assurance.

![KRYPTA offline desktop application — Matrix-inspired security UI](assets/matrix-ui.png)


## Distribution formats (alpha; private CI)

KRYPTA is developed for **Windows x64 (`.exe`)**, **Linux x64 (ELF)** and **Android (`.apk`)**. GitHub Actions definitions under `.github/workflows/` build these artifacts for private internal testing. **Android is currently a UI-only APK — it does not encrypt anything.** Desktop builds expose the research file vault for disposable files, not full-disk encryption. See [`docs/BUILD_AND_RELEASE.md`](docs/BUILD_AND_RELEASE.md) and [`android/README.md`](android/README.md). No installer or executable has been independently audited. Do not use these builds as your only protection for important data.

## Available now

- **Desktop GUI (Tkinter; local/offline):** low-distraction black/phosphor-green visual design, module navigation, file encryption, decryption, public-header inspection, and generation of optional random keyfiles.
- **File Vault v2:** AES-256-GCM per chunk with independently unique nonces and authenticated final marker. Random 256-bit data-encryption key; Argon2id-based password derivation (64 MiB / 3 passes / p=4); HKDF-SHA-256; wrapped DEK; authenticated metadata and public notice.
- **Human-readable KRYPTA notice** at the beginning of encrypted files (`.kry`), visible in Notepad or any hex editor. Notice describes the actually active cryptographic suite and research status. Header **is not independently authenticated before unlock**.
- **PIN compatibility:** arbitrary nonempty password, including `1` or four-digit PIN. The UI warns plainly that a short PIN alone is vulnerable to unlimited offline guessing.
- **Optional random keyfile:** second independent secret. The keyfile is not a non-exportable TPM key and can be copied. Do **not** put it on the encrypted device.
- **Non-destructive tests:** no overwriting outputs, original file remains unchanged, integrity checks, negative tests (wrong PIN, bit flip, truncation, missing/wrong keyfile).

## Not implemented

| Module | Status | Minimum architecture requirement |
|:--|:--|:--|
| File Vault | **Research prototype** | Independent crypto/security audit and fuzz testing required before production |
| Drive Shield — external disks / USB | **Not implemented** | Reviewed volume-encryption backend + independent key provisioning and recovery |
| System Shield — Windows boot | **Not implemented** | Windows-supported full-disk engine, TPM 2.0, measured boot, recovery tests |
| Password Shield | **Not implemented** | Proper OS-level secret handling and per-use authentication integrations |
| Android Shield | **Not implemented** | Android File-Based Encryption, hardware Gatekeeper/Weaver/Keystore APIs |
| Hardware-backed anti-brute-force | **Not implemented** | TPM/secure element enforcement, rollback protection and recovery model |
| Security audit / certification | **Not completed** | Third-party review, tests and reproducible releases |

## Install and launch

Python 3.10+ on Windows; Tkinter is part of many default CPython distributions.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m krypta gui
```

CLI also remains available:

```powershell
python -m krypta --help
python -m krypta gen-keyfile example.key
python -m krypta encrypt source-test.txt source-test.kry --keyfile example.key
python -m krypta info source-test.kry
python -m krypta decrypt source-test.kry restored-test.txt --keyfile example.key
python -m pytest -q
```

Use disposable test data, **not** the only copy of important files. The program does not remove original files. Passwords are requested interactively in the CLI, never as command-line arguments.

## Readable file notice

Every newly encrypted file starts with plain ASCII notice similar to:

```text
KRYPTA / AUTHENTICATED ENCRYPTED FILE
Format: KRYPTA-FILE/2
Cipher: AES-256-GCM authenticated encryption
Key material: random 256-bit data encryption key
Key derivation: Argon2id / HKDF-SHA-256
Unlock factors: PIN/password AND external keyfile
Security status: RESEARCH ALPHA / NOT INDEPENDENTLY AUDITED
Security claim: strong encryption does NOT protect short PINs from offline guesses
Public header: UNVERIFIED until successful decryption
END KRYPTA NOTICE
```

`Unlock factors` accurately changes to **PIN/password only (offline guessing possible)** if no keyfile is supplied. The header is an *identification and technical transparency feature*, **not** proof against offline attacks or evidence of independent certification. See [`docs/FORMAT.md`](docs/FORMAT.md).

## Critical security distinction: encryption vs. PIN

A 4-digit PIN has at most 10,000 combinations. No AES mode, visible security notice or software timer can make the PIN high entropy. A short PIN can be secure as an *authentication gesture* when an independently strong secret is held in TPM/TEE/secure element **and the hardware enforces non-replayable attempt restrictions**. Such binding is not implemented in this prototype. A keyfile helps only if unavailable to an attacker with the ciphertext.

## Threat model and transparency

- Encrypted files reveal that KRYPTA was used, and the original file size can be approximated from ciphertext size. There is no plausible deniability guarantee.
- This research implementation does not lock secrets into protected memory or provide protection against malware running on an unlocked machine, keyloggers, RAM extraction, firmware compromise, or side channels.
- Decryption uses a temporary plaintext file on the destination volume before publishing it; deleting it does not guarantee secure erasure. Choose a pre-encrypted destination if data is sensitive.
- The current format and software have no independent cryptographic audit or FIPS validation. Do not describe them as military-certified or quantum-proof.
- AES-256 is a widely trusted symmetric cipher. Adding exotic ciphers without evidence may reduce security instead of improving it.

Further reading: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md).

## GitHub: private until reviewed

The authoritative private development repository is **`promirmir/KRYPTA`**. Repository visibility must remain **PRIVATE** unless the owner explicitly authorizes publication. This source tree is experimental and **not an audited security product**.

Clone into a development environment using an authenticated GitHub account with access to the private repository. Never check in keys, actual passwords, recovery codes, user data, or private credentials. `.gitignore` reduces accidental staging but does not guarantee that secrets are excluded — inspect every commit.

**Do not enable public visibility or publish binaries until independently validated.** See `SECURITY.md` and `docs/RELEASE_CHECKLIST.md`.

## Languages / języki (Windows, Linux, Android)

The current Matrix-inspired UI supports **11 languages**: Polish, English, Russian,
Simplified Chinese, Spanish, Arabic, Hindi, Portuguese, French, German and Indonesian.
Desktop users can switch language within the application. The APK follows the device
language or a selection saved locally inside the app. All three platforms use the
same semantic catalogue; Android resources are generated and validated before APK builds.
The plaintext `.kry` security notice and encrypted file format remain language-independent.
**All security warnings remain mandatory in every locale.** Translations require
human language/UX review before any public release. See [docs/LANGUAGES.md](docs/LANGUAGES.md).

## TPM 2.0 readiness investigation (read-only)

The Windows PowerShell diagnostic `windows/Get-KryptaTpmReadiness.ps1` reads TPM,
Secure Boot and Microsoft Platform Crypto Provider readiness without changing device
configuration, creating keys or testing passwords. See
[docs/TPM_SECURITY_GATE.md](docs/TPM_SECURITY_GATE.md). A positive capability report
**does not prove** brute-force-resistant PIN authorization or production-ready full-disk
encryption. Hardware-backed unlock, disk encryption and Android key management remain
unimplemented.
