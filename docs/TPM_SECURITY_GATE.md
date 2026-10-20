# KRYPTA / Hardware PIN gate (design + read-only readiness, NOT implemented)

**Status:** Windows capability inventory and advisory logic only. No hardware keys are created; no KRYPTA decryption is bound to TPM; no PIN attempts are rate-limited by this project.

## Why a four-digit PIN is not a cryptographic key

Four-digit numeric PIN = 10,000 combinations; one-digit PIN = 10 combinations. Argon2id and AES-256 do not change that entropy. A software timer, a counter stored on the USB volume, or a file header can be bypassed by cloning data and guessing offline. Threatening banner text cannot provide additional protection.

The proposed verified path must instead keep an independent cryptographically random unlock secret **inside** a TPM/secure element and require PIN authorization enforced by that hardware. A generic nonexportable TPM *encryption key* alone is **not** evidence of PIN anti-hammering: malicious code might call permitted unwrap operations repeatedly if PIN authorization is not enforced by the TPM. The on-disk key envelope must be unusable offline without hardware and must be bound to verified policy. All TPM parameters, authentication controls and key export restrictions must be tested end to end.

## Supported paths (separate security models)

| Use case | Feasible design | Missing evidence |
|---|---|---|
| Windows system drive | OS-supported BitLocker TPM + preboot PIN + Secure/Measured Boot | Machine-specific settings, protector and recovery tests; Windows may require at least 6 PIN characters depending on policy |
| Windows locally bound files | Prototype CNG Platform Crypto Provider key with TPM-enforced PIN *authorization* | Nonexportability, rate limiting, anti-rollback, malware and recovery tests |
| USB encrypted for transport | Independent high-entropy recovery secret or external physical hardware token | Portability, device-loss recovery and attacker with copied ciphertext |
| Android | Native Android FBE + Keystore/Gatekeeper/Weaver | Device-dependent secure hardware evaluation |

A 4-digit PIN can be allowed in the application **only with a prominently accurate security classification**. It is not an approved high-assurance unlock on the existing File Vault. Changing a GUI label cannot alter this limit.

## Read-only Windows TPM inventory

On your own Windows test machine:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\Get-KryptaTpmReadiness.ps1
```

It reads `Get-Tpm`, `Confirm-SecureBootUEFI` and tries opening the public `Microsoft Platform Crypto Provider` handle via CNG. Reports a minimal JSON document with possible `null` when privileges/capabilities are missing. It never creates keys, reads private material, modifies lockout settings, changes boot configuration, or encrypts drives. The Python diagnostic evaluator in `krypta/hardware_readiness.py` rejects malformed inputs and **never** marks PIN anti-hammering as verified.

## Acceptance tests before any 'protected short PIN' claim

1. Independently verify a non-exportable TPM-created random secret is cryptographically required for every successful unwrap, including offline copies of the ciphertext.
2. Prove TPM-side PIN authorization is *mandatory* for each unwrap; monitor TPM dictionary-attack behavior and test clock, power cycle and rollback attacks on disposable hardware. Avoid intentionally locking a user's primary TPM.
3. Test TPM reset / motherboard failure, incorrect PIN and key loss, with verified recovery; recovery path must never weaken normal short-PIN security.
4. Validate measured boot/PCR policy and software updates; confirm that compromise of an unlocked OS is outside the promise without further isolation.
5. Test a cloned USB volume on another device: if the hardware secret is absent, it must remain unavailable, and a separate recovery path must exist.
6. Record TPM model/firmware, Windows build, key policy, lockout configuration, artifacts and independent reviewer sign-off.

Fail closed, without pretending hardware capability = proven security. No destructive actions on production equipment.

### Primary technical sources

- Microsoft, *How Windows uses the TPM*: https://learn.microsoft.com/windows/security/hardware-security/tpm/how-windows-uses-the-tpm
- Microsoft, *TPM fundamentals / anti-hammering*: https://learn.microsoft.com/windows/security/hardware-security/tpm/tpm-fundamentals
- Microsoft, *CNG Key Storage Providers*: https://learn.microsoft.com/windows/win32/seccertenroll/cng-key-storage-providers
- Microsoft, *BitLocker countermeasures*: https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/countermeasures