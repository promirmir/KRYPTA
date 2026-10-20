# TPM 2.0 — non-exportable key proof of concept (design gate)

Status: opt-in disposable-key test script prepared and its no-key default validated in Windows CI; **physical TPM key testing has NOT been performed.** This is not a short-PIN anti-brute-force claim.

## Objective

Demonstrate that an explicitly opted-in Windows test device can generate and use a **new disposable non-exportable key** in the Microsoft Platform Crypto Provider. Its public key may be inspected; secret material must not be exported, logged or copied into GitHub artifacts.

Do not modify: BitLocker, existing TPM keys, Secure Boot, BIOS/UEFI, disks, recovery protectors or Windows sign-in configuration.

## Threat model and non-goals

- CNG Platform Crypto Provider reports a TPM-backed provider, but **a successfully created key does not by itself establish hardware-enforced retry limits, PIN authentication, measured-boot binding or resistance to rollback**.
- The File Vault password+keyfile flow is presently vulnerable to offline password guesses when the attacker has all unlocking material. Do not claim otherwise.
- A plain removable volume has no dependable local retry counter; offline copies can be attempted elsewhere.
- A 4-digit PIN alone has at most 10,000 possibilities. Resist offline guesses with a separately protected high-entropy secret and an independently evaluated hardware authorization policy. Verify that *all* unlocking paths enforce the policy.
- Successful Windows CI tests prove software correctness only. GitHub-hosted Windows runners should not be treated as representative physical TPMs.

## Milestone 1: safe hardware proof (explicit opt-in)

1. Inventory TPM version, readiness and lockout state, Secure Boot and CNG provider capability. Missing privileges/unsupported API => UNKNOWN, not SECURE.
2. Generate a new uniquely named disposable CNG key from the **Microsoft Platform Crypto Provider**. Never overwrite existing keys. Allow operation only with an explicit operator flag and warning. Do not generate the key in a normal application startup.
3. Exercise an ephemeral challenge-response sign/verify with the public key. Test private-key export rejection without outputting any private key bytes.
4. Clean up only the specifically generated test key. Record the test-key label, key provider, pass/fail/unknown and sanitized error types, not any passwords, recovery strings or secret material.
5. Unit tests must exercise denial/unsupported-provider cases and cleanup behavior, and build CI must run in read-only/no-TPM mode.
6. Inspect the design with a second independent implementation or expert before relying on it for data storage.

**Acceptance:** pass a disposable hardware test plus a comprehensive failure-path audit. This milestone never advertises PIN protection or volume encryption.

## Milestone 2: authorization and recovery design (separate security gate)

Define the protected high-entropy wrapping secret; which TPM policies gate release; measured-boot/PCR update and recovery handling; an anti-rollback policy; device loss, mainboard replacement and firmware/OS updates; explicit recovery-key backups; safe retry-budget experiments; and how successful authorization binds to the particular encrypted object.

**Acceptance:** demonstrate rate-limiting and anti-rollback on real hardware *without* harming the user's everyday device. Do not assume Windows Hello PIN, Windows CNG signing, or software delay means KRYPTA has enforced anti-hammering.

## Milestone 3: removable storage (separate compatibility architecture)

For disk encryption choose an audited backend, test removable drive recovery/portability and interruption scenarios. Define behavior when the user's hardware secret is absent; in PIN-only mode present the offline-attack vulnerability accurately.

## Release blockers

Independent cryptographic review, threat-model tests, repeated power-loss and rollback simulations, signed builds, recovery and upgrade tests, independent audit. Until then keep repository PRIVATE and mark builds RESEARCH ONLY.


## Implementation status

- `windows/Test-KryptaTpmKey.ps1` exists as a manual **opt-in** proof of concept. Normal invocation without `-RunDisposableTest` reports `NOT_RUN` and must not create/delete any key.
- Windows GitHub Actions statically checks script syntax and its default no-key path. This is **not** a TPM signing test or evidence of hardware throttling.
- Running the opt-in key creation path requires explicit operator approval on a noncritical TPM-equipped Windows test device; cleanup and provider behavior must be recorded.

## Milestone 1b: disposable 256-bit data-key wrapping (NEW RESEARCH PROBE)

`windows/Test-KryptaTpmWrap.ps1` is a separate, opt-in experiment:

- The **default invocation** returns `NOT_RUN` immediately and does not request or modify a TPM key.
- With `-RunDisposableTest` on explicitly designated disposable Windows hardware, it attempts a newly generated, uniquely named **Microsoft Platform Crypto Provider** RSA key with export disabled.
- A random 256-bit *test* secret is locally wrapped and unwrapped using **RSA-OAEP-SHA256**. The script compares the recovered bytes without printing any key material and best-effort clears managed byte arrays.
- It attempts one PKCS#8 export to verify that specific API rejects private material, then deletes the specifically named key with a fresh handle.
- Unexpected creation/wrapping results fail closed. If deletion fails, the report contains the *generated test-key name* to permit reviewed manual cleanup. No existing key, actual encrypted file, recovery policy or disk is touched.
- This probe **does not** authenticate a human PIN, rate-limit authorization attempts, configure TPM PCR/boot policy, provide recovery, or validate anti-rollback. **Do not wire it into File Vault or present it as disk protection.**
- RSA-OAEP hardware support and key ownership/cleanup remain to be tested on real TPM 2.0 hardware. PowerShell syntax/default-path GitHub tests are necessary but insufficient.
- Managed-runtime secret arrays cannot guarantee zeroization of all native provider internals or copies. Never feed a real disk DEK to this script.

### Explicit opt-in test on a designated disposable test Windows machine only

```powershell
# SAFE DEFAULT: inspect the contract, do not create any key
.\windows\Test-KryptaTpmWrap.ps1

# HARDWARE EXPERIMENT — only after operator reviews and explicitly accepts risks
.\windows\Test-KryptaTpmWrap.ps1 -RunDisposableTest
```

Do not use the second command on your main Windows computer, on a production volume, or to justify short PINs as secure.
