# KRYPTA — Defense / Government Readiness Target (aspirational)

**Status:** engineering target, not certification, authorization, procurement eligibility, or evidence of handling classified information.  
**Binding scope:** [PROJECT_CHARTER.md](PROJECT_CHARTER.md).  
**Release status:** private research. Prototype File Vault and HORIZON/0 lab only. KRYPTA does **not** currently qualify for defense use.

## Strategic objective

Develop an original, independent and verifiably secure encryption platform with properties strong enough that defense, government, critical infrastructure and other high-assurance operators could consider independent evaluation and adoption. This **does not** imply universal superiority to all commercial or classified systems. Specific national defense classified-data approvals and procurement requirements differ and must be established before claims or deployment.

No dependency on BitLocker, LUKS, or VeraCrypt as the KRYPTA **encryption engine**. Independent application design, encrypted-volume format, authenticated metadata, key lifecycle, boot integration and transparent on-write protection are required. Existing OS encryption may be inventoried only for interoperability/diagnostics.

## Adversary scenarios — testable, not marketing

| Scenario | Target and required evidence |
|---|---|
| Stolen / imaged offline disk | Per-volume random high-entropy secret; authenticated encryption. Replicated ciphertext plus 1–4 digit PIN must not yield the key when the designated external hardware secret is withheld. Independently evaluate hardware and recovery paths. |
| Adaptive offline password cracking | Parameterized KDF for password-only mode, truthful weakness disclosure; PIN-only mode must **not** be marketed as brute-force resistant. |
| Physical theft of host and disk | Device key nonexportability; enforced hardware authorization, retry budget and anti-rollback, with separate physical attack characterization. |
| Unauthorized block / metadata editing | Authenticate data + position + generation + public metadata; reject tampering without publishing unauthenticated plaintext. |
| Restoring an old valid volume snapshot | Trusted monotonic/external root, rollback detection, clean recovery policy. Authenticated encryption alone does not solve rollback. |
| Power failure during write | Atomic metadata commit, copy-on-write, replay/crash injection tests; no silent inconsistent data or permanent lockout of the sole data copy. |
| Compromised update server / malicious release | Signed reproducible provenance, offline verification, update rollback controls, response and revocation plan. |
| Malware and autonomous AI on an unlocked device | Privilege separation, process isolation, memory lifetime minimization, restricted APIs and hardening. **Disk encryption alone cannot defend against an attacker already controlling the unlocked endpoint.** |
| Large future quantum computers | 256-bit symmetric encryption, crypto agility, PQ KEM/signatures for applicable key exchange and update verification; monitor cryptanalytic progress. No unconditional future-proof promise. |
| Device loss, firmware replacement, broken recovery | Tested recovery key backup, key rotation, identity/policy migration; no forced irreversible destructive actions after wrong PIN guesses. |
| High-throughput operational use | Independent latency and throughput measurement on identical host/disk workloads; audit overhead and hardware acceleration. |

## Engineering requirements for an evaluator

- Document security boundary, hardware/OS dependencies, threat model, supported product configurations, exclusions and high-assurance profile.
- For each property: automated positive, negative, mutation and fault-injection tests with retained artifacts; signed build provenance and reproducibility evidence.
- Dedicated original-volume simulator with deterministic crash injection and untrusted disk image mutation before any real disk, driver or preboot deployment.
- Formal review of nonce uniqueness, KDF separation, authenticated headers, volume transaction state, parser bounds and rollback anchor.
- Cryptographic agility and known-answer/compatibility test vectors for every supported on-disk revision. HORIZON/0 must remain **research-only** until reviewed against a well-understood baseline.
- Hardware secret policy must include PIN retry enforcement that cannot be bypassed by restoring a copied disk, plus secure recovery when the hardware dies.
- Remote/offline operation, minimal network trust, isolation of update infrastructure, no telemetry by default, least privilege and documented incident response.
- No new cryptographic primitive may be introduced into a protected-data path solely because it appears novel or has multiple layers.

## Independent evaluation — distinguish the three things

1. **Correct algorithm:** AES/ChaCha/PQ primitives can be standards-based, but correct primitives are not enough to make a complete product secure.
2. **Evaluated implementation:** independent testing of the specific compiled module and configuration. Examples of useful applicable frameworks include [NIST FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) for defined cryptographic modules, and ISO/IEC 15408 Common Criteria for security-functional evaluation. Applicability and target-of-evaluation boundaries must be specified. **No accreditation is claimed or in progress.**
3. **Authorization to protect classified defense information:** separate country-, mission- and classification-specific authority and process. It must never be inferred merely from FIPS/CC, an open-source repository, or a vendor's security claim.

NIST post-quantum standards:
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM for key establishment, **not file/disk bulk encryption**.
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA signatures.
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) — SLH-DSA signatures.

## Measurable demonstration milestones

1. Independently functional encrypted volume image with **transparent writes**, not a BitLocker/LUKS shell.
2. Robust crash-consistent authenticated metadata tree, journal and recovery tests.
3. PIN-and-hardware secret design with repeatable tests for guess-rate control and rollback even with stolen ciphertext.
4. Independent isolated hardware test and trusted boot design.
5. Recoverability and backwards compatibility across versions; automated security regression and adversarial testing.
6. Stable signed distributions for Windows/Linux and properly scoped Android capabilities.
7. Independent assessment and documented corrections; only then evaluate suitability for government/defense pilots through appropriate authorities.

**Release gate:** KRYPTA must not be described as “military certified”, “defense approved”, “stronger than every encryption product”, “quantum-proof”, or “unbreakable” without objective evidence supporting that exact claim.

The project's **ambition** can be world-leading. Its **actual current state** remains an experimental alpha.
