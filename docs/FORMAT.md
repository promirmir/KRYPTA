# KRYPTA FILE/2 — experimental encrypted file format

**Version:** 2; **Status:** research, unaudited. This format MUST NOT be treated as permanently stable.

## Layout

```text
ASCII security notice (variable length; ends with END KRYPTA NOTICE\n)
MAGIC     (9 bytes: KRYPTA02\x00)
LENGTH    (4 bytes, big-endian, size of canonical JSON header)
JSON      (ASCII, canonical; max 8192 bytes)
CHUNKS    (repeated 4-byte big-endian size + AES-GCM ciphertext/tag)
TERMINAL  (4-byte zero length + authenticated 16-byte final GCM tag)
```

The notice declares `KRYPTA / AUTHENTICATED ENCRYPTED FILE`, `KRYPTA-FILE/2`, `AES-256-GCM`, `Argon2id`, factor presence, `ALPHA/NOT AUDITED` and an accurate brute-force limitation. It is readable without the decryption key. The format's private metadata and ciphertext are **cryptographically bound to the exact notice bytes**; authenticity still cannot be confirmed until decryption succeeds.

**The readable text is not signed by a trusted certification authority** and cannot itself prove a file originated from genuine KRYPTA software. An attacker can write a fake text notice. Never treat the header as a security certificate.

## Key material

- Random DEK: 32 bytes from OS CSPRNG.
- Random Argon2id salt: 16 bytes; fixed cost m=65536 KiB, t=3, p=4, output=32 bytes.
- Optional external keyfile: 32 bytes from OS CSPRNG, hashed via SHA-256 and combined with password-derived value under HKDF-SHA-256.
- 12-byte independent random AEAD nonce wrapping the DEK.
- Per-file stream prefix: 4 random bytes; each 12-byte chunk nonce is prefix || 8-byte chunk index.
- Each chunk is authenticated using header digest, chunk marker, and 8-byte chunk number. Final marker is independently authenticated to detect truncation.

See `krypta/core.py` for the exact, evolving implementation. The parser rejects unsupported field sets and KDF parameters; malicious input handling has not been fuzz-audited.

## Non-goals and warnings

- No true random-access sector or disk encryption.
- No hardware-enforced attempt limit; copied ciphertext admits offline password guesses.
- No verified delete, no hide-length, no metadata anonymity, no plausible deniability.
- No guarantee against runtime malware, keyloggers or RAM scraping.
- A deliberately tampered notice may be rejected by parsing, but source identification is not cryptographically independent before successful decryption.