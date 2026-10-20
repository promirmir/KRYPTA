# Security Policy

KRYPTA is a security product under active development, not yet a production security release. **No released version has been independently audited or certified.** No claim of absolute brute-force resistance is made. The present File Vault must not protect the only copy of valuable data.

Report vulnerabilities privately to repository maintainers using GitHub private security advisories after repository creation. Do not include real encryption secrets or personal data in issues or test fixtures. Do not publish test ciphertext containing sensitive real-world data.

Planned public-release prerequisites: independent audit of key management and format; fuzz testing; documented cryptographic threat model; signed/reproducible builds; power-loss and rollback testing; incident/response policy; tested recovery workflows and safe update process.