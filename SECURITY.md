# Security Policy — QSIP

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes (active development) |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via:
- **Email**: jago.koenig@proton.me  
- **Subject**: `[QSIP SECURITY] <brief description>`
- **Encrypt with**: the project's public Dilithium signing key (see `docs/PROJECT_KEYS.md`)

You will receive an acknowledgment within **48 hours** and a full response within **7 days**.

## Security Model & Threat Assumptions

### In Scope
- Cryptographic primitive misuse or downgrade attacks
- Key material leakage through any code path
- ZK proof forgery or witness leakage
- DNS record spoofing bypassing PQC validation
- Email header encryption bypass
- Side-channel vulnerabilities in crypto operations

### Out of Scope
- Physical access to a device running QSIP
- Compromise of the underlying OS or hardware
- Attacks requiring the user's keystore passphrase to already be compromised

## Cryptographic Choices

All cryptographic decisions are documented in `docs/ARCHITECTURE.md`.

| Primitive      | Algorithm       | Standard       | Rationale |
|----------------|-----------------|----------------|-----------|
| KEM            | CRYSTALS-Kyber1024 | NIST FIPS 203 | Highest security level, quantum-safe |
| Signatures     | CRYSTALS-Dilithium5 | NIST FIPS 204 | Highest security level, quantum-safe |
| Hash           | SHA3-512        | NIST FIPS 202  | Quantum-resistant (Grover's: 256-bit security) |
| Symmetric enc  | AES-256-GCM     | NIST FIPS 197  | AEAD, widely audited |
| KDF            | HKDF-SHA3-512   | RFC 5869       | Secure key derivation from KEM shared secret |
| ZK Proofs      | Schnorr-based   | —              | Simple, auditable, no trusted setup |

### Hybrid Mode
During the transition period (`QSIP_HYBRID_MODE=true`), QSIP wraps classical X25519 + Kyber1024 so that security holds if either algorithm is broken. This follows IETF draft-ietf-tls-hybrid-design.

## Known Limitations (v0.1)

- Full ZK circuits use a simplified Schnorr-based scheme; production-grade Groth16/Halo2 circuits are planned for v0.2
- BGP validation is an overlay/advisory layer only — it cannot enforce routing policy without ISP cooperation
- liboqs is in active development; production use should track their security advisories

## Secure Development Practices

- All secrets loaded exclusively from `.env` (never hardcoded)
- `.env` is in `.gitignore` — enforced by pre-commit hook
- Key material never written to disk unencrypted
- All cryptographic operations go through `src/crypto/` — no inline crypto elsewhere
- Dependencies pinned with hashes in `requirements.txt`
- CI runs `bandit` (Python SAST) and `safety` (CVE checks) on every push
