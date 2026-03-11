# GitHub Copilot — Workspace Instructions for QSIP

## Project Identity

**QSIP (Quantum-Safe Internet Protocol Suite)** is a foundational security infrastructure project implementing three interlocking protocol layers:

1. **ZK Identity Layer** — Zero-knowledge, self-sovereign identity using post-quantum keypairs
2. **Quantum-Safe DNS** — PQC-signed DNS resolution and BGP route validation overlay
3. **Post-Quantum Email Protocol (PQEP)** — Drop-in quantum-resistant email with encrypted headers

This project is **security-critical**. Every suggestion must prioritize correctness and security over brevity or cleverness.

---

## Architecture Overview

```
src/
├── crypto/        # PQC primitives ONLY — all crypto lives here
│   ├── kem.py         CRYSTALS-Kyber KEM (NIST FIPS 203)
│   ├── signatures.py  CRYSTALS-Dilithium signatures (NIST FIPS 204)
│   └── hybrid.py      Classical + PQC hybrid wrapper
├── identity/      # ZK self-sovereign identity
│   ├── keypair.py     PQC keypair generation and management
│   ├── credential.py  Verifiable credentials and claims
│   └── zk_proof.py    Zero-knowledge proof construction/verification
├── dns/           # PQC-secured DNS layer
│   ├── resolver.py    DNS-over-TLS resolver with DNSSEC++ validation
│   └── validator.py   PQC signature validation on DNS records
├── email/         # Post-Quantum Email Protocol
│   ├── composer.py    Email construction with PQEP headers
│   ├── encryptor.py   Kyber KEM + AES-256-GCM body encryption
│   └── transport.py   SMTP/IMAP with PQ-enhanced TLS
└── common/
    └── config.py      Centralized config loaded from .env ONLY
```

---

## Absolute Rules (Never Violate)

### Cryptography
- **NEVER** implement cryptographic primitives from scratch. Always use `oqs` (liboqs) for PQC or `cryptography` (PyCA) for classical.
- **NEVER** use: MD5, SHA1, RSA < 3072-bit, ECC (quantum-vulnerable), ECB mode, static IVs/nonces.
- **ALWAYS** use authenticated encryption (AES-256-GCM or ChaCha20-Poly1305). Never unauthenticated.
- **ALWAYS** generate nonces/IVs with `secrets.token_bytes()` or `os.urandom()`. Never `random`.
- **NEVER** store key material in plaintext. Use the `KeyStore` abstraction in `src/identity/keypair.py`.
- All KEM operations use `Kyber1024` by default. Override only via config, never hardcoded.
- All signature operations use `Dilithium5` by default.

### Secrets & Configuration
- **NEVER** hardcode secrets, keys, passwords, tokens, or URLs in source code.
- All configuration comes from `src/common/config.py` which reads from `.env`.
- **NEVER** log secret values, key material, or ZK witnesses — not even at DEBUG level.
- `.env` is in `.gitignore`. Only `.env.example` is committed. Keep `.env.example` up to date.

### Code Quality
- All public functions and classes must have docstrings explaining security properties.
- Type hints are mandatory (`from __future__ import annotations`).
- No bare `except:` clauses — catch specific exceptions and handle properly.
- All errors in crypto operations must raise `QSIPCryptoError` (from `src/common/exceptions.py`).
- Constant-time comparison required for any security-sensitive byte comparison: use `hmac.compare_digest()`.

### Testing
- Every crypto function must have a corresponding unit test in `tests/`.
- Tests for crypto MUST include: happy path, tampered ciphertext rejection, wrong-key rejection.
- Use `pytest` and `pytest-cov`. Coverage target: 90%+.
- **NEVER** use real keys or real credentials in tests. Generate ephemeral test keys only.

---

## Dependency Policy

Approved cryptographic libraries only:
| Library | Purpose | Version Constraint |
|---------|---------|-------------------|
| `oqs` | liboqs Python bindings — all PQC operations | >= 0.9.0 |
| `cryptography` | Classical crypto, AES-GCM, HKDF, X25519 | >= 42.0.0 |
| `dnspython` | DNS resolution and record parsing | >= 2.6.0 |
| `python-dotenv` | `.env` loading | >= 1.0.0 |
| `pydantic` | Config validation | >= 2.0.0 |

Adding **any new cryptographic dependency** requires updating this file and `docs/ARCHITECTURE.md` with justification.

---

## Layer Dependencies (Build Order)

```
common/config.py          ← no dependencies
    ↓
crypto/ (kem, sig, hybrid) ← depends on oqs, cryptography
    ↓
identity/ (keypair, cred, zk) ← depends on crypto/
    ↓
dns/ (resolver, validator)    ← depends on identity/, crypto/
    ↓
email/ (composer, enc, transport) ← depends on identity/, crypto/, dns/
```

Never create circular imports between these layers.

---

## Naming Conventions

- Classes: `PascalCase` — e.g., `KyberKEM`, `PQEPComposer`, `ZKCredential`
- Functions: `snake_case` — e.g., `encapsulate_key()`, `verify_signature()`
- Constants: `UPPER_SNAKE_CASE` — e.g., `DEFAULT_KEM_ALGORITHM`
- Exceptions: suffix with `Error` — e.g., `QSIPCryptoError`, `KeystoreError`
- Private methods: prefix with `_` — e.g., `_derive_key()`

---

## What To Do When Uncertain

- If unsure about a cryptographic design decision, add a `# SECURITY-REVIEW:` comment explaining the concern.
- If a feature requires a new algorithm not in the approved list, leave a `# TODO(security): needs review` comment and open an issue.
- Prefer explicit over implicit in all security-sensitive code.
- When in doubt, do less and flag it — under-featured secure code is better than full-featured insecure code.
