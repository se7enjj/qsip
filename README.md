# QSIP — Quantum-Safe Internet Protocol Suite

[![CI](https://github.com/se7enjj/qsip/actions/workflows/ci.yml/badge.svg)](https://github.com/se7enjj/qsip/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-128%20passed-brightgreen)](https://github.com/se7enjj/qsip/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-%3E80%25-brightgreen)](https://github.com/se7enjj/qsip/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20|%203.12-blue)](https://github.com/se7enjj/qsip)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

> **Status**: v0.2 Lab Prototype (March 2026) — Not production-ready  
> **License**: Apache 2.0  
> **Security Policy**: [SECURITY.md](SECURITY.md)  
> **Architecture**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## What Is QSIP?

QSIP is a foundational security infrastructure project that re-architects three
critical internet layers to be quantum-safe and privacy-preserving:

| Layer | Problem It Solves | Algorithms |
|-------|------------------|------------|
| **ZK Identity** | PKI / OAuth / CA trust collapses under Shor's algorithm | Dilithium5, Schnorr ZK (→ Halo2 in v0.3) |
| **PQC DNS** | DNSSEC signatures are forged by quantum computers | Kyber1024 KEM, Dilithium5 DNS TXT records |
| **PQ Email (PQEP)** | "Harvest now, decrypt later" — your encrypted email is being stored now | Kyber1024 KEM, AES-256-GCM, X25519 hybrid |
| **HTTPQ** | HTTPS / TLS uses quantum-breakable ECDH + RSA/ECDSA certificates | Kyber1024 KEM handshake, ML-DSA-87 certificates — real TCP sockets |

These layers form an **interlocking stack**:

```
[ ZK Identity ]       who you are — provably, without revealing private data
       ↓
[ Quantum-Safe DNS ]  how you are found — PQC-signed, unforgeable records
       ↓
[ PQ Email (PQEP) ]   how you communicate — end-to-end quantum-safe
       ↓
[ HTTPQ ]             how you connect — quantum-safe TLS over real TCP sockets
```

---

## Do You Need a Quantum Computer to Use QSIP?

**No. You do not need — and should not have — a quantum computer.**

QSIP runs entirely on ordinary laptops, servers, and phones. It uses
*post-quantum cryptography* (PQC): classical algorithms mathematically
designed to **resist** attacks from future quantum computers.

The threat comes **from** quantum computers (expected within 5–15 years at
cryptographically-relevant scale). QSIP is the defence — protecting your
communications today, before those machines exist.

| Role | Hardware Needed |
|------|----------------|
| Anyone using QSIP | Any modern CPU — laptop, server, phone |
| The attacker QSIP defeats | A cryptographically-relevant quantum computer (does not yet exist) |

If you protect your data with QSIP now, it remains safe even if a quantum
computer is built tomorrow. That is the entire point of deploying PQC today.

---

## Why March 2026 Is the Right Time

- **NIST finalized** CRYSTALS-Kyber (FIPS 203) and Dilithium (FIPS 204) in August 2024
- **"Harvest now, decrypt later"** is confirmed active — state-level adversaries
  collect encrypted traffic today to decrypt once quantum hardware matures
- **NIST & CISA migration guidance** require critical infrastructure to begin PQC
  transition now, not when quantum computers are imminent
- **No unified open-source stack** currently combines quantum-safe identity, DNS,
  and email into one cohesive, auditable suite
- Google, Apple, and Signal have already deployed PQC in TLS/messaging —
  **email and DNS infrastructure remain largely unprotected**

---

## Honest State of the Project (v0.2, March 2026)

QSIP is a **validated lab prototype**. Here is an exact breakdown of what is
real, what uses a development mock, and what is planned.

### What Is Real and Running Today

| Component | State | Notes |
|-----------|-------|-------|
| AES-256-GCM encryption | **Production-grade** | PyCA `cryptography` — NIST-validated |
| HKDF-SHA3-512 key derivation | **Production-grade** | PyCA — used everywhere |
| X25519 hybrid KEM | **Production-grade** | PyCA — classical half of hybrid mode |
| scrypt keystore (AES-256-GCM) | **Production-grade** | 128 MB memory-hard; atomic writes |
| PQEP email protocol logic | **Working** | Full encrypt-sign + verify-decrypt pipeline |
| ZK credential commitments | **Working** | SHA3-256 Pedersen-style; claim value never stored |
| Schnorr ZK proofs | **Working** | Fiat-Shamir heuristic; replaces with Halo2 in v0.3 |
| DNS record parser/validator | **Working** | QSIP TXT record format; tamper detection |
| KeyStore save / load / encrypt | **Working** | Wrong-passphrase rejection enforced |
| HTTPQ Quantum-Safe CA | **Working** | ML-DSA-87 signed certs; like Let's Encrypt but PQC |
| **HTTPQ real TCP handshake** | **Working** | Kyber1024 KEM + AES-256-GCM over real OS sockets |
| **HTTPQ Hybrid KEM (X25519 + Kyber1024)** | **Working** | Secure against classical + quantum adversaries. Auto-detected from cert |
| Live browser demo (FastAPI SSE) | **Working** | `python serve.py` → http://localhost:8000 |
| 128/128 unit tests | **Passing** | See test section below |

### The PQC Algorithms — Written Correctly, Running Under a Dev Mock

The **Kyber1024** and **Dilithium5** code paths in `src/crypto/` call the right
`oqs.KeyEncapsulation` / `oqs.Signature` interfaces, correctly matched to
NIST FIPS 203 and FIPS 204. On this Windows development machine the native
`liboqs` C shared library is not compiled, so tests automatically use
`tests/_oqs_mock.py` — an HMAC-SHA3 stand-in with identical API and identical
security *behaviours*:

- Tampered ciphertexts fail decapsulation ✓
- Wrong recipient key fails decapsulation ✓
- Tampered messages fail signature verification ✓
- Wrong verify key fails verification ✓
- Secrets never leak through `repr()` ✓

The mock does **not** prove mathematical PQC hardness. That is proven by NIST's
multi-year evaluation; unit tests cannot prove it.

On Linux with `liboqs` installed, the real Kyber/Dilithium run with zero code changes:

```bash
# Ubuntu / Debian — build real liboqs
sudo apt-get install cmake ninja-build libssl-dev
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cd liboqs && cmake -GNinja -DBUILD_SHARED_LIBS=ON . && ninja && sudo ninja install
cd .. && pip install liboqs-python
pytest tests/ -v  # now runs against real CRYSTALS algorithms
```

### Not Yet Built

| Feature | Target |
|---------|--------|
| Halo2 / Groth16 ZK circuits (replace Schnorr) | v0.3 Q2 2026 |
| Credential revocation (Merkle accumulator) | v0.3 Q2 2026 |
| Encrypted email headers (not just body) | v0.3 Q2 2026 |
| CLI tools (`qsip-keygen`, `qsip-email-send`, `qsip-id`) | v0.3 Q2 2026 |
| QSIP DNS zone signing + DoH support | v0.3 Q3 2026 |
| HTTPQ browser extension (quantum padlock) | v0.4 Q3 2026 |
| IETF Internet-Draft `draft-qsip-httpq-00` | v0.4 Q3 2026 |
| Certificate Transparency log | v0.4 Q4 2026 |
| BGP route validation overlay | v0.4 Q4 2026 |
| HSM-backed root CA + OCSP responder | v0.4 Q4 2026 |
| External cryptographic audit | v0.4 Q4 2026 |
| Production release | v1.0 2027 |

---

## Test Suite — What 128/128 Passing Actually Means

### What The Tests Genuinely Prove

**Round-trip correctness:**
- KEM encapsulate → decapsulate produces identical shared secret
- Hybrid KEM (X25519 + Kyber) produces identical 32-byte key material for both parties
- `encrypt() → decrypt()` recovers original plaintext exactly
- KeyStore `save() → load()` recovers all key material exactly

**Tamper detection (the tests that matter most):**
- Decapsulating with the **wrong secret key** → different (invalid) shared secret
- Decapsulating a **tampered ciphertext** → different (invalid) shared secret
- Verifying a **tampered message** → `False` (not an exception — no oracle)
- Verifying with the **wrong verify key** → `False`
- Tampered issuer signature on a credential fails `verify_signature()`
- Tampered PQEP email body raises `PQEPError`
- Wrong recipient keypair on decrypt raises `PQEPError`

**Secret isolation:**
- `repr()` of any key type contains `REDACTED`, never raw key bytes
- `list_identities()` returns only public metadata — no private keys

**Keystore security:**
- Wrong passphrase raises `KeystoreError`
- Non-existent identity raises `KeystoreError`

**ZK proof system:**
- Commitment opens with matching `(claim_value, blinding_factor)`
- Wrong claim value fails to open commitment
- Mismatched commitment and proof returns `False`

### What The Tests Do Not Prove

- Mathematical post-quantum hardness of Kyber or Dilithium (proven by NIST, not tests)
- Performance under load or adversarial timing
- Integration with real DNS resolvers or SMTP servers
- Fuzzing / property-based test coverage (planned v0.2)

---

## Architecture

```
src/
├── crypto/         # PQC primitives — ALL crypto lives here, nowhere else
│   ├── kem.py          Kyber1024 KEM (NIST FIPS 203)
│   ├── signatures.py   Dilithium5 (NIST FIPS 204)
│   └── hybrid.py       X25519 + Kyber1024 hybrid
├── identity/       # ZK self-sovereign identity
│   ├── keypair.py      PQC keypair + encrypted keystore
│   ├── credential.py   Verifiable credentials with ZK commitments
│   └── zk_proof.py     Schnorr ZK proofs (→ Halo2 in v0.3)
├── dns/            # PQC-signed DNS
│   ├── resolver.py     DNS-over-TLS resolver
│   └── validator.py    QSIP TXT record parser + PQC validation
├── email/          # Post-Quantum Email Protocol
│   ├── encryptor.py    KEM + AES-256-GCM + Dilithium signing
│   ├── composer.py     RFC 5322 with PQEP extension headers
│   └── transport.py    SMTP/IMAP — mandatory TLS 1.3, no downgrade
├── ca/             # Quantum-safe Certificate Authority (like Let's Encrypt)
│   ├── authority.py    QSIPCertificateAuthority — issue, verify, revoke
│   ├── certificate.py  QSIPCertificate — ML-DSA-87 certs, wire serialisation
│   └── handshake.py    HTTPQHandshake — in-process KEM key exchange
├── httpq/          # Real TCP HTTPQ socket layer ← NEW
│   ├── protocol.py     Binary frame format (type + length-prefixed)
│   ├── connection.py   HTTPQConnection — AES-256-GCM encrypted stream
│   ├── server.py       HTTPQServer — TCP listener + handshake state machine
│   └── client.py       HTTPQClient — TCP connector + handshake state machine
├── web/            # FastAPI SSE live demo server
│   ├── server.py       All 4 layer SSE streams + /api/keygen + /api/handshake
│   └── static/         Browser UI (dark terminal theme)
└── common/
    ├── config.py       Pydantic-settings — all config from .env only
    └── exceptions.py   QSIPCryptoError, PQEPError, ZKProofError …
```

Layer dependency order (no circular imports permitted):

```
common → crypto → identity → dns → email
                     ↓
                    ca → httpq
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- `liboqs` native C library — [build instructions](https://github.com/open-quantum-safe/liboqs)
  *(optional for development — the test suite falls back to the mock automatically)*
- A `.env` file copied from `.env.example`

### Setup

```bash
git clone https://github.com/se7enjj/qsip.git
cd qsip

python -m venv .venv
source .venv/bin/activate      # Linux / macOS
.venv\Scripts\activate         # Windows

pip install -r requirements.txt
pip install -r requirements-dev.txt

cp .env.example .env
# Set QSIP_KEYSTORE_PASSPHRASE to a strong random value — NEVER commit .env

pytest tests/ -v
# Expected: 128 passed
```

### Run the Live Browser Demo

```bash
python serve.py
# Open http://localhost:8000 — click any tab to stream real PQC crypto to the browser
# Tabs: ▶ Run Full Demo | Layer 1 · ZK Identity | Layer 2 · PQEP Email
#       Layer 3 · PQC DNS | Layer 4 · HTTPQ
```

### HTTPQ Quantum-Safe TCP Connection

A real client–server handshake over TCP using Kyber1024 KEM + ML-DSA-87 certificates.

**Pure-Kyber mode** (compatible with all HTTPQ peers):

```python
from src.ca.authority import QSIPCertificateAuthority
from src.crypto.kem import KyberKEM
from src.crypto.signatures import DilithiumSigner
from src.httpq.client import HTTPQClient
from src.httpq.server import HTTPQServer
from src.common.config import Config
import threading

config = Config()
ca     = QSIPCertificateAuthority(config)
ca.initialise("QSIP Root CA")
kem_kp = KyberKEM(config).generate_keypair()
sig_kp = DilithiumSigner(config).generate_keypair()
cert   = ca.issue_certificate("server.example.com", kem_kp.public_key, sig_kp.verify_key)

def serve():
    with srv.accept() as conn:
        conn.send(b"ACK: " + conn.recv())

with HTTPQServer(config, ca, cert, kem_kp.secret_key, port=9000) as srv:
    threading.Thread(target=serve, daemon=True).start()
    with HTTPQClient(config, ca).connect("127.0.0.1", 9000) as conn:
        conn.send(b"Hello, quantum-safe world!")
        print(conn.recv())  # b"ACK: Hello, quantum-safe world!"
```

**Hybrid mode** (X25519 + Kyber1024 — secure against classical *and* quantum adversaries):

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

x25519_sk_obj = X25519PrivateKey.generate()
x25519_pk = x25519_sk_obj.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
x25519_sk = x25519_sk_obj.private_bytes(
    serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
    serialization.NoEncryption()
)
# CA signs canonical bytes that include x25519_pk — forgery still detected
hybrid_cert = ca.issue_certificate(
    "secure.example.com", kem_kp.public_key, sig_kp.verify_key,
    x25519_public_key=x25519_pk,
)

def serve_hybrid():
    with srv_h.accept() as conn:
        conn.send(b"ACK: " + conn.recv())

with HTTPQServer(config, ca, hybrid_cert, kem_kp.secret_key,
                 port=9001, x25519_sk=x25519_sk) as srv_h:
    threading.Thread(target=serve_hybrid, daemon=True).start()
    # Client sees x25519_public_key in cert → auto-selects hybrid handshake
    with HTTPQClient(config, ca).connect("127.0.0.1", 9001) as conn:
        conn.send(b"Hello from the hybrid future!")
        print(conn.recv())  # b"ACK: Hello from the hybrid future!"
```

**CLIENT_HELLO wire format** (server auto-detects mode from payload length):

| Mode | Payload | Length |
|------|---------|--------|
| Pure-Kyber | `session_id (32 B) ‖ kem_ciphertext (1568 B)` | **1600 B** |
| Hybrid | `session_id (32 B) ‖ kem_ciphertext (1568 B) ‖ x25519_eph_pk (32 B)` | **1632 B** |

The handshake replaces every quantum-vulnerable TLS primitive:

| TLS 1.3 (classical) | HTTPQ pure-Kyber | HTTPQ Hybrid (default for new certs) |
|---------------------|-----------------|--------------------------------------|
| X25519 / ECDH | Kyber1024 KEM | X25519 + Kyber1024 KEM (GHP18 combiner) |
| ECDSA / RSA certificate | ML-DSA-87 certificate | ML-DSA-87 certificate + X25519 pk |
| SHA-256 HKDF | SHA3-512 HKDF | SHA3-512 HKDF |
| Quantum-breakable | PQC | PQC + classical (breaks if BOTH break) |

### Generate a PQC Identity

```python
from src.identity.keypair import IdentityKeyPair
from src.common.config import Config

config = Config()
keypair = IdentityKeyPair.generate(config, label="alice@example.com")
print(keypair.fingerprint())
# QSIP:a1b2c3d4:e5f6a7b8:c9d0e1f2:a3b4c5d6
```

### Encrypt an Email with PQEP

```python
from src.email.encryptor import PQEPEncryptor
from src.email.composer import PQEPComposer
from src.identity.keypair import IdentityKeyPair
from src.common.config import Config

config    = Config()
sender    = IdentityKeyPair.generate(config)
recipient = IdentityKeyPair.generate(config)

payload = PQEPEncryptor(config).encrypt(
    plaintext=b"Hello, quantum-safe world!",
    recipient_kem_public_key=recipient.kem_public_key,
    sender_keypair=sender,
)
msg = PQEPComposer(config).compose(
    encrypted_payload=payload,
    sender_keypair=sender,
    recipient_address="bob@example.com",
    sender_address="alice@example.com",
)
print(msg.as_string())
```

---

## Security Model

| Primitive | Algorithm | Standard | Security Level |
|-----------|-----------|---------|----------------|
| KEM | CRYSTALS-Kyber1024 | NIST FIPS 203 | Level 5 — 256-bit PQ |
| Signatures | CRYSTALS-Dilithium5 | NIST FIPS 204 | Level 5 — 256-bit PQ |
| Hybrid KEM | X25519 + Kyber1024 | [GHP18] combiner | Secure if either breaks |
| Symmetric | AES-256-GCM | NIST FIPS 197 | 256-bit classical |
| KDF | HKDF-SHA3-512 | RFC 5869 | — |
| Keystore KDF | scrypt | RFC 7914 | N=2¹⁷, r=8, p=1 (128 MB) |

Full threat model and vulnerability reporting: [SECURITY.md](SECURITY.md)

---

## Roadmap

| Milestone | Target | Focus |
|-----------|--------|-------|
| v0.1 | Q1 2026 | Core crypto, protocol logic, 95 tests |
| **v0.2 ← here** | Q1 2026 | HTTPQ real TCP sockets, hybrid KEM (X25519+Kyber), live browser demo, 128 tests |
| v0.3 | Q2–Q3 2026 | Halo2 ZK circuits, CLI tools, credential revocation, DNS zone signing |
| v0.4 | Q3–Q4 2026 | Browser extension, IETF Internet-Draft, CT log, BGP overlay, external audit |
| v1.0 | 2027 | Full audited production release |

Full details: [docs/ROADMAP.md](docs/ROADMAP.md)

---

## FAQ

**Q: Is QSIP safe for real communications today?**  
No. v0.2 is a research prototype without external audit. Do not protect sensitive
communications with it yet. Target: v0.4 / v1.0.

**Q: Does QSIP replace TLS?**  
Not yet. It is an application-layer suite. PQC-TLS 1.3 integration: planned v0.3+.

**Q: Why not just wait for PQC-TLS to be universal?**  
TLS protects data in transit only. It does not solve identity (who signed your DNS
records?), email header privacy, or ZK credential issuance. QSIP addresses the
full stack.

**Q: When will quantum computers actually break RSA / ECC?**  
Conservative estimates: 10–20 years for cryptographically-relevant machines. But
adversaries harvesting data now are a present threat — the migration window is today.

**Q: The tests use a mock — aren't they fake?**  
No. The mock replaces only the native Kyber/Dilithium C library calls (unavailable
on this Windows dev machine without a C compiler). The mock has identical API and
identical security behaviours — tamper rejection, key isolation, oracle resistance.
All protocol logic, credential handling, and error paths test against real QSIP
code. The PQC mathematical hardness is proven by NIST's evaluation, not by tests.

---

## Contributing

1. Read [SECURITY.md](SECURITY.md) — security rules are non-negotiable  
2. Read [`.github/copilot-instructions.md`](.github/copilot-instructions.md) before touching code  
3. All crypto must use `oqs` (liboqs) or `cryptography` (PyCA) — never implement primitives  
4. All PRs require passing CI (security scan + tests + type check)  
5. Never commit `.env` — only `.env.example` belongs in git

**Maintainer**: Jago König — jago.koenig@proton.me  
**Security reports**: jago.koenig@proton.me (subject: `[QSIP SECURITY] ...`)
