# QSIP Architecture

## Design Principles

1. **Security over convenience** — Every design decision favors correctness first
2. **No crypto outside `src/crypto/`** — Forces auditability of all cryptographic operations
3. **Zero trust** — Each layer verifies; nothing is assumed to be trustworthy
4. **Layered dependencies** — Lower layers never import from higher layers (no circular deps)
5. **Config isolation** — All parameters flow through `src/common/config.py` from `.env`

---

## Layer Stack

```
┌─────────────────────────────────────────────────────────┐
│                    Applications / CLI                    │
├─────────────────────────────────────────────────────────┤
│          email/  (PQEP — Post-Quantum Email)            │
│  composer.py  │  encryptor.py  │  transport.py          │
├─────────────────────────────────────────────────────────┤
│          dns/  (Quantum-Safe DNS + BGP overlay)         │
│  resolver.py  │  validator.py                           │
├─────────────────────────────────────────────────────────┤
│          identity/  (ZK Self-Sovereign Identity)        │
│  keypair.py  │  credential.py  │  zk_proof.py          │
├─────────────────────────────────────────────────────────┤
│          crypto/  (PQC Primitives — ONLY layer)         │
│  kem.py  │  signatures.py  │  hybrid.py                │
├─────────────────────────────────────────────────────────┤
│      common/  (config.py, exceptions.py, logging)       │
└─────────────────────────────────────────────────────────┘
```

---

## Module Descriptions

### `src/common/`

**`config.py`** — Single source of all runtime configuration. Reads exclusively from `.env` via `python-dotenv`. Validated with `pydantic` models. No module ever imports env vars directly — they must go through this.

**`exceptions.py`** — All custom exceptions. Base class `QSIPError`, with specialized subclasses:
- `QSIPCryptoError` — any cryptographic failure
- `KeystoreError` — key management failures
- `IdentityError` — identity/credential failures
- `DNSValidationError` — DNS signature failures
- `PQEPError` — email protocol failures

---

### `src/crypto/`

The **only layer** that interacts with `oqs` and `cryptography` libraries.

**`kem.py` — KyberKEM**  
Wraps `oqs.KeyEncapsulation` for `Kyber1024`.
- `generate_keypair()` → `(public_key: bytes, secret_key: bytes)`
- `encapsulate(public_key)` → `(ciphertext: bytes, shared_secret: bytes)`
- `decapsulate(ciphertext, secret_key)` → `shared_secret: bytes`

**`signatures.py` — DilithiumSigner**  
Wraps `oqs.Signature` for `Dilithium5`.
- `generate_keypair()` → `(verify_key: bytes, sign_key: bytes)`
- `sign(message, sign_key)` → `signature: bytes`
- `verify(message, signature, verify_key)` → `bool`

**`hybrid.py` — HybridKEM**  
Combines X25519 (classical) + Kyber1024 (PQC) using HKDF to combine shared secrets.  
Provides security if **either** algorithm holds. Used for TLS-like session establishment.

---

### `src/identity/`

**`keypair.py` — IdentityKeyPair**  
A user's complete cryptographic identity:
- KEM keypair (Kyber1024) — for receiving encrypted data
- Signature keypair (Dilithium5) — for signing assertions
- Encrypted storage via `KeyStore` (AES-256-GCM wrapped, passphrase-derived via Argon2id)

**`credential.py` — ZKCredential**  
A signed, verifiable claim about an identity attribute:
- `ZKCredential(subject_id, claim_type, claim_value, issuer_keypair)`
- Serializes to a JSON-LD-inspired format with a Dilithium signature
- Claims are committed to via a Pedersen commitment — value never revealed directly

**`zk_proof.py` — ZKProver / ZKVerifier**  
Simplified Schnorr-based non-interactive ZK proofs (via Fiat-Shamir transform).  
Proves knowledge of a credential without revealing the credential.  
`# TODO(security): upgrade to Halo2/Groth16 circuit proofs in v0.2`

---

### `src/dns/`

**`resolver.py` — PQCResolver**  
DNS-over-TLS resolver that fetches records and their associated PQC signatures.  
Uses `dnspython` for record parsing. Validates DNSSEC chain + PQC extension records (`TYPE65534` placeholder, pending RFC).

**`validator.py` — DNSRecordValidator**  
Validates PQC signatures on DNS records using `DilithiumSigner`.  
Implements the QSIP DNS extension format:
```
_pqc.<domain>.  TXT  "v=QSIP1; alg=Dilithium5; pk=<base64>; sig=<base64>"
```

---

### `src/email/`

**`composer.py` — PQEPComposer**  
Constructs RFC 5322-compatible email messages with PQEP extension headers:
```
X-PQEP-Version: 1
X-PQEP-KEM: Kyber1024
X-PQEP-SIG: Dilithium5
X-PQEP-Sender-PK: <base64 Dilithium verify key>
X-PQEP-KEM-Ciphertext: <base64 Kyber ciphertext>
```
Email headers are themselves encrypted where the underlying transport allows (SMTP STARTTLS).

**`encryptor.py` — PQEPEncryptor**  
Full encryption pipeline:
1. Generate ephemeral sender Kyber keypair
2. Encapsulate shared secret against recipient's Kyber public key
3. Derive AES-256-GCM key via HKDF-SHA3-512 from shared secret
4. Encrypt email body (and header block) with AES-256-GCM
5. Sign the entire encrypted payload with sender's Dilithium key

**`transport.py` — PQEPTransport**  
SMTP/IMAP client that sends/receives PQEP messages.  
Enforces TLS 1.3 minimum. Does not fall back to plaintext.

---

## Data Flow: Sending a PQEP Email

```
Sender                                          Recipient
  │                                                 │
  │  1. Resolve recipient's PQC public key          │
  │     via PQCResolver (DNS TXT record)            │
  │                                                 │
  │  2. KyberKEM.encapsulate(recipient_pub_key)     │
  │     → (kem_ciphertext, shared_secret)           │
  │                                                 │
  │  3. HKDF(shared_secret) → aes_key              │
  │                                                 │
  │  4. AES-256-GCM(plaintext, aes_key) → body     │
  │                                                 │
  │  5. Dilithium.sign(kem_ciphertext || body)      │
  │     → signature                                 │
  │                                                 │
  │  6. Compose PQEP email + SMTP send ──────────► │
  │                                                 │
  │                          7. Dilithium.verify()  │
  │                          8. KyberKEM.decap()    │
  │                          9. HKDF → aes_key      │
  │                         10. AES-256-GCM.decrypt │
```

---

## Approved Dependencies

| Library | Purpose | Version |
|---------|---------|---------|
| `oqs` | liboqs Python bindings — Kyber, Dilithium | >= 0.9.0 |
| `cryptography` | AES-GCM, HKDF, X25519, Argon2id | >= 42.0.0 |
| `dnspython` | DNS record parsing | >= 2.6.0 |
| `python-dotenv` | `.env` loading | >= 1.0.0 |
| `pydantic` | Config validation | >= 2.0.0 |

**Adding any new cryptographic dependency requires updating this file with justification.**
