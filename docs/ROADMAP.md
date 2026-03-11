# QSIP Roadmap

## v0.1 — Foundation (Q1 2026) ← Current

### Goals
Establish the core cryptographic foundation and working end-to-end PQEP email flow.

- [x] Project structure, security policy, CI pipeline
- [x] `src/common/` — config, exceptions, structured logging
- [x] `src/crypto/kem.py` — Kyber1024 KEM
- [x] `src/crypto/signatures.py` — Dilithium5 signatures
- [x] `src/crypto/hybrid.py` — X25519 + Kyber1024 hybrid
- [x] `src/identity/keypair.py` — PQC identity keypair + encrypted keystore
- [x] `src/identity/credential.py` — Verifiable credential structure
- [x] `src/identity/zk_proof.py` — Schnorr-based ZK proofs (simplified)
- [x] `src/dns/resolver.py` — PQC-aware DNS-over-TLS resolver
- [x] `src/dns/validator.py` — DNS record PQC signature validation
- [x] `src/email/encryptor.py` — Kyber KEM + AES-256-GCM email body encryption
- [x] `src/email/composer.py` — PQEP header construction
- [x] `src/email/transport.py` — SMTP/IMAP with TLS 1.3 enforcement
- [x] Full test suite (target: 80%+ coverage)

---

## v0.2 — ZK Upgrade & Protocol Hardening (Q2 2026)

### Goals
Replace simplified ZK with production-grade circuits; harden all protocol edges.

- [ ] Migrate ZK proofs from Schnorr to **Halo2** recursive circuits
- [ ] Credential revocation mechanism (Merkle accumulator)
- [ ] PQEP: encrypted header metadata (not just body)
- [ ] PQEP: multi-recipient encryption (multi-KEM)
- [ ] Key rotation protocol + automated rotation reminders
- [ ] Audit log with Dilithium-signed entries
- [ ] CLI tool: `qsip-keygen`, `qsip-email-send`, `qsip-id`
- [ ] Target: 90%+ test coverage
- [ ] External security review of `src/crypto/`

---

## v0.3 — PQC DNS (Production-Ready) (Q3 2026)

### Goals
Production-grade DNS resolver with full PQC signing and verification.

- [ ] QSIP DNS TXT record format (IETF draft submission)
- [ ] Zone signing tool: generate Dilithium-signed DNS zones
- [ ] DNSSEC bridging: wrap existing DNSSEC with PQC co-signatures
- [ ] Caching resolver with signed cache entries
- [ ] DoH (DNS-over-HTTPS) support alongside DoT
- [ ] QSIP DNS Python library — usable standalone
- [ ] Integration: email domain validation via PQC DNS

---

## v0.4 — BGP Validation Overlay (Q4 2026)

### Goals
Advisory-mode BGP route validation using PQC-signed route announcements.

- [ ] Route origin attestation (ROA) format with Dilithium signatures
- [ ] BGP path validation overlay protocol
- [ ] RPKI-compatible PQC extension
- [ ] ISP API for submitting signed route announcements
- [ ] BGP anomaly detection using signed route history
- [ ] `# NOTE: BGP changes require ISP coordination. This layer is advisory in v0.4`

---

## v1.0 — Full Suite, Audited (2027)

### Goals
Production-ready, externally audited, RFC-track protocols.

- [ ] Third-party cryptographic audit (NCC Group / Trail of Bits)
- [ ] IETF RFC submissions for PQEP + QSIP-DNS
- [ ] Reference implementation in Rust (performance-critical paths)
- [ ] Hardware security module (HSM) keystore support
- [ ] Enterprise deployment guide
- [ ] Interoperability testing with other PQC email implementations

---

## Out of Scope (Explicitly)

- Replacing TCP/IP or TLS directly (we augment, not replace)
- Browser integration (plugin ecosystem, separate project)
- Blockchain-based identity (adds complexity without security benefit)
- Custom ZK-VM (use established toolchains: Halo2, Noir)
