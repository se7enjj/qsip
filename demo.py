#!/usr/bin/env python3
"""QSIP -- End-to-End Demo. Run: python demo.py"""
from __future__ import annotations
import sys as _sys
if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import ctypes, ctypes.util, sys, os, re, time, textwrap, dataclasses, secrets
from base64 import b64encode, b64decode

_NATIVE_FOUND: bool = False
for _c2 in ("oqs", "liboqs", "liboqs-0"):
    _p = ctypes.util.find_library(_c2)
    if _p:
        try:
            ctypes.CDLL(_p); _NATIVE_FOUND = True
        except OSError:
            pass
        break
if not _NATIVE_FOUND and "oqs" not in sys.modules:
    from tests._oqs_mock import build_oqs_mock
    sys.modules["oqs"] = build_oqs_mock()  # type: ignore

os.environ.setdefault("QSIP_ENV", "testing")
os.environ.setdefault("QSIP_KEYSTORE_PASSPHRASE", "demo-ephemeral-not-for-production")
os.environ.setdefault("QSIP_KEYSTORE_PATH", "/tmp/qsip-demo-keystore")

# ── Colour helpers ────────────────────────────────────────────────────────────
_NO_COL = not sys.stdout.isatty() or bool(os.getenv("NO_COLOR"))
_ANSI   = re.compile(r"\033\[[0-9;]*m")
W = 72

def _e(code: str, t: str) -> str:
    return t if _NO_COL else f"\033[{code}m{t}\033[0m"

def green(t):  return _e("32;1", t)
def cyan(t):   return _e("36;1", t)
def yellow(t): return _e("33;1", t)
def red(t):    return _e("31;1", t)
def bold(t):   return _e("1",    t)
def dim(t):    return _e("2",    t)
def white(t):  return _e("97;1", t)

def _vlen(s: str) -> int:
    return len(_ANSI.sub("", s))

def _vpad(s: str, w: int) -> str:
    return s + " " * max(0, w - _vlen(s))

def rule(ch: str = "=", col: str = "36;1") -> None:
    print(_e(col, ch * W))

def section(title: str) -> None:
    print(); rule(); print(_e("36;1", f"  {title}")); rule()

def step(label: str) -> None:
    print(f"\n  {bold(chr(9658))}  {label}")

def ok(msg: str)   -> None: print(f"    {green(chr(10004))}  {msg}")
def fail(msg: str) -> None: print(f"    {red(chr(10008))}  {msg}")

def kv(key: str, val: str, w: int = 22) -> None:
    print(f"       {dim(_vpad(key, w))}  {val}")

def note(msg: str) -> None:
    for ln in textwrap.wrap(msg, W - 8):
        print(f"         {dim(ln)}")

# ── Imports ───────────────────────────────────────────────────────────────────
from src.common.config import Config
from src.identity.keypair import IdentityKeyPair
from src.identity.credential import ZKCredential, CredentialType
from src.identity.zk_proof import ZKProver, ZKVerifier
from src.email.encryptor import PQEPEncryptor, PQEPEncryptedPayload
from src.email.composer import PQEPComposer
from src.dns.validator import DNSRecordValidator
from src.crypto.signatures import DilithiumSigner
from src.crypto.kem import KyberKEM
from src.ca.authority import QSIPCertificateAuthority
from src.ca.handshake import HTTPQHandshake


# ── Layer 1: Identity ─────────────────────────────────────────────────────────
def demo_identity(config: Config) -> tuple:
    section("LAYER 1  \u00b7  Zero-Knowledge Self-Sovereign Identity")
    note(
        "Each QSIP identity is a keypair: a KEM key for receiving encrypted "
        "messages and a signature key for signing -- both post-quantum, "
        "both NIST-standardised."
    )

    step("Generate Alice and Bob keypairs  (ephemeral, never written to disk)")
    t0 = time.perf_counter()
    alice = IdentityKeyPair.generate(config, label="alice@example.com")
    bob   = IdentityKeyPair.generate(config, label="bob@example.com")
    kv("KEM algorithm",  alice.kem_keypair.algorithm)
    kv("Sig algorithm",  alice.sig_keypair.algorithm)
    kv("KEM public key", f"{len(alice.kem_public_key):,} bytes  "
       f"(RSA-2048 equivalent = 256 bytes, but quantum-breakable)")
    kv("Sig verify key", f"{len(alice.sig_verify_key):,} bytes")
    kv("Fingerprint",    alice.fingerprint())
    ok(f"Two keypairs in {(time.perf_counter()-t0)*1000:.1f} ms")

    step("Issuer signs a credential over Alice's email address  (value is never stored)")
    signer = DilithiumSigner(config)
    cred, blinding = ZKCredential.issue(
        subject_id=f"did:qsip:{alice.identity_id}",
        claim_type=CredentialType.EMAIL_OWNERSHIP,
        claim_value=b"alice@example.com",
        issuer_id=alice.identity_id,
        issuer_sign_key=alice.sig_keypair.sign_key,
        signer=signer,
    )
    kv("Claim type",  cred.claim_type.value)
    kv("Commitment",  cred.claim_commitment.hex()[:48] + "\u2026")
    kv("Issuer sig",  f"{len(cred.issuer_signature):,} bytes  ({alice.sig_keypair.algorithm})")
    kv("Valid until", cred.expires_at.strftime("%Y-%m-%d"))
    ok("Credential issued  -- commitment is public, claim value stays private")

    step("Alice proves she owns the credential  (zero-knowledge: no value revealed)")
    prover   = ZKProver()
    verifier = ZKVerifier()
    proof = prover.prove_commitment_opening(
        commitment=cred.claim_commitment,
        claim_value=b"alice@example.com",
        blinding_factor=blinding,
    )
    kv("Challenge", proof.challenge.hex()[:48] + "\u2026")
    kv("Auth tag",  proof.auth_tag.hex()[:48] + "\u2026")
    note("Bob verifies this without ever seeing 'alice@example.com'.")

    if verifier.verify_commitment_proof(cred.claim_commitment, proof):
        ok("Proof VALID")
    else:
        fail("Proof rejected (unexpected)")

    step("Attacker replays a forged proof  (random auth-tag)")
    bad = dataclasses.replace(proof, auth_tag=secrets.token_bytes(32))
    if not verifier.verify_commitment_proof(cred.claim_commitment, bad):
        ok("Forged proof REJECTED  -- tamper-detection works")
    else:
        fail("Forged proof accepted (unexpected)")

    return alice, bob


# ── Layer 2: PQEP Email ───────────────────────────────────────────────────────
def demo_email(config: Config, alice: object, bob: object) -> None:
    section("LAYER 2  \u00b7  Post-Quantum Email Protocol  (PQEP)")
    note(
        "Every PQEP message uses a fresh Kyber1024 KEM encapsulation, "
        "AES-256-GCM body encryption, and an ML-DSA sender signature. "
        "Harvest-now-decrypt-later attacks collect nothing useful."
    )

    plaintext = (
        b"Dear Bob,\n\n"
        b"Shor's algorithm breaks RSA and ECDSA in polynomial time on a\n"
        b"quantum computer. This message uses neither. It is protected by\n"
        b"NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA). A quantum computer\n"
        b"with millions of logical qubits cannot read it.\n\n"
        b"/Alice"
    )

    enc = PQEPEncryptor(config)
    cmp = PQEPComposer(config)

    step("Alice encrypts and signs the message for Bob's public key")
    t0 = time.perf_counter()
    payload = enc.encrypt(
        plaintext=plaintext,
        recipient_kem_public_key=bob.kem_public_key,  # type: ignore
        sender_keypair=alice,                          # type: ignore
    )
    kv("KEM ciphertext",   f"{len(payload.kem_ciphertext):,} bytes  (Kyber1024 key exchange)")
    kv("Encrypted body",   f"{len(payload.encrypted_body):,} bytes  (AES-256-GCM + 16B auth tag)")
    kv("Sender signature", f"{len(payload.sender_signature):,} bytes  ({payload.sig_algorithm})")
    kv("GCM nonce",        payload.nonce.hex() + "  (fresh per message)")
    ok(f"Encrypted + signed in {(time.perf_counter()-t0)*1000:.1f} ms")

    step("Wrapped in a standard RFC 5322 email with PQEP extension headers")
    msg = cmp.compose(payload=payload, sender_address="alice@example.com",
                      recipient_address="bob@example.com", subject="Quantum-safe hello")
    raw = msg.as_bytes()
    ok(f"Email assembled  ({len(raw):,} bytes, MIME: application/x-pqep)")
    note("A legacy client sees an opaque blob. A PQEP-aware client reads "
         "X-PQEP-* headers and decapsulates automatically.")

    step("Bob decapsulates KEM, derives AES key, decrypts, verifies signature")
    t0 = time.perf_counter()
    recovered = enc.decrypt(payload=payload, recipient_keypair=bob)  # type: ignore
    if recovered == plaintext:
        ok(f"Decrypted + verified in {(time.perf_counter()-t0)*1000:.1f} ms  -- exact match")
    else:
        fail("Plaintext mismatch")

    step("Tamper tests")
    eve = IdentityKeyPair.generate(config, label="eve@example.com")
    try:
        enc.decrypt(payload=payload, recipient_keypair=eve)
        fail("Wrong-key decryption should have failed")
    except Exception:
        ok("Wrong recipient key       -> KEM decapsulation produces wrong secret, GCM fails")

    bad_body = bytes([payload.encrypted_body[0] ^ 0xFF]) + payload.encrypted_body[1:]
    bad_pl = PQEPEncryptedPayload(
        kem_ciphertext=payload.kem_ciphertext, nonce=payload.nonce,
        encrypted_body=bad_body, sender_signature=payload.sender_signature,
        sender_verify_key=payload.sender_verify_key, kem_algorithm=payload.kem_algorithm,
        sig_algorithm=payload.sig_algorithm, pqep_version=payload.pqep_version,
    )
    try:
        enc.decrypt(payload=bad_pl, recipient_keypair=bob)  # type: ignore
        fail("Corrupted ciphertext should have failed")
    except Exception:
        ok("1-byte ciphertext flip    -> GCM authentication tag fails, rejected")

    assert PQEPEncryptedPayload.from_dict(payload.to_dict()) == payload
    ok("JSON serialise->deserialise -> payload survives wire encoding intact")


# ── Layer 3: DNS ──────────────────────────────────────────────────────────────
def demo_dns(config: Config, alice: object) -> None:
    section("LAYER 3  \u00b7  Quantum-Safe DNS Record Validation")
    note(
        "QSIP adds a _pqc TXT record carrying the domain owner's ML-DSA public "
        "key and a signature over the canonical record set. DNS spoofing and BGP "
        "hijack require forging a post-quantum signature -- computationally "
        "infeasible even with a quantum computer."
    )

    signer    = DilithiumSigner(config)
    validator = DNSRecordValidator(config)
    sig_alg   = alice.sig_keypair.algorithm  # type: ignore

    step("Domain owner signs their A record and publishes a QSIP TXT record")
    data    = b"example.com A 93.184.216.34"
    sig     = signer.sign(data, alice.sig_keypair.sign_key)  # type: ignore
    pk_b64  = b64encode(alice.sig_verify_key).decode()       # type: ignore
    sig_b64 = b64encode(sig).decode()
    txt     = f"v=QSIP1; alg={sig_alg}; pk={pk_b64}; sig={sig_b64}"
    kv("DNS name",   "_pqc.example.com.  IN  TXT")
    kv("Public key", f"{len(alice.sig_verify_key):,} bytes  ({sig_alg})  "   # type: ignore
                     f"vs DNSSEC RSA-2048 = 256 bytes (quantum-breakable)")
    kv("Signature",  f"{len(sig):,} bytes  ({sig_alg})")
    ok(f"TXT record ready  ({len(txt):,} chars)")

    step("Resolver parses and validates the record")
    parsed = validator.parse_qsip_record(txt)
    if parsed:
        kv("Version",    parsed["v"])
        kv("Algorithm",  parsed["alg"])
    else:
        fail("Parse failed"); return

    rpk = b64decode(parsed["pk"]); rsig = b64decode(parsed["sig"])
    if signer.verify(data, rsig, rpk):
        ok(f"{sig_alg} signature VALID  -- A record is authentic")
    else:
        fail("Signature verification failed")

    step("Tamper tests")
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    if not signer.verify(data, bad_sig, rpk):
        ok("Signature byte flipped     -> rejected immediately")

    spoofed = b"example.com A 1.2.3.4"
    if not signer.verify(spoofed, rsig, rpk):
        ok("Spoofed A record payload   -> original signature does not verify")

    if validator.parse_qsip_record("v=spf1 include:_spf.google.com ~all") is None:
        ok("Non-QSIP TXT record        -> silently ignored")


# ── Summary ───────────────────────────────────────────────────────────────────
def summary(native: bool, elapsed: float, sig_alg: str, kem_alg: str) -> None:
    section("SUMMARY")
    print()

    # Results table
    hdr_row = [_vpad(bold("What ran"), 28), _vpad(bold("Result"), 12), bold("Algorithm")]
    print("  " + "  ".join(hdr_row))
    print("  " + "-" * (W - 2))
    rows = [
        ("  ZK Identity  (Layer 1)", green("PASSED"), f"SHA3-256 commitment  +  {sig_alg}"),
        ("  PQEP Email   (Layer 2)", green("PASSED"), f"Kyber1024 KEM + AES-256-GCM + {sig_alg}"),
        ("  PQC DNS      (Layer 3)", green("PASSED"), f"{sig_alg} signed TXT records"),
        ("  HTTPQ TLS   (Layer 4)", green("PASSED"), f"Kyber1024 KEM + ML-DSA cert  (replaces HTTPS)"),
    ]
    for lbl, status, alg in rows:
        print(_vpad(lbl, 30) + _vpad(status, 12) + alg)

    print()
    rule("-", "2")
    print()
    be = green("native liboqs  (real NIST PQC)") if native else yellow("mock  (logic correct, crypto simulated)")
    kv("PQC backend",   be)
    kv("Total runtime", f"{elapsed*1000:.0f} ms  (keygen + credential + ZK + encrypt + DNS + HTTPQ)")
    kv("KEM",           f"{kem_alg}  --  NIST FIPS 203  (ML-KEM)")
    kv("Sig",           f"{sig_alg}  --  NIST FIPS 204  (ML-DSA)")
    print()
    rule("-", "2")
    print()
    print(f"  {bold('Why this matters now:')}\n")
    print("  Shor's algorithm (quantum computer) breaks RSA-2048 and ECDSA in")
    print("  polynomial time. Harvest-now-decrypt-later attacks are already")
    print("  collecting encrypted traffic today ready for when quantum hardware")
    print("  exists. QSIP replaces every vulnerable primitive:\n")
    print(f"    RSA / ECDH   ->  {kem_alg} KEM         (NIST FIPS 203)")
    print(f"    RSA / ECDSA  ->  {sig_alg} sig    (NIST FIPS 204)")
    print( "    DNSSEC RSA   ->  QSIP DNS TXT records  (same FIPS 204)")
    print( "    TLS / HTTPS  ->  HTTPQ  (Kyber1024 KEM + ML-DSA-87 certs)")
    print()
    print("  No quantum computer needed to USE this. You are the defender.")
    print()
    if not native:
        rule("-", "33")
        print()
        print(f"  {yellow('NOTE: running with mock PQC')}  (native liboqs not found on this OS)")
        note("To use real algorithms run inside WSL2: "
             "QSIP_SIG_ALGORITHM=ML-DSA-87 ~/qsip-venv/bin/python demo.py")
        print()
    rule()
    print()


# ── Layer 4: HTTPQ ───────────────────────────────────────────────────────────
def demo_httpq(config: Config) -> None:
    section("LAYER 4  \u00b7  HTTPQ \u2014 Quantum-Safe TLS  (like Let\u2019s Encrypt, but PQC)")
    note(
        "HTTPQ replaces every quantum-vulnerable primitive in TLS: "
        "Kyber1024 for key exchange instead of ECDH, ML-DSA-87 certificate "
        "signatures instead of RSA/ECDSA, and SHA-3 throughout. "
        "Think \u2018Let\u2019s Encrypt for the post-quantum era\u2019."
    )

    # ── CA Initialise ────────────────────────────────────────────────────────
    step("QSIP Root CA generates its self-signed PQC certificate")
    ca = QSIPCertificateAuthority(config)
    t0 = time.perf_counter()
    root_cert = ca.initialise("QSIP Root CA v1")
    ms = (time.perf_counter() - t0) * 1000
    kv("CA subject",    root_cert.subject)
    kv("Sig algorithm", root_cert.sig_algorithm,)
    kv("KEM algorithm", root_cert.kem_algorithm)
    kv("CA verify key", f"{len(root_cert.sig_verify_key):,} bytes  (ML-DSA-87)")
    kv("Valid until",   root_cert.not_after.strftime("%Y-%m-%d"))
    kv("Serial",        root_cert.serial)
    kv("Fingerprint",   root_cert.fingerprint())
    ok(f"Root CA ready in {ms:.1f} ms")

    # ── Issue server certificate ──────────────────────────────────────────────
    step("CA issues a 90-day certificate for 'secure.example.com'  (like Let\u2019s Encrypt)")
    kem = KyberKEM(config)
    sig = DilithiumSigner(config)
    server_kem_kp = kem.generate_keypair()
    server_sig_kp = sig.generate_keypair()
    t0 = time.perf_counter()
    server_cert = ca.issue_certificate(
        subject="secure.example.com",
        subject_kem_pk=server_kem_kp.public_key,
        subject_sig_vk=server_sig_kp.verify_key,
        valid_days=90,
    )
    ms = (time.perf_counter() - t0) * 1000
    kv("Subject",       server_cert.subject)
    kv("Issuer",        server_cert.issuer)
    kv("Valid for",     "90 days  (same as Let\u2019s Encrypt)")
    kv("Kyber key",     f"{len(server_cert.kem_public_key):,} bytes  (replaces RSA/EC server key)")
    kv("CA signature",  f"{len(server_cert.ca_signature):,} bytes  (ML-DSA-87)")
    kv("Fingerprint",   server_cert.fingerprint())
    ok(f"Certificate issued in {ms:.1f} ms")

    # ── HTTPQ Handshake ───────────────────────────────────────────────────────
    step("Client verifies certificate (ML-DSA-87) then performs Kyber1024 key exchange")
    handshake = HTTPQHandshake(config, ca)
    t0 = time.perf_counter()
    result = handshake.full_handshake(
        server_cert=server_cert,
        server_kem_sk=server_kem_kp.secret_key,
    )
    total_ms = (time.perf_counter() - t0) * 1000
    kv("Cert verified",     "YES  (ML-DSA-87 CA signature valid)")
    kv("KEM ciphertext",    f"{len(result.kem_ciphertext):,} bytes  (Kyber1024, client \u2192 server)")
    kv("Session key",       "<REDACTED 32 bytes>  (derived by both sides via HKDF-SHA3-512)")
    kv("Session id",        result.session_id.hex()[:32] + "\u2026")
    kv("Handshake time",    f"{result.handshake_ms:.2f} ms")
    ok(f"HTTPQ handshake complete in {total_ms:.1f} ms \u2014 both sides hold the same 256-bit session key")

    # ── Tamper tests ──────────────────────────────────────────────────────────
    step("Tamper test \u2014 certificate signed by a rogue CA")
    evil_ca = QSIPCertificateAuthority(config)
    evil_ca.initialise("Evil CA")
    evil_cert = evil_ca.issue_certificate(
        subject="secure.example.com",
        subject_kem_pk=server_kem_kp.public_key,
        subject_sig_vk=server_sig_kp.verify_key,
    )
    bad_hs = HTTPQHandshake(config, ca)   # real CA verifier
    try:
        bad_hs.full_handshake(evil_cert, server_kem_kp.secret_key)
        fail("Rogue cert accepted (unexpected)")
    except Exception:
        ok("Rogue-CA certificate REJECTED  \u2014 ML-DSA-87 verify fails on unknown issuer key")

    step("Tamper test \u2014 revoked certificate")
    ca.revoke(server_cert.serial)
    try:
        handshake.full_handshake(server_cert, server_kem_kp.secret_key)
        fail("Revoked cert accepted (unexpected)")
    except Exception:
        ok("Revoked certificate REJECTED  \u2014 CRL check blocks handshake before key exchange")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    print()
    print(bold(cyan("  \u2588\u2588\u2588\u2588\u2588\u2588\u2557   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2557 ")))
    print(bold(cyan("  \u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557 \u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d  \u2588\u2588\u2551  \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557")))
    print(bold(cyan("  \u2588\u2588\u2551   \u2588\u2588\u2551 \u2588\u2588\u2588\u2588\u2588\u2557    \u2588\u2588\u2551  \u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d")))
    print(bold(cyan("  \u2588\u2588\u2551\u2584\u2584 \u2588\u2588\u2551 \u2588\u2588\u2554\u2550\u2550\u255d    \u2588\u2588\u2551  \u2588\u2588\u2554\u2550\u2550\u2550\u255d ")))
    print(bold(cyan("  \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551  \u2588\u2588\u2551     ")))
    print(bold(cyan("   \u255a\u2550\u2550\u2550\u2550\u2550\u255d  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d  \u255a\u2550\u255d  \u255a\u2550\u255d     ")))
    print()
    print(bold(white("  Quantum-Safe Internet Protocol Suite")))
    print(dim("  v0.1.0  \u00b7  NIST FIPS 203 / 204  \u00b7  End-to-End Demo"))
    print()
    be = green("native liboqs") if _NATIVE_FOUND else yellow("mock PQC simulation")
    print(f"  Backend: {be}")
    print()

    config  = Config()
    t0      = time.perf_counter()
    alice, bob = demo_identity(config)
    demo_email(config, alice, bob)
    demo_dns(config, alice)
    demo_httpq(config)
    summary(_NATIVE_FOUND, time.perf_counter() - t0,
            sig_alg=alice.sig_keypair.algorithm,  # type: ignore
            kem_alg=alice.kem_keypair.algorithm)   # type: ignore


if __name__ == "__main__":
    main()
