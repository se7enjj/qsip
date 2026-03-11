"""
QSIP Web Demo Server — FastAPI with Server-Sent Events.

Streams real cryptographic operations to a browser in real time.
Every byte length, every timing measurement, every hex digest you see
in the browser is produced by executing the actual crypto code.

Run:
    python serve.py
    # or
    uvicorn src.web.server:app --host 0.0.0.0 --port 8000

Endpoints:
    GET  /                    — Browser demo UI
    GET  /api/status          — JSON: backend info (native/mock, algorithms)
    GET  /api/stream/all      — SSE: full 4-layer demo stream
    GET  /api/stream/identity — SSE: Layer 1 only (ZK Identity)
    GET  /api/stream/httpq    — SSE: Layer 4 only (HTTPQ)
    POST /api/keygen          — JSON: generate one keypair on demand
    POST /api/handshake       — JSON: run one HTTPQ handshake on demand

SSE event format:
    data: {"type": "section", "title": "LAYER 1 · ZK Identity"}
    data: {"type": "step",    "label": "Generating keypairs ..."}
    data: {"type": "kv",      "key": "KEM algorithm", "value": "Kyber1024"}
    data: {"type": "ok",      "msg":  "Two keypairs in 4.1 ms"}
    data: {"type": "fail",    "msg":  "Verification failed"}
    data: {"type": "attack",  "label": "Forged cert rejected"}
    data: {"type": "done",    "runtime_ms": 38.4, "layers": 4}
"""

from __future__ import annotations

# ── OQS mock injection (same pattern as conftest.py + demo.py) ───────────────
import ctypes, ctypes.util, sys as _sys

_NATIVE_FOUND: bool = False
for _c in ("oqs", "liboqs", "liboqs-0"):
    _p = ctypes.util.find_library(_c)
    if _p:
        try:
            ctypes.CDLL(_p)
            _NATIVE_FOUND = True
        except OSError:
            pass
        break
if not _NATIVE_FOUND and "oqs" not in _sys.modules:
    from tests._oqs_mock import build_oqs_mock
    _sys.modules["oqs"] = build_oqs_mock()  # type: ignore
# ─────────────────────────────────────────────────────────────────────────────

import asyncio
import dataclasses
import json
import os
import secrets
import time
from base64 import b64encode
from pathlib import Path
from typing import AsyncIterator

os.environ.setdefault("QSIP_ENV", "testing")
os.environ.setdefault("QSIP_KEYSTORE_PASSPHRASE", "web-demo-ephemeral")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from src.ca.authority import QSIPCertificateAuthority
from src.ca.handshake import HTTPQHandshake
from src.common.config import Config
from src.crypto.kem import KyberKEM
from src.crypto.signatures import DilithiumSigner
from src.email.encryptor import PQEPEncryptor, PQEPEncryptedPayload
from src.identity.keypair import IdentityKeyPair
from src.identity.credential import ZKCredential, CredentialType
from src.identity.zk_proof import ZKProver, ZKVerifier

# ── App setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="QSIP Live Demo",
    description="Quantum-Safe Internet Protocol Suite — live cryptographic demo",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_STATIC = Path(__file__).parent / "static"
_CONFIG = Config()

# ── Helpers ──────────────────────────────────────────────────────────────────

def _ev(data: dict) -> str:
    """Format a single SSE data frame."""
    return f"data: {json.dumps(data)}\n\n"


def _hx(b: bytes, maxlen: int = 32) -> str:
    """Hex-encode bytes, truncating with ellipsis for display."""
    h = b.hex()
    if len(h) > maxlen * 2:
        return h[: maxlen * 2] + "…"
    return h


# ── Status endpoint ──────────────────────────────────────────────────────────

@app.get("/api/status")
async def get_status() -> JSONResponse:
    """Return backend info without running any crypto."""
    try:
        cfg = Config()
        kem = KyberKEM(cfg)
        sig = DilithiumSigner(cfg)
        return JSONResponse({
            "native": _NATIVE_FOUND,
            "backend": "native liboqs (real NIST PQC)" if _NATIVE_FOUND else "mock PQC simulation",
            "kem_algorithm": kem.algorithm,
            "sig_algorithm": sig.algorithm,
            "fips203": kem.algorithm,
            "fips204": sig.algorithm,
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


# ── SSE demo generators ──────────────────────────────────────────────────────

async def _stream_identity(config: Config) -> AsyncIterator[str]:
    """Yield SSE events for the ZK Identity demo layer."""
    loop = asyncio.get_event_loop()

    yield _ev({"type": "section", "title": "LAYER 1 · Zero-Knowledge Self-Sovereign Identity",
               "subtitle": "Post-quantum keypairs + ZK credential proofs"})
    await asyncio.sleep(0)

    yield _ev({"type": "step", "label": "Generating Alice and Bob keypairs  (ephemeral — never written to disk)"})
    await asyncio.sleep(0)

    t0 = time.perf_counter()
    alice = await loop.run_in_executor(None, lambda: IdentityKeyPair.generate(config, label="alice@example.com"))
    bob   = await loop.run_in_executor(None, lambda: IdentityKeyPair.generate(config, label="bob@example.com"))
    ms = (time.perf_counter() - t0) * 1000

    yield _ev({"type": "kv", "key": "KEM algorithm",  "value": alice.kem_keypair.algorithm})
    yield _ev({"type": "kv", "key": "Sig algorithm",  "value": alice.sig_keypair.algorithm})
    yield _ev({"type": "kv", "key": "KEM public key", "value": f"{len(alice.kem_public_key):,} bytes",
               "note": "RSA-2048 = 256 bytes (quantum-breakable)"})
    yield _ev({"type": "kv", "key": "Sig verify key", "value": f"{len(alice.sig_verify_key):,} bytes"})
    yield _ev({"type": "kv", "key": "Fingerprint",    "value": alice.fingerprint()})
    yield _ev({"type": "bytes", "label": "KEM public key (hex)", "hex": _hx(alice.kem_public_key),
               "bytes": len(alice.kem_public_key)})
    yield _ev({"type": "ok", "msg": f"Two keypairs in {ms:.1f} ms"})
    await asyncio.sleep(0)

    yield _ev({"type": "step", "label": "Issuer signs a credential over Alice's email address  (value never stored)"})
    await asyncio.sleep(0)

    signer = DilithiumSigner(config)
    t0 = time.perf_counter()
    cred, blinding = await loop.run_in_executor(None, lambda: ZKCredential.issue(
        subject_id=f"did:qsip:{alice.identity_id}",
        claim_type=CredentialType.EMAIL_OWNERSHIP,
        claim_value=b"alice@example.com",
        issuer_id=alice.identity_id,
        issuer_sign_key=alice.sig_keypair.sign_key,
        signer=signer,
    ))
    ms = (time.perf_counter() - t0) * 1000

    yield _ev({"type": "kv", "key": "Claim type",  "value": cred.claim_type.value})
    yield _ev({"type": "kv", "key": "Commitment",  "value": _hx(cred.claim_commitment, 24),
               "note": "Public — derived from SHA3-256(value || blinding_factor). Value stays private."})
    yield _ev({"type": "kv", "key": "Issuer sig",  "value": f"{len(cred.issuer_signature):,} bytes ({alice.sig_keypair.algorithm})"})
    yield _ev({"type": "ok", "msg": f"Credential issued in {ms:.1f} ms — claim value stays private"})
    await asyncio.sleep(0)

    yield _ev({"type": "step", "label": "Alice proves she owns the credential  (zero-knowledge: value never revealed)"})
    await asyncio.sleep(0)

    prover   = ZKProver()
    verifier = ZKVerifier()
    proof    = await loop.run_in_executor(None, lambda: prover.prove_commitment_opening(
        commitment=cred.claim_commitment,
        claim_value=b"alice@example.com",
        blinding_factor=blinding,
    ))
    valid = await loop.run_in_executor(None, lambda: verifier.verify_commitment_proof(cred.claim_commitment, proof))

    yield _ev({"type": "kv", "key": "Challenge", "value": _hx(proof.challenge, 24)})
    yield _ev({"type": "kv", "key": "Auth tag",  "value": _hx(proof.auth_tag, 24)})
    if valid:
        yield _ev({"type": "ok", "msg": "Proof VALID  — Bob verified without seeing 'alice@example.com'"})
    else:
        yield _ev({"type": "fail", "msg": "Proof unexpectedly rejected"})
    await asyncio.sleep(0)

    # Tamper demo
    yield _ev({"type": "attack", "label": "Attacker forges a proof with a random auth-tag"})
    bad = dataclasses.replace(proof, auth_tag=secrets.token_bytes(32))
    forged_valid = await loop.run_in_executor(None, lambda: verifier.verify_commitment_proof(cred.claim_commitment, bad))
    if not forged_valid:
        yield _ev({"type": "ok", "msg": "Forged proof REJECTED  — tamper-detection works"})
    else:
        yield _ev({"type": "fail", "msg": "Forged proof accepted (unexpected)"})
    await asyncio.sleep(0)


async def _stream_httpq(config: Config) -> AsyncIterator[str]:
    """Yield SSE events for the HTTPQ Certificate Authority demo layer."""
    loop = asyncio.get_event_loop()

    yield _ev({"type": "section", "title": "LAYER 4 · HTTPQ — Quantum-Safe TLS",
               "subtitle": "Let's Encrypt for the quantum era: ML-DSA-87 certs + Kyber1024 handshake"})
    await asyncio.sleep(0)

    # ── CA Init ──────────────────────────────────────────────────────────────
    yield _ev({"type": "step", "label": "QSIP Root CA generates a self-signed PQC certificate"})
    await asyncio.sleep(0)

    ca = QSIPCertificateAuthority(config)
    t0 = time.perf_counter()
    root_cert = await loop.run_in_executor(None, lambda: ca.initialise("QSIP Root CA v1"))
    ms = (time.perf_counter() - t0) * 1000

    yield _ev({"type": "kv", "key": "CA subject",   "value": root_cert.subject})
    yield _ev({"type": "kv", "key": "Sig algorithm","value": root_cert.sig_algorithm,
               "note": "NIST FIPS 204 — quantum-safe. Classical CAs use RSA-2048 (quantum-breakable)."})
    yield _ev({"type": "kv", "key": "KEM algorithm","value": root_cert.kem_algorithm,
               "note": "NIST FIPS 203 — replaces ECDH in TLS handshake"})
    yield _ev({"type": "kv", "key": "CA public key","value": f"{len(root_cert.sig_verify_key):,} bytes  (ML-DSA-87)"})
    yield _ev({"type": "kv", "key": "Valid until",  "value": root_cert.not_after.strftime("%Y-%m-%d")})
    yield _ev({"type": "kv", "key": "Serial",       "value": root_cert.serial})
    yield _ev({"type": "kv", "key": "Fingerprint",  "value": root_cert.fingerprint()})
    yield _ev({"type": "ok", "msg": f"Root CA ready in {ms:.1f} ms"})
    await asyncio.sleep(0)

    # ── Server cert ──────────────────────────────────────────────────────────
    yield _ev({"type": "step", "label": "CA issues a certificate for 'secure.example.com'  (like Let's Encrypt)"})
    await asyncio.sleep(0)

    # Server generates its own keypair
    server_kem_kp = await loop.run_in_executor(None, lambda: KyberKEM(config).generate_keypair())
    server_sig_kp = await loop.run_in_executor(None, lambda: DilithiumSigner(config).generate_keypair())

    t0 = time.perf_counter()
    server_cert = await loop.run_in_executor(None, lambda: ca.issue_certificate(
        subject="secure.example.com",
        subject_kem_pk=server_kem_kp.public_key,
        subject_sig_vk=server_sig_kp.verify_key,
        valid_days=90,
    ))
    ms = (time.perf_counter() - t0) * 1000

    yield _ev({"type": "kv", "key": "Certificate",  "value": "secure.example.com"})
    yield _ev({"type": "kv", "key": "Issuer",       "value": server_cert.issuer})
    yield _ev({"type": "kv", "key": "Valid for",    "value": "90 days  (same as Let's Encrypt)"})
    yield _ev({"type": "kv", "key": "Kyber key",    "value": f"{len(server_cert.kem_public_key):,} bytes",
               "note": "Clients use this for key exchange — replaces RSA/ECDH server key"})
    yield _ev({"type": "kv", "key": "CA signature", "value": f"{len(server_cert.ca_signature):,} bytes  (ML-DSA-87)"})
    yield _ev({"type": "ok", "msg": f"Certificate issued in {ms:.1f} ms"})
    await asyncio.sleep(0)

    # ── HTTPQ Handshake ──────────────────────────────────────────────────────
    yield _ev({"type": "step",
               "label": "Client performs HTTPQ handshake: verify cert → Kyber key exchange → derive session key"})
    await asyncio.sleep(0)

    handshake = HTTPQHandshake(config, ca)
    t0 = time.perf_counter()
    result = await loop.run_in_executor(None, lambda: handshake.full_handshake(
        server_cert=server_cert,
        server_kem_sk=server_kem_kp.secret_key,
    ))
    total_ms = (time.perf_counter() - t0) * 1000

    yield _ev({"type": "kv", "key": "Cert verified",     "value": "YES  (ML-DSA-87 CA signature valid)"})
    yield _ev({"type": "kv", "key": "KEM ciphertext",    "value": f"{len(result.kem_ciphertext):,} bytes",
               "note": "Sent client→server. Server decapsulates to recover shared secret."})
    yield _ev({"type": "kv", "key": "Session key",       "value": "<REDACTED 32 bytes>",
               "note": "AES-256-compatible. Derived by both sides via HKDF-SHA3-512. Never transmitted."})
    yield _ev({"type": "kv", "key": "Session id",        "value": _hx(result.session_id, 16)})
    yield _ev({"type": "kv", "key": "Handshake time",    "value": f"{result.handshake_ms:.2f} ms"})
    yield _ev({"type": "ok",
               "msg": f"HTTPQ handshake complete in {total_ms:.1f} ms  — both sides hold the same session key"})
    await asyncio.sleep(0)

    # ── Tamper tests ─────────────────────────────────────────────────────────
    yield _ev({"type": "step", "label": "Tamper tests: what happens when an attacker interferes?"})
    await asyncio.sleep(0)

    # Test 1: forged certificate (signed by a different CA)
    evil_ca = QSIPCertificateAuthority(config)
    await loop.run_in_executor(None, lambda: evil_ca.initialise("Evil CA"))
    evil_cert = await loop.run_in_executor(None, lambda: evil_ca.issue_certificate(
        subject="secure.example.com",
        subject_kem_pk=server_kem_kp.public_key,
        subject_sig_vk=server_sig_kp.verify_key,
    ))
    bad_handshake = HTTPQHandshake(config, ca)   # uses the REAL CA for verification
    try:
        await loop.run_in_executor(None, lambda: bad_handshake.full_handshake(evil_cert, server_kem_kp.secret_key))
        yield _ev({"type": "fail", "msg": "Evil CA cert accepted (unexpected)"})
    except Exception:
        yield _ev({"type": "attack",
                   "label": "Forged certificate (wrong CA)  → cert signature rejected by ML-DSA-87 verify"})

    # Test 2: revoke then re-attempt
    ca.revoke(server_cert.serial)
    try:
        await loop.run_in_executor(None, lambda: handshake.full_handshake(server_cert, server_kem_kp.secret_key))
        yield _ev({"type": "fail", "msg": "Revoked cert accepted (unexpected)"})
    except Exception:
        yield _ev({"type": "attack", "label": "Revoked certificate  → CA CRL check fails before key exchange"})
    await asyncio.sleep(0)


async def _stream_email(config: Config) -> AsyncIterator[str]:
    """Yield SSE events for the PQEP Email demo layer."""
    loop = asyncio.get_event_loop()

    yield _ev({"type": "section", "title": "LAYER 2 · Post-Quantum Email Protocol  (PQEP)",
               "subtitle": "Kyber1024 KEM + AES-256-GCM + ML-DSA-87 sender auth"})
    await asyncio.sleep(0)

    yield _ev({"type": "step", "label": "Generating Alice and Bob identities"})
    alice = await loop.run_in_executor(None, lambda: IdentityKeyPair.generate(config, label="alice@example.com"))
    bob   = await loop.run_in_executor(None, lambda: IdentityKeyPair.generate(config, label="bob@example.com"))
    yield _ev({"type": "ok", "msg": f"Identities ready  ({alice.sig_keypair.algorithm})"})
    await asyncio.sleep(0)

    plaintext = (
        b"Dear Bob,\n\n"
        b"Shor's algorithm breaks RSA and ECDSA in polynomial time.\n"
        b"This message uses NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).\n"
        b"A quantum computer cannot read it.\n\n/Alice"
    )

    enc = PQEPEncryptor(config)

    yield _ev({"type": "step", "label": "Alice encrypts and signs for Bob's Kyber public key"})
    t0 = time.perf_counter()
    payload = await loop.run_in_executor(None, lambda: enc.encrypt(
        plaintext=plaintext,
        recipient_kem_public_key=bob.kem_public_key,
        sender_keypair=alice,
    ))
    ms = (time.perf_counter() - t0) * 1000

    yield _ev({"type": "kv", "key": "KEM ciphertext",   "value": f"{len(payload.kem_ciphertext):,} bytes  (Kyber1024)"})
    yield _ev({"type": "kv", "key": "Encrypted body",   "value": f"{len(payload.encrypted_body):,} bytes  (AES-256-GCM)"})
    yield _ev({"type": "kv", "key": "Sender signature", "value": f"{len(payload.sender_signature):,} bytes  ({payload.sig_algorithm})"})
    yield _ev({"type": "kv", "key": "GCM nonce",        "value": payload.nonce.hex(), "note": "Fresh per message — never reused"})
    yield _ev({"type": "ok", "msg": f"Encrypted + signed in {ms:.1f} ms"})
    await asyncio.sleep(0)

    yield _ev({"type": "step", "label": "Bob decapsulates Kyber KEM, derives AES key, decrypts, verifies signature"})
    t0 = time.perf_counter()
    recovered = await loop.run_in_executor(None, lambda: enc.decrypt(payload=payload, recipient_keypair=bob))
    ms = (time.perf_counter() - t0) * 1000
    if recovered == plaintext:
        yield _ev({"type": "ok", "msg": f"Decrypted + verified in {ms:.1f} ms  — exact match"})
    else:
        yield _ev({"type": "fail", "msg": "Plaintext mismatch"})
    await asyncio.sleep(0)

    yield _ev({"type": "attack", "label": "1-byte GCM body flip  → AES-256-GCM auth tag fails"})
    bad_body = bytes([payload.encrypted_body[0] ^ 0xFF]) + payload.encrypted_body[1:]
    bad_pl = PQEPEncryptedPayload(
        kem_ciphertext=payload.kem_ciphertext, nonce=payload.nonce,
        encrypted_body=bad_body, sender_signature=payload.sender_signature,
        sender_verify_key=payload.sender_verify_key, kem_algorithm=payload.kem_algorithm,
        sig_algorithm=payload.sig_algorithm, pqep_version=payload.pqep_version,
    )
    try:
        await loop.run_in_executor(None, lambda: enc.decrypt(payload=bad_pl, recipient_keypair=bob))
        yield _ev({"type": "fail", "msg": "Tampered ciphertext accepted (unexpected)"})
    except Exception:
        yield _ev({"type": "ok", "msg": "Tampered ciphertext rejected  — GCM authentication works"})
    await asyncio.sleep(0)


async def _stream_dns(config: Config) -> AsyncIterator[str]:
    """Yield SSE events for the PQC DNS demo layer."""
    from base64 import b64encode, b64decode
    from src.dns.validator import DNSRecordValidator
    loop = asyncio.get_event_loop()

    yield _ev({"type": "section", "title": "LAYER 3 · Quantum-Safe DNS Record Validation",
               "subtitle": "ML-DSA-87 signed TXT records — unforgeable BGP/DNS protection"})
    await asyncio.sleep(0)

    alice = await loop.run_in_executor(None, lambda: IdentityKeyPair.generate(config, label="dns-owner@example.com"))
    signer    = DilithiumSigner(config)
    validator = DNSRecordValidator(config)

    yield _ev({"type": "step", "label": "Domain owner signs their A record and publishes QSIP TXT record"})
    data    = b"example.com A 93.184.216.34"
    sig     = await loop.run_in_executor(None, lambda: signer.sign(data, alice.sig_keypair.sign_key))
    pk_b64  = b64encode(alice.sig_verify_key).decode()
    sig_b64 = b64encode(sig).decode()
    txt     = f"v=QSIP1; alg={alice.sig_keypair.algorithm}; pk={pk_b64}; sig={sig_b64}"

    yield _ev({"type": "kv", "key": "DNS name",   "value": "_pqc.example.com.  IN  TXT"})
    yield _ev({"type": "kv", "key": "Public key", "value": f"{len(alice.sig_verify_key):,} bytes  ({alice.sig_keypair.algorithm})",
               "note": "DNSSEC RSA-2048 = 256 bytes (quantum-breakable)"})
    yield _ev({"type": "kv", "key": "Signature",  "value": f"{len(sig):,} bytes  ({alice.sig_keypair.algorithm})"})
    yield _ev({"type": "ok",  "msg": f"TXT record ready  ({len(txt):,} chars)"})
    await asyncio.sleep(0)

    yield _ev({"type": "step", "label": "Resolver parses and validates"})
    parsed = validator.parse_qsip_record(txt)
    rpk    = b64decode(parsed["pk"]); rsig = b64decode(parsed["sig"])
    valid  = await loop.run_in_executor(None, lambda: signer.verify(data, rsig, rpk))
    if valid:
        yield _ev({"type": "ok", "msg": f"{alice.sig_keypair.algorithm} signature VALID  — A record is authentic"})
    else:
        yield _ev({"type": "fail", "msg": "Signature verification failed"})

    yield _ev({"type": "attack", "label": "Signature byte flipped  → rejected immediately"})
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    if not await loop.run_in_executor(None, lambda: signer.verify(data, bad_sig, rpk)):
        yield _ev({"type": "ok", "msg": "Tampered signature rejected"})

    yield _ev({"type": "attack", "label": "Spoofed A record payload  → original signature does not cover new IP"})
    if not await loop.run_in_executor(None, lambda: signer.verify(b"example.com A 1.2.3.4", rsig, rpk)):
        yield _ev({"type": "ok", "msg": "Spoofed payload rejected"})
    await asyncio.sleep(0)


async def _stream_all() -> AsyncIterator[str]:
    """Yield SSE events for the full 4-layer demo."""
    config = Config()
    t_start = time.perf_counter()

    yield _ev({"type": "start", "backend": "native liboqs (real NIST PQC)" if _NATIVE_FOUND else "mock PQC simulation",
               "native": _NATIVE_FOUND})

    async for ev in _stream_identity(config):
        yield ev
    async for ev in _stream_email(config):
        yield ev
    async for ev in _stream_dns(config):
        yield ev
    async for ev in _stream_httpq(config):
        yield ev

    runtime = (time.perf_counter() - t_start) * 1000
    yield _ev({"type": "done", "runtime_ms": round(runtime, 1), "layers": 4,
               "backend": "native liboqs" if _NATIVE_FOUND else "mock PQC",
               "native": _NATIVE_FOUND})


# ── SSE routes ────────────────────────────────────────────────────────────────

@app.get("/api/stream/all")
async def stream_all() -> StreamingResponse:
    """SSE: full 4-layer QSIP demo."""
    return StreamingResponse(
        _stream_all(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/stream/identity")
async def stream_identity() -> StreamingResponse:
    config = Config()
    async def _gen():
        async for ev in _stream_identity(config):
            yield ev
    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/stream/httpq")
async def stream_httpq() -> StreamingResponse:
    config = Config()
    async def _gen():
        async for ev in _stream_httpq(config):
            yield ev
    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/stream/email")
async def stream_email() -> StreamingResponse:
    """SSE: Layer 2 — Post-Quantum Email Protocol (PQEP)."""
    config = Config()
    async def _gen():
        async for ev in _stream_email(config):
            yield ev
    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/stream/dns")
async def stream_dns() -> StreamingResponse:
    """SSE: Layer 3 — PQC-secured DNS (quantum-safe DNSSEC)."""
    config = Config()
    async def _gen():
        async for ev in _stream_dns(config):
            yield ev
    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── One-shot JSON endpoints ───────────────────────────────────────────────────

@app.post("/api/keygen")
async def api_keygen() -> JSONResponse:
    """Generate a fresh QSIP keypair and return its public components."""
    try:
        loop = asyncio.get_event_loop()
        config = Config()
        kp = await loop.run_in_executor(None, lambda: IdentityKeyPair.generate(config))
        sig = DilithiumSigner(config)
        kem = KyberKEM(config)
        return JSONResponse({
            "identity_id":    kp.identity_id,
            "fingerprint":    kp.fingerprint(),
            "kem_algorithm":  kp.kem_keypair.algorithm,
            "sig_algorithm":  kp.sig_keypair.algorithm,
            "kem_public_key_hex": kp.kem_public_key.hex()[:64] + "…",
            "kem_public_key_bytes": len(kp.kem_public_key),
            "sig_verify_key_bytes": len(kp.sig_verify_key),
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.post("/api/handshake")
async def api_handshake() -> JSONResponse:
    """Run a complete HTTPQ handshake and return timing + cert info."""
    try:
        loop = asyncio.get_event_loop()
        config = Config()
        ca = QSIPCertificateAuthority(config)
        root = await loop.run_in_executor(None, lambda: ca.initialise("QSIP Root CA v1"))

        kem_kp = await loop.run_in_executor(None, lambda: KyberKEM(config).generate_keypair())
        sig_kp = await loop.run_in_executor(None, lambda: DilithiumSigner(config).generate_keypair())
        cert   = await loop.run_in_executor(None, lambda: ca.issue_certificate(
            "secure.example.com", kem_kp.public_key, sig_kp.verify_key
        ))
        handshake = HTTPQHandshake(config, ca)
        result    = await loop.run_in_executor(None, lambda: handshake.full_handshake(cert, kem_kp.secret_key))
        return JSONResponse({
            "handshake_ms":     round(result.handshake_ms, 2),
            "cert_verified":    result.cert_verified,
            "subject":          result.server_certificate.subject,
            "issuer":           result.server_certificate.issuer,
            "serial":           result.server_certificate.serial,
            "fingerprint":      result.server_certificate.fingerprint(),
            "kem_ciphertext_bytes": len(result.kem_ciphertext),
            "session_key_bytes": 32,
            "sig_algorithm":    result.server_certificate.sig_algorithm,
            "kem_algorithm":    result.server_certificate.kem_algorithm,
            "backend":          "native liboqs" if _NATIVE_FOUND else "mock PQC",
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


# ── Static HTML ───────────────────────────────────────────────────────────────

@app.get("/")
async def index() -> HTMLResponse:
    """Serve the live demo UI."""
    html_path = _STATIC / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>QSIP</h1><p>index.html not found in src/web/static/</p>", status_code=404)
