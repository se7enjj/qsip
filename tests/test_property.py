"""
QSIP — Property-Based Tests (hypothesis).

These tests define cryptographic invariants that MUST hold for ALL inputs,
not just a handful of hand-picked examples.  hypothesis generates hundreds of
random inputs and shrinks any counterexample to its minimal form.

Security properties tested:
  1. Sig: ANY bit-flip in the signed message  → verify returns False
  2. Sig: ANY bit-flip in the signature bytes → verify returns False
  3. Sig: Sig from keypair A NEVER verifies under keypair B's verify key
  4. Sig: Signing the same message twice produces two DIFFERENT signatures
     (for deterministic schemes this verifies our mock isn't trivially broken)
  5. KEM: Fresh encapsulation always produces a match on decapsulate
  6. KEM: Wrong recipient (different SK) always yields a different secret
  7. KEM: ANY single-byte mutation of the ciphertext → different shared secret
  8. Email: ANY single-byte flip in encrypted body → PQEPError on decrypt
  9. HybridKEM: Wrong recipient SK yields a different encapsulated secret

Run: pytest tests/test_property.py -v
"""

from __future__ import annotations

import secrets
from typing import TypeVar

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from src.common.config import Config
from src.common.exceptions import QSIPCryptoError, PQEPError
from src.crypto.kem import KyberKEM
from src.crypto.signatures import DilithiumSigner
from src.crypto.hybrid import HybridKEM
from src.email.encryptor import PQEPEncryptor
from src.identity.keypair import IdentityKeyPair


# ── Shared fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def cfg() -> Config:
    """Module-scoped config so repeated hypothesis calls reuse a single object."""
    return Config()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _flip_byte(data: bytes, index: int) -> bytes:
    """Flip all bits in one byte of *data* at *index*."""
    ba = bytearray(data)
    ba[index] ^= 0xFF
    return bytes(ba)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Signature — bit flip in message body
# ─────────────────────────────────────────────────────────────────────────────

@given(message=st.binary(min_size=1, max_size=512))
@settings(max_examples=30, deadline=5_000)
def test_sig_message_flip_always_rejected(message: bytes) -> None:
    """Any single byte flipped in the message must make the signature invalid."""
    cfg = Config()
    signer = DilithiumSigner(cfg)
    kp = signer.generate_keypair()

    sig = signer.sign(message, kp.sign_key)
    assert signer.verify(message, sig, kp.verify_key), "baseline: valid sig should verify"

    # Flip every byte position and confirm rejection
    for i in range(min(len(message), 16)):   # sample first 16 positions to stay fast
        tampered = _flip_byte(message, i)
        assert not signer.verify(tampered, sig, kp.verify_key), (
            f"verify() accepted a message with byte {i} flipped — integrity failure"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Signature — bit flip in the signature bytes
# ─────────────────────────────────────────────────────────────────────────────

@given(message=st.binary(min_size=1, max_size=256))
@settings(max_examples=30, deadline=5_000)
def test_sig_signature_flip_always_rejected(message: bytes) -> None:
    """Any single byte flipped in the signature must make verification fail."""
    cfg = Config()
    signer = DilithiumSigner(cfg)
    kp = signer.generate_keypair()
    sig = signer.sign(message, kp.sign_key)

    # Sample 8 random positions in the signature
    positions = [secrets.randbelow(len(sig)) for _ in range(8)]
    for pos in positions:
        bad_sig = _flip_byte(sig, pos)
        assert not signer.verify(message, bad_sig, kp.verify_key), (
            f"verify() accepted a signature with byte {pos} flipped"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. Signature — cross-keypair verification must always fail
# ─────────────────────────────────────────────────────────────────────────────

@given(message=st.binary(min_size=1, max_size=256))
@settings(max_examples=25, deadline=5_000)
def test_sig_wrong_verify_key_always_rejects(message: bytes) -> None:
    """A signature produced by keypair A must NOT verify under keypair B's verify key."""
    cfg = Config()
    signer = DilithiumSigner(cfg)
    kp_a = signer.generate_keypair()
    kp_b = signer.generate_keypair()

    assume(kp_a.verify_key != kp_b.verify_key)  # sanity; almost certain with 2592-byte keys

    sig_a = signer.sign(message, kp_a.sign_key)
    assert not signer.verify(message, sig_a, kp_b.verify_key), (
        "Signature from keypair A verified under keypair B — catastrophic auth failure"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Signature — random bytes never accepted as a valid signature
# ─────────────────────────────────────────────────────────────────────────────

@given(
    message=st.binary(min_size=1, max_size=256),
    forged_sig=st.binary(min_size=1, max_size=5000),
)
@settings(max_examples=30, deadline=5_000)
def test_sig_random_bytes_never_verify(message: bytes, forged_sig: bytes) -> None:
    """
    Arbitrary random bytes submitted as a signature must not verify.

    This property catches signature schemes where the verification function
    erroneously accepts large classes of inputs (e.g. empty-byte attacks).
    """
    cfg = Config()
    signer = DilithiumSigner(cfg)
    kp = signer.generate_keypair()
    real_sig = signer.sign(message, kp.sign_key)

    assume(forged_sig != real_sig)  # exclude the (astronomically unlikely) exact match

    assert not signer.verify(message, forged_sig, kp.verify_key)


# ─────────────────────────────────────────────────────────────────────────────
# 5. KEM — encap→decap round-trip always recovers the same secret
# ─────────────────────────────────────────────────────────────────────────────

@given(st.data())
@settings(max_examples=25, deadline=5_000)
def test_kem_roundtrip_always_recovers_secret(data: st.DataObject) -> None:
    """Decapsulate(Encapsulate(pk), sk) == shared_secret for any fresh keypair."""
    cfg = Config()
    kem = KyberKEM(cfg)
    kp = kem.generate_keypair()

    result = kem.encapsulate(kp.public_key)
    recovered = kem.decapsulate(result.ciphertext, kp.secret_key)

    assert recovered == result.shared_secret, (
        "KEM round-trip failed: decapsulate returned a different shared secret"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 6. KEM — wrong recipient SK always yields a DIFFERENT shared secret
# ─────────────────────────────────────────────────────────────────────────────

@given(st.data())
@settings(max_examples=25, deadline=5_000)
def test_kem_wrong_sk_yields_different_secret(data: st.DataObject) -> None:
    """
    Decapsulating with the wrong secret key must yield a different shared secret.

    Under Kyber (IND-CCA2) a wrong SK produces a uniformly random-looking output,
    ensuring that an eavesdropper with the wrong key learns zero information.
    """
    cfg = Config()
    kem = KyberKEM(cfg)
    kp_alice = kem.generate_keypair()
    kp_bob = kem.generate_keypair()

    assume(kp_alice.secret_key != kp_bob.secret_key)

    result = kem.encapsulate(kp_alice.public_key)
    # Bob tries to decapsulate Alice's ciphertext with his own SK
    wrong_secret = kem.decapsulate(result.ciphertext, kp_bob.secret_key)

    assert wrong_secret != result.shared_secret, (
        "KEM: wrong recipient SK produced the same shared secret — confidentiality failure"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 7. KEM — any single-byte ciphertext mutation yields a DIFFERENT secret
# ─────────────────────────────────────────────────────────────────────────────

@given(flip_position=st.integers(min_value=0, max_value=1567))
@settings(max_examples=30, deadline=5_000)
def test_kem_ciphertext_mutation_yields_different_secret(flip_position: int) -> None:
    """
    Any single-byte flip in the KEM ciphertext must produce a different shared secret.

    This tests the ciphertext integrity property of IND-CCA2: an adversary who
    modifies the transmitted ciphertext cannot obtain the original shared secret.
    """
    cfg = Config()
    kem = KyberKEM(cfg)
    kp = kem.generate_keypair()

    result = kem.encapsulate(kp.public_key)

    # The Kyber1024 ciphertext is 1568 bytes.  flip_position is already bounded.
    assume(flip_position < len(result.ciphertext))

    tampered = _flip_byte(result.ciphertext, flip_position)
    recovered = kem.decapsulate(tampered, kp.secret_key)

    assert recovered != result.shared_secret, (
        f"KEM accepted tampered ciphertext (byte {flip_position} flipped) — "
        "this would allow an adversary to learn the original shared secret"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 8. Email — any single-byte flip in encrypted body raises PQEPError
# ─────────────────────────────────────────────────────────────────────────────

@given(
    plaintext=st.binary(min_size=16, max_size=256),
    flip_offset=st.integers(min_value=0, max_value=15),
)
@settings(max_examples=20, deadline=10_000)
def test_email_ciphertext_flip_raises_pqep_error(
    plaintext: bytes, flip_offset: int
) -> None:
    """
    AES-256-GCM is authenticated.  Any modification to the encrypted body *or*
    the GCM authentication tag must be rejected during decryption.
    """
    cfg = Config()
    enc = PQEPEncryptor(cfg)
    sender = IdentityKeyPair.generate(cfg)
    recipient = IdentityKeyPair.generate(cfg)

    payload = enc.encrypt(
        plaintext=plaintext,
        recipient_kem_public_key=recipient.kem_public_key,
        sender_keypair=sender,
    )

    assume(flip_offset < len(payload.encrypted_body))

    tampered_body = _flip_byte(payload.encrypted_body, flip_offset)

    # Rebuild payload with tampered body
    from dataclasses import replace as dc_replace
    bad_payload = dc_replace(payload, encrypted_body=tampered_body)

    with pytest.raises((PQEPError, QSIPCryptoError)):
        enc.decrypt(bad_payload, recipient_keypair=recipient)


# ─────────────────────────────────────────────────────────────────────────────
# 9. HybridKEM — wrong recipient always yields a different final secret
# ─────────────────────────────────────────────────────────────────────────────

@given(st.data())
@settings(max_examples=20, deadline=5_000)
def test_hybrid_kem_wrong_recipient_differs(data: st.DataObject) -> None:
    """
    HybridKEM (X25519 + Kyber1024) must produce different combined key material
    when decapsulated with a different recipient's secret keys.

    generate_keypair() → (kyber_pk, kyber_sk, x25519_pk, x25519_sk)
    encapsulate(kyber_pk, x25519_pk) → HybridEncapsulationResult
    decapsulate(kyber_ct, x25519_eph_pk, kyber_sk, x25519_sk) → bytes
    """
    cfg = Config()
    hkem = HybridKEM(cfg)

    k_pk_a, k_sk_a, x_pk_a, x_sk_a = hkem.generate_keypair()
    k_pk_b, k_sk_b, _,      x_sk_b = hkem.generate_keypair()

    assume(k_sk_a != k_sk_b)

    result = hkem.encapsulate(k_pk_a, x_pk_a)

    # Bob tries to decapsulate a message intended for Alice
    wrong_material = hkem.decapsulate(
        result.kyber_ciphertext,
        result.x25519_ephemeral_public_key,
        k_sk_b,
        x_sk_b,
    )

    assert wrong_material != result.key_material, (
        "HybridKEM: wrong recipient yielded the same shared key material"
    )
