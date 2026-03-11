"""
QSIP — Crypto Module Tests.

Tests for src/crypto/kem.py, src/crypto/signatures.py, and src/crypto/hybrid.py.

Each crypto function tested for:
1. Happy path (correct usage produces expected output)
2. Tampered ciphertext/data rejection
3. Wrong key rejection
4. Invalid input handling

Security: All keys are ephemeral and generated fresh per test.
"""

from __future__ import annotations

import os
import secrets

import pytest

from src.common.config import Config
from src.common.exceptions import QSIPCryptoError
from src.crypto.kem import KyberKEM, KEMKeypair
from src.crypto.signatures import DilithiumSigner
from src.crypto.hybrid import HybridKEM


class TestKyberKEM:
    """Tests for CRYSTALS-Kyber Key Encapsulation Mechanism."""

    def test_generate_keypair_returns_keypair(self, config: Config) -> None:
        """Keypair generation should produce non-empty public and secret keys."""
        kem = KyberKEM(config)
        kp = kem.generate_keypair()
        assert isinstance(kp, KEMKeypair)
        assert len(kp.public_key) > 0
        assert len(kp.secret_key) > 0
        assert kp.algorithm == "Kyber1024"

    def test_keypair_repr_does_not_expose_secret_key(self, config: Config) -> None:
        """Secret key must never appear in repr()."""
        kem = KyberKEM(config)
        kp = kem.generate_keypair()
        repr_str = repr(kp)
        assert "REDACTED" in repr_str
        assert kp.secret_key.hex() not in repr_str

    def test_encapsulate_decapsulate_round_trip(self, config: Config) -> None:
        """Encapsulate and decapsulate should produce the same shared secret."""
        kem = KyberKEM(config)
        kp = kem.generate_keypair()
        result = kem.encapsulate(kp.public_key)
        recovered = kem.decapsulate(result.ciphertext, kp.secret_key)
        assert recovered == result.shared_secret

    def test_encapsulate_result_repr_does_not_expose_secret(self, config: Config) -> None:
        """Shared secret must never appear in encapsulation result repr()."""
        kem = KyberKEM(config)
        kp = kem.generate_keypair()
        result = kem.encapsulate(kp.public_key)
        repr_str = repr(result)
        assert "REDACTED" in repr_str
        assert result.shared_secret.hex() not in repr_str

    def test_decapsulate_with_wrong_key_fails(self, config: Config) -> None:
        """Decapsulating with a different secret key should fail or produce different output."""
        kem = KyberKEM(config)
        kp1 = kem.generate_keypair()
        kp2 = kem.generate_keypair()
        result = kem.encapsulate(kp1.public_key)
        # With wrong key: either raises or produces different (wrong) shared secret
        try:
            wrong_secret = kem.decapsulate(result.ciphertext, kp2.secret_key)
            # If it doesn't raise, the output must differ
            assert wrong_secret != result.shared_secret
        except QSIPCryptoError:
            pass  # Acceptable — rejection is correct behaviour

    def test_decapsulate_tampered_ciphertext_fails(self, config: Config) -> None:
        """Tampered KEM ciphertext should not produce the original shared secret."""
        kem = KyberKEM(config)
        kp = kem.generate_keypair()
        result = kem.encapsulate(kp.public_key)
        # Flip a byte in the ciphertext
        tampered = bytearray(result.ciphertext)
        tampered[42] ^= 0xFF
        try:
            recovered = kem.decapsulate(bytes(tampered), kp.secret_key)
            assert recovered != result.shared_secret
        except QSIPCryptoError:
            pass  # Acceptable

    def test_encapsulate_empty_public_key_raises(self, config: Config) -> None:
        """Encapsulating with empty public key should raise QSIPCryptoError."""
        kem = KyberKEM(config)
        with pytest.raises(QSIPCryptoError):
            kem.encapsulate(b"")

    def test_two_encapsulations_produce_different_ciphertexts(self, config: Config) -> None:
        """Each encapsulation should be fresh (different ciphertexts)."""
        kem = KyberKEM(config)
        kp = kem.generate_keypair()
        r1 = kem.encapsulate(kp.public_key)
        r2 = kem.encapsulate(kp.public_key)
        assert r1.ciphertext != r2.ciphertext
        # Shared secrets may or may not differ (KEM-dependent), but ciphertexts must

    def test_shared_secret_length_is_reasonable(self, config: Config) -> None:
        """Shared secret should be at least 32 bytes for 256-bit security."""
        kem = KyberKEM(config)
        kp = kem.generate_keypair()
        result = kem.encapsulate(kp.public_key)
        assert len(result.shared_secret) >= 32


class TestDilithiumSigner:
    """Tests for CRYSTALS-Dilithium digital signatures."""

    def test_generate_keypair_returns_keypair(self, config: Config) -> None:
        """Keypair generation should produce non-empty verify and sign keys."""
        signer = DilithiumSigner(config)
        kp = signer.generate_keypair()
        assert len(kp.verify_key) > 0
        assert len(kp.sign_key) > 0
        assert kp.algorithm == "Dilithium5"

    def test_keypair_repr_does_not_expose_sign_key(self, config: Config) -> None:
        """Sign key must never appear in repr()."""
        signer = DilithiumSigner(config)
        kp = signer.generate_keypair()
        repr_str = repr(kp)
        assert "REDACTED" in repr_str
        assert kp.sign_key.hex() not in repr_str

    def test_sign_verify_round_trip(self, config: Config) -> None:
        """A valid signature should verify successfully."""
        signer = DilithiumSigner(config)
        kp = signer.generate_keypair()
        message = b"test message for QSIP signature"
        sig = signer.sign(message, kp.sign_key)
        assert signer.verify(message, sig, kp.verify_key)

    def test_verify_tampered_message_returns_false(self, config: Config) -> None:
        """Verification of a tampered message should return False, not raise."""
        signer = DilithiumSigner(config)
        kp = signer.generate_keypair()
        message = b"original message"
        sig = signer.sign(message, kp.sign_key)
        tampered = b"tampered message"
        assert not signer.verify(tampered, sig, kp.verify_key)

    def test_verify_tampered_signature_returns_false(self, config: Config) -> None:
        """Verification of a tampered signature should return False."""
        signer = DilithiumSigner(config)
        kp = signer.generate_keypair()
        message = b"test message"
        sig = signer.sign(message, kp.sign_key)
        tampered_sig = bytearray(sig)
        tampered_sig[10] ^= 0xFF
        assert not signer.verify(message, bytes(tampered_sig), kp.verify_key)

    def test_verify_wrong_key_returns_false(self, config: Config) -> None:
        """Verification with the wrong verify key should return False."""
        signer = DilithiumSigner(config)
        kp1 = signer.generate_keypair()
        kp2 = signer.generate_keypair()
        message = b"test message"
        sig = signer.sign(message, kp1.sign_key)
        assert not signer.verify(message, sig, kp2.verify_key)

    def test_sign_empty_message_raises(self, config: Config) -> None:
        """Signing an empty message should raise QSIPCryptoError."""
        signer = DilithiumSigner(config)
        kp = signer.generate_keypair()
        with pytest.raises(QSIPCryptoError):
            signer.sign(b"", kp.sign_key)

    def test_verify_empty_inputs_returns_false(self, config: Config) -> None:
        """Verifying with empty inputs should return False, not raise."""
        signer = DilithiumSigner(config)
        assert not signer.verify(b"", b"fake_sig", b"fake_key")
        assert not signer.verify(b"message", b"", b"fake_key")
        assert not signer.verify(b"message", b"fake_sig", b"")


class TestHybridKEM:
    """Tests for Hybrid X25519 + Kyber1024 KEM."""

    def test_generate_keypair_returns_four_keys(self, config: Config) -> None:
        """Hybrid keypair generation should return all four key components."""
        hybrid = HybridKEM(config)
        kyber_pk, kyber_sk, x25519_pk, x25519_sk = hybrid.generate_keypair()
        assert len(kyber_pk) > 0
        assert len(kyber_sk) > 0
        assert len(x25519_pk) == 32  # X25519 public key is always 32 bytes
        assert len(x25519_sk) == 32  # X25519 private key is always 32 bytes

    def test_encapsulate_decapsulate_produces_same_key(self, config: Config) -> None:
        """Hybrid encapsulate and decapsulate should produce identical 32-byte key material."""
        hybrid = HybridKEM(config)
        kyber_pk, kyber_sk, x25519_pk, x25519_sk = hybrid.generate_keypair()

        result = hybrid.encapsulate(kyber_pk, x25519_pk)
        recovered = hybrid.decapsulate(
            result.kyber_ciphertext,
            result.x25519_ephemeral_public_key,
            kyber_sk,
            x25519_sk,
        )
        assert recovered == result.key_material
        assert len(recovered) == 32

    def test_result_repr_does_not_expose_key_material(self, config: Config) -> None:
        """key_material must never appear in repr of HybridEncapsulationResult."""
        hybrid = HybridKEM(config)
        kyber_pk, _, x25519_pk, _ = hybrid.generate_keypair()
        result = hybrid.encapsulate(kyber_pk, x25519_pk)
        repr_str = repr(result)
        assert "REDACTED" in repr_str
        assert result.key_material.hex() not in repr_str

    def test_two_encapsulations_produce_different_key_material(self, config: Config) -> None:
        """Each encapsulation should produce unique key material."""
        hybrid = HybridKEM(config)
        kyber_pk, _, x25519_pk, _ = hybrid.generate_keypair()
        r1 = hybrid.encapsulate(kyber_pk, x25519_pk)
        r2 = hybrid.encapsulate(kyber_pk, x25519_pk)
        assert r1.key_material != r2.key_material
