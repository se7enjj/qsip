"""
QSIP — Email Module Tests.

Tests for:
- PQEPEncryptor encrypt/decrypt round-trip
- Tampered ciphertext rejection
- Signature verification failure handling
- PQEPComposer header composition and parsing
"""

from __future__ import annotations

import pytest

from src.common.config import Config
from src.common.exceptions import PQEPError
from src.email.encryptor import PQEPEncryptor, PQEPEncryptedPayload
from src.email.composer import PQEPComposer
from src.identity.keypair import IdentityKeyPair


class TestPQEPEncryptor:
    """Tests for the PQEP email encryption pipeline."""

    def test_encrypt_decrypt_round_trip(self, config: Config) -> None:
        """Encrypting and decrypting should recover the original plaintext."""
        encryptor = PQEPEncryptor(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)

        plaintext = b"Hello, QSIP! This is a quantum-safe message."
        payload = encryptor.encrypt(
            plaintext=plaintext,
            recipient_kem_public_key=recipient.kem_public_key,
            sender_keypair=sender,
        )
        recovered = encryptor.decrypt(payload, recipient_keypair=recipient)
        assert recovered == plaintext

    def test_encrypt_produces_non_empty_payload(self, config: Config) -> None:
        """Encrypted payload should have non-empty ciphertext and KEM fields."""
        encryptor = PQEPEncryptor(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)

        payload = encryptor.encrypt(b"test", recipient.kem_public_key, sender)
        assert len(payload.kem_ciphertext) > 0
        assert len(payload.nonce) == 12
        assert len(payload.encrypted_body) > 0
        assert len(payload.sender_signature) > 0
        assert len(payload.sender_verify_key) > 0

    def test_repr_does_not_expose_plaintext(self, config: Config) -> None:
        """PQEPEncryptedPayload repr should not expose sensitive data."""
        encryptor = PQEPEncryptor(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)
        payload = encryptor.encrypt(b"secret data", recipient.kem_public_key, sender)
        r = repr(payload)
        assert "secret data" not in r

    def test_decrypt_tampered_body_raises(self, config: Config) -> None:
        """Tampered encrypted body should cause decryption to fail (GCM auth tag)."""
        encryptor = PQEPEncryptor(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)

        payload = encryptor.encrypt(b"original", recipient.kem_public_key, sender)
        # Tamper with the encrypted body (flip a byte — breaks GCM auth tag)
        tampered_body = bytearray(payload.encrypted_body)
        tampered_body[5] ^= 0xFF
        tampered_payload = PQEPEncryptedPayload(
            kem_ciphertext=payload.kem_ciphertext,
            nonce=payload.nonce,
            encrypted_body=bytes(tampered_body),
            sender_signature=payload.sender_signature,
            sender_verify_key=payload.sender_verify_key,
            kem_algorithm=payload.kem_algorithm,
            sig_algorithm=payload.sig_algorithm,
            pqep_version=payload.pqep_version,
        )
        with pytest.raises(PQEPError):
            encryptor.decrypt(tampered_payload, recipient_keypair=recipient)

    def test_decrypt_with_wrong_recipient_raises(self, config: Config) -> None:
        """Decrypting with the wrong recipient key should fail."""
        encryptor = PQEPEncryptor(config)
        sender = IdentityKeyPair.generate(config)
        real_recipient = IdentityKeyPair.generate(config)
        wrong_recipient = IdentityKeyPair.generate(config)

        payload = encryptor.encrypt(b"secret", real_recipient.kem_public_key, sender)
        with pytest.raises(PQEPError):
            # Wrong recipient cannot decapsulate the KEM key or will get wrong AES key
            encryptor.decrypt(payload, recipient_keypair=wrong_recipient)

    def test_empty_plaintext_raises(self, config: Config) -> None:
        """Encrypting empty plaintext should raise PQEPError."""
        encryptor = PQEPEncryptor(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)
        with pytest.raises(PQEPError):
            encryptor.encrypt(b"", recipient.kem_public_key, sender)

    def test_payload_serialization_round_trip(self, config: Config) -> None:
        """PQEPEncryptedPayload should serialize and deserialize correctly."""
        encryptor = PQEPEncryptor(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)

        payload = encryptor.encrypt(b"serialize test", recipient.kem_public_key, sender)
        d = payload.to_dict()
        restored = PQEPEncryptedPayload.from_dict(d)

        assert restored.kem_ciphertext == payload.kem_ciphertext
        assert restored.nonce == payload.nonce
        assert restored.encrypted_body == payload.encrypted_body
        assert restored.sender_signature == payload.sender_signature

    def test_two_encryptions_produce_different_ciphertexts(self, config: Config) -> None:
        """Each encryption should produce a unique ciphertext (fresh nonce + KEM)."""
        encryptor = PQEPEncryptor(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)
        msg = b"duplicate test"

        p1 = encryptor.encrypt(msg, recipient.kem_public_key, sender)
        p2 = encryptor.encrypt(msg, recipient.kem_public_key, sender)

        assert p1.nonce != p2.nonce
        assert p1.kem_ciphertext != p2.kem_ciphertext
        assert p1.encrypted_body != p2.encrypted_body


class TestPQEPComposer:
    """Tests for PQEP email message composition."""

    def test_compose_produces_pqep_headers(self, config: Config) -> None:
        """Composed message should contain all required PQEP headers."""
        encryptor = PQEPEncryptor(config)
        composer = PQEPComposer(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)

        payload = encryptor.encrypt(b"test email body", recipient.kem_public_key, sender)
        message = composer.compose(
            payload=payload,
            sender_address="alice@example.com",
            recipient_address="bob@example.com",
            subject="Test",
        )

        assert message["X-PQEP-Version"] == "1"
        assert message["X-PQEP-KEM"] == "Kyber1024"
        assert message["X-PQEP-SIG"] == "Dilithium5"
        assert message["X-PQEP-Sender-PK"] is not None
        assert message["X-PQEP-KEM-CT"] is not None
        assert message["X-PQEP-Nonce"] is not None

    def test_compose_subject_too_long_raises(self, config: Config) -> None:
        """Subject longer than 200 chars should raise PQEPError."""
        encryptor = PQEPEncryptor(config)
        composer = PQEPComposer(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)
        payload = encryptor.encrypt(b"x", recipient.kem_public_key, sender)

        with pytest.raises(PQEPError):
            composer.compose(payload, "a@b.com", "c@d.com", subject="X" * 201)

    def test_parse_headers_from_composed_message(self, config: Config) -> None:
        """parse_pqep_headers() should extract all headers from composed message."""
        encryptor = PQEPEncryptor(config)
        composer = PQEPComposer(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)
        payload = encryptor.encrypt(b"header test", recipient.kem_public_key, sender)
        message = composer.compose(payload, "s@example.com", "r@example.com")

        headers = composer.parse_pqep_headers(message)
        assert "X-PQEP-Version" in headers
        assert "X-PQEP-KEM" in headers
        assert "X-PQEP-Sender-PK" in headers

    def test_default_subject_used_when_empty(self, config: Config) -> None:
        """Empty subject should produce a default PQEP subject line."""
        encryptor = PQEPEncryptor(config)
        composer = PQEPComposer(config)
        sender = IdentityKeyPair.generate(config)
        recipient = IdentityKeyPair.generate(config)
        payload = encryptor.encrypt(b"no subject", recipient.kem_public_key, sender)
        message = composer.compose(payload, "a@b.com", "c@d.com", subject="")
        assert "PQEP" in message["Subject"] or "[" in message["Subject"]
