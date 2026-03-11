"""
QSIP — Identity Module Tests.

Tests for:
- IdentityKeyPair generation and properties
- KeyStore encrypt/save/load round-trip
- ZKCredential issuance and verification
- ZKProver and ZKVerifier
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from src.common.config import Config
from src.common.exceptions import IdentityError, KeystoreError, ZKProofError
from src.identity.keypair import IdentityKeyPair, KeyStore
from src.identity.credential import ZKCredential, CredentialType
from src.identity.zk_proof import ZKProver, ZKVerifier
from src.crypto.signatures import DilithiumSigner


class TestIdentityKeyPair:
    """Tests for IdentityKeyPair generation and properties."""

    def test_generate_produces_valid_keypair(self, config: Config) -> None:
        """Generated identity should have non-empty keys and a UUID."""
        kp = IdentityKeyPair.generate(config)
        assert len(kp.identity_id) == 36  # UUID format
        assert len(kp.kem_public_key) > 0
        assert len(kp.sig_verify_key) > 0

    def test_repr_does_not_expose_secret_keys(self, config: Config) -> None:
        """repr() must not contain secret key material."""
        kp = IdentityKeyPair.generate(config)
        r = repr(kp)
        assert kp.kem_keypair.secret_key.hex() not in r
        assert kp.sig_keypair.sign_key.hex() not in r

    def test_fingerprint_format(self, config: Config) -> None:
        """Fingerprint should follow QSIP:xxxxxxxx:xxxxxxxx:xxxxxxxx:xxxxxxxx format."""
        kp = IdentityKeyPair.generate(config)
        fp = kp.fingerprint()
        assert fp.startswith("QSIP:")
        parts = fp.split(":")
        assert len(parts) == 5  # QSIP + 4 hex blocks

    def test_two_generated_keypairs_are_different(self, config: Config) -> None:
        """Each generated identity should be unique."""
        kp1 = IdentityKeyPair.generate(config)
        kp2 = IdentityKeyPair.generate(config)
        assert kp1.identity_id != kp2.identity_id
        assert kp1.kem_public_key != kp2.kem_public_key

    def test_created_at_is_utc(self, config: Config) -> None:
        """created_at timestamp should be UTC-aware."""
        kp = IdentityKeyPair.generate(config, label="test@example.com")
        assert kp.created_at.tzinfo is not None
        assert kp.label == "test@example.com"


class TestKeyStore:
    """Tests for KeyStore encrypt/save/load operations."""

    def test_save_and_load_round_trip(self, config: Config, tmp_path: Path) -> None:
        """Saved keypair should be recoverable via load()."""
        # Point keystore to a temp file
        config_override = Config(identity_keystore_path=tmp_path / "test_keystore.enc")
        kp = IdentityKeyPair.generate(config_override)
        store = KeyStore(config_override)
        store.save(kp)
        loaded = store.load(kp.identity_id)

        assert loaded.identity_id == kp.identity_id
        assert loaded.kem_keypair.public_key == kp.kem_keypair.public_key
        assert loaded.kem_keypair.secret_key == kp.kem_keypair.secret_key
        assert loaded.sig_keypair.verify_key == kp.sig_keypair.verify_key

    def test_load_wrong_passphrase_raises(self, config: Config, tmp_path: Path) -> None:
        """Loading with wrong passphrase should raise KeystoreError."""
        config_ok = Config(
            identity_keystore_path=tmp_path / "ks.enc",
            keystore_passphrase="correct-passphrase",  # type: ignore[arg-type]
        )
        kp = IdentityKeyPair.generate(config_ok)
        KeyStore(config_ok).save(kp)

        config_wrong = Config(
            identity_keystore_path=tmp_path / "ks.enc",
            keystore_passphrase="wrong-passphrase",  # type: ignore[arg-type]
        )
        with pytest.raises(KeystoreError):
            KeyStore(config_wrong).load(kp.identity_id)

    def test_load_missing_identity_raises(self, config: Config, tmp_path: Path) -> None:
        """Loading a non-existent identity should raise KeystoreError."""
        config_override = Config(identity_keystore_path=tmp_path / "empty.enc")
        store = KeyStore(config_override)
        with pytest.raises(KeystoreError):
            store.load("nonexistent-identity-id")

    def test_list_identities_shows_public_info_only(self, config: Config, tmp_path: Path) -> None:
        """list_identities() should return metadata without secret keys."""
        config_override = Config(identity_keystore_path=tmp_path / "list_test.enc")
        kp = IdentityKeyPair.generate(config_override, label="alice@example.com")
        store = KeyStore(config_override)
        store.save(kp)

        identities = store.list_identities()
        assert len(identities) == 1
        entry = identities[0]
        assert entry["identity_id"] == kp.identity_id
        assert entry["label"] == "alice@example.com"
        # Secret keys must not appear
        assert "secret_key" not in entry
        assert "sign_key" not in entry


class TestZKCredential:
    """Tests for verifiable credential issuance and verification."""

    def test_issue_and_verify_credential(self, config: Config) -> None:
        """Issued credential signature should verify successfully."""
        issuer = IdentityKeyPair.generate(config)
        signer = DilithiumSigner(config)

        cred, blinding_factor = ZKCredential.issue(
            subject_id="did:qsip:subject123",
            claim_type=CredentialType.EMAIL_OWNERSHIP,
            claim_value=b"test@example.com",
            issuer_id=issuer.identity_id,
            issuer_sign_key=issuer.sig_keypair.sign_key,
            signer=signer,
        )

        assert cred.verify_signature(issuer.sig_verify_key, signer)

    def test_credential_commitment_opens_correctly(self, config: Config) -> None:
        """Credential commitment should open with correct claim_value and blinding_factor."""
        issuer = IdentityKeyPair.generate(config)
        signer = DilithiumSigner(config)

        cred, blinding_factor = ZKCredential.issue(
            subject_id="did:qsip:subject456",
            claim_type=CredentialType.DOMAIN_OWNERSHIP,
            claim_value=b"example.com",
            issuer_id=issuer.identity_id,
            issuer_sign_key=issuer.sig_keypair.sign_key,
            signer=signer,
        )

        assert cred.verify_claim(b"example.com", blinding_factor)

    def test_wrong_claim_value_does_not_open_commitment(self, config: Config) -> None:
        """Wrong claim value should not open the commitment."""
        issuer = IdentityKeyPair.generate(config)
        signer = DilithiumSigner(config)
        cred, blinding_factor = ZKCredential.issue(
            subject_id="did:qsip:x",
            claim_type=CredentialType.EMAIL_OWNERSHIP,
            claim_value=b"correct@example.com",
            issuer_id=issuer.identity_id,
            issuer_sign_key=issuer.sig_keypair.sign_key,
            signer=signer,
        )
        assert not cred.verify_claim(b"wrong@example.com", blinding_factor)

    def test_tampered_signature_does_not_verify(self, config: Config) -> None:
        """Tampered issuer signature should fail verification."""
        issuer = IdentityKeyPair.generate(config)
        signer = DilithiumSigner(config)
        cred, _ = ZKCredential.issue(
            subject_id="did:qsip:y",
            claim_type=CredentialType.AGE_OVER_18,
            claim_value=b"dob:2000-01-01",
            issuer_id=issuer.identity_id,
            issuer_sign_key=issuer.sig_keypair.sign_key,
            signer=signer,
        )
        tampered_sig = bytearray(cred.issuer_signature)
        tampered_sig[5] ^= 0xFF
        tampered_cred = ZKCredential(
            credential_id=cred.credential_id,
            subject_id=cred.subject_id,
            issuer_id=cred.issuer_id,
            claim_type=cred.claim_type,
            claim_commitment=cred.claim_commitment,
            issued_at=cred.issued_at,
            expires_at=cred.expires_at,
            issuer_signature=bytes(tampered_sig),
            sig_algorithm=cred.sig_algorithm,
        )
        assert not tampered_cred.verify_signature(issuer.sig_verify_key, signer)

    def test_expired_credential_does_not_verify(self, config: Config) -> None:
        """Expired credentials should fail verification."""
        issuer = IdentityKeyPair.generate(config)
        signer = DilithiumSigner(config)
        cred, _ = ZKCredential.issue(
            subject_id="did:qsip:z",
            claim_type=CredentialType.EMAIL_OWNERSHIP,
            claim_value=b"old@example.com",
            issuer_id=issuer.identity_id,
            issuer_sign_key=issuer.sig_keypair.sign_key,
            signer=signer,
            validity_days=1,
        )
        # Manually create an expired credential
        expired_cred = ZKCredential(
            credential_id=cred.credential_id,
            subject_id=cred.subject_id,
            issuer_id=cred.issuer_id,
            claim_type=cred.claim_type,
            claim_commitment=cred.claim_commitment,
            issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2020, 1, 2, tzinfo=timezone.utc),  # In the past
            issuer_signature=cred.issuer_signature,
            sig_algorithm=cred.sig_algorithm,
        )
        assert expired_cred.is_expired()
        assert not expired_cred.verify_signature(issuer.sig_verify_key, signer)


class TestZKProof:
    """Tests for zero-knowledge proof generation and verification."""

    def test_prove_and_verify_valid_proof(self, config: Config) -> None:
        """A valid proof should verify successfully."""
        import hashlib, secrets
        prover = ZKProver()
        verifier = ZKVerifier()

        claim_value = b"alice@example.com"
        blinding_factor = secrets.token_bytes(32)
        commitment = hashlib.sha3_256(claim_value + blinding_factor).digest()

        proof = prover.prove_commitment_opening(commitment, claim_value, blinding_factor)
        assert verifier.verify_commitment_proof(commitment, proof)

    def test_proof_for_wrong_commitment_raises(self) -> None:
        """Proving with values that don't match commitment should raise ZKProofError."""
        import hashlib, secrets
        prover = ZKProver()

        claim_value = b"alice@example.com"
        blinding_factor = secrets.token_bytes(32)
        # Wrong commitment — different blinding factor
        wrong_blinding = secrets.token_bytes(32)
        wrong_commitment = hashlib.sha3_256(claim_value + wrong_blinding).digest()

        with pytest.raises(ZKProofError):
            prover.prove_commitment_opening(wrong_commitment, claim_value, blinding_factor)

    def test_verification_with_wrong_commitment_returns_false(self) -> None:
        """Verifying proof against wrong commitment should return False."""
        import hashlib, secrets
        prover = ZKProver()
        verifier = ZKVerifier()

        claim_value = b"alice@example.com"
        blinding_factor = secrets.token_bytes(32)
        commitment = hashlib.sha3_256(claim_value + blinding_factor).digest()
        proof = prover.prove_commitment_opening(commitment, claim_value, blinding_factor)

        # Different commitment
        wrong_commitment = hashlib.sha3_256(b"different" + blinding_factor).digest()
        assert not verifier.verify_commitment_proof(wrong_commitment, proof)
