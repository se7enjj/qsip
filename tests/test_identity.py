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
from src.identity.revocation import RevocationAccumulator, SignedRevocationRoot, RevocationProof
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


class TestRevocationAccumulator:
    """
    Tests for the Merkle-accumulator-based credential revocation system.

    Security properties verified:
    - Empty/populated accumulator produces deterministic Merkle roots.
    - revoke() adds to the set; is_revoked() reflects the change.
    - commit() produces a Dilithium-signed root; verify_signature() confirms it.
    - Tampered signatures are rejected.
    - prove_revocation() returns a valid Merkle inclusion proof.
    - Non-revoked credential returns None proof.
    - Tampered proof fails verify().
    - ZKCredential.verify_signature() honours the accumulator.
    - Serialization round-trips preserve the full revocation set.
    """

    # ── Fixtures ──────────────────────────────────────────────────────────────

    def _make_credential(self, config: Config) -> tuple:
        """Issue an ephemeral test credential and return (cred, blinding, issuer_kp)."""
        from src.identity.credential import ZKCredential, CredentialType
        from src.crypto.signatures import DilithiumSigner

        signer = DilithiumSigner(config)
        issuer = IdentityKeyPair.generate(config, label="test-issuer")
        cred, blinding = ZKCredential.issue(
            subject_id="did:qsip:subject",
            claim_type=CredentialType.EMAIL_OWNERSHIP,
            claim_value=b"test@example.com",
            issuer_id=issuer.identity_id,
            issuer_sign_key=issuer.sig_keypair.sign_key,
            signer=signer,
        )
        return cred, blinding, issuer, signer

    # ── Basic accumulator behaviour ───────────────────────────────────────────

    def test_empty_accumulator_root_is_deterministic(self) -> None:
        """Two empty accumulators must produce identical Merkle roots."""
        acc1 = RevocationAccumulator()
        acc2 = RevocationAccumulator()
        assert acc1.build_root() == acc2.build_root()

    def test_revoke_adds_to_set(self) -> None:
        """is_revoked() must return True immediately after revoke()."""
        acc = RevocationAccumulator()
        cred_id = "00000000-0000-0000-0000-000000000001"
        assert not acc.is_revoked(cred_id)
        acc.revoke(cred_id)
        assert acc.is_revoked(cred_id)
        assert acc.revocation_count == 1

    def test_revoke_empty_id_raises(self) -> None:
        """Revoking an empty string must raise IdentityError."""
        acc = RevocationAccumulator()
        with pytest.raises(IdentityError):
            acc.revoke("")

    def test_revoke_is_idempotent(self) -> None:
        """Revoking the same credential twice must not increase the count."""
        acc = RevocationAccumulator()
        acc.revoke("dup-cred-id")
        acc.revoke("dup-cred-id")
        assert acc.revocation_count == 1

    def test_multiple_revocations(self) -> None:
        """Multiple different credentials can be revoked independently."""
        acc = RevocationAccumulator()
        ids = [f"cred-{i}" for i in range(5)]
        for cid in ids:
            acc.revoke(cid)
        assert acc.revocation_count == 5
        for cid in ids:
            assert acc.is_revoked(cid)
        assert not acc.is_revoked("not-in-set")

    def test_root_changes_when_credential_added(self) -> None:
        """Merkle root must differ before and after a revocation."""
        acc = RevocationAccumulator()
        root_before = acc.build_root()
        acc.revoke("new-cred-id")
        root_after = acc.build_root()
        assert root_before != root_after

    def test_root_is_deterministic_regardless_of_insertion_order(self) -> None:
        """The Merkle root must be identical regardless of revocation order."""
        ids = ["alpha", "beta", "gamma", "delta"]
        acc1 = RevocationAccumulator()
        for cid in ids:
            acc1.revoke(cid)

        acc2 = RevocationAccumulator()
        for cid in reversed(ids):
            acc2.revoke(cid)

        assert acc1.build_root() == acc2.build_root()

    # ── Signed root ───────────────────────────────────────────────────────────

    def test_signed_root_verifies(self, config: Config) -> None:
        """commit() must produce a root whose signature verifies correctly."""
        from src.crypto.signatures import DilithiumSigner

        signer = DilithiumSigner(config)
        issuer = IdentityKeyPair.generate(config)
        acc = RevocationAccumulator()
        acc.revoke("cred-abc")

        signed_root = acc.commit(issuer.sig_keypair.sign_key, signer, issuer.identity_id)
        assert signed_root.revocation_count == 1
        assert signed_root.issuer_id == issuer.identity_id
        assert signed_root.verify_signature(issuer.sig_keypair.verify_key, signer)

    def test_signed_root_tampered_signature_fails(self, config: Config) -> None:
        """A one-byte flip in the signature must fail verify_signature()."""
        from src.crypto.signatures import DilithiumSigner

        signer = DilithiumSigner(config)
        issuer = IdentityKeyPair.generate(config)
        acc = RevocationAccumulator()
        acc.revoke("cred-xyz")

        signed_root = acc.commit(issuer.sig_keypair.sign_key, signer, issuer.identity_id)
        # Flip one byte of the signature
        bad_sig = bytes([signed_root.signature[0] ^ 0xFF]) + signed_root.signature[1:]
        tampered = SignedRevocationRoot(
            accumulator_root=signed_root.accumulator_root,
            signature=bad_sig,
            sig_algorithm=signed_root.sig_algorithm,
            issuer_id=signed_root.issuer_id,
            revocation_count=signed_root.revocation_count,
        )
        assert not tampered.verify_signature(issuer.sig_keypair.verify_key, signer)

    def test_signed_root_wrong_key_fails(self, config: Config) -> None:
        """Verifying with a different issuer's key must fail."""
        from src.crypto.signatures import DilithiumSigner

        signer = DilithiumSigner(config)
        issuer = IdentityKeyPair.generate(config)
        other = IdentityKeyPair.generate(config)
        acc = RevocationAccumulator()
        acc.revoke("cred-1")

        signed_root = acc.commit(issuer.sig_keypair.sign_key, signer, issuer.identity_id)
        assert not signed_root.verify_signature(other.sig_keypair.verify_key, signer)

    # ── Merkle inclusion proofs ───────────────────────────────────────────────

    def test_prove_revocation_returns_valid_proof(self) -> None:
        """prove_revocation() must return a proof that verifies."""
        acc = RevocationAccumulator()
        acc.revoke("prove-me")
        proof = acc.prove_revocation("prove-me")
        assert proof is not None
        assert proof.verify()

    def test_prove_revocation_single_element_tree(self) -> None:
        """A single-entry accumulator proof must still verify correctly."""
        acc = RevocationAccumulator()
        acc.revoke("only-cred")
        proof = acc.prove_revocation("only-cred")
        assert proof is not None
        assert proof.verify()
        assert proof.accumulator_root == acc.build_root()

    def test_prove_revocation_multi_element_tree(self) -> None:
        """Proofs must hold for every element in a larger accumulator."""
        acc = RevocationAccumulator()
        ids = [f"cred-{i}" for i in range(7)]
        for cid in ids:
            acc.revoke(cid)
        for cid in ids:
            proof = acc.prove_revocation(cid)
            assert proof is not None, f"No proof for {cid}"
            assert proof.verify(), f"Proof failed for {cid}"

    def test_prove_revocation_non_revoked_returns_none(self) -> None:
        """prove_revocation() must return None for a non-revoked credential."""
        acc = RevocationAccumulator()
        acc.revoke("other-cred")
        assert acc.prove_revocation("not-revoked") is None

    def test_prove_revocation_tampered_proof_fails(self) -> None:
        """Flipping a sibling hash in the proof must cause verify() to fail."""
        acc = RevocationAccumulator()
        acc.revoke("cred-a")
        acc.revoke("cred-b")
        proof = acc.prove_revocation("cred-a")
        assert proof is not None

        if proof.siblings:
            bad_siblings = [bytes([proof.siblings[0][0] ^ 0xFF]) + proof.siblings[0][1:]]
            bad_siblings += list(proof.siblings[1:])
            tampered = RevocationProof(
                credential_id=proof.credential_id,
                siblings=bad_siblings,
                path_bits=list(proof.path_bits),
                accumulator_root=proof.accumulator_root,
            )
            assert not tampered.verify()

    def test_proof_wrong_credential_id_fails(self) -> None:
        """A proof with a wrong credential_id must fail verification."""
        acc = RevocationAccumulator()
        acc.revoke("real-cred")
        proof = acc.prove_revocation("real-cred")
        assert proof is not None

        wrong = RevocationProof(
            credential_id="other-cred",
            siblings=list(proof.siblings),
            path_bits=list(proof.path_bits),
            accumulator_root=proof.accumulator_root,
        )
        assert not wrong.verify()

    # ── Integration with ZKCredential ─────────────────────────────────────────

    def test_verify_signature_returns_false_when_revoked(self, config: Config) -> None:
        """ZKCredential.verify_signature() must return False for revoked credentials."""
        cred, _, issuer, signer = self._make_credential(config)

        acc = RevocationAccumulator()
        acc.revoke(cred.credential_id)

        # Without accumulator: signature is valid
        assert cred.verify_signature(issuer.sig_keypair.verify_key, signer)
        # With accumulator containing this credential: must return False
        assert not cred.verify_signature(
            issuer.sig_keypair.verify_key, signer, accumulator=acc
        )

    def test_verify_signature_true_when_not_in_accumulator(self, config: Config) -> None:
        """verify_signature() with an accumulator that lacks this ID must still pass."""
        cred, _, issuer, signer = self._make_credential(config)

        acc = RevocationAccumulator()
        acc.revoke("some-other-credential-id")

        assert cred.verify_signature(
            issuer.sig_keypair.verify_key, signer, accumulator=acc
        )

    # ── Serialization ─────────────────────────────────────────────────────────

    def test_accumulator_serialization_roundtrip(self) -> None:
        """to_dict() / from_dict() must preserve the full revocation set."""
        acc = RevocationAccumulator()
        ids = ["cred-1", "cred-2", "cred-3"]
        for cid in ids:
            acc.revoke(cid)

        restored = RevocationAccumulator.from_dict(acc.to_dict())
        assert restored.revocation_count == acc.revocation_count
        assert restored.build_root() == acc.build_root()
        for cid in ids:
            assert restored.is_revoked(cid)

    def test_signed_root_serialization_roundtrip(self, config: Config) -> None:
        """SignedRevocationRoot.to_dict() / from_dict() round-trip must preserve all fields."""
        from src.crypto.signatures import DilithiumSigner

        signer = DilithiumSigner(config)
        issuer = IdentityKeyPair.generate(config)
        acc = RevocationAccumulator()
        acc.revoke("sr-cred")

        signed_root = acc.commit(issuer.sig_keypair.sign_key, signer, issuer.identity_id)
        restored = SignedRevocationRoot.from_dict(signed_root.to_dict())

        assert restored.accumulator_root == signed_root.accumulator_root
        assert restored.signature == signed_root.signature
        assert restored.issuer_id == signed_root.issuer_id
        assert restored.revocation_count == signed_root.revocation_count
        # Signature must still verify after round-trip
        assert restored.verify_signature(issuer.sig_keypair.verify_key, signer)
