"""
QSIP — Zero-Knowledge Proofs (v0.1: Schnorr-based).

Implements non-interactive Schnorr proofs (via Fiat-Shamir transform) to prove
knowledge of a blinding factor that opens a credential commitment — without
revealing the committed value or the blinding factor itself.

This is a SIMPLIFIED ZK implementation for v0.1. It proves:
  "I know a value `x` such that SHA3-256(claim || x) == commitment"
using a hash-based simulated commitment scheme.

IMPORTANT SECURITY NOTE:
    This implementation has LIMITED soundness.  Because the statement
    "SHA3-256(a || b) == commitment" involves only a hash function (no
    algebraic group), the verifier CANNOT reconstruct the Schnorr response
    equation algebraically.  The current verifier:
      1. Verifies the commitment hash is correct (trivial — it is the commitment)
      2. Verifies the challenge is correctly derived from public values (sound)
      3. Verifies the auth_tag (HMAC over public values using commitment as key)
      4. Verifies structural lengths

    Step 3 provides COMMITMENT BINDING: a valid proof for commitment A cannot
    be replayed for commitment B.  However, anyone who knows the public commitment
    CAN compute a valid auth_tag, so the proof does NOT prove knowledge of the
    opening.

    The actual security guarantee for credential issuance comes from the issuer's
    CRYSTALS-Dilithium5 signature (src/identity/credential.py), not from this
    proof system.

    Full circuit-based ZK (Groth16 / Halo2) with formal soundness proofs
    is planned for v0.2.

    # TODO(security): Replace with Halo2/Groth16 circuits in v0.2

Security properties (v0.1):
- Commitment binding: proof is uniquely tied to the specific commitment (challenge binding)
- Challenge soundness: challenge is correctly derived (Fiat-Shamir); cannot be altered
- Auth-tag: HMAC(key=commitment, msg=nonce_commitment || challenge) — prevents cross-replay
- NOT witness-sound: a cheating prover who knows only the commitment (not the opening)
  can still compute a structurally valid proof. Formal soundness requires Halo2 (v0.2).
- Quantum resistance: relies only on SHA3-256 (Grover: 128-bit security)

Usage:
    from src.identity.zk_proof import ZKProver, ZKVerifier

    prover = ZKProver()
    proof = prover.prove_commitment_opening(
        commitment=cred.claim_commitment,
        claim_value=b"user@example.com",
        blinding_factor=blinding_factor,
    )
    verifier = ZKVerifier()
    assert verifier.verify_commitment_proof(cred.claim_commitment, proof)
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from src.common.exceptions import ZKProofError

# Domain separation tags for Fiat-Shamir hash and HMAC binding
_FS_TAG_CHALLENGE = b"QSIP-ZK-v1-challenge:"
_FS_TAG_RESPONSE = b"QSIP-ZK-v1-response:"
_HMAC_AUTH_TAG = b"QSIP-ZK-v1-auth:"


@dataclass(frozen=True)
class ZKProof:
    """
    A non-interactive Schnorr-style ZK proof (v0.1 limited soundness).

    Proves knowledge of `blinding_factor` such that:
        SHA3-256(claim_value || blinding_factor) == commitment

    WITHOUT revealing `claim_value` or `blinding_factor`.

    SECURITY NOTE (v0.1): This proof provides COMMITMENT BINDING and
    CHALLENGE SOUNDNESS but NOT WITNESS SOUNDNESS.  A party who knows the
    public commitment can compute a structurally valid (auth_tag-passing)
    proof without knowing the opening.  Formal ZK soundness requires the
    Halo2 migration planned for v0.2.

    The real security guarantee for credentials is the issuer's Dilithium5
    signature on the commitment — not this proof alone.

    Attributes
    ----------
    commitment_hash : bytes
        The SHA3-256 commitment this proof is for (public input).
    nonce_commitment : bytes
        SHA3-256 of the prover's ephemeral nonce (public).
    challenge : bytes
        Fiat-Shamir challenge = SHA3-256(tag || commitment_hash || nonce_commitment).
    response : bytes
        Prover's response incorporating the secret and nonce.
    auth_tag : bytes
        HMAC(key=commitment, msg=nonce_commitment || challenge).
        Provides commitment binding: the proof is uniquely tied to this
        specific commitment and challenge; cannot be replayed for a different
        commitment.  Verifiable by anyone who holds the public commitment.
    version : int
        Proof format version.
    """

    commitment_hash: bytes
    nonce_commitment: bytes
    challenge: bytes
    response: bytes
    auth_tag: bytes
    version: int = 1

    def __repr__(self) -> str:
        return (
            f"ZKProof(version={self.version}, "
            f"commitment_hash={self.commitment_hash.hex()[:16]}..., "
            f"challenge={self.challenge.hex()[:16]}...)"
        )


class ZKProver:
    """
    Generates zero-knowledge proofs of commitment opening.

    The prover demonstrates knowledge of (claim_value, blinding_factor) such
    that SHA3-256(claim_value || blinding_factor) == commitment, without
    revealing either secret value.

    # SECURITY-REVIEW: This Schnorr simulation provides informal ZK properties
    # via hash-based commitments. For production use with formal ZK guarantees,
    # migrate to Halo2 circuits (v0.2 target).
    """

    def prove_commitment_opening(
        self,
        commitment: bytes,
        claim_value: bytes,
        blinding_factor: bytes,
    ) -> ZKProof:
        """
        Prove knowledge of (claim_value, blinding_factor) that opens `commitment`.

        Parameters
        ----------
        commitment : bytes
            The SHA3-256(claim_value || blinding_factor) commitment.
        claim_value : bytes
            The secret claim value (e.g., email address). NOT included in proof.
        blinding_factor : bytes
            The secret blinding factor from credential issuance. NOT included.

        Returns
        -------
        ZKProof
            A non-interactive proof. Safe to share publicly.

        Raises
        ------
        ZKProofError
            If the provided values don't match the commitment, or proof generation fails.
        """
        # Verify the witness is consistent before proving
        expected = hashlib.sha3_256(claim_value + blinding_factor).digest()
        if not hmac.compare_digest(expected, commitment):
            raise ZKProofError(
                "Cannot generate proof: provided claim_value and blinding_factor "
                "do not open the given commitment."
            )

        try:
            # 1. Generate ephemeral nonce (witness randomness)
            nonce = secrets.token_bytes(64)

            # 2. Nonce commitment: H(nonce)
            nonce_commitment = hashlib.sha3_256(nonce).digest()

            # 3. Fiat-Shamir challenge: H(tag || commitment || nonce_commitment)
            challenge_input = _FS_TAG_CHALLENGE + commitment + nonce_commitment
            challenge = hashlib.sha3_256(challenge_input).digest()

            # 4. Response: H(tag || nonce || challenge || H(claim_value || blinding_factor))
            #    Binds the response to both the witness and the challenge without
            #    directly exposing either.  NOTE: the verifier cannot reproduce
            #    this without knowing the nonce and witness — see module docstring
            #    for the v0.1 soundness limitation and the v0.2 Halo2 migration.
            response_input = (
                _FS_TAG_RESPONSE
                + nonce
                + challenge
                + hashlib.sha3_256(claim_value + blinding_factor).digest()
            )
            response = hashlib.sha3_256(response_input).digest()

            # 5. Auth tag: HMAC(key=commitment, msg=nonce_commitment || challenge)
            #    Commitment binding: prevents cross-replay to a different commitment.
            #    The commitment is the HMAC key; the verifier can reproduce this
            #    using the public commitment — this does NOT require witness knowledge.
            #    Security-review: this provides binding but not soundness (see docstring).
            auth_tag = hmac.new(
                commitment,
                _HMAC_AUTH_TAG + nonce_commitment + challenge,
                hashlib.sha3_256,
            ).digest()

        except ZKProofError:
            raise
        except Exception as exc:
            raise ZKProofError(f"Proof generation failed: {exc}") from exc

        return ZKProof(
            commitment_hash=commitment,
            nonce_commitment=nonce_commitment,
            challenge=challenge,
            response=response,
            auth_tag=auth_tag,
        )


class ZKVerifier:
    """
    Verifies zero-knowledge proofs of commitment opening.

    The verifier checks that the proof is internally consistent given the
    public commitment, without learning anything about the committed value.

    Note: The verifier does NOT have access to the claim_value or blinding_factor.
    It verifies only the structural consistency of the proof under the hash function.
    """

    def verify_commitment_proof(
        self,
        commitment: bytes,
        proof: ZKProof,
    ) -> bool:
        """
        Verify a ZKProof of commitment opening.

        Parameters
        ----------
        commitment : bytes
            The commitment the proof claims to open.
        proof : ZKProof
            The proof to verify.

        Returns
        -------
        bool
            True if the proof is valid; False otherwise.
        """
        if not commitment or not proof:
            return False

        # Step 1: Verify the proof claims to open this specific commitment
        if not hmac.compare_digest(proof.commitment_hash, commitment):
            return False

        try:
            # Step 2: Recompute challenge from public values (challenge soundness)
            challenge_input = _FS_TAG_CHALLENGE + commitment + proof.nonce_commitment
            expected_challenge = hashlib.sha3_256(challenge_input).digest()

            if not hmac.compare_digest(expected_challenge, proof.challenge):
                return False

            # Step 3: Verify the auth_tag — commitment binding check.
            #   auth_tag = HMAC(key=commitment, msg=tag || nonce_commitment || challenge)
            #   The verifier reproduces this using the public commitment as the HMAC key.
            #   This prevents cross-commitment replay: a valid proof for commitment A
            #   cannot be substituted for commitment B.
            #   SECURITY-REVIEW(v0.1): This is verifiable by anyone who knows the
            #   public commitment, so it does NOT prove witness knowledge.
            #   Moving to Halo2 circuit verification in v0.2 will add full soundness.
            #   TODO(security): Replace with Halo2/Groth16 circuit verification in v0.2
            expected_auth = hmac.new(
                commitment,
                _HMAC_AUTH_TAG + proof.nonce_commitment + proof.challenge,
                hashlib.sha3_256,
            ).digest()

            if not hmac.compare_digest(expected_auth, proof.auth_tag):
                return False

            # Step 4: Structural sanity checks
            return (
                len(proof.response) == 32
                and len(proof.nonce_commitment) == 32
                and len(proof.challenge) == 32
                and len(proof.auth_tag) == 32
            )

        except Exception:
            return False
