"""
QSIP — Verifiable Credentials (ZKCredential).

A ZKCredential represents a cryptographically signed claim about an identity
attribute (e.g., "this identity is over 18", "holds a valid domain certificate").

The claim value is committed to using a Pedersen-style commitment:
    commitment = SHA3-256(claim_value || blinding_factor)
The actual value is never included in the credential; only the commitment.
This allows a holder to prove possession of the claim without revealing the value.

The credential is signed by an issuer using their Dilithium5 key.

Security properties:
- Claim values are never stored; only SHA3-256(value || blinding_factor) commitments
- Blinding factors are cryptographically random (secrets.token_bytes)
- Issuer signatures use Dilithium5 (post-quantum)
- Credential IDs are UUIDs (no enumeration)

Usage:
    from src.identity.credential import ZKCredential, CredentialType
    cred = ZKCredential.issue(
        subject_id="did:qsip:abc123",
        claim_type=CredentialType.EMAIL_OWNERSHIP,
        claim_value=b"user@example.com",
        issuer_keypair=issuer_identity,
        signer=DilithiumSigner(config),
    )
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from uuid import uuid4

from src.common.exceptions import IdentityError, QSIPCryptoError
from src.crypto.signatures import DilithiumSigner


class CredentialType(str, Enum):
    """Supported verifiable credential claim types."""
    EMAIL_OWNERSHIP = "EmailOwnership"
    DOMAIN_OWNERSHIP = "DomainOwnership"
    AGE_OVER_18 = "AgeOver18"
    CITIZENSHIP = "Citizenship"
    DEVELOPER_IDENTITY = "DeveloperIdentity"
    CUSTOM = "Custom"


@dataclass(frozen=True)
class ZKCredential:
    """
    A post-quantum verifiable credential with hidden claim value.

    The credential contains:
    - A public commitment to the claim value (not the value itself)
    - Metadata: subject, issuer, type, validity period
    - An issuer Dilithium5 signature over the whole structure

    Security:
    - The `blinding_factor` must never be stored alongside the credential;
      it is needed only to open/prove the commitment.
    - The issuer's signing key must be Dilithium5.

    Attributes
    ----------
    credential_id : str
        Public UUID for this credential.
    subject_id : str
        DID or identity ID of the credential subject.
    issuer_id : str
        DID or identity ID of the credential issuer.
    claim_type : CredentialType
        The type of claim being made.
    claim_commitment : bytes
        SHA3-256(claim_value || blinding_factor) — the committed claim.
    issued_at : datetime
        UTC issuance time.
    expires_at : datetime
        UTC expiry time.
    issuer_signature : bytes
        Dilithium5 signature over the canonical credential bytes.
    sig_algorithm : str
        Signature algorithm used by the issuer.
    """

    credential_id: str
    subject_id: str
    issuer_id: str
    claim_type: CredentialType
    claim_commitment: bytes
    issued_at: datetime
    expires_at: datetime
    issuer_signature: bytes
    sig_algorithm: str

    @classmethod
    def issue(
        cls,
        subject_id: str,
        claim_type: CredentialType,
        claim_value: bytes,
        issuer_id: str,
        issuer_sign_key: bytes,
        signer: DilithiumSigner,
        validity_days: int = 365,
    ) -> tuple["ZKCredential", bytes]:
        """
        Issue a new verifiable credential.

        Parameters
        ----------
        subject_id : str
            The identity ID of the credential subject.
        claim_type : CredentialType
            The type of claim.
        claim_value : bytes
            The actual claim value (e.g., b"user@example.com").
            This is committed to and never stored in the credential.
        issuer_id : str
            The identity ID of the issuer.
        issuer_sign_key : bytes
            The issuer's Dilithium signing key.
        signer : DilithiumSigner
            Configured Dilithium signer.
        validity_days : int
            Credential validity period in days (default: 365).

        Returns
        -------
        tuple[ZKCredential, bytes]
            (credential, blinding_factor)
            The blinding_factor is needed to prove the commitment later.
            Store it SEPARATELY and SECURELY from the credential.
            NEVER log the blinding_factor.

        Raises
        ------
        IdentityError
            If credential issuance fails.
        """
        if not claim_value:
            raise IdentityError("claim_value must not be empty.")
        if not issuer_sign_key:
            raise IdentityError("issuer_sign_key must not be empty.")

        try:
            blinding_factor = secrets.token_bytes(32)
            commitment = cls._compute_commitment(claim_value, blinding_factor)

            now = datetime.now(tz=timezone.utc)
            expires = now + timedelta(days=validity_days)
            cred_id = str(uuid4())

            # Canonical bytes to sign (deterministic, no floating-point ambiguity)
            signable = cls._canonical_bytes(
                credential_id=cred_id,
                subject_id=subject_id,
                issuer_id=issuer_id,
                claim_type=claim_type.value,
                claim_commitment=commitment,
                issued_at=now.isoformat(),
                expires_at=expires.isoformat(),
            )

            try:
                signature = signer.sign(signable, issuer_sign_key)
            except QSIPCryptoError as exc:
                raise IdentityError(f"Credential signing failed: {exc}") from exc

            cred = cls(
                credential_id=cred_id,
                subject_id=subject_id,
                issuer_id=issuer_id,
                claim_type=claim_type,
                claim_commitment=commitment,
                issued_at=now,
                expires_at=expires,
                issuer_signature=signature,
                sig_algorithm=signer.algorithm,
            )
        except IdentityError:
            raise
        except Exception as exc:
            raise IdentityError(f"Credential issuance failed: {exc}") from exc

        return cred, blinding_factor

    def verify_signature(self, issuer_verify_key: bytes, signer: DilithiumSigner) -> bool:
        """
        Verify the issuer's signature on this credential.

        Parameters
        ----------
        issuer_verify_key : bytes
            The issuer's Dilithium verification key.
        signer : DilithiumSigner
            Configured Dilithium signer.

        Returns
        -------
        bool
            True if signature is valid and credential is not expired.
        """
        if self.is_expired():
            return False

        signable = self._canonical_bytes(
            credential_id=self.credential_id,
            subject_id=self.subject_id,
            issuer_id=self.issuer_id,
            claim_type=self.claim_type.value,
            claim_commitment=self.claim_commitment,
            issued_at=self.issued_at.isoformat(),
            expires_at=self.expires_at.isoformat(),
        )
        return signer.verify(signable, self.issuer_signature, issuer_verify_key)

    def verify_claim(self, claim_value: bytes, blinding_factor: bytes) -> bool:
        """
        Verify that a claim_value opens the stored commitment.

        Used by the holder (or auditor with both values) to confirm the
        credential commits to a specific value.

        Parameters
        ----------
        claim_value : bytes
            The original claim value.
        blinding_factor : bytes
            The random blinding factor used during issuance.

        Returns
        -------
        bool
            True if SHA3-256(claim_value || blinding_factor) == commitment.
        """
        expected = self._compute_commitment(claim_value, blinding_factor)
        # Constant-time comparison
        import hmac as _hmac
        return _hmac.compare_digest(expected, self.claim_commitment)

    def is_expired(self) -> bool:
        """Return True if the credential has passed its expiry date."""
        return datetime.now(tz=timezone.utc) > self.expires_at

    def to_dict(self) -> dict[str, object]:
        """Serialize to a public JSON-safe dict (no secrets)."""
        from base64 import b64encode
        return {
            "credential_id": self.credential_id,
            "subject_id": self.subject_id,
            "issuer_id": self.issuer_id,
            "claim_type": self.claim_type.value,
            "claim_commitment": b64encode(self.claim_commitment).decode(),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "issuer_signature": b64encode(self.issuer_signature).decode(),
            "sig_algorithm": self.sig_algorithm,
        }

    @staticmethod
    def _compute_commitment(claim_value: bytes, blinding_factor: bytes) -> bytes:
        """Compute SHA3-256(claim_value || blinding_factor)."""
        return hashlib.sha3_256(claim_value + blinding_factor).digest()

    @staticmethod
    def _canonical_bytes(**fields: str | bytes) -> bytes:
        """Produce deterministic canonical bytes for signing."""
        parts = [
            f"{k}={v.hex() if isinstance(v, bytes) else v}"
            for k, v in sorted(fields.items())
        ]
        return "\n".join(parts).encode("utf-8")
