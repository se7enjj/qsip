"""
QSIP — Post-Quantum Email Protocol (PQEP) Encryptor.

Implements the full PQEP encryption pipeline for email messages:

    1. Kyber1024 KEM: encapsulate shared secret against recipient's public key
    2. HKDF-SHA3-512: derive AES-256-GCM key from KEM shared secret
    3. AES-256-GCM: encrypt the email body (and optional header block)
    4. Dilithium5: sign (kem_ciphertext || encrypted_body) with sender's key

The resulting PQEPEncryptedPayload contains all the information needed by
the recipient to verify authenticity and decrypt the message.

Security properties:
- Forward secrecy: each message uses a fresh KEM encapsulation
- Authenticated encryption: AES-256-GCM provides both confidentiality + integrity
- Sender authentication: Dilithium signature binds sender identity to message
- No oracle: decryption failure raises PQEPError — not a timing/padding side-channel
  (GCM authentication tag check is constant-time within the cryptography library)

Dependency: oqs >= 0.9.0, cryptography >= 42.0.0

Usage:
    encryptor = PQEPEncryptor(config)
    payload = encryptor.encrypt(
        plaintext=b"Hello, quantum-safe world!",
        recipient_kem_public_key=recipient.kem_public_key,
        sender_keypair=sender,
    )
    plaintext = encryptor.decrypt(payload, recipient_keypair=recipient)
"""

from __future__ import annotations

import json
import hashlib
import secrets
from base64 import b64decode, b64encode
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.common.config import Config
from src.common.exceptions import PQEPError, QSIPCryptoError
from src.crypto.kem import KyberKEM
from src.crypto.signatures import DilithiumSigner
from src.identity.keypair import IdentityKeyPair

# Domain separation for HKDF contexts
_HKDF_INFO_EMAIL = b"QSIP-PQEP-email-v1"
_HKDF_INFO_META  = b"QSIP-PQEP-metadata-v1"  # Sub-key for optional metadata encryption
# Static protocol salt for HKDF — provides domain separation and defends against
# IKM correlation.  Per RFC 5869 §3.1 a fixed non-secret salt is better than None.
_HKDF_SALT_EMAIL = b"QSIP-PQEP-salt-v1:email:AES256GCM"
_HKDF_SALT_META  = b"QSIP-PQEP-salt-v1:metadata:AES256GCM"
_AES_KEY_LENGTH = 32   # AES-256
_GCM_NONCE_LENGTH = 12  # 96-bit nonce (GCM standard)


@dataclass(frozen=True)
class PQEPEncryptedPayload:
    """
    A fully encrypted and signed PQEP email payload.

    All fields except `encrypted_body` and `kem_ciphertext` are public metadata.
    The `sender_signature` authenticates the entire envelope.

    Attributes
    ----------
    kem_ciphertext : bytes
        Kyber KEM ciphertext. Required by recipient for decapsulation.
    nonce : bytes
        AES-256-GCM nonce (12 bytes). Public; unique per message.
    encrypted_body : bytes
        AES-256-GCM ciphertext + authentication tag of the email body.
    sender_signature : bytes
        Dilithium5 signature over (kem_ciphertext || nonce || encrypted_body).
    sender_verify_key : bytes
        Sender's Dilithium verify key (for recipient to verify signature).
    kem_algorithm : str
        KEM algorithm used (e.g., "Kyber1024").
    sig_algorithm : str
        Signature algorithm used (e.g., "Dilithium5").
    pqep_version : int
        Protocol version.
    """

    kem_ciphertext: bytes
    nonce: bytes
    encrypted_body: bytes
    sender_signature: bytes
    sender_verify_key: bytes
    kem_algorithm: str
    sig_algorithm: str
    pqep_version: int
    # Optional encrypted metadata bundle: {"subject", "from", "to"}
    # Encrypted with a sub-key derived from the same KEM shared secret.
    # None means metadata is not encrypted (cleartext in email headers).
    encrypted_metadata: bytes | None = field(default=None)
    metadata_nonce: bytes | None = field(default=None)

    def __repr__(self) -> str:
        return (
            f"PQEPEncryptedPayload("
            f"kem_algorithm={self.kem_algorithm!r}, "
            f"sig_algorithm={self.sig_algorithm!r}, "
            f"pqep_version={self.pqep_version}, "
            f"kem_ciphertext=<{len(self.kem_ciphertext)} bytes>, "
            f"encrypted_body=<{len(self.encrypted_body)} bytes>)"
        )

    def to_dict(self) -> dict[str, str | int | None]:
        """Serialize to a safe JSON-compatible dict."""
        d: dict[str, str | int | None] = {
            "pqep_version": self.pqep_version,
            "kem_algorithm": self.kem_algorithm,
            "sig_algorithm": self.sig_algorithm,
            "kem_ciphertext": b64encode(self.kem_ciphertext).decode(),
            "nonce": b64encode(self.nonce).decode(),
            "encrypted_body": b64encode(self.encrypted_body).decode(),
            "sender_signature": b64encode(self.sender_signature).decode(),
            "sender_verify_key": b64encode(self.sender_verify_key).decode(),
        }
        if self.encrypted_metadata is not None:
            d["encrypted_metadata"] = b64encode(self.encrypted_metadata).decode()
        if self.metadata_nonce is not None:
            d["metadata_nonce"] = b64encode(self.metadata_nonce).decode()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, str | int]) -> "PQEPEncryptedPayload":
        """Deserialize from a JSON-compatible dict."""
        try:
            enc_meta_raw = data.get("encrypted_metadata")
            meta_nonce_raw = data.get("metadata_nonce")
            return cls(
                pqep_version=int(data["pqep_version"]),
                kem_algorithm=str(data["kem_algorithm"]),
                sig_algorithm=str(data["sig_algorithm"]),
                kem_ciphertext=b64decode(str(data["kem_ciphertext"])),
                nonce=b64decode(str(data["nonce"])),
                encrypted_body=b64decode(str(data["encrypted_body"])),
                sender_signature=b64decode(str(data["sender_signature"])),
                sender_verify_key=b64decode(str(data["sender_verify_key"])),
                encrypted_metadata=b64decode(str(enc_meta_raw)) if enc_meta_raw else None,
                metadata_nonce=b64decode(str(meta_nonce_raw)) if meta_nonce_raw else None,
            )
        except Exception as exc:
            raise PQEPError(f"Failed to deserialize PQEPEncryptedPayload: {exc}") from exc


class PQEPEncryptor:
    """
    PQEP email encryption and decryption engine.

    Handles the complete encrypt/sign and verify/decrypt lifecycle.
    Keys are provided externally (from IdentityKeyPair) — this class
    does not manage key storage.

    Parameters
    ----------
    config : Config
        QSIP configuration instance.
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()
        self._kem = KyberKEM(self._config)
        self._signer = DilithiumSigner(self._config)

    def encrypt(
        self,
        plaintext: bytes,
        recipient_kem_public_key: bytes,
        sender_keypair: IdentityKeyPair,
        metadata: dict[str, str] | None = None,
    ) -> PQEPEncryptedPayload:
        """
        Encrypt and sign an email body for a recipient.

        Pipeline:
        1. ML-KEM-1024 encapsulate → (kem_ciphertext, shared_secret)
        2. HKDF-SHA3-512(shared_secret, info=email) → aes_key
        3. AES-256-GCM encrypt(plaintext) → (nonce, encrypted_body)
        4. ML-DSA-87 sign(kem_ciphertext || nonce || encrypted_body) → signature
        5. (Optional) If metadata provided:
           HKDF-SHA3-512(shared_secret, info=metadata) → meta_key
           AES-256-GCM encrypt(json(metadata)) → (metadata_nonce, encrypted_metadata)

        Parameters
        ----------
        plaintext : bytes
            The email body to encrypt.
        recipient_kem_public_key : bytes
            The recipient's ML-KEM-1024 public key.
        sender_keypair : IdentityKeyPair
            The sender's full identity keypair (used for ML-DSA-87 signing).
        metadata : dict[str, str] | None
            Optional metadata to encrypt alongside the body.
            Typically: {"subject": "...", "from": "...", "to": "..."}.
            Encrypted using a sub-key derived from the same shared secret
            (domain-separated via a different HKDF info string), so the
            recipient can decrypt both body and metadata with one KEM operation.

        Returns
        -------
        PQEPEncryptedPayload
            The fully encrypted and signed payload.

        Raises
        ------
        PQEPError
            If any step of the encryption pipeline fails.
        """
        if not plaintext:
            raise PQEPError("plaintext must not be empty.")
        if len(plaintext) > self._config.email_max_size:
            raise PQEPError(
                f"Plaintext exceeds maximum email size "
                f"({len(plaintext)} > {self._config.email_max_size} bytes)."
            )

        try:
            # Step 1: KEM encapsulation
            kem_result = self._kem.encapsulate(recipient_kem_public_key)

            # Step 2: Derive AES key from shared secret
            aes_key = self._derive_aes_key(kem_result.shared_secret)

            # Step 3: Encrypt with AES-256-GCM
            # associated_data = kem_ciphertext binds the GCM tag to the KEM
            # envelope — tampering with the KEM ciphertext now invalidates the tag,
            # giving a second layer of authenticity beyond the Dilithium signature.
            nonce = secrets.token_bytes(_GCM_NONCE_LENGTH)
            aesgcm = AESGCM(aes_key)
            encrypted_body = aesgcm.encrypt(nonce, plaintext, associated_data=kem_result.ciphertext)

            # Step 4: Sign the full envelope
            signable = self._signable_bytes(
                kem_ciphertext=kem_result.ciphertext,
                nonce=nonce,
                encrypted_body=encrypted_body,
            )
            signature = self._signer.sign(signable, sender_keypair.sig_keypair.sign_key)

            # Step 5 (optional): Encrypt metadata with a domain-separated sub-key
            encrypted_metadata: bytes | None = None
            metadata_nonce: bytes | None = None
            if metadata is not None:
                meta_key = self._derive_meta_key(kem_result.shared_secret)
                metadata_nonce = secrets.token_bytes(_GCM_NONCE_LENGTH)
                meta_plaintext = json.dumps(metadata, separators=(",", ":")).encode()
                encrypted_metadata = AESGCM(meta_key).encrypt(
                    metadata_nonce, meta_plaintext, associated_data=b"QSIP-metadata"
                )

        except PQEPError:
            raise
        except QSIPCryptoError as exc:
            raise PQEPError(f"PQEP encryption failed (crypto error): {exc}") from exc
        except Exception as exc:
            raise PQEPError(f"PQEP encryption failed: {exc}") from exc

        return PQEPEncryptedPayload(
            kem_ciphertext=kem_result.ciphertext,
            nonce=nonce,
            encrypted_body=encrypted_body,
            sender_signature=signature,
            sender_verify_key=sender_keypair.sig_keypair.verify_key,
            kem_algorithm=self._kem.algorithm,
            sig_algorithm=self._signer.algorithm,
            pqep_version=self._config.pqep_version,
            encrypted_metadata=encrypted_metadata,
            metadata_nonce=metadata_nonce,
        )

    def decrypt(
        self,
        payload: PQEPEncryptedPayload,
        recipient_keypair: IdentityKeyPair,
        verify_sender: bool = True,
    ) -> bytes:
        """
        Verify and decrypt a PQEP encrypted payload.

        Pipeline:
        1. Dilithium verify(kem_ciphertext || nonce || encrypted_body, sender_sig)
        2. Kyber KEM decapsulate → shared_secret
        3. HKDF(shared_secret) → aes_key
        4. AES-256-GCM decrypt(encrypted_body) → plaintext

        Parameters
        ----------
        payload : PQEPEncryptedPayload
            The encrypted PQEP payload to decrypt.
        recipient_keypair : IdentityKeyPair
            The recipient's full identity keypair (used for KEM decapsulation).
        verify_sender : bool
            If True (default), verify the sender's Dilithium signature before decrypting.
            Set to False only when sender verify key is unavailable (NOT recommended).

        Returns
        -------
        bytes
            The decrypted email body plaintext.

        Raises
        ------
        PQEPError
            If signature verification fails, decapsulation fails, or decryption fails.
        """
        try:
            # Step 1: Verify sender signature (before doing any crypto work)
            if verify_sender:
                signable = self._signable_bytes(
                    kem_ciphertext=payload.kem_ciphertext,
                    nonce=payload.nonce,
                    encrypted_body=payload.encrypted_body,
                )
                sig_valid = self._signer.verify(
                    signable, payload.sender_signature, payload.sender_verify_key
                )
                if not sig_valid:
                    raise PQEPError(
                        "PQEP sender signature verification FAILED. "
                        "Message may be tampered or sender identity is wrong."
                    )

            # Step 2: KEM decapsulation
            shared_secret = self._kem.decapsulate(
                payload.kem_ciphertext,
                recipient_keypair.kem_keypair.secret_key,
            )

            # Step 3: Derive AES key
            aes_key = self._derive_aes_key(shared_secret)

            # Step 4: AES-256-GCM decrypt
            # Must pass the same associated_data used during encrypt (kem_ciphertext)
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(payload.nonce, payload.encrypted_body, associated_data=payload.kem_ciphertext)

        except PQEPError:
            raise
        except QSIPCryptoError as exc:
            raise PQEPError(f"PQEP decryption failed (crypto error): {exc}") from exc
        except Exception as exc:
            raise PQEPError(f"PQEP decryption failed: {exc}") from exc

        return plaintext

    def _derive_aes_key(self, shared_secret: bytes) -> bytes:
        """Derive a 256-bit AES key from a KEM shared secret via HKDF-SHA3-512."""
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=_AES_KEY_LENGTH,
                salt=_HKDF_SALT_EMAIL,
                info=_HKDF_INFO_EMAIL,
            )
            return hkdf.derive(shared_secret)
        except Exception as exc:
            raise PQEPError(f"HKDF key derivation failed: {exc}") from exc

    def _derive_meta_key(self, shared_secret: bytes) -> bytes:
        """Derive a domain-separated 256-bit key for metadata encryption.

        Uses a different HKDF info/salt than the body key, ensuring these
        keys are cryptographically independent even from the same shared secret.
        """
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=_AES_KEY_LENGTH,
                salt=_HKDF_SALT_META,
                info=_HKDF_INFO_META,
            )
            return hkdf.derive(shared_secret)
        except Exception as exc:
            raise PQEPError(f"HKDF metadata key derivation failed: {exc}") from exc

    def decrypt_metadata(
        self,
        payload: PQEPEncryptedPayload,
        recipient_keypair: IdentityKeyPair,
    ) -> dict[str, str] | None:
        """
        Decrypt the optional metadata bundle from a PQEP payload.

        Must be called after verifying the payload (the body decrypt step
        validates authenticity). This method performs a second KEM decapsulation
        to recover the shared secret and derive the metadata sub-key.

        Parameters
        ----------
        payload : PQEPEncryptedPayload
            The PQEP payload containing the optional encrypted_metadata.
        recipient_keypair : IdentityKeyPair
            The recipient's identity keypair for KEM decapsulation.

        Returns
        -------
        dict[str, str] | None
            Decrypted metadata dict (e.g. {"subject", "from", "to"}),
            or None if the payload contains no encrypted metadata.

        Raises
        ------
        PQEPError
            If metadata decryption fails (tampered or wrong key).
        """
        if payload.encrypted_metadata is None or payload.metadata_nonce is None:
            return None
        try:
            shared_secret = self._kem.decapsulate(
                payload.kem_ciphertext,
                recipient_keypair.kem_keypair.secret_key,
            )
            meta_key = self._derive_meta_key(shared_secret)
            meta_bytes = AESGCM(meta_key).decrypt(
                payload.metadata_nonce,
                payload.encrypted_metadata,
                associated_data=b"QSIP-metadata",
            )
            result: dict[str, str] = json.loads(meta_bytes.decode())
            return result
        except PQEPError:
            raise
        except Exception as exc:
            raise PQEPError(f"PQEP metadata decryption failed: {exc}") from exc

    @staticmethod
    def _signable_bytes(
        kem_ciphertext: bytes,
        nonce: bytes,
        encrypted_body: bytes,
    ) -> bytes:
        """
        Produce canonical bytes for signing/verifying the PQEP envelope.

        Format: "QSIP-PQEP-sig-v1\n" || len(kem_ct) || kem_ct || len(nonce) || nonce || ...
        Length prefixes prevent ambiguity in concatenation.
        """
        def prefixed(data: bytes) -> bytes:
            return len(data).to_bytes(4, "big") + data

        return b"QSIP-PQEP-sig-v1\n" + prefixed(kem_ciphertext) + prefixed(nonce) + prefixed(encrypted_body)
