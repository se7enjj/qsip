"""
QSIP — Hybrid Classical + Post-Quantum KEM.

Combines X25519 (classical Diffie-Hellman) with CRYSTALS-Kyber (PQC KEM) using
HKDF-SHA3-512 to combine the two shared secrets. The resulting combined secret
is secure if **either** of the underlying algorithms remains unbroken.

This follows the hybrid approach from IETF draft-ietf-tls-hybrid-design and
NIST guidance on PQC migration. It is the default key establishment mechanism
in QSIP until full PQC deployment is widespread (Hybrid mode on by default
via QSIP_HYBRID_MODE=true).

Security properties:
- CLASSICAL component: X25519 (secure against classical adversaries)
- PQC component: Kyber1024 (secure against quantum adversaries)
- COMBINER: HKDF-SHA3-512 — concatenation combiner, secure per [GHP18]
- Final output: 32-byte AES-256-compatible key material
- A quantum adversary must break BOTH algorithms to recover the secret

Reference: Giacon et al., "KEM Combiners", PKC 2018 [GHP18]

Usage:
    from src.crypto.hybrid import HybridKEM
    kem = HybridKEM()
    # Sender:
    result = kem.encapsulate(recipient_kyber_pk, recipient_x25519_pk)
    # Recipient:
    key_material = kem.decapsulate(result.kyber_ct, result.x25519_ephemeral_pk, sk_kyber, sk_x25519)
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.common.config import Config
from src.common.exceptions import QSIPCryptoError
from src.crypto.kem import KyberKEM

# KDF parameters
_HKDF_HASH = hashes.SHA3_512()
_OUTPUT_KEY_LENGTH = 32  # 256 bits — AES-256 compatible

# Domain separation string ensures the KDF output is unique to QSIP hybrid mode
_HKDF_INFO = b"QSIP-HybridKEM-v1"
# Static protocol salt per RFC 5869 §3.1: using a non-secret salt is better than
# None (which is equivalent to a zero-byte key) and provides domain separation
# between QSIP hybrid mode and any other usage of the same IKM.
_HKDF_SALT = b"QSIP-HybridKEM-salt-v1:X25519+Kyber1024"


@dataclass(frozen=True)
class HybridEncapsulationResult:
    """
    Result of a hybrid KEM encapsulation.

    All fields except `key_material` are safe to transmit to the recipient.
    The `key_material` is the final combined key and MUST NOT be transmitted.

    Attributes
    ----------
    kyber_ciphertext : bytes
        Kyber KEM ciphertext — send to recipient.
    x25519_ephemeral_public_key : bytes
        Ephemeral X25519 public key — send to recipient.
    key_material : bytes
        Final 32-byte combined key material. Feed to AES-256-GCM.
        NEVER transmit, log, or store.
    """

    kyber_ciphertext: bytes
    x25519_ephemeral_public_key: bytes
    key_material: bytes

    def __repr__(self) -> str:
        """Never print key_material in repr."""
        return (
            f"HybridEncapsulationResult("
            f"kyber_ciphertext=<{len(self.kyber_ciphertext)} bytes>, "
            f"x25519_ephemeral_public_key=<{len(self.x25519_ephemeral_public_key)} bytes>, "
            f"key_material=<REDACTED>)"
        )


class HybridKEM:
    """
    Hybrid Key Encapsulation combining X25519 and Kyber1024.

    When hybrid mode is enabled (default), this is the standard key establishment
    mechanism for QSIP. When QSIP_HYBRID_MODE=false, raw Kyber is used instead.

    The combiner uses HKDF-SHA3-512:
        key_material = HKDF(
            input_keying_material = kyber_ss || x25519_ss,
            info = "QSIP-HybridKEM-v1",
            length = 32
        )

    Parameters
    ----------
    config : Config
        QSIP configuration instance.
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()
        self._kyber = KyberKEM(self._config)

    def generate_keypair(self) -> tuple[bytes, bytes, bytes, bytes]:
        """
        Generate a combined Hybrid KEM keypair.

        Returns
        -------
        tuple[bytes, bytes, bytes, bytes]
            (kyber_public_key, kyber_secret_key, x25519_public_key_bytes, x25519_private_key_bytes)

        Raises
        ------
        QSIPCryptoError
            If keypair generation fails.
        """
        try:
            kyber_kp = self._kyber.generate_keypair()

            x25519_sk = X25519PrivateKey.generate()
            x25519_pk = x25519_sk.public_key()

            x25519_pk_bytes = x25519_pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            x25519_sk_bytes = x25519_sk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        except Exception as exc:
            raise QSIPCryptoError(f"Hybrid keypair generation failed: {exc}") from exc

        return (
            kyber_kp.public_key,
            kyber_kp.secret_key,
            x25519_pk_bytes,
            x25519_sk_bytes,
        )

    def encapsulate(
        self,
        recipient_kyber_public_key: bytes,
        recipient_x25519_public_key: bytes,
    ) -> HybridEncapsulationResult:
        """
        Encapsulate a shared secret using both Kyber and X25519.

        Parameters
        ----------
        recipient_kyber_public_key : bytes
            Recipient's Kyber public key.
        recipient_x25519_public_key : bytes
            Recipient's X25519 public key (32 bytes, Raw format).

        Returns
        -------
        HybridEncapsulationResult
            Contains both ciphertexts (safe to send) and the combined key_material.

        Raises
        ------
        QSIPCryptoError
            If encapsulation fails.
        """
        try:
            # Kyber encapsulation
            kyber_result = self._kyber.encapsulate(recipient_kyber_public_key)

            # X25519 ephemeral key exchange
            ephemeral_sk = X25519PrivateKey.generate()
            ephemeral_pk = ephemeral_sk.public_key()

            recipient_x25519_pk = X25519PublicKey.from_public_bytes(recipient_x25519_public_key)
            x25519_shared_secret: bytes = ephemeral_sk.exchange(recipient_x25519_pk)

            ephemeral_pk_bytes = ephemeral_pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            # Combine via HKDF — kyber_ss || x25519_ss
            key_material = self._combine_secrets(
                kyber_shared_secret=kyber_result.shared_secret,
                x25519_shared_secret=x25519_shared_secret,
            )
        except QSIPCryptoError:
            raise
        except Exception as exc:
            raise QSIPCryptoError(f"Hybrid encapsulation failed: {exc}") from exc

        return HybridEncapsulationResult(
            kyber_ciphertext=kyber_result.ciphertext,
            x25519_ephemeral_public_key=ephemeral_pk_bytes,
            key_material=key_material,
        )

    def decapsulate(
        self,
        kyber_ciphertext: bytes,
        x25519_ephemeral_public_key: bytes,
        kyber_secret_key: bytes,
        x25519_secret_key: bytes,
    ) -> bytes:
        """
        Decapsulate to recover the combined key material.

        Parameters
        ----------
        kyber_ciphertext : bytes
            The Kyber ciphertext received from the sender.
        x25519_ephemeral_public_key : bytes
            The sender's ephemeral X25519 public key.
        kyber_secret_key : bytes
            The recipient's Kyber secret key.
        x25519_secret_key : bytes
            The recipient's X25519 secret key (32 bytes, Raw format).

        Returns
        -------
        bytes
            32-byte combined key material. Use directly with AES-256-GCM.

        Raises
        ------
        QSIPCryptoError
            If decapsulation fails.
        """
        try:
            # Kyber decapsulation
            kyber_ss = self._kyber.decapsulate(kyber_ciphertext, kyber_secret_key)

            # X25519 decapsulation
            x25519_sk = X25519PrivateKey.from_private_bytes(x25519_secret_key)
            sender_ephemeral_pk = X25519PublicKey.from_public_bytes(x25519_ephemeral_public_key)
            x25519_ss: bytes = x25519_sk.exchange(sender_ephemeral_pk)

            # Combine via same HKDF
            key_material = self._combine_secrets(
                kyber_shared_secret=kyber_ss,
                x25519_shared_secret=x25519_ss,
            )
        except QSIPCryptoError:
            raise
        except Exception as exc:
            raise QSIPCryptoError(f"Hybrid decapsulation failed: {exc}") from exc

        return key_material

    def _combine_secrets(
        self,
        kyber_shared_secret: bytes,
        x25519_shared_secret: bytes,
    ) -> bytes:
        """
        Combine two shared secrets using HKDF-SHA3-512.

        The combiner concatenates both secrets as IKM to HKDF. This is secure
        per the KEM combiners analysis [GHP18]: if either component is secure,
        the combined output is secure.

        Parameters
        ----------
        kyber_shared_secret : bytes
            Shared secret from Kyber encapsulation/decapsulation.
        x25519_shared_secret : bytes
            Shared secret from X25519 key exchange.

        Returns
        -------
        bytes
            32-byte derived key material.
        """
        # Domain-separated concatenation: kyber_ss || x25519_ss
        ikm = kyber_shared_secret + x25519_shared_secret

        try:
            hkdf = HKDF(
                algorithm=_HKDF_HASH,
                length=_OUTPUT_KEY_LENGTH,
                salt=_HKDF_SALT,
                info=_HKDF_INFO,
            )
            return hkdf.derive(ikm)
        except Exception as exc:
            raise QSIPCryptoError(f"HKDF combination failed: {exc}") from exc
        finally:
            # Zero the intermediate material from local scope
            # Python doesn't guarantee memory zeroing, but we try
            del ikm

    def __repr__(self) -> str:
        return f"HybridKEM(kyber={self._kyber.algorithm!r}, x25519=X25519)"
