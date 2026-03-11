"""
QSIP — Digital Signatures.

Implements CRYSTALS-Dilithium (NIST FIPS 204) via the liboqs Python bindings.
Dilithium5 is used by default, providing ~256-bit post-quantum security.

Security properties:
- EUF-CMA secure under the Module Learning With Errors (MLWE) problem
- Signing key must be stored in the KeyStore — never plaintext on disk
- Verification is deterministic; `verify()` returns bool, never raises on bad sig
- Use `hmac.compare_digest` for any downstream byte-level equality checks

Approved algorithm: Dilithium5 (NIST FIPS 204, highest security level)
Dependency: oqs >= 0.9.0

Usage:
    from src.crypto.signatures import DilithiumSigner
    signer = DilithiumSigner()
    verify_key, sign_key = signer.generate_keypair()
    sig = signer.sign(b"message", sign_key)
    assert signer.verify(b"message", sig, verify_key)
"""

from __future__ import annotations

from dataclasses import dataclass

import oqs  # type: ignore[import]

from src.common.config import Config
from src.common.exceptions import QSIPCryptoError


@dataclass(frozen=True)
class SignatureKeypair:
    """
    An immutable Dilithium signature keypair.

    Attributes
    ----------
    verify_key : bytes
        Public verification key. Safe to publish openly.
    sign_key : bytes
        Private signing key. Must be stored in KeyStore. Never log or transmit.
    algorithm : str
        The signature algorithm used to generate this keypair.
    """

    verify_key: bytes
    sign_key: bytes
    algorithm: str

    def __repr__(self) -> str:
        """Never print sign_key material in repr."""
        return (
            f"SignatureKeypair(algorithm={self.algorithm!r}, "
            f"verify_key=<{len(self.verify_key)} bytes>, "
            f"sign_key=<REDACTED>)"
        )


class DilithiumSigner:
    """
    Post-Quantum digital signatures using CRYSTALS-Dilithium.

    Wraps liboqs `oqs.Signature` to provide a clean, type-safe signing and
    verification API. The algorithm is configured via QSIP_SIG_ALGORITHM.

    Security:
    - The sign_key MUST never leave the KeyStore in plaintext.
    - Signature verification failures return False rather than raising, to avoid
      oracle attacks. Check the return value — do not catch exceptions as a proxy.
    - Dilithium5 signatures are ~4595 bytes; account for this in protocol buffers.

    Parameters
    ----------
    config : Config
        QSIP configuration instance. Algorithm read from config.sig_algorithm.
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()
        self._algorithm = self._config.sig_algorithm
        self._validate_algorithm()

    def _validate_algorithm(self) -> None:
        """Verify the algorithm is supported by the installed liboqs version."""
        supported = oqs.get_enabled_sig_mechanisms()
        if self._algorithm not in supported:
            raise QSIPCryptoError(
                f"Signature algorithm '{self._algorithm}' is not supported by the "
                f"installed liboqs version. "
                f"Supported algorithms: {sorted(supported)}"
            )

    def generate_keypair(self) -> SignatureKeypair:
        """
        Generate a new Dilithium keypair.

        Returns
        -------
        SignatureKeypair
            A new immutable signature keypair. The sign_key must be stored
            securely via the KeyStore — never in plaintext.

        Raises
        ------
        QSIPCryptoError
            If keypair generation fails.
        """
        try:
            with oqs.Signature(self._algorithm) as signer:
                verify_key: bytes = signer.generate_keypair()
                sign_key: bytes = signer.export_secret_key()
        except Exception as exc:
            raise QSIPCryptoError(
                f"Dilithium keypair generation failed for '{self._algorithm}': {exc}"
            ) from exc

        return SignatureKeypair(
            verify_key=verify_key,
            sign_key=sign_key,
            algorithm=self._algorithm,
        )

    def sign(self, message: bytes, sign_key: bytes) -> bytes:
        """
        Sign a message with a Dilithium signing key.

        Parameters
        ----------
        message : bytes
            The message to sign. Should be a digest or commitment in large
            message scenarios, not raw data.
        sign_key : bytes
            The Dilithium private signing key.

        Returns
        -------
        bytes
            The Dilithium signature (~4595 bytes for Dilithium5).

        Raises
        ------
        QSIPCryptoError
            If signing fails.
        """
        if not message:
            raise QSIPCryptoError("message must not be empty.")
        if not sign_key:
            raise QSIPCryptoError("sign_key must not be empty.")

        try:
            with oqs.Signature(self._algorithm, secret_key=sign_key) as signer:
                signature: bytes = signer.sign(message)
        except Exception as exc:
            # SECURITY: Never include sign_key or message content in error
            raise QSIPCryptoError(
                f"Dilithium signing failed: {exc}"
            ) from exc

        return signature

    def verify(self, message: bytes, signature: bytes, verify_key: bytes) -> bool:
        """
        Verify a Dilithium signature.

        This method returns False for any verification failure rather than
        raising an exception. ALWAYS check the return value.

        Parameters
        ----------
        message : bytes
            The original message.
        signature : bytes
            The signature to verify.
        verify_key : bytes
            The signer's Dilithium public verification key.

        Returns
        -------
        bool
            True if the signature is valid; False otherwise.
        """
        if not message or not signature or not verify_key:
            return False

        try:
            with oqs.Signature(self._algorithm) as verifier:
                return bool(verifier.verify(message, signature, verify_key))
        except Exception:
            # Any library-level exception means verification failed
            return False

    @property
    def algorithm(self) -> str:
        """Return the configured signature algorithm name."""
        return self._algorithm

    def __repr__(self) -> str:
        return f"DilithiumSigner(algorithm={self._algorithm!r})"
