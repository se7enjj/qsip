"""
QSIP — Key Encapsulation Mechanism (KEM).

Implements CRYSTALS-Kyber (NIST FIPS 203) via the liboqs Python bindings.
Kyber1024 is used by default, providing ~256-bit post-quantum security.

Security properties:
- IND-CCA2 secure under the Module Learning With Errors (MLWE) problem
- No classical fallback in this module — classical keys handled in hybrid.py
- Shared secrets MUST be used as input to a KDF (HKDF) before use as keys
- This module NEVER derives final encryption keys directly; always use HKDF

Approved algorithm: Kyber1024 (highest NIST security level)
Dependency: oqs >= 0.9.0 (liboqs Python bindings)

Usage:
    from src.crypto.kem import KyberKEM
    kem = KyberKEM()
    pk, sk = kem.generate_keypair()
    ciphertext, shared_secret = kem.encapsulate(pk)
    recovered = kem.decapsulate(ciphertext, sk)
    assert recovered == shared_secret
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import oqs

from src.common.config import Config
from src.common.exceptions import QSIPCryptoError


@dataclass(frozen=True)
class KEMKeypair:
    """
    An immutable KEM keypair.

    Attributes
    ----------
    public_key : bytes
        The public key suitable for sharing. Used to encapsulate shared secrets.
    secret_key : bytes
        The secret key. Must be kept confidential and stored in the KeyStore.
    algorithm : str
        The KEM algorithm used to generate this keypair.
    """

    public_key: bytes
    secret_key: bytes
    algorithm: str

    def __repr__(self) -> str:
        """Never print secret key material in repr."""
        return (
            f"KEMKeypair(algorithm={self.algorithm!r}, "
            f"public_key=<{len(self.public_key)} bytes>, "
            f"secret_key=<REDACTED>)"
        )


@dataclass(frozen=True)
class EncapsulationResult:
    """
    Result of a KEM encapsulation operation.

    Attributes
    ----------
    ciphertext : bytes
        The KEM ciphertext. Safe to transmit publicly.
    shared_secret : bytes
        The shared secret established via encapsulation.
        MUST be passed through HKDF before use as a symmetric key.
        MUST NOT be logged or stored.
    """

    ciphertext: bytes
    shared_secret: bytes

    def __repr__(self) -> str:
        """Never print shared secret in repr."""
        return (
            f"EncapsulationResult(ciphertext=<{len(self.ciphertext)} bytes>, "
            f"shared_secret=<REDACTED>)"
        )


class KyberKEM:
    """
    Post-Quantum Key Encapsulation Mechanism using CRYSTALS-Kyber.

    Wraps liboqs `oqs.KeyEncapsulation` to provide a clean, type-safe API
    for Kyber KEM operations. The algorithm is configured via QSIP_KEM_ALGORITHM
    in the environment; hardcoding is not permitted.

    Security:
    - Shared secrets from `encapsulate()` and `decapsulate()` MUST pass through
      HKDF before being used as symmetric keys. Use `src.crypto.hybrid` or the
      PQEP encryptor for full key derivation.
    - Constant-time decapsulation is handled internally by liboqs.
    - Keypairs should be rotated per QSIP_KEY_ROTATION_DAYS in config.

    Parameters
    ----------
    config : Config
        QSIP configuration instance. Algorithm read from config.kem_algorithm.
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()
        self._algorithm = self._config.kem_algorithm
        self._validate_algorithm()

    def _validate_algorithm(self) -> None:
        """Verify the algorithm is supported by the installed liboqs version."""
        supported = oqs.get_enabled_kem_mechanisms()
        if self._algorithm not in supported:
            raise QSIPCryptoError(
                f"KEM algorithm '{self._algorithm}' is not supported by the "
                f"installed liboqs version. "
                f"Supported algorithms: {sorted(supported)}"
            )

    def generate_keypair(self) -> KEMKeypair:
        """
        Generate a new Kyber keypair.

        Returns
        -------
        KEMKeypair
            A new immutable keypair. The secret_key must be stored securely
            via the KeyStore — never in plaintext.

        Raises
        ------
        QSIPCryptoError
            If keypair generation fails.
        """
        try:
            with oqs.KeyEncapsulation(self._algorithm) as kem:
                public_key: bytes = kem.generate_keypair()
                secret_key: bytes = kem.export_secret_key()
        except Exception as exc:
            raise QSIPCryptoError(
                f"Kyber keypair generation failed for algorithm '{self._algorithm}': {exc}"
            ) from exc

        return KEMKeypair(
            public_key=public_key,
            secret_key=secret_key,
            algorithm=self._algorithm,
        )

    def encapsulate(self, public_key: bytes) -> EncapsulationResult:
        """
        Encapsulate a shared secret against a public key.

        Called by the *sender* to establish a shared secret with the holder of
        the corresponding secret key. The ciphertext is sent to the recipient;
        the shared_secret is the mutual secret.

        Parameters
        ----------
        public_key : bytes
            The recipient's Kyber public key.

        Returns
        -------
        EncapsulationResult
            `ciphertext` to send to recipient; `shared_secret` to use (via HKDF).

        Raises
        ------
        QSIPCryptoError
            If encapsulation fails (e.g. malformed public key).
        """
        if not public_key:
            raise QSIPCryptoError("public_key must not be empty.")

        try:
            with oqs.KeyEncapsulation(self._algorithm) as kem:
                ciphertext: bytes
                shared_secret: bytes
                ciphertext, shared_secret = kem.encap_secret(public_key)
        except Exception as exc:
            raise QSIPCryptoError(
                f"Kyber encapsulation failed: {exc}"
            ) from exc

        return EncapsulationResult(ciphertext=ciphertext, shared_secret=shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate a ciphertext to recover the shared secret.

        Called by the *recipient* using their secret key. Recovers the same
        shared secret the sender established during encapsulation.

        Parameters
        ----------
        ciphertext : bytes
            The KEM ciphertext received from the sender.
        secret_key : bytes
            The recipient's Kyber secret key.

        Returns
        -------
        bytes
            The recovered shared secret. MUST be passed through HKDF before use.

        Raises
        ------
        QSIPCryptoError
            If decapsulation fails (malformed ciphertext, wrong key, tampering).
        """
        if not ciphertext:
            raise QSIPCryptoError("ciphertext must not be empty.")
        if not secret_key:
            raise QSIPCryptoError("secret_key must not be empty.")

        try:
            with oqs.KeyEncapsulation(self._algorithm, secret_key=secret_key) as kem:
                shared_secret: bytes = kem.decap_secret(ciphertext)
        except Exception as exc:
            # SECURITY: Do not include ciphertext content or key details in error
            raise QSIPCryptoError(
                f"Kyber decapsulation failed — ciphertext may be malformed or tampered: {exc}"
            ) from exc

        return shared_secret

    @property
    def algorithm(self) -> str:
        """Return the configured KEM algorithm name."""
        return self._algorithm

    def __repr__(self) -> str:
        return f"KyberKEM(algorithm={self._algorithm!r})"
