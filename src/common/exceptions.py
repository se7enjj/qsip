"""
QSIP Exception Hierarchy.

All exceptions raised within QSIP derive from QSIPError.
Layer-specific exceptions provide contextual information without
leaking cryptographic material or internal state.

Security: exception messages MUST NOT contain key material, witnesses,
plaintexts, or any security-sensitive values. Sanitize before raising.
"""

from __future__ import annotations


class QSIPError(Exception):
    """
    Base exception for all QSIP errors.

    Attributes
    ----------
    message : str
        Human-readable error description (must not contain sensitive data).
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return f"[QSIP] {self.message}"


class QSIPCryptoError(QSIPError):
    """
    Raised when a cryptographic operation fails.

    Examples
    --------
    - KEM encapsulation failure
    - Signature verification failure
    - Invalid ciphertext (tampered data)
    - Nonce reuse detected
    - Unsupported algorithm requested

    Security note: Do NOT include the plaintext, key material, or shared
    secret in the error message. Use generic descriptions only.
    """


class KeystoreError(QSIPError):
    """
    Raised for keystore read/write/unlock failures.

    Examples
    --------
    - Wrong passphrase
    - Corrupted keystore file
    - Key not found
    - Permission denied
    """


class IdentityError(QSIPError):
    """
    Raised for identity layer failures.

    Examples
    --------
    - Invalid credential format
    - Credential signature verification failure
    - Unknown credential type
    - Identity registry unreachable
    """


class ZKProofError(QSIPError):
    """
    Raised for zero-knowledge proof failures.

    Examples
    --------
    - Proof verification failed
    - Malformed proof structure
    - Witness inconsistency (internal logic error)

    Security note: NEVER include witness values in this exception.
    """


class DNSValidationError(QSIPError):
    """
    Raised when PQC DNS validation fails.

    Examples
    --------
    - Missing QSIP DNS TXT record
    - PQC signature on DNS record invalid
    - DNSSEC chain broken
    - Algorithm mismatch
    """


class PQEPError(QSIPError):
    """
    Raised for Post-Quantum Email Protocol failures.

    Examples
    --------
    - Missing PQEP headers
    - KEM ciphertext malformed
    - Sender signature invalid
    - Decryption failure (wrong recipient key)
    """


class ConfigError(QSIPError):
    """
    Raised for configuration errors.

    Examples
    --------
    - Required environment variable missing
    - Invalid algorithm name in config
    - Config validation failure
    """
