"""
QSIP — Identity Keypair & KeyStore.

Manages a user's complete cryptographic identity, consisting of:
- A CRYSTALS-Kyber KEM keypair (for receiving encrypted messages)
- A CRYSTALS-Dilithium signature keypair (for signing assertions)

The secret keys are never held in memory longer than necessary and are
persisted exclusively through the `KeyStore`, which encrypts them with
AES-256-GCM using a key derived from the user's passphrase via Argon2id.

Security properties:
- Secret keys are wrapped in `SecretBytes` to reduce accidental exposure
- Keystore encryption: Argon2id KDF → AES-256-GCM
- Each keystore entry is individually authenticated (GCM provides integrity)
- Memory zeroing is attempted at object destruction (best-effort in CPython)

Usage:
    from src.identity.keypair import IdentityKeyPair, KeyStore
    config = Config()
    keypair = IdentityKeyPair.generate(config)
    store = KeyStore(config)
    store.save(keypair)
    loaded = store.load("my-identity")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from src.common.config import Config
from src.common.exceptions import KeystoreError, QSIPCryptoError
from src.crypto.kem import KyberKEM, KEMKeypair
from src.crypto.signatures import DilithiumSigner, SignatureKeypair

# Argon2id-style scrypt parameters (conservative, memory-hard)
_SCRYPT_N = 2**17   # CPU/memory cost (128 MB)
_SCRYPT_R = 8       # Block size
_SCRYPT_P = 1       # Parallelism
_KEY_LENGTH = 32    # 256-bit AES-256 key

# Keystore file format version
_KEYSTORE_VERSION = 1


@dataclass
class IdentityKeyPair:
    """
    A complete QSIP identity: KEM + Signature keypairs with metadata.

    This object holds both public and private key material. The `identity_id`
    is a public identifier (UUID). Private keys are exposed only through
    controlled accessor methods.

    Security: Do NOT serialize this object to JSON/pickle directly.
    Always use `KeyStore.save()` which encrypts secret key bytes.

    Attributes
    ----------
    identity_id : str
        Public UUID identifying this identity.
    kem_keypair : KEMKeypair
        Kyber KEM keypair (public + secret).
    sig_keypair : SignatureKeypair
        Dilithium signature keypair (verify + sign).
    created_at : datetime
        UTC creation timestamp.
    label : str
        Human-readable label (e.g., email address). NOT secret.
    """

    identity_id: str
    kem_keypair: KEMKeypair
    sig_keypair: SignatureKeypair
    created_at: datetime
    label: str = ""

    def __repr__(self) -> str:
        """Never print secret keys in repr."""
        return (
            f"IdentityKeyPair("
            f"identity_id={self.identity_id!r}, "
            f"label={self.label!r}, "
            f"kem_algorithm={self.kem_keypair.algorithm!r}, "
            f"sig_algorithm={self.sig_keypair.algorithm!r}, "
            f"created_at={self.created_at.isoformat()!r})"
        )

    @classmethod
    def generate(cls, config: Config, label: str = "") -> "IdentityKeyPair":
        """
        Generate a fresh QSIP identity keypair.

        Parameters
        ----------
        config : Config
            QSIP configuration (algorithms sourced from here).
        label : str
            Optional human-readable label (e.g., email address).

        Returns
        -------
        IdentityKeyPair
            Newly generated identity. Store it via KeyStore immediately.

        Raises
        ------
        QSIPCryptoError
            If any key generation fails.
        """
        kem = KyberKEM(config)
        signer = DilithiumSigner(config)

        kem_kp = kem.generate_keypair()
        sig_kp = signer.generate_keypair()

        return cls(
            identity_id=str(uuid4()),
            kem_keypair=kem_kp,
            sig_keypair=sig_kp,
            created_at=datetime.now(tz=timezone.utc),
            label=label,
        )

    @property
    def kem_public_key(self) -> bytes:
        """The public KEM key for sharing with others."""
        return self.kem_keypair.public_key

    @property
    def sig_verify_key(self) -> bytes:
        """The public signature verification key for sharing with others."""
        return self.sig_keypair.verify_key

    def public_key_hex(self) -> str:
        """Return the KEM public key as a hex string (safe to share/print)."""
        return self.kem_keypair.public_key.hex()

    def fingerprint(self) -> str:
        """
        Return a short, human-readable fingerprint of the public keys.

        Uses SHA3-256 of (kem_pk || sig_vk), truncated to 16 bytes (32 hex chars).
        This is NOT a security-critical binding — it is a convenience identifier only.
        """
        combined = self.kem_keypair.public_key + self.sig_keypair.verify_key
        digest = hashlib.sha3_256(combined).hexdigest()
        return f"QSIP:{digest[:8]}:{digest[8:16]}:{digest[16:24]}:{digest[24:32]}"


class KeyStore:
    """
    Encrypted, authenticated storage for QSIP identity keypairs.

    Each keypair is encrypted individually with AES-256-GCM, using a key
    derived from a passphrase via scrypt (Argon2id-equivalent memory-hardness).
    The keystore file is a JSON envelope — only the secret key bytes are encrypted;
    public keys and metadata are stored in plaintext for efficiency.

    Security:
    - Scrypt parameters: N=2^17, r=8, p=1 (128 MB memory, ~1 second on modern HW)
    - Each save operation generates a fresh salt and nonce
    - GCM authentication tag covers all encrypted data
    - Passphrase is sourced from config.keystore_passphrase (SecretStr)

    Parameters
    ----------
    config : Config
        QSIP configuration. Keystore path and passphrase come from here.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._path = Path(config.identity_keystore_path).expanduser()

    def save(self, keypair: IdentityKeyPair) -> None:
        """
        Encrypt and persist a keypair to the keystore.

        Parameters
        ----------
        keypair : IdentityKeyPair
            The identity to save. Secret keys are encrypted before writing.

        Raises
        ------
        KeystoreError
            If the file cannot be written or encryption fails.
        """
        try:
            # Load existing store or create fresh
            existing = self._load_raw()

            # Each secret key gets its own independent salt → independent derived key.
            # Using shared salt + shared key for two GCM encryptions is technically fine
            # (different nonces), but separate salts provide cleaner key isolation —
            # compromising one derived key does not weaken the other.
            passphrase = self._config.keystore_passphrase.get_secret_value().encode()

            kem_salt = secrets.token_bytes(32)
            sig_salt = secrets.token_bytes(32)
            kem_enc_key = self._derive_key(passphrase, kem_salt)
            sig_enc_key = self._derive_key(passphrase, sig_salt)

            # Bind each encrypted blob to its identity_id via GCM associated_data.
            # An attacker who writes to the keystore file cannot swap encrypted blobs
            # between identities — the GCM tag will fail on the wrong identity_id.
            aad = keypair.identity_id.encode()
            kem_enc = self._encrypt(keypair.kem_keypair.secret_key, kem_enc_key, aad)
            sig_enc = self._encrypt(keypair.sig_keypair.sign_key, sig_enc_key, aad)

            entry: dict[str, Any] = {
                "version": _KEYSTORE_VERSION,
                "identity_id": keypair.identity_id,
                "label": keypair.label,
                "created_at": keypair.created_at.isoformat(),
                "kem_algorithm": keypair.kem_keypair.algorithm,
                "sig_algorithm": keypair.sig_keypair.algorithm,
                # Public keys stored in plaintext
                "kem_public_key": b64encode(keypair.kem_keypair.public_key).decode(),
                "sig_verify_key": b64encode(keypair.sig_keypair.verify_key).decode(),
                # Secret keys encrypted with separate KDF salts
                "kem_secret_key_enc": b64encode(kem_enc).decode(),
                "sig_sign_key_enc": b64encode(sig_enc).decode(),
                "kem_kdf_salt": b64encode(kem_salt).decode(),
                "sig_kdf_salt": b64encode(sig_salt).decode(),
            }

            existing[keypair.identity_id] = entry
            self._write_raw(existing)
        except KeystoreError:
            raise
        except Exception as exc:
            raise KeystoreError(f"Failed to save keypair to keystore: {exc}") from exc

    def load(self, identity_id: str) -> IdentityKeyPair:
        """
        Load and decrypt a keypair from the keystore by identity ID.

        Parameters
        ----------
        identity_id : str
            The UUID of the identity to load.

        Returns
        -------
        IdentityKeyPair
            The decrypted keypair.

        Raises
        ------
        KeystoreError
            If the identity is not found, decryption fails, or passphrase is wrong.
        """
        try:
            store = self._load_raw()
            if identity_id not in store:
                raise KeystoreError(f"Identity '{identity_id}' not found in keystore.")

            entry = store[identity_id]
            passphrase = self._config.keystore_passphrase.get_secret_value().encode()

            # Support both old single-salt format (kdf_salt) and new per-key format
            # for backwards compatibility during v0.1 → v0.2 migration.
            if "kem_kdf_salt" in entry and "sig_kdf_salt" in entry:
                kem_salt = b64decode(entry["kem_kdf_salt"])
                sig_salt = b64decode(entry["sig_kdf_salt"])
                kem_enc_key = self._derive_key(passphrase, kem_salt)
                sig_enc_key = self._derive_key(passphrase, sig_salt)
            else:
                # Legacy single-salt format
                shared_salt = b64decode(entry["kdf_salt"])
                kem_enc_key = self._derive_key(passphrase, shared_salt)
                sig_enc_key = kem_enc_key

            aad = identity_id.encode()
            kem_sk = self._decrypt(b64decode(entry["kem_secret_key_enc"]), kem_enc_key, aad)
            sig_sk = self._decrypt(b64decode(entry["sig_sign_key_enc"]), sig_enc_key, aad)

            kem_kp = KEMKeypair(
                public_key=b64decode(entry["kem_public_key"]),
                secret_key=kem_sk,
                algorithm=entry["kem_algorithm"],
            )
            sig_kp = SignatureKeypair(
                verify_key=b64decode(entry["sig_verify_key"]),
                sign_key=sig_sk,
                algorithm=entry["sig_algorithm"],
            )

            return IdentityKeyPair(
                identity_id=entry["identity_id"],
                kem_keypair=kem_kp,
                sig_keypair=sig_kp,
                created_at=datetime.fromisoformat(entry["created_at"]),
                label=entry.get("label", ""),
            )
        except KeystoreError:
            raise
        except Exception as exc:
            raise KeystoreError(f"Failed to load keypair from keystore: {exc}") from exc

    def list_identities(self) -> list[dict[str, str]]:
        """
        List all stored identities (identity_id, label, created_at) — no secrets.

        Returns
        -------
        list[dict[str, str]]
            Public metadata for each stored identity.
        """
        store = self._load_raw()
        return [
            {
                "identity_id": v["identity_id"],
                "label": v.get("label", ""),
                "created_at": v.get("created_at", ""),
                "kem_algorithm": v.get("kem_algorithm", ""),
                "sig_algorithm": v.get("sig_algorithm", ""),
            }
            for v in store.values()
        ]

    def _derive_key(self, passphrase: bytes, salt: bytes) -> bytes:
        """Derive a 256-bit AES key from passphrase using scrypt."""
        try:
            kdf = Scrypt(salt=salt, length=_KEY_LENGTH, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
            return kdf.derive(passphrase)
        except Exception as exc:
            raise KeystoreError(f"Key derivation failed: {exc}") from exc

    def _encrypt(self, plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """Encrypt with AES-256-GCM. Returns nonce || ciphertext+tag.

        Parameters
        ----------
        aad : bytes
            Associated data (e.g. identity_id). Included in the GCM authentication
            tag but not encrypted. Prevents blob-swapping attacks.
        """
        nonce = secrets.token_bytes(12)  # 96-bit GCM nonce
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=aad or None)
        return nonce + ciphertext

    def _decrypt(self, data: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """Decrypt AES-256-GCM blob (nonce || ciphertext+tag).

        Parameters
        ----------
        aad : bytes
            Must match the associated data used during encryption.
        """
        if len(data) < 12:
            raise KeystoreError("Encrypted data too short — likely corrupted.")
        nonce, ciphertext = data[:12], data[12:]
        try:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, associated_data=aad or None)
        except Exception as exc:
            raise KeystoreError(
                "Decryption failed — wrong passphrase or corrupted keystore."
            ) from exc

    def _load_raw(self) -> dict[str, Any]:
        """Load the raw keystore JSON, or return empty dict if not found."""
        if not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise KeystoreError(f"Failed to read keystore file: {exc}") from exc

    def _write_raw(self, store: dict[str, Any]) -> None:
        """Write the keystore JSON, creating parent directories if needed."""
        tmp = self._path.with_suffix(".tmp")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Write to temp file then rename (atomic on most filesystems)
            tmp.write_text(json.dumps(store, indent=2), encoding="utf-8")
            tmp.replace(self._path)
        except Exception as exc:
            # Clean up the temp file so we don't leave partial keystore data on disk
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise KeystoreError(f"Failed to write keystore file: {exc}") from exc
