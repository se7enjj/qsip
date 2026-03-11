"""
QSIP — oqs library mock for testing.

This module provides a minimal mock of the liboqs Python API so that
unit tests for business logic can run without requiring the native
liboqs C shared library to be compiled and installed.

IMPORTANT: This mock does NOT implement real post-quantum cryptography.
It exists solely so the test suite can validate protocol logic, error
handling, state management, and serialization without a native C build
dependency. It uses HMAC-SHA3 as a substitute for Kyber and Dilithium.

Security behaviours preserved by this mock vs real liboqs:
  - KEM: encap → decap produces the same shared secret             ✓
  - KEM: wrong secret key produces a DIFFERENT shared secret       ✓
  - KEM: tampered ciphertext produces a DIFFERENT shared secret    ✓
  - Sig: sign → verify succeeds                                    ✓
  - Sig: tampered message → verify returns False                   ✓
  - Sig: wrong verify key → verify returns False                   ✓

Tests that require REAL cryptographic correctness (e.g. "does Kyber
actually resist attacks?") are marked with @pytest.mark.requires_liboqs
and are skipped when the native library is unavailable.
"""

from __future__ import annotations

import hashlib
import secrets
from unittest.mock import MagicMock


def build_oqs_mock() -> MagicMock:
    """
    Build a complete mock of the oqs module.

    The mock:
    - Responds to get_enabled_kem_mechanisms() with Kyber algorithm names
    - Responds to get_enabled_sig_mechanisms() with Dilithium algorithm names
    - Provides KeyEncapsulation and Signature classes with correct interfaces
    - FakeSig correctly rejects tampered messages and wrong keys
    """
    mock_oqs = MagicMock()

    mock_oqs.get_enabled_kem_mechanisms.return_value = [
        "Kyber512", "Kyber768", "Kyber1024",
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    ]
    mock_oqs.get_enabled_sig_mechanisms.return_value = [
        "Dilithium2", "Dilithium3", "Dilithium5",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    ]

    # Provide real-ish KEM and Sig classes
    # We need key agreement to actually work (encap→decap → same secret)
    # so we use a simple symmetric scheme based on the public key
    class RealishKEM:
        def __init__(self, alg: str, secret_key: bytes | None = None) -> None:
            self.alg = alg
            self._secret_key = secret_key
            self._public_key: bytes | None = None

        def __enter__(self) -> "RealishKEM":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def generate_keypair(self) -> bytes:
            seed = secrets.token_bytes(32)
            self._secret_key = hashlib.sha3_512(seed + b"sk").digest() * 50  # ~3200 bytes
            self._public_key = hashlib.sha3_512(seed + b"pk").digest() * 25  # ~1600 bytes
            # Store seed for reference
            _seed_store[self._public_key[:16]] = seed
            _seed_store[self._secret_key[:16]] = seed
            # Map secret key → returned public key so wrong-key decap can be detected
            pk_returned = self._public_key[:1568]
            _skpk_map[self._secret_key[:32]] = pk_returned
            return pk_returned

        def export_secret_key(self) -> bytes:
            return self._secret_key[:3168] if self._secret_key else b"\x00" * 3168

        def encap_secret(self, public_key: bytes) -> tuple[bytes, bytes]:
            # Shared secret = SHA3-256(public_key || nonce)
            nonce = secrets.token_bytes(32)
            shared_secret = hashlib.sha3_256(public_key + nonce).digest()
            ciphertext = nonce + secrets.token_bytes(1536)  # pad to 1568
            # Key the store on a hash of the FULL ciphertext so any tampered byte
            # (including bytes outside the nonce prefix) misses the lookup.
            ct_hash = hashlib.sha3_256(ciphertext[:1568]).digest()
            _ct_store[ct_hash] = (public_key, shared_secret)
            return ciphertext[:1568], shared_secret

        def decap_secret(self, ciphertext: bytes) -> bytes:
            ct_hash = hashlib.sha3_256(ciphertext).digest()
            stored = _ct_store.get(ct_hash)
            if stored is None:
                return secrets.token_bytes(32)  # tampered ciphertext → not found
            enc_public_key, shared_secret = stored
            # Verify this instance's secret key corresponds to the public key
            # that was used for encapsulation.
            expected_pk = _skpk_map.get(self._secret_key[:32]) if self._secret_key else None
            if expected_pk is None or expected_pk != enc_public_key:
                return secrets.token_bytes(32)  # unknown sk or wrong recipient
            return shared_secret

    class RealishSig:
        import hmac as _hmac_module

        def __init__(self, alg: str, secret_key: bytes | None = None) -> None:
            self.alg = alg
            self._sign_key = secret_key
            self._verify_key: bytes | None = None

        def __enter__(self) -> "RealishSig":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def generate_keypair(self) -> bytes:
            self._sign_key = secrets.token_bytes(4864)
            self._verify_key = hashlib.sha3_256(self._sign_key).digest() * 80  # ~2560 bytes
            # Store sign key indexed by verify key prefix for verification
            _sig_key_store[self._verify_key[:32]] = self._sign_key
            return self._verify_key[:2592]

        def export_secret_key(self) -> bytes:
            return self._sign_key if self._sign_key else secrets.token_bytes(4864)

        def sign(self, message: bytes) -> bytes:
            if not self._sign_key:
                raise RuntimeError("No signing key")
            import hmac as _hmac
            mac = _hmac.new(self._sign_key[:64], message, hashlib.sha3_512).digest()
            return (mac * 72)[:4595]  # Dilithium5 signature size

        def verify(self, message: bytes, signature: bytes, verify_key: bytes) -> bool:
            import hmac as _hmac
            sign_key = _sig_key_store.get(verify_key[:32])
            if sign_key is None:
                return False
            expected_mac = _hmac.new(sign_key[:64], message, hashlib.sha3_512).digest()
            expected_sig = (expected_mac * 72)[:4595]
            # Compare the FULL signature so any bit flip at any position is detected.
            # Padding submitted signatures to expected length before constant-time compare.
            padded_sig = (signature + bytes(4595))[:4595]
            return _hmac.compare_digest(expected_sig, padded_sig)

    mock_oqs.KeyEncapsulation = RealishKEM
    mock_oqs.Signature = RealishSig
    return mock_oqs


# Shared state for mock KEM agreement
_seed_store: dict[bytes, bytes] = {}
_ct_store: dict[bytes, tuple[bytes, bytes]] = {}
_skpk_map: dict[bytes, bytes] = {}
_sig_key_store: dict[bytes, bytes] = {}
