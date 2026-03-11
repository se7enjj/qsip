"""
Tests for the QSIP CA layer: QSIPCertificateAuthority, QSIPCertificate, HTTPQHandshake.

Coverage targets:
  - Root CA self-signed cert verifies
  - End-entity cert issued by CA verifies
  - Forged cert (wrong signer) is rejected
  - Revoked cert is rejected at verification and at handshake
  - Expired cert is rejected
  - Fingerprint format is stable / unique
  - Full HTTPQ handshake: both sides derive the same session key
  - Wrong server KEM key yields a different session key / raises
  - CA round-trip: issue → to_dict → from_dict → verify
"""

from __future__ import annotations

import os
import sys
import ctypes
import ctypes.util
import dataclasses
from datetime import datetime, timezone, timedelta

# ── Mock injection (same pattern as conftest.py) ─────────────────────────────
_NATIVE = False
for _c in ("oqs", "liboqs", "liboqs-0"):
    _p = ctypes.util.find_library(_c)
    if _p:
        try:
            ctypes.CDLL(_p)
            _NATIVE = True
        except OSError:
            pass
        break
if not _NATIVE and "oqs" not in sys.modules:
    from tests._oqs_mock import build_oqs_mock
    sys.modules["oqs"] = build_oqs_mock()  # type: ignore

os.environ.setdefault("QSIP_ENV", "testing")
os.environ.setdefault("QSIP_KEYSTORE_PASSPHRASE", "test-ca-ephemeral")

import pytest

from src.common.config import Config
from src.crypto.kem import KyberKEM
from src.crypto.signatures import DilithiumSigner
from src.ca.authority import QSIPCertificateAuthority, CAError
from src.ca.certificate import QSIPCertificate, CertificateType
from src.ca.handshake import HTTPQHandshake, HTTPQHandshakeResult, HTTPQError


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def config() -> Config:
    return Config()


@pytest.fixture(scope="module")
def ca(config: Config) -> QSIPCertificateAuthority:
    """One CA per module — generating keypairs is expensive."""
    authority = QSIPCertificateAuthority(config)
    authority.initialise("QSIP Test Root CA")
    return authority


@pytest.fixture(scope="module")
def server_keypairs(config: Config):
    """Server KEM + sig keypairs, shared across module tests."""
    kem = KyberKEM(config)
    sig = DilithiumSigner(config)
    return kem.generate_keypair(), sig.generate_keypair()


@pytest.fixture(scope="module")
def server_cert(ca: QSIPCertificateAuthority, server_keypairs):
    kem_kp, sig_kp = server_keypairs
    return ca.issue_certificate(
        subject="test.example.com",
        subject_kem_pk=kem_kp.public_key,
        subject_sig_vk=sig_kp.verify_key,
        valid_days=90,
    )


# ── Certificate Authority tests ───────────────────────────────────────────────

class TestQSIPCertificateAuthority:
    def test_root_ca_is_self_signed(self, ca: QSIPCertificateAuthority) -> None:
        root = ca.root_certificate
        assert root is not None
        assert root.is_self_signed(), "Root CA certificate must be self-signed"
        assert root.cert_type == CertificateType.ROOT_CA

    def test_root_ca_not_expired(self, ca: QSIPCertificateAuthority) -> None:
        root = ca.root_certificate
        assert not root.is_expired(), "Freshly-created root CA must not be expired"
        # Root CA valid_days=3650; allow up to 2 days slippage for slow machines
        days_remaining = (root.not_after - datetime.now(timezone.utc)).days
        assert days_remaining >= 3648, f"Root CA only has {days_remaining} days left"

    def test_root_ca_verify_signature(self, ca: QSIPCertificateAuthority) -> None:
        assert ca.verify_certificate(ca.root_certificate), "Root CA must verify its own signature"

    def test_issue_certificate_returns_end_entity(
        self, server_cert: QSIPCertificate
    ) -> None:
        assert server_cert.cert_type == CertificateType.END_ENTITY
        assert server_cert.subject == "test.example.com"
        assert not server_cert.is_self_signed()

    def test_issued_cert_verifies(
        self, ca: QSIPCertificateAuthority, server_cert: QSIPCertificate
    ) -> None:
        assert ca.verify_certificate(server_cert), "Freshly-issued cert must verify"

    def test_issued_cert_valid_window(self, server_cert: QSIPCertificate) -> None:
        assert not server_cert.is_expired()
        days = (server_cert.not_after - datetime.now(timezone.utc)).days
        assert 88 <= days <= 91, f"90-day cert has unexpected validity: {days} days"

    def test_issued_cert_has_correct_issuer(
        self, ca: QSIPCertificateAuthority, server_cert: QSIPCertificate
    ) -> None:
        assert server_cert.issuer == ca.root_certificate.subject
        assert server_cert.issuer_serial == ca.root_certificate.serial

    def test_forged_cert_rejected(
        self, config: Config, ca: QSIPCertificateAuthority, server_keypairs
    ) -> None:
        """A certificate signed by a rogue CA must fail verification."""
        kem_kp, sig_kp = server_keypairs
        evil = QSIPCertificateAuthority(config)
        evil.initialise("Evil CA")
        evil_cert = evil.issue_certificate(
            subject="test.example.com",
            subject_kem_pk=kem_kp.public_key,
            subject_sig_vk=sig_kp.verify_key,
        )
        assert not ca.verify_certificate(evil_cert), "Cert from wrong CA must be rejected"

    def test_revoke_prevents_verification(
        self,
        config: Config,
        server_keypairs,
    ) -> None:
        """Revoked cert is rejected by verify_certificate."""
        kem_kp, sig_kp = server_keypairs
        local_ca = QSIPCertificateAuthority(config)
        local_ca.initialise("Revocation Test CA")
        cert = local_ca.issue_certificate(
            "revoke-me.example.com", kem_kp.public_key, sig_kp.verify_key
        )
        assert local_ca.verify_certificate(cert)
        local_ca.revoke(cert.serial)
        assert local_ca.is_revoked(cert.serial)
        assert not local_ca.verify_certificate(cert), "Revoked cert must be rejected"

    def test_revoke_unknown_serial_is_noop(self, ca: QSIPCertificateAuthority) -> None:
        ca.revoke("nonexistent-serial-00000000")  # must not raise

    def test_not_initialised_raises(self, config: Config) -> None:
        """Issuing before initialise() must raise."""
        uninit_ca = QSIPCertificateAuthority(config)
        with pytest.raises((CAError, Exception)):
            uninit_ca.issue_certificate("x.com", b"\x00" * 10, b"\x00" * 10)


# ── Certificate dataclass tests ───────────────────────────────────────────────

class TestQSIPCertificate:
    def test_fingerprint_format(self, server_cert: QSIPCertificate) -> None:
        fp = server_cert.fingerprint()
        assert fp.startswith("QSIP:"), f"Unexpected fingerprint prefix: {fp}"
        parts = fp.split(":")
        assert len(parts) == 5, f"Expected 5 colon-separated parts, got {len(parts)}: {fp}"

    def test_fingerprint_is_deterministic(self, server_cert: QSIPCertificate) -> None:
        assert server_cert.fingerprint() == server_cert.fingerprint()

    def test_fingerprints_are_unique(
        self, config: Config, server_keypairs, ca: QSIPCertificateAuthority
    ) -> None:
        kem_kp, sig_kp = server_keypairs
        cert2 = ca.issue_certificate("other.example.com", kem_kp.public_key, sig_kp.verify_key)
        assert server_keypairs  # reuse fixture cert
        # Two certs for different subjects must have different fingerprints
        # (also different serials, but fingerprint covers more fields)
        # We just check they're different from each other
        fp_a = cert2.fingerprint()
        other_ca = QSIPCertificateAuthority(config)
        other_ca.initialise("Another CA")
        cert3 = other_ca.issue_certificate("other.example.com", kem_kp.public_key, sig_kp.verify_key)
        assert fp_a != cert3.fingerprint()

    def test_to_dict_from_dict_roundtrip(
        self, ca: QSIPCertificateAuthority, server_cert: QSIPCertificate
    ) -> None:
        d = server_cert.to_dict()
        assert isinstance(d, dict)
        restored = QSIPCertificate.from_dict(d)
        assert restored.serial == server_cert.serial
        assert restored.subject == server_cert.subject
        assert restored.kem_public_key == server_cert.kem_public_key
        assert restored.sig_verify_key == server_cert.sig_verify_key
        assert restored.ca_signature == server_cert.ca_signature
        assert restored.fingerprint() == server_cert.fingerprint()

    def test_restored_cert_verifies(
        self, ca: QSIPCertificateAuthority, server_cert: QSIPCertificate
    ) -> None:
        restored = QSIPCertificate.from_dict(server_cert.to_dict())
        assert ca.verify_certificate(restored)

    def test_canonical_bytes_are_stable(self, server_cert: QSIPCertificate) -> None:
        b1 = server_cert.canonical_bytes()
        b2 = server_cert.canonical_bytes()
        assert b1 == b2, "canonical_bytes() must be deterministic"

    def test_signed_digest_is_sha3_256(self, server_cert: QSIPCertificate) -> None:
        digest = server_cert.signed_digest()
        assert len(digest) == 32, "SHA3-256 digest must be exactly 32 bytes"


# ── HTTPQ Handshake tests ─────────────────────────────────────────────────────

class TestHTTPQHandshake:
    def test_full_handshake_succeeds(
        self,
        config: Config,
        ca: QSIPCertificateAuthority,
        server_cert: QSIPCertificate,
        server_keypairs,
    ) -> None:
        kem_kp, _ = server_keypairs
        hs = HTTPQHandshake(config, ca)
        result = hs.full_handshake(server_cert, kem_kp.secret_key)
        assert isinstance(result, HTTPQHandshakeResult)
        assert result.cert_verified is True
        assert len(result.session_key) == 32, "Session key must be 32 bytes"
        assert len(result.session_id) > 0
        assert len(result.kem_ciphertext) > 0
        assert result.handshake_ms > 0

    def test_session_key_is_32_bytes(
        self,
        config: Config,
        ca: QSIPCertificateAuthority,
        server_cert: QSIPCertificate,
        server_keypairs,
    ) -> None:
        kem_kp, _ = server_keypairs
        result = HTTPQHandshake(config, ca).full_handshake(server_cert, kem_kp.secret_key)
        assert len(result.session_key) == 32

    def test_two_handshakes_yield_different_session_keys(
        self,
        config: Config,
        ca: QSIPCertificateAuthority,
        server_cert: QSIPCertificate,
        server_keypairs,
    ) -> None:
        """Fresh Kyber encapsulation each time → fresh session key each time."""
        kem_kp, _ = server_keypairs
        r1 = HTTPQHandshake(config, ca).full_handshake(server_cert, kem_kp.secret_key)
        r2 = HTTPQHandshake(config, ca).full_handshake(server_cert, kem_kp.secret_key)
        # With overwhelming probability fresh encapsulations ≠ each other
        assert r1.session_id != r2.session_id
        assert r1.session_key != r2.session_key

    def test_session_key_repr_is_redacted(
        self,
        config: Config,
        ca: QSIPCertificateAuthority,
        server_cert: QSIPCertificate,
        server_keypairs,
    ) -> None:
        kem_kp, _ = server_keypairs
        result = HTTPQHandshake(config, ca).full_handshake(server_cert, kem_kp.secret_key)
        r = repr(result)
        assert result.session_key.hex() not in r, "session_key bytes must not appear in repr"
        assert "REDACTED" in r

    def test_revoked_cert_raises(
        self,
        config: Config,
        server_keypairs,
    ) -> None:
        kem_kp, sig_kp = server_keypairs
        local_ca = QSIPCertificateAuthority(config)
        local_ca.initialise("Revoke Test CA for Handshake")
        cert = local_ca.issue_certificate("revoked.example.com", kem_kp.public_key, sig_kp.verify_key)
        local_ca.revoke(cert.serial)
        with pytest.raises(Exception):
            HTTPQHandshake(config, local_ca).full_handshake(cert, kem_kp.secret_key)

    def test_forged_cert_raises(
        self,
        config: Config,
        ca: QSIPCertificateAuthority,
        server_keypairs,
    ) -> None:
        kem_kp, sig_kp = server_keypairs
        evil = QSIPCertificateAuthority(config)
        evil.initialise("Evil CA 2")
        evil_cert = evil.issue_certificate("victim.example.com", kem_kp.public_key, sig_kp.verify_key)
        with pytest.raises(Exception):
            HTTPQHandshake(config, ca).full_handshake(evil_cert, kem_kp.secret_key)

    def test_wrong_server_kem_key_raises_or_diverges(
        self,
        config: Config,
        ca: QSIPCertificateAuthority,
        server_cert: QSIPCertificate,
        server_keypairs,
    ) -> None:
        """Decapsulation with a wrong private key must either raise or produce a wrong key."""
        kem_kp, _ = server_keypairs
        wrong_kp = KyberKEM(config).generate_keypair()
        # full_handshake checks client_key == server_key; wrong key → must raise
        with pytest.raises(Exception):
            HTTPQHandshake(config, ca).full_handshake(server_cert, wrong_kp.secret_key)

    def test_handshake_result_has_certificate(
        self,
        config: Config,
        ca: QSIPCertificateAuthority,
        server_cert: QSIPCertificate,
        server_keypairs,
    ) -> None:
        kem_kp, _ = server_keypairs
        result = HTTPQHandshake(config, ca).full_handshake(server_cert, kem_kp.secret_key)
        assert result.server_certificate.serial == server_cert.serial
