"""
QSIP CA — QSIPCertificate: quantum-safe X.509-equivalent certificate format.

A QSIPCertificate plays the same role as an X.509 certificate in TLS — it
binds a public key to a subject identity and is signed by a Certificate
Authority — but uses only post-quantum algorithms:

    Key exchange   : Kyber1024   (NIST FIPS 203 / ML-KEM)
    Signatures     : ML-DSA-87   (NIST FIPS 204)
    Fingerprinting : SHA3-256

Structure:

    ┌─────────────────────────────────────────────────────────┐
    │  QSIP Certificate (v1)                                  │
    │                                                         │
    │  subject        : "secure.example.com"                  │
    │  issuer         : "QSIP Root CA v1"                     │
    │  cert_type      : ROOT_CA | END_ENTITY                  │
    │  kem_public_key : Kyber1024  (1568 bytes)               │
    │  sig_verify_key : ML-DSA-87  (2592 bytes)               │
    │  not_before / not_after                                  │
    │  ca_signature   : ML-DSA-87 over sha3-256(above)        │
    │  ca_verify_key  : issuer's ML-DSA-87 verify key         │
    └─────────────────────────────────────────────────────────┘

Comparison with classical TLS:

    Classical TLS                   HTTPQ (QSIP)
    ─────────────────────           ─────────────────────────
    ECDH key exchange               Kyber1024 KEM
    RSA/ECDSA signature (CA)        ML-DSA-87 signature
    SHA-256 fingerprint             SHA3-256 fingerprint
    2048-bit RSA key (256 bytes)    1568-byte Kyber public key
    quantum-breakable               quantum-safe

Security:
- The issuer's ML-DSA-87 signature binds all certificate fields.
- `ca_verify_key` is included to enable chain verification without fetching
  the full issuer cert (useful in constrained environments).
- Fingerprints use SHA3-256; Grover's algorithm gives 128-bit PQ security.
- Certificate serialisation is canonical JSON → sha3-256 → ML-DSA-87 sign.

Usage:
    ca = QSIPCertificateAuthority(config)
    root = ca.initialise("QSIP Root CA v1")
    cert = ca.issue_certificate("secure.example.com", kem_pk, sig_vk)
    assert ca.verify_certificate(cert)
"""

from __future__ import annotations

import hashlib
import json
from base64 import b64decode, b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class CertificateType(str, Enum):
    """Certificate role in the trust chain."""
    ROOT_CA    = "ROOT_CA"
    END_ENTITY = "END_ENTITY"


@dataclass(frozen=True)
class QSIPCertificate:
    """
    A post-quantum TLS-equivalent certificate.

    Attributes
    ----------
    serial : str
        Unique certificate serial (UUID v4).
    subject : str
        Entity the certificate is issued to. E.g. "secure.example.com" or
        a QSIP DID.
    issuer : str
        Human-readable name of the issuer (e.g. "QSIP Root CA v1").
    issuer_serial : str | None
        Serial of the issuer's own certificate. None for root CA (self-signed).
    cert_type : CertificateType
        ROOT_CA or END_ENTITY.
    kem_public_key : bytes
        Kyber1024 public key. Used by clients to encapsulate a shared secret
        during the HTTPQ handshake.
    sig_verify_key : bytes
        ML-DSA-87 public verification key. Used to verify messages signed by
        the subject.
    not_before : datetime
        UTC not-valid-before datetime (ISO-8601).
    not_after : datetime
        UTC not-valid-after datetime (ISO-8601).
    ca_signature : bytes
        ML-DSA-87 signature over sha3-256(canonical_json) produced by the
        issuing CA.
    ca_verify_key : bytes
        The issuing CA's ML-DSA-87 verify key. Included for offline chain
        verification.
    sig_algorithm : str
        Signature algorithm (e.g. "ML-DSA-87").
    kem_algorithm : str
        KEM algorithm (e.g. "Kyber1024").
    """

    serial: str
    subject: str
    issuer: str
    issuer_serial: str | None
    cert_type: CertificateType
    kem_public_key: bytes
    sig_verify_key: bytes
    not_before: datetime
    not_after: datetime
    ca_signature: bytes
    ca_verify_key: bytes
    sig_algorithm: str
    kem_algorithm: str
    # Optional X25519 public key — present only in hybrid-mode (X25519+Kyber1024)
    # certificates.  When set, the HTTPQ handshake uses HybridKEM instead of
    # plain Kyber so the connection is secure against both classical and quantum.
    x25519_public_key: bytes | None = None

    # ── Serialisation ────────────────────────────────────────────────────────

    def canonical_bytes(self) -> bytes:
        """
        Deterministic canonical representation of the signed fields.

        This is the exact byte string that the CA signs, and that a verifier
        must reconstruct to check the signature. It excludes `ca_signature`
        (signed over everything else).
        """
        doc: dict[str, Any] = {
            "serial":         self.serial,
            "subject":        self.subject,
            "issuer":         self.issuer,
            "issuer_serial":  self.issuer_serial,
            "cert_type":      self.cert_type.value,
            "kem_algorithm":  self.kem_algorithm,
            "sig_algorithm":  self.sig_algorithm,
            "kem_public_key": b64encode(self.kem_public_key).decode(),
            "sig_verify_key": b64encode(self.sig_verify_key).decode(),
            "ca_verify_key":  b64encode(self.ca_verify_key).decode(),
            "not_before":     self.not_before.isoformat(),
            "not_after":      self.not_after.isoformat(),
        }
        # Only include x25519_public_key when present — keeps pure-Kyber certs
        # backward-compatible with older parsers that don't know this field.
        if self.x25519_public_key is not None:
            doc["x25519_public_key"] = b64encode(self.x25519_public_key).decode()
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()

    def signed_digest(self) -> bytes:
        """SHA3-256 over the canonical bytes — what the CA actually signs."""
        return hashlib.sha3_256(self.canonical_bytes()).digest()

    def fingerprint(self) -> str:
        """
        Certificate fingerprint as QSIP:xxxxxxxx:xxxxxxxx:xxxxxxxx:xxxxxxxx.

        SHA3-256 over the complete canonical bytes (including ca_signature).
        """
        full = self.canonical_bytes() + self.ca_signature
        digest = hashlib.sha3_256(full).hexdigest()
        return f"QSIP:{digest[0:8]}:{digest[8:16]}:{digest[16:24]}:{digest[24:32]}"

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return True if the certificate is past its not_after date."""
        t = now or datetime.now(timezone.utc)
        return t > self.not_after

    def is_self_signed(self) -> bool:
        """Return True if this is a self-signed root CA certificate."""
        return self.cert_type == CertificateType.ROOT_CA and self.issuer_serial is None

    def to_dict(self) -> dict[str, Any]:
        """Full serialisation including ca_signature — for wire transfer / storage."""
        d = {
            **json.loads(self.canonical_bytes()),
            "ca_signature": b64encode(self.ca_signature).decode(),
        }
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "QSIPCertificate":
        """Deserialise a certificate previously produced by to_dict()."""
        x25519_raw = d.get("x25519_public_key")
        return cls(
            serial=d["serial"],
            subject=d["subject"],
            issuer=d["issuer"],
            issuer_serial=d.get("issuer_serial"),
            cert_type=CertificateType(d["cert_type"]),
            kem_public_key=b64decode(d["kem_public_key"]),
            sig_verify_key=b64decode(d["sig_verify_key"]),
            not_before=datetime.fromisoformat(d["not_before"]),
            not_after=datetime.fromisoformat(d["not_after"]),
            ca_signature=b64decode(d["ca_signature"]),
            ca_verify_key=b64decode(d["ca_verify_key"]),
            sig_algorithm=d["sig_algorithm"],
            kem_algorithm=d["kem_algorithm"],
            x25519_public_key=b64decode(x25519_raw) if x25519_raw else None,
        )

    def to_json(self) -> str:
        """Serialise to a JSON string suitable for wire transfer."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, s: str) -> "QSIPCertificate":
        """Deserialise a certificate previously produced by ``to_json()``."""
        return cls.from_dict(json.loads(s))

    def __repr__(self) -> str:
        return (
            f"QSIPCertificate(serial={self.serial!r}, subject={self.subject!r}, "
            f"issuer={self.issuer!r}, cert_type={self.cert_type.value!r}, "
            f"kem={self.kem_algorithm!r}, sig={self.sig_algorithm!r})"
        )
