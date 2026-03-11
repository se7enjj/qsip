"""
QSIP CA — QSIPCertificateAuthority: quantum-safe certificate authority.

This is the "Let's Encrypt for quantum-safe TLS" component.  It:
  - Generates a self-signed root CA certificate using ML-DSA-87 + Kyber1024
  - Issues end-entity certificates for domains / DIDs
  - Verifies certificate chain signatures
  - Tracks revoked certificate serials (in-memory CRL for v0.1)

Classical Let's Encrypt vs QSIP CA:

    Let's Encrypt                   QSIP CA
    ─────────────────────           ───────────────────────────
    RSA / ECDSA root CA key         ML-DSA-87 root CA key
    ECDSA leaf cert signatures      ML-DSA-87 leaf cert signatures
    ACME protocol (HTTP-01)         QSIP-ACME (coming in v0.2)
    90-day cert lifetime            90-day cert lifetime (same)
    Quantum-breakable chain         PQC chain — survives quantum era

Security:
- Root CA keypairs are ephemeral in v0.1 (in-memory).  A production CA
  would store them in an HSM or QSIP KeyStore.
- Private signing keys NEVER leave the authority object.
- Certificate signatures use ML-DSA-87 over sha3-256(canonical_json).
- Revocation is checked before verification.

Usage:
    config = Config()
    ca = QSIPCertificateAuthority(config)
    root = ca.initialise("QSIP Root CA v1")

    # Issue a cert for a server
    server_cert = ca.issue_certificate(
        subject="secure.example.com",
        subject_kem_pk=server_kem_pk,
        subject_sig_vk=server_sig_vk,
    )

    # Verify before use
    assert ca.verify_certificate(server_cert)
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from uuid import uuid4

from src.ca.certificate import QSIPCertificate, CertificateType
from src.common.config import Config
from src.common.exceptions import QSIPCryptoError
from src.crypto.kem import KyberKEM
from src.crypto.signatures import DilithiumSigner


class CAError(QSIPCryptoError):
    """Raised for CA-level operation failures."""


class QSIPCertificateAuthority:
    """
    Quantum-safe Certificate Authority — the HTTPQ trust anchor.

    Analogous to a Let's Encrypt root CA but using only NIST PQC algorithms.
    Instances hold their root signing key in memory (ephemeral in v0.1).

    Parameters
    ----------
    config : Config
        QSIP configuration (algorithm, env settings).
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config   = config or Config()
        self._kem      = KyberKEM(self._config)
        self._signer   = DilithiumSigner(self._config)
        self._root_cert: QSIPCertificate | None = None
        self._root_sig_sk: bytes | None = None  # CA's ML-DSA signing key — NEVER expose
        self._root_kem_sk: bytes | None = None  # CA's Kyber secret key  — NEVER expose
        self._revoked: set[str] = set()

    # ── Initialisation ───────────────────────────────────────────────────────

    def initialise(self, subject: str = "QSIP Root CA v1") -> QSIPCertificate:
        """
        Generate the root CA keypairs and a self-signed root certificate.

        This is the quantum-safe equivalent of creating a new root CA key and
        self-signed certificate (like a Let's Encrypt root).

        Must be called exactly once before issuing any certificates.

        Parameters
        ----------
        subject : str
            Human-readable CA name, e.g. "QSIP Root CA v1".

        Returns
        -------
        QSIPCertificate
            Self-signed root CA certificate.

        Raises
        ------
        CAError
            If already initialised.
        """
        if self._root_cert is not None:
            raise CAError("CA is already initialised — call initialise() only once.")

        # Generate CA's own Kyber + ML-DSA keypairs
        try:
            kem_kp = self._kem.generate_keypair()
            sig_kp = self._signer.generate_keypair()
        except QSIPCryptoError as exc:
            raise CAError(f"Root CA keypair generation failed: {exc}") from exc

        # Stash secret keys (private to this instance — never serialised)
        self._root_kem_sk = kem_kp.secret_key
        self._root_sig_sk = sig_kp.sign_key

        now = datetime.now(timezone.utc)
        serial = str(uuid4())

        # Build the (unsigned) certificate to derive canonical bytes
        partial = QSIPCertificate(
            serial=serial,
            subject=subject,
            issuer=subject,
            issuer_serial=None,
            cert_type=CertificateType.ROOT_CA,
            kem_public_key=kem_kp.public_key,
            sig_verify_key=sig_kp.verify_key,
            not_before=now,
            not_after=now + timedelta(days=3650),   # 10-year root like major CAs
            ca_signature=b"",                        # placeholder for signing
            ca_verify_key=sig_kp.verify_key,         # self-signed: CA vk == own vk
            sig_algorithm=self._signer.algorithm,
            kem_algorithm=self._kem.algorithm,
        )

        # Sign SHA3-256 of canonical bytes with the root's own signing key
        sig = self._signer.sign(partial.signed_digest(), sig_kp.sign_key)

        self._root_cert = QSIPCertificate(
            serial=serial,
            subject=subject,
            issuer=subject,
            issuer_serial=None,
            cert_type=CertificateType.ROOT_CA,
            kem_public_key=kem_kp.public_key,
            sig_verify_key=sig_kp.verify_key,
            not_before=now,
            not_after=now + timedelta(days=3650),
            ca_signature=sig,
            ca_verify_key=sig_kp.verify_key,
            sig_algorithm=self._signer.algorithm,
            kem_algorithm=self._kem.algorithm,
        )
        return self._root_cert

    # ── Certificate issuance ─────────────────────────────────────────────────

    def issue_certificate(
        self,
        subject: str,
        subject_kem_pk: bytes,
        subject_sig_vk: bytes,
        valid_days: int = 90,
        x25519_public_key: bytes | None = None,
    ) -> QSIPCertificate:
        """
        Issue a signed end-entity certificate — the HTTPQ equivalent of a
        Let's Encrypt DV certificate.

        The CA signs the combination of:
            SHA3-256(subject + kem_pk + sig_vk + serial + validity + algorithms
                     [+ x25519_pk if hybrid mode])
        using the root CA's ML-DSA-87 signing key.

        Parameters
        ----------
        subject : str
            Domain name or DID being certified (e.g. "secure.example.com").
        subject_kem_pk : bytes
            Subject's Kyber1024 public key. Clients use this for key exchange.
        subject_sig_vk : bytes
            Subject's ML-DSA verify key. Used to verify messages from the subject.
        valid_days : int
            Certificate lifetime in days (default 90, like Let's Encrypt).
        x25519_public_key : bytes | None
            Optional subject X25519 public key (32 bytes, Raw format).
            When provided, the certificate enables hybrid KEM mode:
            clients will perform X25519 + Kyber1024 key exchange instead of
            pure Kyber1024.  Secure against both classical and quantum adversaries.

        Returns
        -------
        QSIPCertificate
            CA-signed certificate ready for deployment.

        Raises
        ------
        CAError
            If CA not initialised, or subject/key material is invalid.
        """
        if self._root_cert is None or self._root_sig_sk is None:
            raise CAError("CA not initialised.  Call ca.initialise() first.")
        if not subject or not subject_kem_pk or not subject_sig_vk:
            raise CAError("subject, subject_kem_pk, subject_sig_vk must all be non-empty.")

        now    = datetime.now(timezone.utc)
        serial = str(uuid4())

        partial = QSIPCertificate(
            serial=serial,
            subject=subject,
            issuer=self._root_cert.subject,
            issuer_serial=self._root_cert.serial,
            cert_type=CertificateType.END_ENTITY,
            kem_public_key=subject_kem_pk,
            sig_verify_key=subject_sig_vk,
            not_before=now,
            not_after=now + timedelta(days=valid_days),
            ca_signature=b"",
            ca_verify_key=self._root_cert.sig_verify_key,
            sig_algorithm=self._signer.algorithm,
            kem_algorithm=self._kem.algorithm,
            x25519_public_key=x25519_public_key,
        )

        try:
            sig = self._signer.sign(partial.signed_digest(), self._root_sig_sk)
        except QSIPCryptoError as exc:
            raise CAError(f"Certificate signing failed: {exc}") from exc

        return QSIPCertificate(
            serial=serial,
            subject=subject,
            issuer=self._root_cert.subject,
            issuer_serial=self._root_cert.serial,
            cert_type=CertificateType.END_ENTITY,
            kem_public_key=subject_kem_pk,
            sig_verify_key=subject_sig_vk,
            not_before=now,
            not_after=now + timedelta(days=valid_days),
            ca_signature=sig,
            ca_verify_key=self._root_cert.sig_verify_key,
            sig_algorithm=self._signer.algorithm,
            kem_algorithm=self._kem.algorithm,
            x25519_public_key=x25519_public_key,
        )

    # ── Verification ─────────────────────────────────────────────────────────

    def verify_certificate(
        self,
        cert: QSIPCertificate,
        now: datetime | None = None,
    ) -> bool:
        """
        Verify a certificate's ML-DSA-87 signature and validity period.

        For ROOT_CA certs: verifies self-signature (ca_verify_key == sig_verify_key).
        For END_ENTITY certs: verifies against the root CA's verify key.

        Parameters
        ----------
        cert : QSIPCertificate
            Certificate to verify.
        now : datetime | None
            Time to check validity against (default: utcnow).

        Returns
        -------
        bool
            True only if signature and validity period are both valid and the
            certificate serial has not been revoked.
        """
        if self._root_cert is None:
            raise CAError("CA not initialised.")

        check_time = now or datetime.now(timezone.utc)

        # Revocation check first
        if cert.serial in self._revoked:
            return False

        # Validity window
        if check_time < cert.not_before or check_time > cert.not_after:
            return False

        # SECURITY: Always verify against the KNOWN root CA verify key, never
        # against the key embedded in the cert being verified.  Trusting the
        # cert's own ca_verify_key field would allow an attacker to substitute
        # their own CA key and forge a cert that "passes" verification.
        #
        # ROOT_CA certificates are self-signed: verify against their own sig_verify_key.
        # END_ENTITY certificates: verify against the trusted root CA's sig_verify_key.
        if cert.cert_type == CertificateType.ROOT_CA:
            # Self-signed: the cert's own sig_verify_key IS the signing key
            verify_key = cert.sig_verify_key
        else:
            # End-entity: MUST verify against the CA's own recorded root verify key
            verify_key = self._root_cert.sig_verify_key
        return self._signer.verify(cert.signed_digest(), cert.ca_signature, verify_key)

    # ── Revocation ───────────────────────────────────────────────────────────

    def revoke(self, serial: str) -> None:
        """
        Revoke a certificate by serial.

        In v0.1 revocation is in-memory only.  A production CA would publish
        an ML-DSA-signed CRL or OCSP staple.

        Parameters
        ----------
        serial : str
            Certificate serial to revoke.
        """
        self._revoked.add(serial)

    def is_revoked(self, serial: str) -> bool:
        """Return True if the serial has been revoked."""
        return serial in self._revoked

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def root_certificate(self) -> QSIPCertificate:
        """The root CA certificate (requires prior call to initialise())."""
        if self._root_cert is None:
            raise CAError("CA not initialised.")
        return self._root_cert

    @property
    def algorithm(self) -> str:
        """Returns the configured signature algorithm."""
        return self._signer.algorithm

    def __repr__(self) -> str:
        serial = self._root_cert.serial[:8] if self._root_cert else "uninitialised"
        return f"QSIPCertificateAuthority(serial_prefix={serial!r}, alg={self.algorithm!r})"
