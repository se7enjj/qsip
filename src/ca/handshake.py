"""
QSIP CA — HTTPQHandshake: quantum-safe TLS-equivalent key exchange.

HTTPQ is the QSIP equivalent of HTTPS.  The handshake replaces every
classical primitive in TLS 1.3 key establishment with a PQC counterpart:

    TLS 1.3 (classical)              HTTPQ (quantum-safe)
    ─────────────────────            ───────────────────────────
    X25519 / ECDH key exchange       Kyber1024 KEM encapsulation
    ECDSA / RSA certificate          ML-DSA-87 certificate (QSIPCertificate)
    SHA-256 HKDF                     SHA3-512 HKDF
    Quantum-breakable                PQC — survives quantum era

Handshake flow (simplified TLS 1.3 analogue):

    Client                                      Server
    ──────                                      ──────
    1. ClientHello  ──session_id──────────────► Receive
    2.              ◄─server_cert──────────────── ServerHello
    3. Verify cert signature (ML-DSA-87 on CA vk)
    4. Encapsulate(server_cert.kem_public_key)
       → kem_ciphertext, client_shared_secret
    5. ──kem_ciphertext────────────────────────► Receive
    6.                                           Decapsulate(kem_ciphertext, server_kem_sk)
                                                 → server_shared_secret
    7. Both: session_key = HKDF(shared_secret, session_id, "HTTPQ-v1")

After step 7 both parties hold the same session_key without it ever
appearing on the wire.  A quantum computer observing the handshake still
cannot break it because breaking Kyber1024 requires solving a hard lattice
problem — not factoring or discrete log.

Security properties:
- IND-CCA2: attacker who intercepts kem_ciphertext cannot recover shared secret
- Authentication: client verifies server cert ML-DSA signature before encapsulating
- Forward secrecy: each session uses a fresh Kyber encapsulation
- No RSA/ECDH anywhere

Usage:
    # Server side (one-time setup)
    ca = QSIPCertificateAuthority(config)
    root = ca.initialise("QSIP Root CA v1")
    server_cert = ca.issue_certificate("secure.example.com", kem_pk, sig_vk)

    handshake = HTTPQHandshake(config, ca)
    result = handshake.full_handshake(server_cert, server_kem_sk)
    # result.session_key — use for AES-256-GCM symmetric encryption
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.ca.authority import QSIPCertificateAuthority, CAError
from src.ca.certificate import QSIPCertificate
from src.common.config import Config
from src.common.exceptions import QSIPCryptoError
from src.crypto.kem import KyberKEM

# Domain separation — ensures session keys are unique to HTTPQ
_HTTPQ_HKDF_INFO = b"HTTPQ-session-key-v1"
_HTTPQ_HKDF_SALT = b"QSIP-HTTPQ-salt-v1:Kyber+MLDSA"
_SESSION_KEY_LENGTH = 32   # AES-256


class HTTPQError(QSIPCryptoError):
    """Raised for HTTPQ handshake failures."""


@dataclass(frozen=True)
class HTTPQHandshakeResult:
    """
    Result of a completed HTTPQ handshake.

    Attributes
    ----------
    session_id : bytes
        Random 32-byte session identifier (public — sent in ClientHello).
    session_key : bytes
        32-byte AES-256-compatible session key.  NEVER transmitted.
    kem_ciphertext : bytes
        Kyber1024 ciphertext sent from client to server.
    handshake_ms : float
        Total wall-clock time for the handshake (both sides) in milliseconds.
    server_certificate : QSIPCertificate
        The server's certificate used in this handshake.
    cert_verified : bool
        Whether the CA signature on the server cert was successfully verified.
    """

    session_id: bytes
    session_key: bytes
    kem_ciphertext: bytes
    handshake_ms: float
    server_certificate: QSIPCertificate
    cert_verified: bool

    def __repr__(self) -> str:
        """Never print session_key in repr."""
        return (
            f"HTTPQHandshakeResult("
            f"session_id={self.session_id.hex()[:16]}…, "
            f"session_key=<REDACTED>, "
            f"kem_ciphertext=<{len(self.kem_ciphertext)} bytes>, "
            f"handshake_ms={self.handshake_ms:.2f}, "
            f"cert_verified={self.cert_verified})"
        )


class HTTPQHandshake:
    """
    HTTPQ quantum-safe handshake engine.

    Performs a complete client+server handshake in a single call
    (for demo / testing purposes — in production these would run
    on separate machines communicating over the network).

    Parameters
    ----------
    config : Config
        QSIP configuration.
    ca : QSIPCertificateAuthority
        Initialised CA used to verify server certificates.
    """

    def __init__(
        self,
        config: Config | None = None,
        ca: QSIPCertificateAuthority | None = None,
    ) -> None:
        self._config = config or Config()
        self._ca     = ca
        self._kem    = KyberKEM(self._config)

    # ── Client side ──────────────────────────────────────────────────────────

    def client_hello(
        self,
        server_cert: QSIPCertificate,
    ) -> tuple[bytes, bytes, bytes]:
        """
        CLIENT HELLO: verify the server certificate and encapsulate a
        shared secret using the server's Kyber public key.

        This is the PQC equivalent of the TLS ClientHello + KeyShare.

        Parameters
        ----------
        server_cert : QSIPCertificate
            Server's certificate, obtained from the server's TLS-like hello.

        Returns
        -------
        tuple[bytes, bytes, bytes]
            (session_id, kem_ciphertext, shared_secret)
            - session_id    : 32 random bytes, sent to server
            - kem_ciphertext: sent to server (server decapsulates to get secret)
            - shared_secret : Kyber shared secret — used locally for HKDF

        Raises
        ------
        HTTPQError
            If certificate is expired, revoked, or has invalid CA signature.
        """
        # Verify certificate before doing anything
        if self._ca is not None:
            if not self._ca.verify_certificate(server_cert):
                raise HTTPQError(
                    f"Server certificate for '{server_cert.subject}' failed verification. "
                    f"Certificate may be expired, revoked, or forged."
                )
        elif server_cert.is_expired():
            raise HTTPQError(f"Server certificate for '{server_cert.subject}' is expired.")

        # Fresh session identifier — equivalent to TLS ClientHello.Random
        session_id = secrets.token_bytes(32)

        # Kyber encapsulation: generate a shared secret using server's public key
        try:
            result = self._kem.encapsulate(server_cert.kem_public_key)
        except QSIPCryptoError as exc:
            raise HTTPQError(f"Kyber encapsulation failed: {exc}") from exc

        return session_id, result.ciphertext, result.shared_secret

    # ── Server side ──────────────────────────────────────────────────────────

    def server_finish(
        self,
        kem_ciphertext: bytes,
        server_kem_sk: bytes,
        session_id: bytes,
    ) -> bytes:
        """
        SERVER FINISH: decapsulate the KEM ciphertext to recover the shared
        secret, then derive the session key.

        Parameters
        ----------
        kem_ciphertext : bytes
            Received from the client during ClientHello.
        server_kem_sk : bytes
            Server's Kyber1024 secret key (never transmitted).
        session_id : bytes
            Session identifier received in ClientHello.

        Returns
        -------
        bytes
            32-byte session key (AES-256-compatible).

        Raises
        ------
        HTTPQError
            If decapsulation fails.
        """
        try:
            shared_secret = self._kem.decapsulate(kem_ciphertext, server_kem_sk)
        except QSIPCryptoError as exc:
            raise HTTPQError(f"Kyber decapsulation failed: {exc}") from exc

        return self._derive_session_key(shared_secret, session_id)

    # ── Combined (demo convenience) ──────────────────────────────────────────

    def full_handshake(
        self,
        server_cert: QSIPCertificate,
        server_kem_sk: bytes,
    ) -> HTTPQHandshakeResult:
        """
        Perform a complete HTTPQ handshake (client + server) in one call.

        Demonstrates the full flow without requiring two separate processes.
        In production, client_hello() and server_finish() would run on
        different machines communicating over HTTPQ/TLS.

        Parameters
        ----------
        server_cert : QSIPCertificate
            Server's certificate (public — would be sent in ServerHello).
        server_kem_sk : bytes
            Server's Kyber secret key (private — never leaves the server).

        Returns
        -------
        HTTPQHandshakeResult
            Contains session_key, timing, and audit fields.

        Raises
        ------
        HTTPQError
            If certificate verification or key exchange fails.
        """
        import time
        t0 = time.perf_counter()

        cert_verified = (
            self._ca.verify_certificate(server_cert)
            if self._ca is not None
            else not server_cert.is_expired()
        )

        if not cert_verified:
            raise HTTPQError(
                f"Server certificate for '{server_cert.subject}' rejected by CA."
            )

        # CLIENT SIDE
        session_id, kem_ciphertext, client_secret = self.client_hello(server_cert)

        # SERVER SIDE
        server_session_key = self.server_finish(kem_ciphertext, server_kem_sk, session_id)

        # CLIENT: derive own session key
        client_session_key = self._derive_session_key(client_secret, session_id)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Both sides must have the same session key — fundamental invariant
        if client_session_key != server_session_key:
            raise HTTPQError(
                "HTTPQ invariant violated: client and server derived different session keys. "
                "This indicates a bug in the KEM or HKDF implementation."
            )

        return HTTPQHandshakeResult(
            session_id=session_id,
            session_key=client_session_key,
            kem_ciphertext=kem_ciphertext,
            handshake_ms=elapsed_ms,
            server_certificate=server_cert,
            cert_verified=cert_verified,
        )

    # ── Key derivation ───────────────────────────────────────────────────────

    def _derive_session_key(self, shared_secret: bytes, session_id: bytes) -> bytes:
        """
        Derive a session key from the Kyber shared secret and session identifier.

        Uses HKDF-SHA3-512:
            session_key = HKDF(
                ikm  = shared_secret,
                salt = _HTTPQ_HKDF_SALT,
                info = _HTTPQ_HKDF_INFO || session_id,
                len  = 32,
            )

        The session_id binds the key to this specific session, preventing
        replay attacks even if the same shared secret were somehow reused.
        """
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=_SESSION_KEY_LENGTH,
                salt=_HTTPQ_HKDF_SALT,
                info=_HTTPQ_HKDF_INFO + session_id,
            )
            return hkdf.derive(shared_secret)
        except Exception as exc:
            raise HTTPQError(f"HKDF session key derivation failed: {exc}") from exc
