"""
HTTPQClient — TCP client with HTTPQ quantum-safe handshake.

Connects to an ``HTTPQServer``, executes the handshake state machine,
and returns an ``HTTPQConnection`` ready for encrypted application data.

Handshake (client perspective):

    1. TCP connect to host:port
    2. Recv  SERVER_HELLO  — JSON-serialised QSIPCertificate
    3. Verify server cert ML-DSA-87 signature against CA root key
    4. Kyber encapsulate(cert.kem_public_key) → kem_ciphertext, shared_secret
    5. Send  CLIENT_HELLO  — session_id (32 B) ‖ kem_ciphertext (1568 B)
    6. Derive session_key = HKDF-SHA3-512(shared_secret, session_id)
    7. Recv  SERVER_FINISH — verify HMAC
    8. Send  CLIENT_FINISH — HMAC-SHA3-256(session_key, CLIENT_FINISH_LABEL)
    9. Return HTTPQConnection(sock, session_key)

Usage::

    config = Config()
    ca     = QSIPCertificateAuthority(config)
    # ca must be initialised with the same root as the server

    client = HTTPQClient(config, ca)
    with client.connect("127.0.0.1", 8765) as conn:
        conn.send(b"Hello, quantum-safe world!")
        reply = conn.recv()
        print(reply.decode())
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import socket

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.ca.authority import QSIPCertificateAuthority
from src.ca.certificate import QSIPCertificate
from src.ca.handshake import (
    HTTPQHandshake,
    _HTTPQ_HKDF_INFO,
    _HTTPQ_HKDF_SALT,
    _SESSION_KEY_LENGTH,
)
from src.common.config import Config
from src.crypto.hybrid import HybridKEM
from src.httpq.connection import (
    HTTPQConnection,
    HTTPQConnectionError,
    HMAC_LABEL_CLIENT_FINISH,
    HMAC_LABEL_SERVER_FINISH,
)
from src.httpq.protocol import (
    Frame,
    MsgType,
    ProtocolError,
    expect_msg_type,
    read_frame,
    send_alert,
)

log = logging.getLogger(__name__)

_SOCKET_TIMEOUT = 30.0  # seconds


class HTTPQClient:
    """
    HTTPQ TCP client.

    Connects to a server, verifies its quantum-safe certificate, performs
    the Kyber1024 key encapsulation, and returns an authenticated encrypted
    ``HTTPQConnection``.

    Parameters
    ----------
    config : Config
        QSIP configuration.
    ca : QSIPCertificateAuthority
        Initialised CA whose root key is used to verify the server certificate.
        Must be the same CA that issued the server's certificate.

    Security
    --------
    - The server certificate is verified (ML-DSA-87 sig, expiry, revocation)
      *before* any key exchange material is sent.  An invalid cert aborts the
      connection immediately.
    - SERVER_FINISH HMAC is verified with ``hmac.compare_digest()`` (constant
      time) before CLIENT_FINISH is sent, so a rogue server cannot elicit the
      client's HMAC.
    - The session key is derived via HKDF-SHA3-512 — same parameters as
      ``HTTPQHandshake._derive_session_key()``.
    """

    def __init__(
        self,
        config: Config,
        ca: QSIPCertificateAuthority,
    ) -> None:
        self._config = config
        self._ca     = ca

    def connect(self, host: str, port: int) -> HTTPQConnection:
        """
        Connect to an HTTPQ server and return a fully-established connection.

        Parameters
        ----------
        host : str
            Server hostname or IP address.
        port : int
            Server port.

        Returns
        -------
        HTTPQConnection
            An authenticated, encrypted duplex connection.

        Raises
        ------
        HTTPQConnectionError
            If certificate verification, MAC verification, or the TCP
            connection fails.
        ProtocolError
            If the server sends a malformed frame.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_SOCKET_TIMEOUT)
        try:
            sock.connect((host, port))
        except OSError as exc:
            sock.close()
            raise HTTPQConnectionError(
                f"Cannot connect to HTTPQ server at {host}:{port}: {exc}"
            ) from exc

        try:
            return self._handshake(sock)
        except Exception as exc:
            send_alert(sock, str(exc))
            sock.close()
            raise

    # ── Handshake state machine (client) ─────────────────────────────────

    def _handshake(self, conn: socket.socket) -> HTTPQConnection:
        """Execute the HTTPQ handshake state machine (client side)."""
        handshake = HTTPQHandshake(self._config, self._ca)

        # ── Step 1: SERVER_HELLO ─────────────────────────────────────────
        frame = read_frame(conn)
        expect_msg_type(frame, MsgType.SERVER_HELLO)

        try:
            server_cert = QSIPCertificate.from_json(frame.payload.decode())
        except Exception as exc:
            raise HTTPQConnectionError(
                f"Failed to deserialise server certificate: {exc}"
            ) from exc

        # ── Step 2: Verify cert + Key encapsulation ────────────────────
        # client_hello() verifies the cert (sig + expiry + revocation).
        # For hybrid certs, we then perform X25519 + Kyber encapsulation.
        # For pure-Kyber certs, client_hello() also performs Kyber encapsulation.

        is_hybrid = server_cert.x25519_public_key is not None

        if is_hybrid:
            # Verify cert independently first (client_hello also verifies, but
            # we need to call it separately to get the Kyber-only ciphertext
            # for the first step before appending the X25519 ephemeral key).
            if self._ca is not None and not self._ca.verify_certificate(server_cert):
                raise HTTPQConnectionError(
                    f"Server certificate for '{server_cert.subject}' failed verification."
                )
            elif server_cert.is_expired():
                raise HTTPQConnectionError(
                    f"Server certificate for '{server_cert.subject}' is expired."
                )
            import secrets as _sec
            session_id   = _sec.token_bytes(32)
            hybrid       = HybridKEM(self._config)
            hybrid_result = hybrid.encapsulate(
                server_cert.kem_public_key,
                server_cert.x25519_public_key,  # type: ignore[arg-type]
            )
            kem_ciphertext  = hybrid_result.kyber_ciphertext
            x25519_eph_pk   = hybrid_result.x25519_ephemeral_public_key
            shared_secret   = hybrid_result.key_material
        else:
            try:
                session_id, kem_ciphertext, shared_secret = handshake.client_hello(
                    server_cert
                )
            except Exception as exc:
                raise HTTPQConnectionError(
                    f"Server certificate rejected or encapsulation failed: {exc}"
                ) from exc
            x25519_eph_pk = None

        # ── Step 3: CLIENT_HELLO ─────────────────────────────────────────
        payload = session_id + kem_ciphertext
        if is_hybrid and x25519_eph_pk is not None:
            payload += x25519_eph_pk
        conn.sendall(Frame(MsgType.CLIENT_HELLO, payload).encode())

        # ── Step 4: Derive session key ────────────────────────────────────
        if is_hybrid:
            session_key = _derive_hybrid_session_key(shared_secret, session_id)
        else:
            session_key = _derive_session_key(shared_secret, session_id)

        # ── Step 5: SERVER_FINISH ─────────────────────────────────────────
        frame = read_frame(conn)
        expect_msg_type(frame, MsgType.SERVER_FINISH)

        expected_server_mac = hmac.new(
            session_key, HMAC_LABEL_SERVER_FINISH, hashlib.sha3_256
        ).digest()
        if not hmac.compare_digest(frame.payload, expected_server_mac):
            raise HTTPQConnectionError(
                "SERVER_FINISH MAC verification failed — "
                "server cannot prove knowledge of session key (possible MitM)"
            )

        # ── Step 6: CLIENT_FINISH ─────────────────────────────────────────
        client_mac = hmac.new(
            session_key, HMAC_LABEL_CLIENT_FINISH, hashlib.sha3_256
        ).digest()
        conn.sendall(Frame(MsgType.CLIENT_FINISH, client_mac).encode())

        log.debug(
            "HTTPQClient: handshake complete with %r, "
            "session_id=%s",
            server_cert.subject,
            session_id.hex()[:16],
        )
        return HTTPQConnection(conn, session_key)


# ── HKDF helpers ─────────────────────────────────────────────────────────────

def _derive_session_key(shared_secret: bytes, session_id: bytes) -> bytes:
    """
    Derive a 32-byte session key from a Kyber shared secret and session ID.

    Identical to ``HTTPQHandshake._derive_session_key()``:
        session_key = HKDF-SHA3-512(
            ikm  = shared_secret,
            salt = _HTTPQ_HKDF_SALT,
            info = _HTTPQ_HKDF_INFO ‖ session_id,
            len  = 32,
        )
    """
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=_SESSION_KEY_LENGTH,
        salt=_HTTPQ_HKDF_SALT,
        info=_HTTPQ_HKDF_INFO + session_id,
    )
    return hkdf.derive(shared_secret)


def _derive_hybrid_session_key(hybrid_shared_secret: bytes, session_id: bytes) -> bytes:
    """
    Derive a 32-byte session key from a HybridKEM combined secret.

    Uses a distinct info tag ``HTTPQ-hybrid-session-key-v1`` (matching server.py)
    so pure-Kyber and hybrid session keys can never be confused.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=_SESSION_KEY_LENGTH,
        salt=_HTTPQ_HKDF_SALT,
        info=b"HTTPQ-hybrid-session-key-v1" + session_id,
    )
    return hkdf.derive(hybrid_shared_secret)
