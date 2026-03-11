"""
HTTPQServer — TCP server with HTTPQ quantum-safe handshake.

Listens on a TCP port, accepts client connections, executes the
HTTPQ handshake state machine, and returns an ``HTTPQConnection``
ready for encrypted application data.

Handshake (server perspective):

    1. Accept TCP connection
    2. Send  SERVER_HELLO  — certificate (JSON-serialised QSIPCertificate)
    3. Recv  CLIENT_HELLO  — session_id (32 B) ‖ kem_ciphertext (1568 B)
    4. Decapsulate KEM ciphertext with server secret key
    5. Derive session_key = HKDF-SHA3-512(shared_secret, session_id)
    6. Send  SERVER_FINISH — HMAC-SHA3-256(session_key, SERVER_FINISH_LABEL)
    7. Recv  CLIENT_FINISH — verify HMAC
    8. Return HTTPQConnection(sock, session_key)

Usage::

    config   = Config()
    ca       = QSIPCertificateAuthority(config)
    root     = ca.initialise("QSIP Root CA")
    kem_kp   = KyberKEM(config).generate_keypair()
    sig_kp   = DilithiumSigner(config).generate_keypair()
    cert     = ca.issue_certificate("server.example.com",
                                    kem_kp.public_key, sig_kp.verify_key)

    with HTTPQServer(config, ca, cert, kem_kp.secret_key) as srv:
        conn = srv.accept()              # blocks until client connects
        with conn:
            data = conn.recv()
            conn.send(b"ACK: " + data)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import socket

from src.ca.authority import QSIPCertificateAuthority
from src.ca.certificate import QSIPCertificate
from src.ca.handshake import HTTPQHandshake, _HTTPQ_HKDF_SALT, _SESSION_KEY_LENGTH
from src.common.config import Config
from src.crypto.hybrid import HybridKEM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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

_SOCKET_TIMEOUT    = 30.0   # seconds — per-connection handshake + I/O timeout
_BACKLOG           = 5      # listen() backlog
_SESSION_ID_OFFSET = 0
_SESSION_ID_LEN    = 32
_KEM_CT_OFFSET     = _SESSION_ID_LEN  # 32
_X25519_PK_LEN     = 32    # raw X25519 public key length


class HTTPQServer:
    """
    HTTPQ TCP server.

    Binds to *host*:*port*, accepts a single TLS-equivalent HTTPQ
    connection, performs the quantum-safe handshake, and returns an
    ``HTTPQConnection`` for encrypted application data.

    For testing and demos this is single-shot (one ``accept()`` at a time).
    A production service would call ``accept()`` in a loop on a thread pool.

    Parameters
    ----------
    config : Config
        QSIP configuration.
    ca : QSIPCertificateAuthority
        Initialised CA used to issue the server certificate.
    server_cert : QSIPCertificate
        The server's end-entity certificate (public — sent to clients).
    server_kem_sk : bytes
        The server's Kyber1024 secret key (private — never transmitted).
    host : str
        Bind address. Default ``"127.0.0.1"``.
    port : int
        Bind port. Default ``8765``. Use ``0`` for OS-assigned ephemeral port.

    Security
    --------
    - ``server_kem_sk`` never appears in logs, repr, or network traffic.
    - Each ``accept()`` call creates a new ``HTTPQHandshake`` instance with
      a fresh session ID, so session keys are never reused.
    - CLIENT_FINISH HMAC is verified with ``hmac.compare_digest()``
      (constant-time) before the HTTPQConnection is returned.
    """

    def __init__(
        self,
        config: Config,
        ca: QSIPCertificateAuthority,
        server_cert: QSIPCertificate,
        server_kem_sk: bytes,
        host: str = "127.0.0.1",
        port: int = 8765,
        x25519_sk: bytes | None = None,
    ) -> None:
        self._config        = config
        self._ca            = ca
        self._server_cert   = server_cert
        self._server_kem_sk = server_kem_sk
        self._host          = host
        self._port          = port
        self._x25519_sk     = x25519_sk   # None = pure Kyber; bytes = hybrid
        self._sock: socket.socket | None = None

    # ── Context manager ──────────────────────────────────────────────────

    def __enter__(self) -> "HTTPQServer":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(_BACKLOG)
        # Update port in case OS assigned one (port=0)
        self._port = self._sock.getsockname()[1]
        log.debug("HTTPQServer listening on %s:%d", self._host, self._port)
        return self

    def __exit__(self, *_args: object) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ── Public API ───────────────────────────────────────────────────────

    @property
    def port(self) -> int:
        """The actual bound port (useful when ``port=0`` was passed)."""
        return self._port

    def accept(self) -> HTTPQConnection:
        """
        Accept one TCP connection and complete the HTTPQ handshake.

        Blocks until a client connects.  Returns a fully-established
        ``HTTPQConnection`` ready for ``send()`` / ``recv()``.

        Raises
        ------
        RuntimeError
            If the server is not running (not used as a context manager).
        HTTPQConnectionError
            If the handshake fails (cert verification, bad MAC, etc.).
        ProtocolError
            If the client sends a malformed frame.
        """
        if self._sock is None:
            raise RuntimeError(
                "HTTPQServer is not listening. Use it as a context manager: "
                "with HTTPQServer(...) as srv:"
            )
        conn, addr = self._sock.accept()
        conn.settimeout(_SOCKET_TIMEOUT)
        log.debug("HTTPQServer: accepted connection from %s:%d", *addr)
        try:
            return self._handshake(conn)
        except Exception as exc:
            send_alert(conn, str(exc))
            conn.close()
            raise

    # ── Handshake state machine (server) ─────────────────────────────────

    def _handshake(self, conn: socket.socket) -> HTTPQConnection:
        """Execute the HTTPQ handshake state machine (server side)."""
        handshake = HTTPQHandshake(self._config, self._ca)

        # ── Step 1: SERVER_HELLO ─────────────────────────────────────────
        cert_json = self._server_cert.to_json()
        conn.sendall(Frame(MsgType.SERVER_HELLO, cert_json.encode()).encode())

        # ── Step 2: CLIENT_HELLO ─────────────────────────────────────────
        frame = read_frame(conn)
        expect_msg_type(frame, MsgType.CLIENT_HELLO)

        kem_ct_len  = self._kem_ct_len()
        pure_len    = _SESSION_ID_LEN + kem_ct_len
        hybrid_len  = pure_len + _X25519_PK_LEN
        payload_len = len(frame.payload)

        if payload_len == hybrid_len:
            is_hybrid = True
        elif payload_len == pure_len:
            is_hybrid = False
        else:
            raise HTTPQConnectionError(
                f"CLIENT_HELLO payload wrong length: got {payload_len}, "
                f"expected {pure_len} (pure-Kyber) or {hybrid_len} (hybrid)"
            )

        session_id     = frame.payload[:_SESSION_ID_LEN]
        kem_ciphertext = frame.payload[_KEM_CT_OFFSET : _KEM_CT_OFFSET + kem_ct_len]

        # ── Step 3: Derive shared secret ──────────────────────────────────
        if is_hybrid:
            if self._x25519_sk is None:
                raise HTTPQConnectionError(
                    "Client sent a hybrid CLIENT_HELLO but server has no X25519 "
                    "secret key. Pass x25519_sk= to HTTPQServer to enable hybrid mode."
                )
            x25519_eph_pk = frame.payload[_KEM_CT_OFFSET + kem_ct_len:]
            hybrid        = HybridKEM(self._config)
            shared_secret = hybrid.decapsulate(
                kem_ciphertext, x25519_eph_pk,
                self._server_kem_sk, self._x25519_sk,
            )
            session_key = _derive_session_key_from_hybrid(shared_secret, session_id)
        else:
            session_key = handshake.server_finish(
                kem_ciphertext, self._server_kem_sk, session_id
            )

        # ── Step 4: SERVER_FINISH ─────────────────────────────────────────
        mac = hmac.new(session_key, HMAC_LABEL_SERVER_FINISH, hashlib.sha3_256).digest()
        conn.sendall(Frame(MsgType.SERVER_FINISH, mac).encode())

        # ── Step 5: CLIENT_FINISH ─────────────────────────────────────────
        frame = read_frame(conn)
        expect_msg_type(frame, MsgType.CLIENT_FINISH)

        expected_mac = hmac.new(
            session_key, HMAC_LABEL_CLIENT_FINISH, hashlib.sha3_256
        ).digest()
        if not hmac.compare_digest(frame.payload, expected_mac):
            raise HTTPQConnectionError(
                "CLIENT_FINISH MAC verification failed — "
                "possible man-in-the-middle or implementation bug"
            )

        log.debug(
            "HTTPQServer: handshake complete (%s), session_id=%s",
            "hybrid" if is_hybrid else "pure-Kyber",
            session_id.hex()[:16],
        )
        return HTTPQConnection(conn, session_key)

    def _kem_ct_len(self) -> int:
        """Expected Kyber1024 ciphertext length (1568 bytes)."""
        # Kyber1024 ciphertext is always 1568 bytes.
        # We compute from the cert kem_public_key length to stay algorithm-agnostic.
        # Kyber512→768→1024 ciphertext lengths: 736→1088→1568
        pk_len = len(self._server_cert.kem_public_key)
        _KEM_CT_LENGTHS = {800: 768, 1184: 1088, 1568: 1568}
        return _KEM_CT_LENGTHS.get(pk_len, 1568)


# ── HKDF helper for hybrid shared secrets ──────────────────────────────────────

def _derive_session_key_from_hybrid(hybrid_shared_secret: bytes, session_id: bytes) -> bytes:
    """
    Derive an HTTPQ session key from a hybrid (X25519+Kyber) combined secret.

    Distinct info tag ``HTTPQ-hybrid-session-key-v1`` ensures hybrid session keys
    cannot be confused with pure-Kyber session keys.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=_SESSION_KEY_LENGTH,
        salt=_HTTPQ_HKDF_SALT,
        info=b"HTTPQ-hybrid-session-key-v1" + session_id,
    )
    return hkdf.derive(hybrid_shared_secret)



