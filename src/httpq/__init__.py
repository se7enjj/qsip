"""
QSIP HTTPQ — Quantum-Safe TLS-equivalent transport layer.

This package contains the real TCP socket implementation of the HTTPQ
handshake and encrypted application-data stream.

    Protocol layers
    ───────────────────────────────────────────────────────────────
    httpq.protocol     Wire frame format (type + length-prefixed)
    httpq.connection   AES-256-GCM encrypted duplex stream
    httpq.server       HTTPQServer — TCP listener + handshake state machine
    httpq.client       HTTPQClient — TCP connector + handshake state machine

Handshake flow over a real TCP socket:

    Client                                   Server
    ──────                                   ──────
    connect()
                            ←── SERVER_HELLO (QSIPCertificate in wire format)
    verify ML-DSA-87 cert sig
    Kyber encapsulate(cert.kem_public_key)
    ──── CLIENT_HELLO (session_id ‖ kem_ct) ──►
                                             Kyber decapsulate
                                             HKDF-SHA3-512(shared_secret, session_id)
                                             → session_key
                            ←── SERVER_FINISH (HMAC-SHA3-256(session_key, label))
    verify HMAC
    HKDF-SHA3-512(shared_secret, session_id)
    → session_key
    ──── CLIENT_FINISH (HMAC-SHA3-256(session_key, label)) ──►
                                             verify HMAC
    ══════════════════ APP_DATA (AES-256-GCM) ══════════════════

After the handshake both parties hold the same 32-byte session_key,
which is used exclusively for AES-256-GCM encrypted application data.
The session_key never appears on the wire.

Security properties:
  IND-CCA2   : ciphertext interception cannot recover shared secret
  Auth       : server ML-DSA-87 cert verified before key exchange
  Fwd secr.  : fresh Kyber encapsulation per connection
  KE         : HMAC Finished messages bind session_key to both sides
  PQC        : no RSA, ECDH, or ECDSA anywhere
"""

from src.httpq.client import HTTPQClient
from src.httpq.connection import HTTPQConnection, HTTPQConnectionError
from src.httpq.protocol import Frame, MsgType
from src.httpq.server import HTTPQServer

__all__ = [
    "HTTPQClient",
    "HTTPQServer",
    "HTTPQConnection",
    "HTTPQConnectionError",
    "Frame",
    "MsgType",
]
