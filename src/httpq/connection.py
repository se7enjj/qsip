"""
HTTPQConnection — AES-256-GCM encrypted duplex stream.

After the HTTPQ handshake completes, both client and server hold an
``HTTPQConnection`` backed by the same 32-byte session key.  All
application data flows through ``send()`` / ``recv()`` over this connection.

Wire format for APP_DATA frames:

    ┌─────────────────────────────────────────────────────────────┐
    │  nonce      (12 bytes, random per message)                  │
    │  ciphertext (variable) + GCM auth tag (16 bytes)            │
    └─────────────────────────────────────────────────────────────┘

Security:
- AES-256-GCM provides authenticated encryption: any bitflip in the
  ciphertext raises InvalidTag, which ``recv()`` converts to
  HTTPQConnectionError.
- Each message uses a fresh 12-byte nonce from ``secrets.token_bytes()``.
  The nonce space (2^96) is large enough that nonce collision probability
  is negligible for any realistic session (< 2^32 messages per session).
- ``session_key`` is held in memory only; it is never written to disk or
  printed (``__repr__`` returns a redacted placeholder).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import socket
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.common.exceptions import QSIPCryptoError
from src.httpq.protocol import Frame, MsgType, ProtocolError, read_frame, send_alert

if TYPE_CHECKING:
    pass

# ── Constants ──────────────────────────────────────────────────────────────
_GCM_NONCE_SIZE  = 12   # 96-bit GCM nonce — standard recommended size
_GCM_TAG_SIZE    = 16   # AES-GCM auth tag
_SESSION_KEY_LEN = 32   # AES-256

# Domain labels for Finished HMAC — prevent cross-direction reuse
HMAC_LABEL_SERVER_FINISH = b"HTTPQ-server-finished-v1"
HMAC_LABEL_CLIENT_FINISH = b"HTTPQ-client-finished-v1"


# ── Exceptions ────────────────────────────────────────────────────────────

class HTTPQConnectionError(QSIPCryptoError):
    """Raised for errors on an established HTTPQ connection."""


# ── Connection ────────────────────────────────────────────────────────────

class HTTPQConnection:
    """
    AES-256-GCM authenticated encrypted duplex stream.

    Created by ``HTTPQServer.accept()`` and ``HTTPQClient.connect()`` once
    the handshake is complete.  Do not instantiate directly.

    Parameters
    ----------
    sock : socket.socket
        The connected TCP socket (already past the handshake).
    session_key : bytes
        32-byte session key derived by both parties via HKDF-SHA3-512.
        Must NEVER be transmitted.

    Security
    --------
    - Every ``send()`` call generates a fresh 12-byte nonce.
    - AES-256-GCM authentication tag is verified on every ``recv()``.
    - Any decryption failure raises HTTPQConnectionError immediately.
    - ``session_key`` is stored only in this object's ``_session_key``
      attribute and never written to logs, repr, or disk.
    """

    __slots__ = ("_sock", "_aes", "_session_key", "_closed")

    def __init__(self, sock: socket.socket, session_key: bytes) -> None:
        if len(session_key) != _SESSION_KEY_LEN:
            raise HTTPQConnectionError(
                f"Session key must be {_SESSION_KEY_LEN} bytes, got {len(session_key)}"
            )
        self._sock         = sock
        self._aes          = AESGCM(session_key)
        self._session_key  = session_key  # kept for finished_mac()
        self._closed       = False

    # ── Application Data ─────────────────────────────────────────────────

    def send(self, plaintext: bytes) -> None:
        """
        Encrypt *plaintext* with AES-256-GCM and send it as an APP_DATA frame.

        A fresh 12-byte nonce is generated for every call.

        Parameters
        ----------
        plaintext : bytes
            Arbitrary application data.

        Raises
        ------
        HTTPQConnectionError
            If the connection is closed or the send fails.
        """
        if self._closed:
            raise HTTPQConnectionError("Connection is closed")
        nonce      = secrets.token_bytes(_GCM_NONCE_SIZE)
        ciphertext = self._aes.encrypt(nonce, plaintext, None)
        try:
            self._sock.sendall(Frame(MsgType.APP_DATA, nonce + ciphertext).encode())
        except OSError as exc:
            self._closed = True
            raise HTTPQConnectionError(f"Send failed: {exc}") from exc

    def recv(self) -> bytes:
        """
        Receive one APP_DATA frame and return the authenticated plaintext.

        Parameters
        ----------
        None

        Returns
        -------
        bytes
            Decrypted, authenticated plaintext.

        Raises
        ------
        HTTPQConnectionError
            If authentication fails, the connection is closed, or an
            unexpected frame type is received.
        """
        if self._closed:
            raise HTTPQConnectionError("Connection is closed")
        try:
            frame = read_frame(self._sock)
        except (ProtocolError, OSError) as exc:
            self._closed = True
            raise HTTPQConnectionError(f"Receive failed: {exc}") from exc

        if frame.msg_type == MsgType.ALERT:
            self._closed = True
            raise HTTPQConnectionError(
                f"Remote ALERT: {frame.payload.decode('utf-8', errors='replace')}"
            )
        if frame.msg_type != MsgType.APP_DATA:
            raise HTTPQConnectionError(
                f"Expected APP_DATA (0x{MsgType.APP_DATA:02x}), "
                f"got {frame.msg_type.name} (0x{int(frame.msg_type):02x})"
            )
        if len(frame.payload) < _GCM_NONCE_SIZE + _GCM_TAG_SIZE:
            raise HTTPQConnectionError("APP_DATA frame too short to contain nonce + tag")

        nonce      = frame.payload[:_GCM_NONCE_SIZE]
        ciphertext = frame.payload[_GCM_NONCE_SIZE:]
        try:
            return self._aes.decrypt(nonce, ciphertext, None)
        except Exception as exc:  # cryptography raises InvalidTag
            raise HTTPQConnectionError(
                "AES-256-GCM authentication tag verification failed — "
                "message tampered or corrupted"
            ) from exc

    # ── Finished MAC ─────────────────────────────────────────────────────

    def finished_mac(self, label: bytes) -> bytes:
        """
        Compute HMAC-SHA3-256 over *label* keyed with the session key.

        Used to produce and verify Finished messages during the handshake.
        Constant-time via ``hmac.compare_digest()``.

        Parameters
        ----------
        label : bytes
            Domain separation label (e.g. ``HMAC_LABEL_SERVER_FINISH``).

        Returns
        -------
        bytes
            32-byte MAC.
        """
        return hmac.new(self._session_key, label, hashlib.sha3_256).digest()

    def verify_finished_mac(self, received: bytes, label: bytes) -> bool:
        """Return True if *received* matches the expected Finished MAC (constant-time)."""
        expected = self.finished_mac(label)
        return hmac.compare_digest(received, expected)

    # ── Lifecycle ────────────────────────────────────────────────────────

    def send_alert(self, reason: str) -> None:
        """Best-effort: send an ALERT frame before closing."""
        if not self._closed:
            send_alert(self._sock, reason)

    def close(self) -> None:
        """Close the underlying socket."""
        if not self._closed:
            self._closed = True
            try:
                self._sock.close()
            except OSError:
                pass

    def __enter__(self) -> "HTTPQConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"HTTPQConnection(session_key=<REDACTED>, closed={self._closed})"
        )
