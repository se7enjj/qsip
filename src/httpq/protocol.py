"""
HTTPQ wire protocol — binary frame format.

Every TCP message, in both directions, is wrapped in an HTTPQ frame:

    ┌──────────────────────────────────────────────────────┐
    │  Frame Header (5 bytes)                              │
    │  ┌──────────┬───────────────────────────────────┐   │
    │  │ msg_type │ payload_length (big-endian uint32) │   │
    │  │ (1 byte) │ (4 bytes)                         │   │
    │  └──────────┴───────────────────────────────────┘   │
    ├──────────────────────────────────────────────────────┤
    │  Payload (payload_length bytes)                      │
    └──────────────────────────────────────────────────────┘

Message types and their payloads:

    SERVER_HELLO  0x01   JSON-encoded QSIPCertificate (sent by server)
    CLIENT_HELLO  0x02   session_id (32 bytes) ‖ kem_ciphertext (1568 bytes)
    SERVER_FINISH 0x03   HMAC-SHA3-256 proof of session key ownership (32 bytes)
    CLIENT_FINISH 0x04   HMAC-SHA3-256 proof of session key ownership (32 bytes)
    APP_DATA      0x10   nonce (12 bytes) ‖ AES-256-GCM ciphertext+tag
    ALERT         0xFF   UTF-8 error reason (best-effort, sent before close)

Design notes:
- Max frame payload is 64 KiB. Larger application data must be fragmented
  at the layer above (not yet implemented — planned v0.2).
- `read_frame()` performs exactly two `recv()` calls: one 5-byte header,
  one payload. This avoids partial-read bugs that cause protocol confusion.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import socket as _socket_mod

# ── Constants ──────────────────────────────────────────────────────────────
FRAME_HEADER_SIZE = 5           # 1 type byte + 4 length bytes
MAX_FRAME_PAYLOAD = 64 * 1024   # 64 KiB — prevents allocation-of-death
_STRUCT_HEADER = struct.Struct(">BI")  # unsigned byte + unsigned int, big-endian


# ── Message Types ──────────────────────────────────────────────────────────

class MsgType(IntEnum):
    """HTTPQ frame message types."""

    # Handshake messages
    SERVER_HELLO  = 0x01
    CLIENT_HELLO  = 0x02
    SERVER_FINISH = 0x03
    CLIENT_FINISH = 0x04

    # Application data (post-handshake)
    APP_DATA = 0x10

    # Error (best-effort, sent before closing the connection)
    ALERT = 0xFF


# ── Frame ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Frame:
    """
    A single HTTPQ wire frame.

    Attributes
    ----------
    msg_type : MsgType
        Frame type — determines how the payload is interpreted.
    payload : bytes
        Raw payload bytes. Maximum ``MAX_FRAME_PAYLOAD`` bytes.

    Security
    --------
    The frame format itself provides no authentication or confidentiality.
    Authentication and encryption are provided by the session layer:
    Finished messages use HMAC-SHA3-256; APP_DATA uses AES-256-GCM.
    """

    msg_type: MsgType
    payload: bytes

    def encode(self) -> bytes:
        """Serialise to wire bytes (header + payload)."""
        if len(self.payload) > MAX_FRAME_PAYLOAD:
            raise ValueError(
                f"HTTPQ frame payload too large: {len(self.payload)} bytes "
                f"(max {MAX_FRAME_PAYLOAD})"
            )
        return _STRUCT_HEADER.pack(int(self.msg_type), len(self.payload)) + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "Frame":
        """Deserialise a frame from raw bytes (header + payload)."""
        if len(data) < FRAME_HEADER_SIZE:
            raise ProtocolError(
                f"Frame too short: {len(data)} bytes (need at least {FRAME_HEADER_SIZE})"
            )
        msg_type_byte, length = _STRUCT_HEADER.unpack(data[:FRAME_HEADER_SIZE])
        payload = data[FRAME_HEADER_SIZE:]
        if len(payload) != length:
            raise ProtocolError(
                f"Frame payload size mismatch: expected {length}, got {len(payload)}"
            )
        try:
            return cls(msg_type=MsgType(msg_type_byte), payload=payload)
        except ValueError as exc:
            raise ProtocolError(f"Unknown message type: 0x{msg_type_byte:02x}") from exc


# ── Socket I/O ────────────────────────────────────────────────────────────

class ProtocolError(Exception):
    """Raised for HTTPQ wire protocol violations."""


def read_frame(sock: "_socket_mod.socket") -> Frame:
    """
    Read exactly one HTTPQ frame from *sock*.

    Performs two ``recv()`` calls:
    1. Read the 5-byte frame header.
    2. Read exactly ``payload_length`` bytes.

    Parameters
    ----------
    sock : socket.socket
        A connected TCP socket with an optional timeout already set.

    Returns
    -------
    Frame
        The decoded frame.

    Raises
    ------
    ProtocolError
        If the connection is closed, a frame is malformed, or the payload
        exceeds ``MAX_FRAME_PAYLOAD``.
    """
    header = _recv_exact(sock, FRAME_HEADER_SIZE)
    msg_type_byte, length = _STRUCT_HEADER.unpack(header)
    if length > MAX_FRAME_PAYLOAD:
        raise ProtocolError(f"Frame payload too large: {length} (max {MAX_FRAME_PAYLOAD})")
    payload = _recv_exact(sock, length)
    try:
        msg_type = MsgType(msg_type_byte)
    except ValueError as exc:
        raise ProtocolError(f"Unknown MsgType: 0x{msg_type_byte:02x}") from exc
    return Frame(msg_type=msg_type, payload=payload)


def send_frame(sock: "_socket_mod.socket", frame: Frame) -> None:
    """Encode *frame* and send it atomically with ``sendall``."""
    sock.sendall(frame.encode())


def send_alert(sock: "_socket_mod.socket", reason: str) -> None:
    """
    Best-effort: send an ALERT frame and close the socket.

    Does not raise — alerts are fired in error paths where raising would
    mask the underlying exception.
    """
    try:
        sock.sendall(Frame(MsgType.ALERT, reason.encode("utf-8", errors="replace")).encode())
    except OSError:
        pass  # Already closed — nothing we can do


# ── Protocol validation helper ───────────────────────────────────────────

def expect_msg_type(frame: "Frame", expected: "MsgType") -> None:
    """
    Raise ProtocolError if *frame* is not the expected message type.

    Used by both HTTPQServer and HTTPQClient to validate each handshake step.
    """
    if frame.msg_type != expected:
        raise ProtocolError(
            f"HTTPQ handshake error: expected {expected.name} "
            f"(0x{int(expected):02x}), got {frame.msg_type.name} "
            f"(0x{int(frame.msg_type):02x})"
        )


# ── Helpers ───────────────────────────────────────────────────────────────

def _recv_exact(sock: "_socket_mod.socket", n: int) -> bytes:
    """Receive exactly *n* bytes from *sock*, handling short reads."""
    buf = bytearray(n)
    view = memoryview(buf)
    received = 0
    while received < n:
        chunk = sock.recv_into(view[received:], n - received)
        if chunk == 0:
            raise ProtocolError(
                f"Connection closed after {received} bytes (expected {n})"
            )
        received += chunk
    return bytes(buf)
