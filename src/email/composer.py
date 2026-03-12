"""
QSIP — PQEP Email Composer.

Constructs RFC 5322-compatible email messages with Post-Quantum Email Protocol
(PQEP) extension headers that carry the KEM ciphertext and sender identity.

PQEP Headers added to each message:
    X-PQEP-Version: 1
    X-PQEP-KEM: ML-KEM-1024
    X-PQEP-SIG: ML-DSA-87
    X-PQEP-Sender-PK: <base64 ML-DSA-87 verify key>
    X-PQEP-KEM-CT: <base64 ML-KEM ciphertext>
    X-PQEP-Nonce: <base64 AES-GCM nonce>

Optional encrypted-metadata headers (v0.2+):
    X-PQEP-Metadata: <base64 AES-256-GCM ciphertext of {subject, from, to}>
    X-PQEP-Metadata-Nonce: <base64 AES-GCM nonce for metadata>

When encrypted metadata is present, the plaintext Subject header is replaced
with "[PQEP Encrypted]", hiding message subject and addressing from observers.
The recipient uses PQEPEncryptor.decrypt_metadata() to recover the real values.

Security:
- When metadata is not encrypted (default), Subject is plaintext (metadata leak!).
- Enable metadata encryption by passing `metadata=...` to PQEPEncryptor.encrypt().
- All headers exposing key material are base64-encoded for compactness.
- The sender_signature is included in the body (not a header) to avoid header size limits.

Usage (with encrypted metadata):
    encryptor = PQEPEncryptor(config)
    payload = encryptor.encrypt(
        plaintext=b"Hello!",
        recipient_kem_public_key=recipient_pk,
        sender_keypair=sender,
        metadata={"subject": "Secret topic", "from": "alice@example.com", "to": "bob@example.com"},
    )
    composer = PQEPComposer(config)
    message = composer.compose(payload, sender_address="alice@example.com", recipient_address="bob@example.com")
    # Subject is now "[PQEP Encrypted]" in outbound email.
"""

from __future__ import annotations

import json
from base64 import b64encode
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email import encoders
from datetime import datetime, timezone

from src.common.config import Config
from src.common.exceptions import PQEPError
from src.email.encryptor import PQEPEncryptedPayload

# PQEP MIME content type
_PQEP_CONTENT_TYPE = "application/x-pqep"

# Maximum subject line length (not encrypted, keep short to minimize metadata)
_MAX_SUBJECT_LENGTH = 200


class PQEPComposer:
    """
    Composes RFC 5322 email messages with PQEP headers and encrypted body.

    Takes a PQEPEncryptedPayload (produced by PQEPEncryptor) and assembles
    a complete email message with PQEP extension headers.

    Parameters
    ----------
    config : Config
        QSIP configuration instance.
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()

    def compose(
        self,
        payload: PQEPEncryptedPayload,
        sender_address: str,
        recipient_address: str,
        subject: str = "",
    ) -> MIMEMultipart:
        """
        Compose a PQEP email message.

        Parameters
        ----------
        payload : PQEPEncryptedPayload
            The encrypted payload from PQEPEncryptor.
        sender_address : str
            Sender's email address (goes into the From header).
        recipient_address : str
            Recipient's email address.
        subject : str
            Email subject line. Used as cleartext ONLY when the payload does
            not contain encrypted metadata. When payload.encrypted_metadata is
            set, this param is ignored and Subject becomes "[PQEP Encrypted]".
            Max length: 200 characters.

        Returns
        -------
        MIMEMultipart
            Complete email message with PQEP headers and encrypted body.

        Raises
        ------
        PQEPError
            If message composition fails.
        """
        # Only validate plaintext subject length when metadata is NOT encrypted.
        # When metadata IS encrypted, the subject arg is ignored entirely.
        metadata_encrypted = payload.encrypted_metadata is not None
        if not metadata_encrypted and len(subject) > _MAX_SUBJECT_LENGTH:
            raise PQEPError(
                f"Subject line too long ({len(subject)} > {_MAX_SUBJECT_LENGTH} chars). "
                f"Note: subject lines are NOT encrypted — keep them minimal."
            )

        try:
            message = MIMEMultipart("mixed")
            message["From"] = sender_address
            message["To"] = recipient_address
            message["Date"] = datetime.now(tz=timezone.utc).strftime(
                "%a, %d %b %Y %H:%M:%S %z"
            )

            # Subject: hide behind generic placeholder when metadata is encrypted.
            # The real subject is in payload.encrypted_metadata (decryptable by recipient).
            if metadata_encrypted:
                message["Subject"] = "[PQEP Encrypted]"
            else:
                message["Subject"] = subject if subject else "[PQEP Encrypted Message]"

            # PQEP extension headers
            message["X-PQEP-Version"] = str(payload.pqep_version)
            message["X-PQEP-KEM"] = payload.kem_algorithm
            message["X-PQEP-SIG"] = payload.sig_algorithm
            message["X-PQEP-Sender-PK"] = b64encode(payload.sender_verify_key).decode()
            message["X-PQEP-KEM-CT"] = b64encode(payload.kem_ciphertext).decode()
            message["X-PQEP-Nonce"] = b64encode(payload.nonce).decode()

            # Optional encrypted metadata headers (v0.2+)
            if payload.encrypted_metadata is not None and payload.metadata_nonce is not None:
                message["X-PQEP-Metadata"] = b64encode(payload.encrypted_metadata).decode()
                message["X-PQEP-Metadata-Nonce"] = b64encode(payload.metadata_nonce).decode()

            # Build the PQEP body: JSON envelope containing encrypted content + sig
            body_envelope = json.dumps({
                "pqep_version": payload.pqep_version,
                "encrypted_body": b64encode(payload.encrypted_body).decode(),
                "sender_signature": b64encode(payload.sender_signature).decode(),
            }, separators=(",", ":"))

            # Attach as application/x-pqep MIME part
            pqep_part = MIMEBase("application", "x-pqep")
            pqep_part.set_payload(body_envelope.encode("utf-8"))
            pqep_part["Content-Disposition"] = "inline"
            pqep_part["Content-Description"] = "PQEP Encrypted Email Body"
            message.attach(pqep_part)

        except PQEPError:
            raise
        except Exception as exc:
            raise PQEPError(f"PQEP message composition failed: {exc}") from exc

        return message

    def parse_pqep_headers(self, message: MIMEMultipart) -> dict[str, str]:
        """
        Extract PQEP headers from a received email message.

        Parameters
        ----------
        message : MIMEMultipart
            The received email message.

        Returns
        -------
        dict[str, str]
            Extracted PQEP header values keyed by header name.

        Raises
        ------
        PQEPError
            If required PQEP headers are missing.
        """
        required = [
            "X-PQEP-Version",
            "X-PQEP-KEM",
            "X-PQEP-SIG",
            "X-PQEP-Sender-PK",
            "X-PQEP-KEM-CT",
            "X-PQEP-Nonce",
        ]
        headers = {}
        missing = []

        for header in required:
            value = message.get(header)
            if value is None:
                missing.append(header)
            else:
                headers[header] = value

        if missing:
            raise PQEPError(
                f"Received email is missing required PQEP headers: {missing}. "
                f"This message may not be PQEP-encrypted."
            )

        # Optional metadata headers (v0.2+) — include if present
        for opt_header in ("X-PQEP-Metadata", "X-PQEP-Metadata-Nonce"):
            value = message.get(opt_header)
            if value is not None:
                headers[opt_header] = value

        return headers
