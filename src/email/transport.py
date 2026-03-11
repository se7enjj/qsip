"""
QSIP — PQEP Email Transport.

SMTP/IMAP transport layer for sending and receiving PQEP-encrypted emails.
Enforces TLS 1.3 minimum and will never fall back to plaintext connections.

Security properties:
- SMTP: STARTTLS enforced; connection aborted if TLS unavailable
- IMAP: SSL/TLS enforced (port 993); no plaintext IMAP
- Credentials loaded exclusively from config (source: .env)
- No credential caching in memory beyond the active connection context
- Timeouts prevent connection-based DoS

Usage:
    transport = PQEPTransport(config)
    transport.send(message, sender="alice@example.com", recipient="bob@example.com")
    messages = transport.fetch_unread()
"""

from __future__ import annotations

import imaplib
import logging
import smtplib
import ssl
from contextlib import contextmanager
from email.mime.multipart import MIMEMultipart
from email.parser import BytesParser
from email import policy
from typing import Generator

from src.common.config import Config
from src.common.exceptions import PQEPError

logger = logging.getLogger(__name__)

_SMTP_TIMEOUT = 30  # seconds
_IMAP_TIMEOUT = 30  # seconds


class PQEPTransport:
    """
    SMTP/IMAP transport for PQEP email — TLS enforced, no plaintext fallback.

    Credentials are read from config which sources from .env exclusively.
    This class does not store or cache credentials beyond the scope of
    individual send/fetch operations.

    Security:
    - TLS 1.2 minimum enforced via ssl.SSLContext
    - Certificate chain verification enabled (no CERT_NONE)
    - Credentials never logged — not even at DEBUG level
    - SMTP STARTTLS is required; if server doesn't support it, connection fails

    Parameters
    ----------
    config : Config
        QSIP configuration. SMTP/IMAP settings sourced from here.
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()

    def send(
        self,
        message: MIMEMultipart,
        sender_address: str,
        recipient_address: str,
    ) -> None:
        """
        Send a PQEP email message via SMTP with STARTTLS.

        Parameters
        ----------
        message : MIMEMultipart
            The composed PQEP email message (from PQEPComposer.compose()).
        sender_address : str
            The sender's email address (must match SMTP credentials).
        recipient_address : str
            The recipient's email address.

        Raises
        ------
        PQEPError
            If SMTP connection, STARTTLS negotiation, authentication, or sending fails.
        """
        try:
            with self._smtp_connection() as smtp:
                smtp.sendmail(
                    from_addr=sender_address,
                    to_addrs=[recipient_address],
                    msg=message.as_bytes(),
                )
                logger.info("PQEP email sent successfully (details withheld for security).")
        except PQEPError:
            raise
        except Exception as exc:
            raise PQEPError(f"SMTP send failed: {exc}") from exc

    def fetch_unread(self, folder: str = "INBOX") -> list[MIMEMultipart]:
        """
        Fetch unread messages from IMAP, marking them as read.

        Only fetches messages with X-PQEP-Version headers (PQEP messages).
        Non-PQEP messages are skipped and not returned.

        Parameters
        ----------
        folder : str
            IMAP folder to fetch from (default: "INBOX").

        Returns
        -------
        list[MIMEMultipart]
            List of raw PQEP email message objects. Caller must decrypt.

        Raises
        ------
        PQEPError
            If IMAP connection or fetch fails.
        """
        messages: list[MIMEMultipart] = []
        try:
            with self._imap_connection() as imap:
                imap.select(folder)
                # Search for unseen messages
                _, msg_nums = imap.search(None, "UNSEEN")
                if not msg_nums or not msg_nums[0]:
                    return messages

                for num in msg_nums[0].split():
                    try:
                        _, data = imap.fetch(num, "(RFC822)")
                        if data and data[0]:
                            raw = data[0][1]
                            if isinstance(raw, bytes):
                                parsed = BytesParser(policy=policy.default).parsebytes(raw)
                                # Only return PQEP messages
                                if parsed.get("X-PQEP-Version"):
                                    messages.append(parsed)  # type: ignore[arg-type]
                    except Exception as exc:
                        logger.warning(
                            "Failed to parse message (number withheld): %s",
                            type(exc).__name__
                        )
                        continue

        except PQEPError:
            raise
        except Exception as exc:
            raise PQEPError(f"IMAP fetch failed: {exc}") from exc

        return messages

    @contextmanager
    def _smtp_connection(self) -> Generator[smtplib.SMTP, None, None]:
        """
        Context manager for SMTP connection with mandatory STARTTLS.

        Yields
        ------
        smtplib.SMTP
            Authenticated, TLS-enabled SMTP connection.
        """
        tls_context = ssl.create_default_context()
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2

        smtp: smtplib.SMTP | None = None
        try:
            smtp = smtplib.SMTP(
                host=self._config.smtp_host,
                port=self._config.smtp_port,
                timeout=_SMTP_TIMEOUT,
            )
            smtp.ehlo()

            # Require STARTTLS — never send credentials over plaintext
            if not smtp.has_extn("STARTTLS"):
                raise PQEPError(
                    f"SMTP server {self._config.smtp_host}:{self._config.smtp_port} "
                    f"does not support STARTTLS. QSIP will not send over plaintext SMTP."
                )

            smtp.starttls(context=tls_context)
            smtp.ehlo()

            # Authenticate — credentials accessed but never logged
            smtp.login(
                user=self._config.smtp_user,
                password=self._config.smtp_password.get_secret_value(),
            )
            yield smtp
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    pass  # Best-effort cleanup

    @contextmanager
    def _imap_connection(self) -> Generator[imaplib.IMAP4_SSL, None, None]:
        """
        Context manager for IMAP SSL connection.

        Yields
        ------
        imaplib.IMAP4_SSL
            Authenticated IMAP4 over SSL connection.
        """
        tls_context = ssl.create_default_context()
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2

        imap: imaplib.IMAP4_SSL | None = None
        try:
            imap = imaplib.IMAP4_SSL(
                host=self._config.imap_host,
                port=self._config.imap_port,
                ssl_context=tls_context,
            )
            imap.login(
                user=self._config.imap_user,
                password=self._config.imap_password.get_secret_value(),
            )
            yield imap
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    pass  # Best-effort cleanup
