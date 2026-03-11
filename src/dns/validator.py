"""
QSIP — DNS Record PQC Validator.

Parses and validates QSIP PQC extension TXT records.

QSIP DNS TXT record format:
    _pqc.<domain>.  IN  TXT  "v=QSIP1; alg=Dilithium5; pk=<base64>; sig=<base64>"

Fields:
- v     : Protocol version (must be "QSIP1")
- alg   : Signature algorithm (must be from ALLOWED_SIG_ALGORITHMS)
- pk    : Dilithium verify key, base64-encoded
- sig   : Dilithium signature over the canonical record set, base64-encoded

Security properties:
- Algorithm is validated against the QSIP allowlist before any crypto operation
- Malformed records are rejected (not silently ignored)
- Base64 decode errors produce DNSValidationError, not generic exceptions

Usage:
    from src.dns.validator import DNSRecordValidator
    validator = DNSRecordValidator(config)
    parsed = validator.parse_qsip_record(txt_record_string)
    # parsed = {"v": "QSIP1", "alg": "Dilithium5", "pk": "...", "sig": "..."}
    # or None if the record is not a QSIP record
"""

from __future__ import annotations

import logging
import re
from base64 import b64decode
from typing import Any

from src.common.config import Config, ALLOWED_SIG_ALGORITHMS
from src.common.exceptions import DNSValidationError

logger = logging.getLogger(__name__)

# Maximum lengths to prevent DoS via oversized records
_MAX_PK_B64_LEN = 12_000     # Dilithium5 verify key: ~2592 bytes = ~3456 b64 chars
_MAX_SIG_B64_LEN = 12_000    # Dilithium5 signature: ~4595 bytes = ~6128 b64 chars

# Required QSIP record version
_QSIP_VERSION = "QSIP1"


class DNSRecordValidator:
    """
    Parses QSIP PQC extension TXT records and validates their structure.

    Does NOT perform cryptographic signature verification — that is the
    responsibility of the caller (PQCResolver) using DilithiumSigner.verify().
    This class handles parsing, format validation, and algorithm allowlisting.

    Parameters
    ----------
    config : Config
        QSIP configuration instance.
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()

    def parse_qsip_record(self, txt_record: str) -> dict[str, str] | None:
        """
        Parse a DNS TXT record string into QSIP fields.

        Returns None if the record is not a QSIP record (missing `v=QSIP1`).
        Raises DNSValidationError if it looks like a QSIP record but is malformed.

        Parameters
        ----------
        txt_record : str
            Raw TXT record string (e.g., '"v=QSIP1; alg=Dilithium5; pk=...; sig=..."').

        Returns
        -------
        dict[str, str] | None
            Parsed fields or None if not a QSIP record.

        Raises
        ------
        DNSValidationError
            If the record is malformed, has unsupported algorithm, or invalid b64.
        """
        # Strip surrounding quotes from DNS record string
        record = txt_record.strip().strip('"').strip("'")

        # Quick check: is this a QSIP record at all?
        if "v=QSIP" not in record:
            return None

        # Parse semicolon-separated key=value pairs
        fields: dict[str, str] = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            key, _, value = part.partition("=")
            fields[key.strip().lower()] = value.strip()

        # Validate version
        if fields.get("v") != _QSIP_VERSION:
            raise DNSValidationError(
                f"Unsupported QSIP record version '{fields.get('v')}'. "
                f"Expected '{_QSIP_VERSION}'."
            )

        # Validate required fields
        for required in ("alg", "pk", "sig"):
            if required not in fields:
                raise DNSValidationError(
                    f"QSIP TXT record missing required field '{required}'."
                )

        # Validate algorithm allowlist
        alg = fields["alg"]
        if alg not in ALLOWED_SIG_ALGORITHMS:
            raise DNSValidationError(
                f"QSIP record uses disallowed signature algorithm '{alg}'. "
                f"Allowed: {sorted(ALLOWED_SIG_ALGORITHMS)}"
            )

        # Validate base64 lengths and decodability
        pk_b64 = fields["pk"]
        sig_b64 = fields["sig"]

        if len(pk_b64) > _MAX_PK_B64_LEN:
            raise DNSValidationError(
                f"QSIP record 'pk' field exceeds maximum length ({_MAX_PK_B64_LEN} chars)."
            )
        if len(sig_b64) > _MAX_SIG_B64_LEN:
            raise DNSValidationError(
                f"QSIP record 'sig' field exceeds maximum length ({_MAX_SIG_B64_LEN} chars)."
            )

        try:
            b64decode(pk_b64, validate=True)
        except Exception as exc:
            raise DNSValidationError(
                f"QSIP record 'pk' field is not valid base64: {exc}"
            ) from exc

        try:
            b64decode(sig_b64, validate=True)
        except Exception as exc:
            raise DNSValidationError(
                f"QSIP record 'sig' field is not valid base64: {exc}"
            ) from exc

        return {
            "v": fields["v"],
            "alg": alg,
            "pk": pk_b64,
            "sig": sig_b64,
        }

    @staticmethod
    def format_qsip_record(
        verify_key_b64: str,
        signature_b64: str,
        algorithm: str = "Dilithium5",
    ) -> str:
        """
        Format a QSIP PQC extension TXT record string for publication.

        Parameters
        ----------
        verify_key_b64 : str
            Base64-encoded Dilithium verify key.
        signature_b64 : str
            Base64-encoded Dilithium signature over the canonical record set.
        algorithm : str
            Signature algorithm identifier (default: "Dilithium5").

        Returns
        -------
        str
            Formatted TXT record value.
        """
        if algorithm not in ALLOWED_SIG_ALGORITHMS:
            raise DNSValidationError(
                f"Algorithm '{algorithm}' is not in the QSIP allowlist."
            )
        return f"v={_QSIP_VERSION}; alg={algorithm}; pk={verify_key_b64}; sig={signature_b64}"
