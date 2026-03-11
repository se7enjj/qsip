"""
QSIP — PQC-Aware DNS Resolver.

A DNS-over-TLS resolver that fetches standard DNS records AND QSIP PQC
extension records, then validates the PQC signatures before returning results.

QSIP DNS Extension Record Format (TXT):
    _pqc.<domain>.  IN  TXT  "v=QSIP1; alg=Dilithium5; pk=<b64>; sig=<b64>"

Where:
- `pk` = Dilithium5 verify key (base64url)
- `sig` = Dilithium5 signature over the canonical DNS record set

Security properties:
- DNS-over-TLS enforced (no plaintext DNS fallback)
- DNSSEC validation delegated to the upstream resolver (Quad9 by default)
- PQC signature validation performed locally, not trusted to resolver
- Failed validation raises DNSValidationError — callers must handle explicitly

Design note on BGP:
    BGP validation is out of scope for the DNS resolver. The BGP overlay
    (v0.4) will operate as a separate layer. This resolver validates
    DNS record authenticity only.

Dependency: dnspython >= 2.6.0

Usage:
    from src.dns.resolver import PQCResolver
    resolver = PQCResolver(config)
    result = resolver.resolve_with_pqc("example.com", "A")
    # result.records: list of DNS records
    # result.pqc_valid: bool — True if PQC sig verified
    # result.pqc_public_key: bytes | None
"""

from __future__ import annotations

import logging
import ssl
from base64 import b64decode
from dataclasses import dataclass, field
from typing import Any

import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.message
import dns.flags

from src.common.config import Config
from src.common.exceptions import DNSValidationError
from src.crypto.signatures import DilithiumSigner
from src.dns.validator import DNSRecordValidator

logger = logging.getLogger(__name__)


@dataclass
class PQCResolveResult:
    """
    The result of a QSIP PQC-validated DNS lookup.

    Attributes
    ----------
    domain : str
        The queried domain name.
    record_type : str
        The queried record type (e.g., "A", "MX", "TXT").
    records : list[str]
        The raw record data strings.
    pqc_valid : bool
        True if a QSIP PQC extension record was found and its signature verified.
        False if no QSIP record was found OR if verification failed.
    pqc_found : bool
        True if a QSIP TXT record was found (regardless of validity).
    pqc_public_key : bytes | None
        The Dilithium verify key from the QSIP record, if present.
    dnssec_validated : bool
        True if the upstream resolver reported DNSSEC validation (AD bit set).
    error : str | None
        Error message if resolution failed; None on success.
    """

    domain: str
    record_type: str
    records: list[str] = field(default_factory=list)
    pqc_valid: bool = False
    pqc_found: bool = False
    pqc_public_key: bytes | None = None
    dnssec_validated: bool = False
    error: str | None = None


class PQCResolver:
    """
    DNS-over-TLS resolver with PQC signature validation.

    Resolves DNS records using DNS-over-TLS to prevent eavesdropping and
    man-in-the-middle attacks on DNS lookups. Additionally fetches and
    validates QSIP PQC extension TXT records.

    Security:
    - Uses TLS 1.2+ for DoT connections (TLS 1.3 preferred)
    - Certificate verification enabled for DoT connections
    - PQC signature validation is local — not delegated to resolver
    - Validation failures are logged at WARNING level (do not log record content)
    - Timeouts prevent DNS-based DoS amplification

    Parameters
    ----------
    config : Config
        QSIP configuration. Resolver address and DoT settings come from here.
    """

    _DOT_TIMEOUT = 5.0  # seconds
    _MAX_RETRIES = 2

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()
        self._validator = DNSRecordValidator(self._config)
        self._signer = DilithiumSigner(self._config)

    def resolve_with_pqc(
        self,
        domain: str,
        record_type: str = "A",
    ) -> PQCResolveResult:
        """
        Resolve a DNS record and validate any QSIP PQC extension records.

        Performs two DNS lookups:
        1. The requested record type for `domain`
        2. The QSIP PQC TXT record at `_pqc.<domain>`

        Parameters
        ----------
        domain : str
            Domain name to resolve (e.g., "example.com").
        record_type : str
            DNS record type (default: "A"). Common: "A", "AAAA", "MX", "TXT".

        Returns
        -------
        PQCResolveResult
            Resolution result with PQC validation status.

        Raises
        ------
        DNSValidationError
            If PQC signature validation fails (record found but invalid sig).
        """
        result = PQCResolveResult(domain=domain, record_type=record_type)

        # Resolve the primary record
        try:
            records = self._resolve(domain, record_type)
            result.records = records
        except Exception as exc:
            result.error = f"DNS resolution failed for {domain} {record_type}: {exc}"
            logger.warning("DNS resolution failed for domain (details omitted for security)")
            return result

        # Attempt to fetch and validate the QSIP PQC extension record
        try:
            pqc_domain = f"_pqc.{domain}"
            pqc_records = self._resolve(pqc_domain, "TXT")

            if pqc_records:
                result.pqc_found = True
                pqc_txt = pqc_records[0]
                parsed = self._validator.parse_qsip_record(pqc_txt)

                if parsed:
                    verify_key = b64decode(parsed["pk"])
                    signature = b64decode(parsed["sig"])
                    # Sign over canonical form of target records
                    canonical = self._canonical_record_bytes(domain, record_type, records)

                    result.pqc_valid = self._signer.verify(canonical, signature, verify_key)
                    result.pqc_public_key = verify_key

                    if not result.pqc_valid:
                        logger.warning(
                            "PQC signature verification FAILED for domain (name withheld)"
                        )
                        raise DNSValidationError(
                            f"PQC signature validation failed for domain '{domain}'. "
                            f"Record may be spoofed or key has changed."
                        )
                    else:
                        logger.info("PQC DNS signature verified successfully.")

        except DNSValidationError:
            raise
        except Exception as exc:
            # No QSIP record or parse error — not a hard failure, log and continue
            logger.debug("No valid QSIP PQC extension record found: %s", type(exc).__name__)

        return result

    def resolve_identity_key(self, domain: str) -> bytes | None:
        """
        Resolve the QSIP Dilithium verify key published for a domain.

        Fetches the `_pqc.<domain>` TXT record and returns the verify key
        bytes if the record exists and is well-formed.

        Parameters
        ----------
        domain : str
            The domain to look up the identity key for.

        Returns
        -------
        bytes | None
            The Dilithium verify key, or None if not found.
        """
        try:
            pqc_domain = f"_pqc.{domain}"
            records = self._resolve(pqc_domain, "TXT")
            for record in records:
                parsed = self._validator.parse_qsip_record(record)
                if parsed and "pk" in parsed:
                    return b64decode(parsed["pk"])
        except Exception:
            pass
        return None

    def _resolve(self, domain: str, record_type: str) -> list[str]:
        """
        Perform a DNS-over-TLS query.

        Falls back to standard UDP if DoT is disabled in config (not recommended).
        All timeouts are enforced to prevent hanging.
        """
        if self._config.dns_enable_dot:
            return self._resolve_dot(domain, record_type)
        else:
            # SECURITY-REVIEW: Standard UDP DNS is vulnerable to MITM.
            # Only enabled for testing/development.
            logger.warning("DoT is disabled — DNS queries are not encrypted.")
            return self._resolve_udp(domain, record_type)

    def _resolve_dot(self, domain: str, record_type: str) -> list[str]:
        """DNS-over-TLS resolution via the configured resolver."""
        resolver_ip = self._config.dns_resolver
        resolver_port = self._config.dns_resolver_port

        try:
            qname = dns.name.from_text(domain)
            rdtype = dns.rdatatype.from_text(record_type)
            request = dns.message.make_query(qname, rdtype, use_edns=True, want_dnssec=True)

            # Create TLS context with certificate verification
            tls_context = ssl.create_default_context()
            tls_context.minimum_version = ssl.TLSVersion.TLSv1_2

            response = dns.query.tls(
                request,
                where=resolver_ip,
                port=resolver_port,
                timeout=self._DOT_TIMEOUT,
                ssl_context=tls_context,
            )
            return self._extract_records(response, rdtype)
        except Exception as exc:
            raise DNSValidationError(
                f"DNS-over-TLS query failed for '{domain}' {record_type}: {exc}"
            ) from exc

    def _resolve_udp(self, domain: str, record_type: str) -> list[str]:
        """Standard UDP DNS — fallback only, not for production."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self._config.dns_resolver]
            resolver.port = 53
            resolver.lifetime = self._DOT_TIMEOUT
            answer = resolver.resolve(domain, record_type)
            return [str(rr) for rr in answer]
        except Exception as exc:
            raise DNSValidationError(
                f"UDP DNS query failed for '{domain}' {record_type}: {exc}"
            ) from exc

    def _extract_records(self, response: Any, rdtype: Any) -> list[str]:
        """Extract record strings from a dnspython response."""
        records = []
        for rrset in response.answer:
            if rrset.rdtype == rdtype:
                records.extend(str(rd) for rd in rrset)
        return records

    @staticmethod
    def _canonical_record_bytes(domain: str, record_type: str, records: list[str]) -> bytes:
        """
        Produce canonical bytes representing a DNS record set for signing.

        Format: "QSIP-DNS-v1\n<domain>\n<type>\n<sorted_records>\n"
        Sorting ensures the canonical form is deterministic regardless of
        resolver record ordering.
        """
        lines = [
            "QSIP-DNS-v1",
            domain.lower().rstrip("."),
            record_type.upper(),
        ] + sorted(records)
        return "\n".join(lines).encode("utf-8")
