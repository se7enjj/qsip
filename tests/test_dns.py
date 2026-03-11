"""
QSIP — DNS Module Tests.

Tests for:
- DNSRecordValidator QSIP TXT record parsing
- Valid and invalid record formats
- Algorithm allowlist enforcement

Note: PQCResolver network tests are skipped unless QSIP_INTEGRATION_TESTS=1
to avoid requiring live DNS resolution in CI.
"""

from __future__ import annotations

import os
from base64 import b64encode

import pytest

from src.common.config import Config
from src.common.exceptions import DNSValidationError
from src.dns.validator import DNSRecordValidator


class TestDNSRecordValidator:
    """Tests for QSIP DNS TXT record parsing and validation."""

    def test_parse_valid_qsip_record(self, config: Config) -> None:
        """A correctly formatted QSIP TXT record should parse successfully."""
        validator = DNSRecordValidator(config)
        fake_pk = b64encode(b"A" * 100).decode()
        fake_sig = b64encode(b"B" * 200).decode()
        record = f"v=QSIP1; alg=Dilithium5; pk={fake_pk}; sig={fake_sig}"
        result = validator.parse_qsip_record(record)
        assert result is not None
        assert result["v"] == "QSIP1"
        assert result["alg"] == "Dilithium5"
        assert result["pk"] == fake_pk
        assert result["sig"] == fake_sig

    def test_parse_non_qsip_record_returns_none(self, config: Config) -> None:
        """A non-QSIP TXT record should return None (not raise)."""
        validator = DNSRecordValidator(config)
        result = validator.parse_qsip_record("v=spf1 include:_spf.example.com ~all")
        assert result is None

    def test_parse_wrong_version_raises(self, config: Config) -> None:
        """An unsupported QSIP version should raise DNSValidationError."""
        validator = DNSRecordValidator(config)
        fake_pk = b64encode(b"A" * 100).decode()
        fake_sig = b64encode(b"B" * 200).decode()
        record = f"v=QSIP99; alg=Dilithium5; pk={fake_pk}; sig={fake_sig}"
        with pytest.raises(DNSValidationError):
            validator.parse_qsip_record(record)

    def test_parse_disallowed_algorithm_raises(self, config: Config) -> None:
        """A record using a disallowed algorithm should raise DNSValidationError."""
        validator = DNSRecordValidator(config)
        fake_pk = b64encode(b"A" * 100).decode()
        fake_sig = b64encode(b"B" * 200).decode()
        record = f"v=QSIP1; alg=RSA4096; pk={fake_pk}; sig={fake_sig}"
        with pytest.raises(DNSValidationError):
            validator.parse_qsip_record(record)

    def test_parse_missing_pk_field_raises(self, config: Config) -> None:
        """Missing required 'pk' field should raise DNSValidationError."""
        validator = DNSRecordValidator(config)
        fake_sig = b64encode(b"B" * 200).decode()
        record = f"v=QSIP1; alg=Dilithium5; sig={fake_sig}"
        with pytest.raises(DNSValidationError):
            validator.parse_qsip_record(record)

    def test_parse_missing_sig_field_raises(self, config: Config) -> None:
        """Missing required 'sig' field should raise DNSValidationError."""
        validator = DNSRecordValidator(config)
        fake_pk = b64encode(b"A" * 100).decode()
        record = f"v=QSIP1; alg=Dilithium5; pk={fake_pk}"
        with pytest.raises(DNSValidationError):
            validator.parse_qsip_record(record)

    def test_parse_invalid_base64_pk_raises(self, config: Config) -> None:
        """Invalid base64 in 'pk' field should raise DNSValidationError."""
        validator = DNSRecordValidator(config)
        record = "v=QSIP1; alg=Dilithium5; pk=!!!invalid!!!; sig=AAAA"
        with pytest.raises(DNSValidationError):
            validator.parse_qsip_record(record)

    def test_format_qsip_record_produces_parseable_output(self, config: Config) -> None:
        """format_qsip_record() output should be parseable by parse_qsip_record()."""
        validator = DNSRecordValidator(config)
        fake_pk = b64encode(b"C" * 100).decode()
        fake_sig = b64encode(b"D" * 200).decode()
        formatted = validator.format_qsip_record(fake_pk, fake_sig, "Dilithium5")
        parsed = validator.parse_qsip_record(formatted)
        assert parsed is not None
        assert parsed["alg"] == "Dilithium5"

    def test_format_disallowed_algorithm_raises(self, config: Config) -> None:
        """format_qsip_record() with disallowed algorithm should raise DNSValidationError."""
        validator = DNSRecordValidator(config)
        with pytest.raises(DNSValidationError):
            validator.format_qsip_record("pk", "sig", "MD5")

    def test_parse_record_with_surrounding_quotes(self, config: Config) -> None:
        """Records with surrounding quotes (as returned by DNS) should parse correctly."""
        validator = DNSRecordValidator(config)
        fake_pk = b64encode(b"E" * 100).decode()
        fake_sig = b64encode(b"F" * 200).decode()
        record = f'"v=QSIP1; alg=Dilithium5; pk={fake_pk}; sig={fake_sig}"'
        result = validator.parse_qsip_record(record)
        assert result is not None
        assert result["v"] == "QSIP1"
