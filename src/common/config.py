"""
QSIP Centralized Configuration.

ALL runtime configuration is sourced exclusively from environment variables,
loaded via python-dotenv from a .env file. No other module reads os.environ
directly or contains hardcoded configuration values.

Security properties:
- Passphrase values are stored as SecretStr and never logged
- Algorithm names are validated against an allowlist
- Configuration is loaded once at startup and cached

Usage:
    from src.common.config import Config
    config = Config()
    print(config.kem_algorithm)   # "Kyber1024"
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.common.exceptions import ConfigError

logger = logging.getLogger(__name__)

# Allowlisted KEM algorithms (NIST PQC + classical for hybrid)
# Includes both the liboqs legacy names (Kyber*) and the NIST FIPS 203 names (ML-KEM-*)
ALLOWED_KEM_ALGORITHMS: frozenset[str] = frozenset({
    "Kyber512",
    "Kyber768",
    "Kyber1024",
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
})

# Allowlisted signature algorithms (NIST PQC)
# Includes both the liboqs legacy names (Dilithium*) and the NIST FIPS 204 names (ML-DSA-*)
ALLOWED_SIG_ALGORITHMS: frozenset[str] = frozenset({
    "Dilithium2",
    "Dilithium3",
    "Dilithium5",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
})

# Allowlisted hash algorithms (quantum-resistant hash sizes only)
ALLOWED_HASH_ALGORITHMS: frozenset[str] = frozenset({
    "SHA3-256",
    "SHA3-512",
    "SHAKE256",
})


class Config(BaseSettings):
    """
    QSIP runtime configuration, loaded from environment variables.

    All fields have sensible secure defaults where possible. Secrets are
    wrapped in SecretStr to prevent accidental logging.

    Security: Never log config.keystore_passphrase or config.smtp_password
    or any other SecretStr field. Pydantic will mask them in repr().
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="QSIP_",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    env: Literal["development", "staging", "production", "testing"] = Field(
        default="development",
        description="Deployment environment.",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging verbosity. Never set to DEBUG in production.",
    )
    version: str = Field(default="0.1.0")

    # ── Cryptographic Algorithms ─────────────────────────────────────────────
    kem_algorithm: str = Field(
        default="Kyber1024",
        description="Key Encapsulation Mechanism. Default: Kyber1024 (highest security).",
    )
    sig_algorithm: str = Field(
        default="Dilithium5",
        description="Digital signature algorithm. Default: Dilithium5 (highest security).",
    )
    hash_algorithm: str = Field(
        default="SHA3-512",
        description="Hash algorithm for all internal operations.",
    )
    hybrid_mode: bool = Field(
        default=True,
        description="Enable X25519+Kyber hybrid KEM for transition period security.",
    )

    # ── Identity / Keystore ───────────────────────────────────────────────────
    identity_keystore_path: Path = Field(
        default=Path.home() / ".qsip" / "keystore.enc",
        description="Path to encrypted identity keystore file.",
    )
    keystore_passphrase: SecretStr = Field(
        default=SecretStr("CHANGE_ME"),
        description="Passphrase for the encrypted keystore. NEVER log this value.",
    )
    identity_registry_url: str = Field(
        default="https://registry.qsip.example.com",
        description="Endpoint for publishing/resolving public identity keys.",
    )

    # ── Zero-Knowledge ────────────────────────────────────────────────────────
    zk_backend: Literal["python_native"] = Field(
        default="python_native",
        description="ZK proof backend. python_native = Schnorr-based (v0.1).",
    )
    zk_max_proof_size: int = Field(
        default=65536,
        ge=1024,
        le=1_048_576,
        description="Maximum ZK proof size in bytes.",
    )

    # ── DNS ──────────────────────────────────────────────────────────────────
    dns_resolver: str = Field(
        default="9.9.9.9",
        description="Upstream DNS-over-TLS resolver IP.",
    )
    dns_resolver_port: int = Field(
        default=853,
        ge=1,
        le=65535,
        description="DNS-over-TLS port.",
    )
    dns_enable_dot: bool = Field(default=True, description="Enable DNS-over-TLS.")
    dns_enable_doh: bool = Field(default=False, description="Enable DNS-over-HTTPS.")

    # ── Email ─────────────────────────────────────────────────────────────────
    smtp_host: str = Field(default="smtp.example.com")
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_user: str = Field(default="")
    smtp_password: SecretStr = Field(
        default=SecretStr(""),
        description="SMTP password. NEVER log this value.",
    )
    imap_host: str = Field(default="imap.example.com")
    imap_port: int = Field(default=993, ge=1, le=65535)
    imap_user: str = Field(default="")
    imap_password: SecretStr = Field(
        default=SecretStr(""),
        description="IMAP password. NEVER log this value.",
    )
    email_max_size: int = Field(
        default=26_214_400,
        description="Maximum email size in bytes (default: 25 MB).",
    )
    pqep_version: int = Field(
        default=1,
        ge=1,
        description="PQEP header version to emit.",
    )

    # ── Key Rotation ──────────────────────────────────────────────────────────
    key_rotation_days: int = Field(
        default=90,
        ge=1,
        description="Days before a key should be flagged for rotation.",
    )

    # ── Audit ─────────────────────────────────────────────────────────────────
    audit_log_enabled: bool = Field(default=True)
    audit_log_path: Path = Field(default=Path.home() / ".qsip" / "audit.log")
    audit_log_signed: bool = Field(
        default=True,
        description="Sign each audit log entry with Dilithium to prevent tampering.",
    )

    # ── Validators ───────────────────────────────────────────────────────────

    @field_validator("kem_algorithm")
    @classmethod
    def validate_kem_algorithm(cls, v: str) -> str:
        """Reject any KEM algorithm not in the approved allowlist."""
        if v not in ALLOWED_KEM_ALGORITHMS:
            raise ConfigError(
                f"KEM algorithm '{v}' is not allowed. "
                f"Choose from: {sorted(ALLOWED_KEM_ALGORITHMS)}"
            )
        return v

    @field_validator("sig_algorithm")
    @classmethod
    def validate_sig_algorithm(cls, v: str) -> str:
        """Reject any signature algorithm not in the approved allowlist."""
        if v not in ALLOWED_SIG_ALGORITHMS:
            raise ConfigError(
                f"Signature algorithm '{v}' is not allowed. "
                f"Choose from: {sorted(ALLOWED_SIG_ALGORITHMS)}"
            )
        return v

    @field_validator("hash_algorithm")
    @classmethod
    def validate_hash_algorithm(cls, v: str) -> str:
        """Reject any hash algorithm not in the approved allowlist."""
        if v not in ALLOWED_HASH_ALGORITHMS:
            raise ConfigError(
                f"Hash algorithm '{v}' is not allowed. "
                f"Choose from: {sorted(ALLOWED_HASH_ALGORITHMS)}"
            )
        return v

    @model_validator(mode="after")
    def warn_on_default_passphrase(self) -> "Config":
        """Warn loudly if the keystore passphrase is still the default value."""
        if self.keystore_passphrase.get_secret_value() == "CHANGE_ME":
            if self.env == "production":
                raise ConfigError(
                    "QSIP_KEYSTORE_PASSPHRASE must be changed from the default "
                    "before running in production."
                )
            # Non-production: warn only, don't block
            logger.warning(
                "SECURITY WARNING: QSIP_KEYSTORE_PASSPHRASE is set to the default "
                "value 'CHANGE_ME'. Update .env before storing real key material."
            )
        return self

    def is_production(self) -> bool:
        """Return True if running in a production environment."""
        return self.env == "production"

    def is_testing(self) -> bool:
        """Return True if running in a test environment."""
        return self.env == "testing"


@lru_cache(maxsize=1)
def get_config() -> Config:
    """
    Return the singleton Config instance, loaded once from .env.

    Use this in application code. Use Config() directly only in tests
    where you need to override settings.

    Returns
    -------
    Config
        Validated QSIP configuration instance.
    """
    return Config()
