"""
QSIP — pytest configuration and shared fixtures.

Security rules for tests:
- NEVER use real keys, real credentials, or real network addresses
- All keypairs are ephemeral (generated fresh per test, discarded after)
- All config uses QSIP_ENV=testing overrides — never reads production .env
- Tests MUST NOT write to disk (use tmp_path for any file operations)

liboqs availability:
- If the native liboqs shared library (oqs.dll / liboqs.so) is present on
  the system, real crypto is used in tests.
- If it is absent (e.g. Windows dev setup without a native build), a
  behaviorally-correct mock is injected into sys.modules BEFORE the
  liboqs-python package is ever imported. This prevents the package's
  built-in auto-installer from running and calling sys.exit().
- The mock uses HMAC-SHA3 internally so tampered signatures DO fail and
  wrong keys produce different shared secrets — tests remain meaningful.
"""

from __future__ import annotations

# ── OQS mock injection — must happen BEFORE any 'import oqs' ─────────────────
# We use ctypes to probe for the native shared library without loading
# the liboqs-python package (which would trigger its auto-installer on miss).
import ctypes
import ctypes.util
import sys

_NATIVE_FOUND: bool = False
for _candidate in ("oqs", "liboqs", "liboqs-0"):
    _path = ctypes.util.find_library(_candidate)
    if _path is not None:
        try:
            ctypes.CDLL(_path)
            _NATIVE_FOUND = True
        except OSError:
            pass
        break

if not _NATIVE_FOUND and "oqs" not in sys.modules:
    # Inject mock before liboqs-python is ever imported so its
    # auto-installer (which calls sys.exit on failure) never runs.
    from tests._oqs_mock import build_oqs_mock
    sys.modules["oqs"] = build_oqs_mock()  # type: ignore[assignment]
# ─────────────────────────────────────────────────────────────────────────────

import pytest

from src.common.config import Config  # noqa: E402


@pytest.fixture(autouse=True)
def testing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Force all tests to run with testing environment variables.

    Runs automatically for every test to ensure no test accidentally
    reads from a production .env or uses real credentials.
    """
    monkeypatch.setenv("QSIP_ENV", "testing")
    monkeypatch.setenv("QSIP_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("QSIP_KEM_ALGORITHM", "Kyber1024")
    monkeypatch.setenv("QSIP_SIG_ALGORITHM", "Dilithium5")
    monkeypatch.setenv("QSIP_HYBRID_MODE", "false")
    monkeypatch.setenv("QSIP_KEYSTORE_PASSPHRASE", "test-passphrase-ephemeral-only")
    monkeypatch.setenv("QSIP_SMTP_HOST", "smtp.test.invalid")
    monkeypatch.setenv("QSIP_IMAP_HOST", "imap.test.invalid")
    monkeypatch.setenv("QSIP_DNS_ENABLE_DOT", "false")


@pytest.fixture
def config() -> Config:
    """Return a test Config instance (reads test env vars)."""
    return Config()


# ── Marker for tests that require the REAL liboqs C library ──────────────────
requires_liboqs = pytest.mark.skipif(
    not _NATIVE_FOUND,
    reason="Requires native liboqs C library (see docs/ARCHITECTURE.md for build instructions)",
)
