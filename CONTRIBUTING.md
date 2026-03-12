# Contributing to QSIP

Thank you for your interest in contributing to the Quantum-Safe Internet Protocol Suite.
QSIP is security-critical infrastructure. Please read this document fully before opening a PR.

---

## Before You Start

1. Read [SECURITY.md](SECURITY.md) — the security rules are non-negotiable.
2. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for layer dependency rules.

---

## What We Welcome

- Bug fixes (especially in protocol logic or key handling)
- New tests — coverage is never too high for security code
- Performance improvements to existing primitives
- Documentation clarifications
- Implementations of roadmap items listed in [docs/ROADMAP.md](docs/ROADMAP.md)

## What We Do Not Accept

- New cryptographic primitives implemented from scratch — use `oqs` or `cryptography` (PyCA) only
- Any cryptographic dependency not listed in the [Approved Dependencies](docs/ARCHITECTURE.md#approved-dependencies) section of the architecture docs, without prior discussion
- Anything that weakens algorithm strengths (e.g. downgrading Kyber1024 to Kyber512)
- PRs that break the test suite

---

## Development Setup

```bash
git clone https://github.com/se7enjj/qsip.git
cd qsip

python -m venv .venv
source .venv/bin/activate   # Linux / macOS
.venv\Scripts\activate      # Windows

pip install -r requirements.txt
pip install -r requirements-dev.txt

cp .env.example .env
# Edit .env — set QSIP_KEYSTORE_PASSPHRASE to a strong random value

pytest tests/ -v
# All 128 tests must pass before submitting a PR
```

---

## Pull Request Process

1. Fork the repository and create a branch: `git checkout -b feat/your-feature`
2. Write tests for any new code. Coverage must not decrease.
3. Ensure `pytest tests/` passes with no failures.
4. Run `ruff check src/ tests/` and fix any issues.
5. Ensure no secrets, `.env` files, or key material are included in the commit.
6. Open a PR with a clear description of what changed and why.
7. Reference any related issue numbers.

---

## Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Report them privately via email to **jago.koenig@proton.me** following the process in [SECURITY.md](SECURITY.md).

---

## Style Guide

- All public functions and classes must have docstrings explaining security properties.
- Type hints are mandatory (`from __future__ import annotations`).
- No bare `except:` — catch specific exceptions.
- Constant-time comparison for any security-sensitive byte comparison: `hmac.compare_digest()`.
- Never log secret values, key material, or ZK witnesses — not even at DEBUG level.
- Classes: `PascalCase` | Functions: `snake_case` | Constants: `UPPER_SNAKE_CASE`

---

## License

By contributing, you agree that your contributions will be licensed under the
[Apache 2.0 License](LICENSE).
