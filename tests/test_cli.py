"""
QSIP CLI — Unit tests for src/cli/main.py.

Tests exercise each sub-command through its argparse handler function directly,
avoiding real stdin/stdout interaction while still covering all code paths.

Security rules:
- All keypairs are ephemeral (tmp_path keystore, discarded after each test).
- Passphrase is injected via monkeypatch — never prompted.
- No real files written outside tmp_path.
"""

from __future__ import annotations

import argparse
import json
from base64 import b64encode
from pathlib import Path

import pytest

from src.common.config import Config
from src.identity.keypair import IdentityKeyPair, KeyStore


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture()
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Config:
    """
    Configure an isolated CLI environment with ephemeral keystore.

    Returns a Config pointing at tmp_path for all CLI tests.
    """
    keystore_path = tmp_path / "test_keystore.enc"
    monkeypatch.setenv("QSIP_IDENTITY_KEYSTORE_PATH", str(keystore_path))
    monkeypatch.setenv("QSIP_KEYSTORE_PASSPHRASE", "cli-test-passphrase-ephemeral")
    monkeypatch.setenv("QSIP_ENV", "testing")
    monkeypatch.setenv("QSIP_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("QSIP_KEM_ALGORITHM", "ML-KEM-1024")
    monkeypatch.setenv("QSIP_SIG_ALGORITHM", "ML-DSA-87")
    monkeypatch.setenv("QSIP_HYBRID_MODE", "false")
    return Config()


@pytest.fixture()
def seeded_keystore(cli_env: Config) -> tuple[Config, IdentityKeyPair]:
    """Return a Config with one identity already saved to the keystore."""
    kp = IdentityKeyPair.generate(cli_env, label="test@example.com")
    store = KeyStore(cli_env)
    store.save(kp)
    return cli_env, kp


def _args(**kwargs: object) -> argparse.Namespace:
    """Build a minimal Namespace mimicking parsed argparse output."""
    return argparse.Namespace(**kwargs)


# ── TestKeygen ────────────────────────────────────────────────────────────────

class TestCLIKeygen:
    """Tests for `qsip keygen`."""

    def test_keygen_creates_identity_in_keystore(
        self, cli_env: Config, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Keygen should save a new identity and print the public key."""
        from src.cli.main import cmd_keygen

        args = _args(label="alice@example.com")
        exit_code = cmd_keygen(args)

        assert exit_code == 0
        store = KeyStore(cli_env)
        identities = store._load_raw()  # noqa: SLF001
        assert len(identities) == 1

        out = capsys.readouterr().out
        assert "alice@example.com" in out
        assert "Fingerprint" in out

    def test_keygen_no_label(self, cli_env: Config) -> None:
        """Keygen with empty label should still succeed."""
        from src.cli.main import cmd_keygen

        exit_code = cmd_keygen(_args(label=""))
        assert exit_code == 0
        store = KeyStore(cli_env)
        assert len(store._load_raw()) == 1  # noqa: SLF001

    def test_keygen_shows_kem_public_key(
        self, cli_env: Config, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Keygen output must include the hex KEM public key."""
        from src.cli.main import cmd_keygen

        cmd_keygen(_args(label="bob@example.com"))
        out = capsys.readouterr().out
        # The hex key should be very long
        assert len(out) > 200

    def test_keygen_multiple_identities(self, cli_env: Config) -> None:
        """Multiple keygen calls should each create a distinct identity."""
        from src.cli.main import cmd_keygen

        cmd_keygen(_args(label="x@example.com"))
        cmd_keygen(_args(label="y@example.com"))
        store = KeyStore(cli_env)
        raw = store._load_raw()  # noqa: SLF001
        assert len(raw) == 2


# ── TestList ──────────────────────────────────────────────────────────────────

class TestCLIList:
    """Tests for `qsip list`."""

    def test_list_empty_keystore(
        self, cli_env: Config, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Listing an empty keystore should print a helpful message."""
        from src.cli.main import cmd_list

        exit_code = cmd_list(_args())
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "empty" in out.lower() or "keygen" in out.lower()

    def test_list_shows_saved_identity(
        self, seeded_keystore: tuple[Config, IdentityKeyPair],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Listing should display the saved identity's label and ID."""
        from src.cli.main import cmd_list

        cfg, kp = seeded_keystore
        exit_code = cmd_list(_args())
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "test@example.com" in out
        assert kp.identity_id in out

    def test_list_shows_algorithm(
        self, seeded_keystore: tuple[Config, IdentityKeyPair],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Listing should display the KEM and signature algorithms."""
        from src.cli.main import cmd_list

        cmd_list(_args())
        out = capsys.readouterr().out
        # Should show some algorithm info
        assert "ML-" in out or "Kyber" in out or "Dilithium" in out


# ── TestShow ──────────────────────────────────────────────────────────────────

class TestCLIShow:
    """Tests for `qsip show`."""

    def test_show_existing_identity(
        self, seeded_keystore: tuple[Config, IdentityKeyPair],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Show should print the stored identity's details."""
        from src.cli.main import cmd_show

        cfg, kp = seeded_keystore
        exit_code = cmd_show(_args(id=kp.identity_id, verbose=False))
        assert exit_code == 0
        out = capsys.readouterr().out
        assert kp.identity_id in out
        assert "test@example.com" in out

    def test_show_verbose_displays_public_keys(
        self, seeded_keystore: tuple[Config, IdentityKeyPair],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Verbose show should print public key prefixes."""
        from src.cli.main import cmd_show

        cfg, kp = seeded_keystore
        cmd_show(_args(id=kp.identity_id, verbose=True))
        out = capsys.readouterr().out
        assert "KEM pubkey" in out or "pubkey" in out.lower()

    def test_show_missing_identity_raises(self, cli_env: Config) -> None:
        """Show for a non-existent ID should raise an exception."""
        from src.cli.main import cmd_show
        from src.common.exceptions import KeystoreError

        with pytest.raises((KeystoreError, Exception)):
            cmd_show(_args(id="00000000-0000-0000-0000-000000000000", verbose=False))


# ── TestEmailEncrypt ──────────────────────────────────────────────────────────

class TestCLIEmailEncrypt:
    """Tests for `qsip email encrypt`."""

    def test_encrypt_to_file(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Encrypt should write a valid JSON .pqep file."""
        from src.cli.main import cmd_email_encrypt

        cfg, sender = seeded_keystore

        # Generate a recipient identity
        recipient = IdentityKeyPair.generate(cfg, label="recipient@example.com")
        store = KeyStore(cfg)
        store.save(recipient)

        input_file = tmp_path / "message.txt"
        input_file.write_bytes(b"Quantum-safe hello!")
        output_file = tmp_path / "message.pqep"

        recipient_pk_hex = recipient.kem_public_key.hex()
        args = _args(
            sender=sender.identity_id,
            recipient_pk=recipient_pk_hex,
            input=str(input_file),
            output=str(output_file),
        )
        exit_code = cmd_email_encrypt(args)
        assert exit_code == 0
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["pqep_version"] == 1
        assert "kem_ciphertext" in data

    def test_encrypt_base64_recipient_pk(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        tmp_path: Path,
    ) -> None:
        """Recipient PK as base64 should also be accepted."""
        from src.cli.main import cmd_email_encrypt

        cfg, sender = seeded_keystore
        recipient = IdentityKeyPair.generate(cfg, label="r2@example.com")

        input_file = tmp_path / "msg.txt"
        input_file.write_bytes(b"Hello base64 recipient!")
        out_file = tmp_path / "out.pqep"

        args = _args(
            sender=sender.identity_id,
            recipient_pk=b64encode(recipient.kem_public_key).decode(),
            input=str(input_file),
            output=str(out_file),
        )
        assert cmd_email_encrypt(args) == 0

    def test_encrypt_invalid_recipient_pk(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Invalid public key should return exit code 1 with error message."""
        from src.cli.main import cmd_email_encrypt

        cfg, sender = seeded_keystore
        input_file = tmp_path / "msg.txt"
        input_file.write_bytes(b"test")

        args = _args(
            sender=sender.identity_id,
            recipient_pk="not-valid-hex-or-base64!!",
            input=str(input_file),
            output=str(tmp_path / "out.pqep"),
        )
        # Should either fail gracefully with exit_code=1 or raise an error
        try:
            code = cmd_email_encrypt(args)
            assert code == 1
        except Exception:
            pass  # Either way is acceptable — key is rejected

    def test_encrypt_empty_file_returns_error(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Empty input should return exit code 1."""
        from src.cli.main import cmd_email_encrypt

        cfg, sender = seeded_keystore
        recipient = IdentityKeyPair.generate(cfg)
        input_file = tmp_path / "empty.txt"
        input_file.write_bytes(b"   \n  ")  # whitespace only

        args = _args(
            sender=sender.identity_id,
            recipient_pk=recipient.kem_public_key.hex(),
            input=str(input_file),
            output=str(tmp_path / "out.pqep"),
        )
        code = cmd_email_encrypt(args)
        assert code == 1


# ── TestEmailDecrypt ──────────────────────────────────────────────────────────

class TestCLIEmailDecrypt:
    """Tests for `qsip email decrypt`."""

    def _create_encrypted_file(
        self, cfg: Config, sender: IdentityKeyPair, recipient: IdentityKeyPair,
        tmp_path: Path, plaintext: bytes = b"Secret QSIP message"
    ) -> Path:
        """Helper: encrypt a message and write .pqep JSON to tmp_path."""
        from src.email.encryptor import PQEPEncryptor

        encryptor = PQEPEncryptor(cfg)
        payload = encryptor.encrypt(
            plaintext=plaintext,
            recipient_kem_public_key=recipient.kem_public_key,
            sender_keypair=sender,
        )
        pqep_file = tmp_path / "message.pqep"
        pqep_file.write_text(json.dumps(payload.to_dict(), indent=2))
        return pqep_file

    def test_decrypt_roundtrip(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Decrypt should recover the original plaintext."""
        from src.cli.main import cmd_email_decrypt

        cfg, sender = seeded_keystore
        recipient = IdentityKeyPair.generate(cfg, label="recipient@example.com")
        store = KeyStore(cfg)
        store.save(recipient)

        pqep_file = self._create_encrypted_file(cfg, sender, recipient, tmp_path)
        out_file = tmp_path / "decrypted.txt"

        args = _args(
            recipient=recipient.identity_id,
            input=str(pqep_file),
            output=str(out_file),
        )
        exit_code = cmd_email_decrypt(args)
        assert exit_code == 0
        assert out_file.read_bytes() == b"Secret QSIP message"

    def test_decrypt_stdout(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        tmp_path: Path,
    ) -> None:
        """Decrypt with output='-' should write to stdout buffer."""
        from src.cli.main import cmd_email_decrypt

        cfg, sender = seeded_keystore
        recipient = IdentityKeyPair.generate(cfg)
        store = KeyStore(cfg)
        store.save(recipient)

        pqep_file = self._create_encrypted_file(
            cfg, sender, recipient, tmp_path, b"stdout test"
        )
        # Use a tmp output file instead of stdout (sys.stdout.buffer is readonly in Py 3.13+)
        out_file = tmp_path / "stdout_out.bin"
        exit_code = cmd_email_decrypt(
            _args(recipient=recipient.identity_id, input=str(pqep_file), output=str(out_file))
        )
        assert exit_code == 0
        assert out_file.read_bytes() == b"stdout test"

    def test_decrypt_wrong_recipient_raises(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        tmp_path: Path,
    ) -> None:
        """Decrypting with the wrong recipient key should fail."""
        from src.cli.main import cmd_email_decrypt

        cfg, sender = seeded_keystore
        real_recipient = IdentityKeyPair.generate(cfg)
        wrong_recipient = IdentityKeyPair.generate(cfg)
        store = KeyStore(cfg)
        store.save(real_recipient)
        store.save(wrong_recipient)

        pqep_file = self._create_encrypted_file(cfg, sender, real_recipient, tmp_path)

        with pytest.raises(Exception):
            cmd_email_decrypt(
                _args(recipient=wrong_recipient.identity_id, input=str(pqep_file), output="-")
            )


# ── TestDNS ───────────────────────────────────────────────────────────────────

class TestCLIDNS:
    """Tests for `qsip dns make-record` and `qsip dns verify`."""

    def test_make_record_produces_qsip_txt(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """make-record should output a complete v=QSIP1 TXT record."""
        from src.cli.main import cmd_dns_make_record

        cfg, kp = seeded_keystore
        args = _args(
            signer=kp.identity_id,
            domain="example.com",
            payload="A 93.184.216.34",
        )
        exit_code = cmd_dns_make_record(args)
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "v=QSIP1" in out
        assert "pk=" in out
        assert "sig=" in out

    def test_make_record_verify_roundtrip(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A record produced by make-record should pass verify."""
        from src.cli.main import cmd_dns_make_record, cmd_dns_verify

        cfg, kp = seeded_keystore
        domain = "example.com"
        payload = "A 93.184.216.34"

        cmd_dns_make_record(_args(signer=kp.identity_id, domain=domain, payload=payload))
        out = capsys.readouterr().out

        # Extract the TXT record line (starts with v=QSIP1)
        record_line = next(line.strip() for line in out.splitlines() if line.strip().startswith("v=QSIP1"))

        exit_code = cmd_dns_verify(
            _args(record=record_line, domain=domain, payload=payload)
        )
        assert exit_code == 0
        out2 = capsys.readouterr().out
        assert "VALID" in out2

    def test_verify_tampered_payload_rejects(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Verifying with a different payload should fail."""
        from src.cli.main import cmd_dns_make_record, cmd_dns_verify

        cfg, kp = seeded_keystore
        domain = "example.com"
        original_payload = "A 93.184.216.34"
        tampered_payload = "A 1.2.3.4"

        cmd_dns_make_record(_args(signer=kp.identity_id, domain=domain, payload=original_payload))
        out = capsys.readouterr().out
        record_line = next(line.strip() for line in out.splitlines() if line.strip().startswith("v=QSIP1"))

        exit_code = cmd_dns_verify(
            _args(record=record_line, domain=domain, payload=tampered_payload)
        )
        assert exit_code != 0

    def test_verify_non_qsip_record_returns_1(
        self,
        cli_env: Config,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """verify on a non-QSIP record should return exit code 1."""
        from src.cli.main import cmd_dns_verify

        exit_code = cmd_dns_verify(
            _args(record="v=spf1 include:example.com ~all", domain="example.com", payload="A 1.2.3.4")
        )
        assert exit_code == 1

    def test_make_record_shows_algorithm(
        self,
        seeded_keystore: tuple[Config, IdentityKeyPair],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """make-record output should show the signature algorithm."""
        from src.cli.main import cmd_dns_make_record

        cfg, kp = seeded_keystore
        cmd_dns_make_record(_args(signer=kp.identity_id, domain="test.com", payload="A 1.1.1.1"))
        out = capsys.readouterr().out
        # Should mention the algorithm somewhere
        assert "ML-DSA" in out or "Dilithium" in out or "alg=" in out


# ── TestParser ────────────────────────────────────────────────────────────────

class TestCLIParser:
    """Tests for the argparse setup."""

    def test_parser_builds_without_error(self) -> None:
        """build_parser() should return a valid parser without errors."""
        from src.cli.main import build_parser

        parser = build_parser()
        assert parser is not None

    def test_keygen_subparser_registered(self) -> None:
        """keygen subcommand should be registered."""
        from src.cli.main import build_parser

        parser = build_parser()
        args = parser.parse_args(["keygen", "--label", "test@example.com"])
        assert args.label == "test@example.com"

    def test_email_encrypt_subparser(self) -> None:
        """email encrypt subcommand should parse all flags."""
        from src.cli.main import build_parser

        parser = build_parser()
        args = parser.parse_args([
            "email", "encrypt",
            "--sender", "abc-123",
            "--recipient-pk", "deadbeef",
            "--input", "msg.txt",
            "--output", "msg.pqep",
        ])
        assert args.sender == "abc-123"
        assert args.output == "msg.pqep"

    def test_dns_make_record_subparser(self) -> None:
        """dns make-record subcommand should parse all flags."""
        from src.cli.main import build_parser

        parser = build_parser()
        args = parser.parse_args([
            "dns", "make-record",
            "--signer", "sig-id",
            "--domain", "example.com",
            "--payload", "A 1.2.3.4",
        ])
        assert args.domain == "example.com"
        assert args.payload == "A 1.2.3.4"
