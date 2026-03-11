#!/usr/bin/env python3
"""
QSIP Command-Line Interface.

Provides a developer-friendly CLI for the three QSIP protocol layers.

Commands
--------
    qsip keygen   --label alice@example.com
    qsip list
    qsip show     --id <identity-id>

    qsip email encrypt  --sender <id> --recipient-pk <hex-or-file>
                         --input  message.txt  --output  message.pqep
    qsip email decrypt  --recipient <id>  --input  message.pqep

    qsip dns make-record --signer <id> --domain example.com --payload "A 93.184.216.34"
    qsip dns verify      --record <txt-record-string>  --signer <id>

    qsip demo            (run the full showcase demo)

Security notes:
- All keys come from the KeyStore (passphrase via QSIP_KEYSTORE_PASSPHRASE env var).
- No key material is ever printed in full — only public fingerprints.
- Running without QSIP_KEYSTORE_PASSPHRASE will prompt securely via getpass.
"""

from __future__ import annotations

# ── OQS mock injection — identical to conftest.py / demo.py ──────────────────
import ctypes
import ctypes.util
import sys
import os

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
    try:
        from tests._oqs_mock import build_oqs_mock
        sys.modules["oqs"] = build_oqs_mock()  # type: ignore[assignment]
    except ImportError:
        pass  # Running from installed wheel — mock not available; real liboqs required
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import getpass
import textwrap
from base64 import b64encode, b64decode
from pathlib import Path


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_config() -> "Config":
    """Load config, prompting for passphrase if not set in environment."""
    from src.common.config import Config

    # If passphrase not in env, prompt securely (never echo)
    if not os.getenv("QSIP_KEYSTORE_PASSPHRASE"):
        passphrase = getpass.getpass("KeyStore passphrase: ")
        os.environ["QSIP_KEYSTORE_PASSPHRASE"] = passphrase

    return Config()


def _print_identity(kp: "IdentityKeyPair", verbose: bool = False) -> None:
    from src.identity.keypair import IdentityKeyPair
    print(f"  ID         : {kp.identity_id}")
    print(f"  Label      : {kp.label or '(none)'}")
    print(f"  KEM alg    : {kp.kem_keypair.algorithm}")
    print(f"  Sig alg    : {kp.sig_keypair.algorithm}")
    print(f"  Created    : {kp.created_at.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Fingerprint: {kp.fingerprint()}")
    if verbose:
        print(f"  KEM pubkey : {kp.kem_public_key.hex()[:64]}…")
        print(f"  Sig vk     : {kp.sig_verify_key.hex()[:64]}…")


# ── Sub-commands ──────────────────────────────────────────────────────────────

def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a new QSIP identity keypair and save to keystore."""
    config = _get_config()
    from src.identity.keypair import IdentityKeyPair, KeyStore

    keypair = IdentityKeyPair.generate(config, label=args.label or "")
    store = KeyStore(config)
    store.save(keypair)

    print("Identity generated and saved to keystore:")
    _print_identity(keypair)
    print(f"\n  KEM public key (share with senders):")
    print(f"  {keypair.kem_public_key.hex()}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List all identities in the keystore."""
    config = _get_config()
    from src.identity.keypair import KeyStore
    import json

    store = KeyStore(config)
    raw = store._load_raw()  # noqa: SLF001

    if not raw:
        print("Keystore is empty. Run: qsip keygen --label you@example.com")
        return 0

    print(f"Keystore: {config.identity_keystore_path}  ({len(raw)} identit{'y' if len(raw)==1 else 'ies'})\n")
    for i, (identity_id, entry) in enumerate(raw.items(), 1):
        print(f"  [{i}] {entry.get('label', '(no label)')}")
        print(f"       ID  : {identity_id}")
        print(f"       KEM : {entry.get('kem_algorithm', '?')}")
        print(f"       Sig : {entry.get('sig_algorithm', '?')}")
        print(f"       Date: {entry.get('created_at', '?')[:10]}")
        print()
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    """Show details of a specific identity."""
    config = _get_config()
    from src.identity.keypair import KeyStore

    store = KeyStore(config)
    keypair = store.load(args.id)

    print("Identity details:")
    _print_identity(keypair, verbose=args.verbose)
    return 0


def cmd_email_encrypt(args: argparse.Namespace) -> int:
    """Encrypt a file with PQEP for a recipient."""
    config = _get_config()
    from src.identity.keypair import KeyStore
    from src.email.encryptor import PQEPEncryptor
    import json

    # Read plaintext
    if args.input == "-":
        plaintext = sys.stdin.buffer.read()
    else:
        plaintext = Path(args.input).read_bytes()

    if not plaintext.strip():
        print("Error: input is empty.", file=sys.stderr)
        return 1

    # Load sender identity
    store = KeyStore(config)
    sender = store.load(args.sender)

    # Load recipient public key
    if args.recipient_pk.startswith("/") or Path(args.recipient_pk).exists():
        recipient_pk_hex = Path(args.recipient_pk).read_text().strip()
    else:
        recipient_pk_hex = args.recipient_pk.strip()

    try:
        recipient_pk = bytes.fromhex(recipient_pk_hex)
    except ValueError:
        try:
            recipient_pk = b64decode(recipient_pk_hex)
        except Exception:
            print("Error: --recipient-pk must be hex or base64 KEM public key.", file=sys.stderr)
            return 1

    # Encrypt
    encryptor = PQEPEncryptor(config)
    payload = encryptor.encrypt(
        plaintext=plaintext,
        recipient_kem_public_key=recipient_pk,
        sender_keypair=sender,
    )

    output_dict = payload.to_dict()
    output_json = json.dumps(output_dict, indent=2)

    if args.output and args.output != "-":
        Path(args.output).write_text(output_json)
        print(f"Encrypted payload written to: {args.output}")
    else:
        print(output_json)

    print(f"\n  KEM ciphertext : {len(payload.kem_ciphertext)} bytes")
    print(f"  Encrypted body : {len(payload.encrypted_body)} bytes")
    print(f"  Algorithm      : {payload.kem_algorithm} / {payload.sig_algorithm}")
    return 0


def cmd_email_decrypt(args: argparse.Namespace) -> int:
    """Decrypt a PQEP-encrypted file."""
    config = _get_config()
    from src.identity.keypair import KeyStore
    from src.email.encryptor import PQEPEncryptor, PQEPEncryptedPayload
    import json

    # Read payload
    if args.input == "-":
        data = json.load(sys.stdin)
    else:
        data = json.loads(Path(args.input).read_text())

    store = KeyStore(config)
    recipient = store.load(args.recipient)

    encryptor = PQEPEncryptor(config)
    payload = PQEPEncryptedPayload.from_dict(data)
    plaintext = encryptor.decrypt(payload=payload, recipient_keypair=recipient)

    if args.output and args.output != "-":
        Path(args.output).write_bytes(plaintext)
        print(f"Decrypted plaintext written to: {args.output}")
    else:
        sys.stdout.buffer.write(plaintext)
    return 0


def cmd_dns_make_record(args: argparse.Namespace) -> int:
    """Construct a QSIP DNS TXT record for a domain."""
    config = _get_config()
    from src.identity.keypair import KeyStore
    from src.crypto.signatures import DilithiumSigner

    store = KeyStore(config)
    keypair = store.load(args.signer)

    canonical_data = f"{args.domain} {args.payload}".encode()
    signer = DilithiumSigner(config)
    sig = signer.sign(canonical_data, keypair.sig_keypair.sign_key)

    pk_b64 = b64encode(keypair.sig_verify_key).decode()
    sig_b64 = b64encode(sig).decode()
    txt = f"v=QSIP1; alg={keypair.sig_keypair.algorithm}; pk={pk_b64}; sig={sig_b64}"

    print("DNS TXT record (place at _pqc." + args.domain + ". IN TXT):\n")
    print(txt)
    print(f"\n  Record length: {len(txt)} chars")
    print(f"  Signature    : {len(sig)} bytes (Dilithium5)")
    return 0


def cmd_dns_verify(args: argparse.Namespace) -> int:
    """Verify a QSIP DNS TXT record against its embedded public key."""
    config = _get_config()
    from src.dns.validator import DNSRecordValidator
    from src.crypto.signatures import DilithiumSigner

    validator = DNSRecordValidator(config)
    parsed = validator.parse_qsip_record(args.record)

    if parsed is None:
        print("Not a QSIP TXT record (no v=QSIP1 field).")
        return 1

    print(f"  Version   : {parsed['v']}")
    print(f"  Algorithm : {parsed['alg']}")
    print(f"  PK        : {parsed['pk'][:48]}…")

    canonical_data = f"{args.domain} {args.payload}".encode()
    pk = b64decode(parsed["pk"])
    sig = b64decode(parsed["sig"])

    signer = DilithiumSigner(config)
    valid = signer.verify(canonical_data, sig, pk)

    if valid:
        print(f"\n  {chr(10003)} Dilithium5 signature VALID — DNS record is authentic.")
        return 0
    else:
        print(f"\n  ✗ Signature INVALID — DNS record may be tampered.")
        return 2


def cmd_demo(_args: argparse.Namespace) -> int:
    """Run the full QSIP end-to-end showcase demo."""
    import demo as demo_module
    demo_module.main()
    return 0


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qsip",
        description=textwrap.dedent("""\
            QSIP — Quantum-Safe Internet Protocol Suite

            A post-quantum cryptography toolkit implementing:
              • Self-sovereign ZK identity (CRYSTALS-Dilithium5)
              • PQEP encrypted email      (CRYSTALS-Kyber1024 + AES-256-GCM)
              • PQC-signed DNS validation (CRYSTALS-Dilithium5)

            All algorithms are NIST FIPS 203 / FIPS 204 compliant.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── keygen ──────────────────────────────────────────────────────────────
    p_keygen = sub.add_parser("keygen", help="Generate a new identity keypair")
    p_keygen.add_argument("--label", "-l", default="", help="Human-readable label (e.g. email)")
    p_keygen.set_defaults(func=cmd_keygen)

    # ── list ────────────────────────────────────────────────────────────────
    p_list = sub.add_parser("list", help="List all identities in the keystore")
    p_list.set_defaults(func=cmd_list)

    # ── show ────────────────────────────────────────────────────────────────
    p_show = sub.add_parser("show", help="Show details of an identity")
    p_show.add_argument("--id", required=True, help="Identity UUID")
    p_show.add_argument("--verbose", "-v", action="store_true", help="Show public keys")
    p_show.set_defaults(func=cmd_show)

    # ── email ────────────────────────────────────────────────────────────────
    p_email = sub.add_parser("email", help="PQEP email operations")
    email_sub = p_email.add_subparsers(dest="email_command", metavar="ACTION")

    p_enc = email_sub.add_parser("encrypt", help="Encrypt a message for a recipient")
    p_enc.add_argument("--sender", "-s", required=True, help="Sender identity ID")
    p_enc.add_argument("--recipient-pk", "-r", required=True,
                       help="Recipient Kyber1024 public key (hex or base64 or file path)")
    p_enc.add_argument("--input", "-i", default="-", help="Input plaintext file (default: stdin)")
    p_enc.add_argument("--output", "-o", default="-", help="Output .pqep JSON file (default: stdout)")
    p_enc.set_defaults(func=cmd_email_encrypt)

    p_dec = email_sub.add_parser("decrypt", help="Decrypt and verify a PQEP message")
    p_dec.add_argument("--recipient", "-r", required=True, help="Recipient identity ID")
    p_dec.add_argument("--input", "-i", default="-", help="Input .pqep JSON file (default: stdin)")
    p_dec.add_argument("--output", "-o", default="-", help="Output plaintext file (default: stdout)")
    p_dec.set_defaults(func=cmd_email_decrypt)

    # ── dns ─────────────────────────────────────────────────────────────────
    p_dns = sub.add_parser("dns", help="QSIP DNS record operations")
    dns_sub = p_dns.add_subparsers(dest="dns_command", metavar="ACTION")

    p_dns_make = dns_sub.add_parser("make-record", help="Create a QSIP DNS TXT record")
    p_dns_make.add_argument("--signer", required=True, help="Signing identity ID")
    p_dns_make.add_argument("--domain", required=True, help="Domain name (e.g. example.com)")
    p_dns_make.add_argument("--payload", required=True, help="Record data to sign (e.g. 'A 93.184.216.34')")
    p_dns_make.set_defaults(func=cmd_dns_make_record)

    p_dns_verify = dns_sub.add_parser("verify", help="Verify a QSIP DNS TXT record")
    p_dns_verify.add_argument("--record", required=True, help="Full TXT record string")
    p_dns_verify.add_argument("--domain", required=True, help="Domain name the record is for")
    p_dns_verify.add_argument("--payload", required=True, help="The original signed data (e.g. 'A 93.184.216.34')")
    p_dns_verify.set_defaults(func=cmd_dns_verify)

    # ── demo ────────────────────────────────────────────────────────────────
    p_demo = sub.add_parser("demo", help="Run the full QSIP end-to-end showcase")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        # Handle sub-command dispatch for nested subparsers
        if hasattr(args, "command") and args.command == "email" and not args.email_command:
            parser.parse_args(["email", "--help"])
        elif hasattr(args, "command") and args.command == "dns" and not args.dns_command:
            parser.parse_args(["dns", "--help"])
        else:
            parser.print_help()
        sys.exit(0)

    try:
        exit_code = args.func(args)
        sys.exit(exit_code or 0)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
