"""Command Line Interface for JWT Audit Sentinel."""

import argparse
import datetime
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

from . import __version__
from .audit import JWTAuditor, Severity
from .claims import ClaimsVerifier
from .crypto import sign_token, verify_signature
from .decoder import JWTDecodeError, decode_token
from .reporter import (
    TermColor,
    format_json_report,
    format_markdown_report,
    format_terminal_report,
)


def _read_input(token_arg: Optional[str]) -> str:
    """Read token string from argument, file reference, or stdin."""
    if token_arg is not None:
        if token_arg.startswith("@"):
            filepath = Path(token_arg[1:]).expanduser().resolve()
            if not filepath.exists():
                raise FileNotFoundError(f"File not found: {filepath}")
            return filepath.read_text(encoding="utf-8").strip()
        return token_arg.strip()

    if not sys.stdin.isatty():
        return sys.stdin.read().strip()

    raise ValueError("No token provided. Supply token as argument, @filename, or pipe via stdin.")


def _read_key_or_secret(key_arg: Optional[str]) -> Optional[str]:
    """Read secret/key from string or @filename."""
    if key_arg is None:
        return None
    if key_arg.startswith("@"):
        filepath = Path(key_arg[1:]).expanduser().resolve()
        if not filepath.exists():
            raise FileNotFoundError(f"Key file not found: {filepath}")
        return filepath.read_text(encoding="utf-8").strip()
    return key_arg


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jwt-audit-sentinel",
        description="Fast zero-dependency CLI & library to inspect, decode, verify signatures, detect algorithm confusion, and audit JWT tokens.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # --- inspect / decode ---
    inspect_p = subparsers.add_parser("inspect", aliases=["decode"], help="Decode and inspect JWT components")
    inspect_p.add_argument("token", nargs="?", default=None, help="JWT string or @filepath (or pipe via stdin)")
    inspect_p.add_argument("--json", action="store_true", help="Output full decoded structure as JSON")
    inspect_p.add_argument("--header", action="store_true", help="Output header only")
    inspect_p.add_argument("--payload", action="store_true", help="Output payload only")

    # --- verify ---
    verify_p = subparsers.add_parser("verify", help="Verify cryptographic signature and standard claims")
    verify_p.add_argument("token", nargs="?", default=None, help="JWT string or @filepath")
    verify_p.add_argument("-s", "--secret", type=str, default=None, help="HMAC secret or @file")
    verify_p.add_argument("-k", "--key", type=str, default=None, help="PEM public key or @file")
    verify_p.add_argument("-a", "--allow-alg", action="append", dest="allowed_algs", help="Allowed algorithms (e.g. HS256, RS256)")
    verify_p.add_argument("--iss", "--issuer", type=str, dest="expected_issuer", default=None, help="Expected 'iss' claim")
    verify_p.add_argument("--aud", "--audience", type=str, dest="expected_audience", default=None, help="Expected 'aud' claim")
    verify_p.add_argument("--leeway", type=float, default=0.0, help="Clock skew leeway in seconds (default: 0)")

    # --- audit ---
    audit_p = subparsers.add_parser("audit", help="Run comprehensive security audit on JWT token")
    audit_p.add_argument("token", nargs="?", default=None, help="JWT string or @filepath")
    audit_p.add_argument("-s", "--secret", type=str, default=None, help="Optional HMAC secret to test for weak passwords")
    audit_p.add_argument("-k", "--key", type=str, default=None, help="Optional PEM public key to test for algorithm confusion")
    audit_p.add_argument("-f", "--format", choices=["terminal", "markdown", "json"], default="terminal", help="Output format")
    audit_p.add_argument("--min-grade", choices=["A+", "A", "B", "C", "D"], default=None, help="Minimum acceptable grade for CI/CD gates")

    # --- encode / create ---
    encode_p = subparsers.add_parser("encode", aliases=["create"], help="Generate a new signed or unsigned JWT")
    encode_p.add_argument("-p", "--payload", type=str, required=True, help="Payload JSON string or @filepath")
    encode_p.add_argument("-s", "--secret", type=str, default=None, help="Secret or key for signing")
    encode_p.add_argument("-a", "--alg", type=str, default="HS256", help="Algorithm (default: HS256, or 'none')")
    encode_p.add_argument("--exp-mins", type=int, default=None, help="Add 'exp' claim N minutes in the future")
    encode_p.add_argument("--iss", type=str, default=None, help="Add 'iss' issuer claim")
    encode_p.add_argument("--sub", type=str, default=None, help="Add 'sub' subject claim")
    encode_p.add_argument("--aud", type=str, default=None, help="Add 'aud' audience claim")

    return parser


def cmd_inspect(args: argparse.Namespace) -> int:
    try:
        token_str = _read_input(args.token)
        token = decode_token(token_str)
    except Exception as e:
        print(TermColor.red(f"Error decoding token: {e}"), file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(token.to_dict(), indent=2))
        return 0

    if args.header:
        print(json.dumps(token.header, indent=2))
        return 0

    if args.payload:
        print(json.dumps(token.payload, indent=2))
        return 0

    # Formatted view
    print(TermColor.bold("=================================================="))
    print(TermColor.bold("               DECODED JWT TOKEN                  "))
    print(TermColor.bold("=================================================="))

    print(TermColor.cyan("\n--- HEADER ---"))
    print(json.dumps(token.header, indent=2))

    print(TermColor.cyan("\n--- PAYLOAD ---"))
    print(json.dumps(token.payload, indent=2))

    # Claims breakdown
    print(TermColor.cyan("\n--- CLAIMS SUMMARY ---"))
    payload = token.payload
    now = time.time()
    if "exp" in payload and isinstance(payload["exp"], (int, float)):
        exp_dt = datetime.datetime.fromtimestamp(payload["exp"], datetime.timezone.utc).isoformat()
        diff = payload["exp"] - now
        if diff > 0:
            exp_status = TermColor.green(f"Valid (expires in {int(diff)}s / {diff/3600:.1f}h)")
        else:
            exp_status = TermColor.red(f"EXPIRED ({abs(int(diff))}s ago)")
        print(f"Expiration (exp):   {exp_dt} [{exp_status}]")

    if "iat" in payload and isinstance(payload["iat"], (int, float)):
        iat_dt = datetime.datetime.fromtimestamp(payload["iat"], datetime.timezone.utc).isoformat()
        print(f"Issued At (iat):    {iat_dt}")

    if "nbf" in payload and isinstance(payload["nbf"], (int, float)):
        nbf_dt = datetime.datetime.fromtimestamp(payload["nbf"], datetime.timezone.utc).isoformat()
        print(f"Not Before (nbf):   {nbf_dt}")

    if "iss" in payload:
        print(f"Issuer (iss):       {payload['iss']}")
    if "sub" in payload:
        print(f"Subject (sub):      {payload['sub']}")
    if "aud" in payload:
        print(f"Audience (aud):     {payload['aud']}")
    if "jti" in payload:
        print(f"JWT ID (jti):       {payload['jti']}")

    print(TermColor.cyan("\n--- SIGNATURE ---"))
    if token.has_signature:
        print(f"Signature ({token.algorithm}): {token.signature_b64[:32]}... ({len(token.signature_bytes)} bytes)")
    else:
        print(TermColor.yellow("No signature segment (unsigned token)"))

    print(TermColor.dim("=" * 50))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        token_str = _read_input(args.token)
        token = decode_token(token_str)
    except Exception as e:
        print(TermColor.red(f"Error decoding token: {e}"), file=sys.stderr)
        return 1

    key = _read_key_or_secret(args.secret or args.key)
    if not key and token.algorithm.upper() != "NONE":
        print(TermColor.red("Error: Must provide --secret or --key for signed tokens"), file=sys.stderr)
        return 1

    # 1. Cryptographic Signature Verification
    sig_valid, sig_reason = verify_signature(
        token=token,
        key=key or "",
        allowed_algorithms=args.allowed_algs,
    )

    # 2. Claims Verification
    verifier = ClaimsVerifier(
        leeway=args.leeway,
        expected_issuer=args.expected_issuer,
        expected_audience=args.expected_audience,
    )
    claims_res = verifier.verify(token)

    # Print results
    print(TermColor.bold(f"Token Verification: {token.algorithm}"))
    print(TermColor.dim("-" * 40))

    if sig_valid:
        print(f"Signature: {TermColor.green('VALID')} ({sig_reason})")
    else:
        print(f"Signature: {TermColor.red('INVALID')} ({sig_reason})")

    if claims_res.valid:
        print(f"Claims:    {TermColor.green('VALID')}")
    else:
        print(f"Claims:    {TermColor.red('INVALID')}")
        for err in claims_res.errors:
            print(f"  * {TermColor.red(err)}")

    for warn in claims_res.warnings:
        print(f"  * {TermColor.yellow(f'Warning: {warn}')}")

    overall_valid = sig_valid and claims_res.valid
    print(TermColor.dim("-" * 40))
    if overall_valid:
        print(TermColor.green("RESULT: TOKEN VERIFIED SUCCESSFULLY"))
        return 0
    else:
        print(TermColor.red("RESULT: TOKEN VERIFICATION FAILED"))
        return 1


def cmd_audit(args: argparse.Namespace) -> int:
    try:
        token_str = _read_input(args.token)
        token = decode_token(token_str)
    except Exception as e:
        print(TermColor.red(f"Error decoding token: {e}"), file=sys.stderr)
        return 1

    secret = _read_key_or_secret(args.secret)
    public_key = _read_key_or_secret(args.key)

    auditor = JWTAuditor(secret=secret, public_key=public_key)
    report = auditor.audit(token)

    if args.format == "json":
        print(format_json_report(report))
    elif args.format == "markdown":
        print(format_markdown_report(report))
    else:
        print(format_terminal_report(report))

    # Check minimum grade requirement for CI/CD gates
    if args.min_grade:
        grade_order = {"A+": 5, "A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
        actual_score = grade_order.get(report.grade, 0)
        required_score = grade_order.get(args.min_grade, 0)
        if actual_score < required_score:
            print(
                TermColor.red(
                    f"\nCI/CD Gate Failed: Token grade {report.grade} is below minimum requirement {args.min_grade}"
                ),
                file=sys.stderr,
            )
            return 2

    return 0 if report.is_secure else 1


def cmd_encode(args: argparse.Namespace) -> int:
    try:
        if args.payload.startswith("@"):
            payload_raw = Path(args.payload[1:]).read_text(encoding="utf-8")
        else:
            payload_raw = args.payload
        payload_data = json.loads(payload_raw)
        if not isinstance(payload_data, dict):
            raise ValueError("Payload must be a JSON object")
    except Exception as e:
        print(TermColor.red(f"Error parsing payload JSON: {e}"), file=sys.stderr)
        return 1

    now = int(time.time())
    if "iat" not in payload_data:
        payload_data["iat"] = now

    if args.exp_mins is not None:
        payload_data["exp"] = now + (args.exp_mins * 60)

    if args.iss:
        payload_data["iss"] = args.iss
    if args.sub:
        payload_data["sub"] = args.sub
    if args.aud:
        payload_data["aud"] = args.aud

    secret = _read_key_or_secret(args.secret) or ""
    alg = args.alg.upper()

    try:
        token_str = sign_token(
            header={"alg": alg, "typ": "JWT"},
            payload=payload_data,
            key=secret,
            algorithm=alg,
        )
        print(token_str)
        return 0
    except Exception as e:
        print(TermColor.red(f"Error generating token: {e}"), file=sys.stderr)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0

    if not args.command:
        parser.print_help()
        return 0

    cmd = args.command
    if cmd in ("inspect", "decode"):
        return cmd_inspect(args)
    elif cmd == "verify":
        return cmd_verify(args)
    elif cmd == "audit":
        return cmd_audit(args)
    elif cmd in ("encode", "create"):
        return cmd_encode(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
