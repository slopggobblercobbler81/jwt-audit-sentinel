"""Unit tests for the CLI interface."""

import json
from pathlib import Path
import pytest

from jwt_audit_sentinel.cli import main
from jwt_audit_sentinel.crypto import sign_token


def test_cli_help(capsys):
    ret = main(["--help"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "jwt-audit-sentinel" in captured.out


def test_cli_inspect(capsys):
    secret = "a_very_secure_and_long_secret_key_32_bytes!!"
    token_str = sign_token(
        header={"alg": "HS256"},
        payload={"sub": "user_123", "role": "admin"},
        key=secret,
    )

    # Inspect standard
    ret = main(["inspect", token_str])
    assert ret == 0
    captured = capsys.readouterr()
    assert "DECODED JWT TOKEN" in captured.out
    assert "user_123" in captured.out

    # Inspect json
    ret = main(["inspect", token_str, "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["algorithm"] == "HS256"
    assert data["payload"]["sub"] == "user_123"

    # Inspect header & payload flags
    ret = main(["inspect", token_str, "--header"])
    assert ret == 0
    assert "HS256" in capsys.readouterr().out

    ret = main(["inspect", token_str, "--payload"])
    assert ret == 0
    assert "admin" in capsys.readouterr().out


def test_cli_verify(capsys):
    secret = "a_very_secure_and_long_secret_key_32_bytes!!"
    token_str = sign_token(
        header={"alg": "HS256"},
        payload={"sub": "user_456", "iss": "test_issuer"},
        key=secret,
    )

    # Valid verify
    ret = main(["verify", token_str, "-s", secret, "--iss", "test_issuer"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "TOKEN VERIFIED SUCCESSFULLY" in captured.out

    # Wrong secret
    ret_bad = main(["verify", token_str, "-s", "wrong_secret"])
    assert ret_bad == 1
    assert "TOKEN VERIFICATION FAILED" in capsys.readouterr().out

    # Wrong issuer
    ret_iss = main(["verify", token_str, "-s", secret, "--iss", "wrong_issuer"])
    assert ret_iss == 1


def test_cli_audit(capsys):
    secret = "secret"  # Weak secret
    token_str = sign_token(
        header={"alg": "HS256"},
        payload={"sub": "user_789"},
        key=secret,
    )

    # Terminal audit
    ret = main(["audit", token_str, "-s", secret])
    assert ret == 1  # Fails due to security issues (missing exp, weak secret)
    captured = capsys.readouterr()
    assert "JWT SECURITY AUDIT REPORT" in captured.out

    # JSON audit
    ret_json = main(["audit", token_str, "-s", secret, "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert "findings" in data
    assert any(f["id"] == "SEC-SECRET-WEAK" for f in data["findings"])

    # Markdown audit
    ret_md = main(["audit", token_str, "-s", secret, "-f", "markdown"])
    captured_md = capsys.readouterr().out
    assert "# 🛡️ JWT Security Audit Report" in captured_md


def test_cli_audit_min_grade(capsys):
    token_str = sign_token(
        header={"alg": "none"},
        payload={"sub": "hacker"},
        key="",
        algorithm="none",
    )
    # Require Grade A, but alg=none gives F -> should exit with code 2
    ret = main(["audit", token_str, "--min-grade", "A"])
    assert ret == 2
    assert "CI/CD Gate Failed" in capsys.readouterr().err


def test_cli_encode_and_file_input(tmp_path, capsys):
    payload_file = tmp_path / "payload.json"
    payload_file.write_text('{"sub": "cli_user", "tenant": "prod"}', encoding="utf-8")

    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("secure_cli_secret_key_32_bytes_ok!", encoding="utf-8")

    # Encode
    ret = main([
        "encode",
        "-p",
        f"@{payload_file}",
        "-s",
        f"@{secret_file}",
        "--exp-mins",
        "30",
        "--iss",
        "cli_issuer",
    ])
    assert ret == 0
    token_str = capsys.readouterr().out.strip()
    assert token_str.count(".") == 2

    # Verify generated token using files
    token_file = tmp_path / "token.jwt"
    token_file.write_text(token_str, encoding="utf-8")

    ret_verify = main([
        "verify",
        f"@{token_file}",
        "-s",
        f"@{secret_file}",
        "--iss",
        "cli_issuer",
    ])
    assert ret_verify == 0
    assert "TOKEN VERIFIED SUCCESSFULLY" in capsys.readouterr().out
