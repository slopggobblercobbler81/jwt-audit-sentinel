"""Unit tests for the JWT security auditor."""

import time
import pytest

from jwt_audit_sentinel.audit import JWTAuditor, Severity
from jwt_audit_sentinel.crypto import sign_token
from jwt_audit_sentinel.decoder import decode_token


def test_audit_alg_none():
    token_str = sign_token(
        header={"alg": "none"},
        payload={"sub": "admin", "exp": int(time.time()) + 3600},
        key="",
        algorithm="none",
    )
    token = decode_token(token_str)
    auditor = JWTAuditor()
    report = auditor.audit(token)

    assert report.is_secure is False
    assert any(f.id == "SEC-ALG-NONE" and f.severity == Severity.CRITICAL for f in report.findings)
    assert report.score < 80


def test_audit_algorithm_confusion():
    token_str = sign_token(
        header={"alg": "HS256"},
        payload={"sub": "attacker", "exp": int(time.time()) + 3600},
        key="test_hmac_secret",
    )
    token = decode_token(token_str)

    rsa_pubkey = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0G9\n"
        "-----END PUBLIC KEY-----"
    )

    auditor = JWTAuditor(public_key=rsa_pubkey)
    report = auditor.audit(token)

    assert report.is_secure is False
    assert any(f.id == "SEC-ALG-CONFUSION" and f.severity == Severity.CRITICAL for f in report.findings)


def test_audit_weak_and_short_secret():
    token_str = sign_token(
        header={"alg": "HS256"},
        payload={"sub": "user", "exp": int(time.time()) + 3600},
        key="secret",
    )
    token = decode_token(token_str)

    # Dictionary word 'secret'
    auditor1 = JWTAuditor(secret="secret")
    report1 = auditor1.audit(token)
    assert any(f.id == "SEC-SECRET-WEAK" for f in report1.findings)

    # Short secret
    auditor2 = JWTAuditor(secret="short_pwd")
    report2 = auditor2.audit(token)
    assert any(f.id == "SEC-SECRET-SHORT" for f in report2.findings)


def test_audit_missing_and_long_lived_exp():
    now = 1700000000
    # Missing exp
    token1 = decode_token(sign_token(header={"alg": "HS256"}, payload={"sub": "user"}, key="strong_key_32_characters_minimum!"))
    report1 = JWTAuditor(current_time=now).audit(token1)
    assert any(f.id == "SEC-EXP-MISSING" for f in report1.findings)

    # Long-lived (> 30 days)
    token2 = decode_token(sign_token(
        header={"alg": "HS256"},
        payload={"sub": "user", "exp": now + (60 * 86400)},
        key="strong_key_32_characters_minimum!",
    ))
    report2 = JWTAuditor(current_time=now).audit(token2)
    assert any(f.id == "SEC-EXP-LONG-LIVED" for f in report2.findings)


def test_audit_sensitive_payload():
    token = decode_token(sign_token(
        header={"alg": "HS256"},
        payload={"user_id": 1, "password": "superSecretPassword123", "exp": int(time.time()) + 3600},
        key="strong_key_32_characters_minimum!",
    ))
    report = JWTAuditor().audit(token)
    assert any(f.id == "SEC-PAYLOAD-SENSITIVE" and f.severity == Severity.HIGH for f in report.findings)


def test_audit_suspicious_headers_ssrf():
    token = decode_token(sign_token(
        header={"alg": "HS256", "jku": "http://127.0.0.1:8000/jwks.json"},
        payload={"sub": "user", "exp": int(time.time()) + 3600},
        key="strong_key_32_characters_minimum!",
    ))
    report = JWTAuditor().audit(token)
    assert any(f.id == "SEC-HEADER-SSRF" and f.severity == Severity.CRITICAL for f in report.findings)


def test_audit_secure_token():
    now = 1700000000
    token = decode_token(sign_token(
        header={"alg": "HS256", "typ": "JWT"},
        payload={
            "sub": "user_100",
            "iss": "https://auth.example.com",
            "aud": "https://api.example.com",
            "iat": now,
            "exp": now + 900,  # 15 min TTL
            "jti": "random_uuid_12345",
        },
        key="a_very_strong_and_secure_secret_key_32_bytes!",
    ))
    auditor = JWTAuditor(
        secret="a_very_strong_and_secure_secret_key_32_bytes!",
        current_time=now,
    )
    report = auditor.audit(token)

    assert report.is_secure is True
    assert report.grade in ("A+", "A")
    assert report.score >= 95
    assert len(report.findings) == 0
    assert len(report.passed_checks) > 0
