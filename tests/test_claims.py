"""Unit tests for claims verification."""

import time
import pytest

from jwt_audit_sentinel.claims import ClaimsVerifier
from jwt_audit_sentinel.decoder import decode_token
from jwt_audit_sentinel.crypto import sign_token


def test_claims_expiration():
    now = 1700000000
    # Valid unexpired token
    token_str = sign_token(
        header={"alg": "HS256"},
        payload={"sub": "123", "exp": now + 3600, "iat": now},
        key="secret123",
    )
    token = decode_token(token_str)

    verifier = ClaimsVerifier()
    res = verifier.verify(token, current_time=now)
    assert res.valid is True
    assert res.is_expired is False
    assert res.expires_in_seconds == 3600

    # Expired token
    res_expired = verifier.verify(token, current_time=now + 4000)
    assert res_expired.valid is False
    assert res_expired.is_expired is True
    assert any("expired" in e.lower() for e in res_expired.errors)

    # Leeway allows expired token within window
    verifier_leeway = ClaimsVerifier(leeway=500)
    res_leeway = verifier_leeway.verify(token, current_time=now + 3800)
    assert res_leeway.valid is True


def test_claims_missing_exp():
    token_str = sign_token(header={"alg": "HS256"}, payload={"sub": "123"}, key="secret")
    token = decode_token(token_str)

    verifier = ClaimsVerifier(require_exp=True)
    res = verifier.verify(token)
    assert res.valid is True
    assert len(res.warnings) > 0
    assert "exp" in res.warnings[0]


def test_claims_nbf_and_iat():
    now = 1700000000
    # Future nbf
    token_str = sign_token(
        header={"alg": "HS256"},
        payload={"nbf": now + 600, "iat": now + 100},
        key="secret",
    )
    token = decode_token(token_str)

    verifier = ClaimsVerifier()
    res = verifier.verify(token, current_time=now)
    assert res.valid is False
    assert any("not valid yet" in e.lower() for e in res.errors)
    assert any("future" in e.lower() for e in res.errors)


def test_claims_issuer_and_audience():
    token_str = sign_token(
        header={"alg": "HS256"},
        payload={"iss": "auth.example.com", "aud": ["api.example.com", "billing.example.com"]},
        key="secret",
    )
    token = decode_token(token_str)

    # Valid issuer & audience
    v1 = ClaimsVerifier(expected_issuer="auth.example.com", expected_audience="api.example.com")
    assert v1.verify(token).valid is True

    # Invalid issuer
    v2 = ClaimsVerifier(expected_issuer="wrong.example.com")
    res2 = v2.verify(token)
    assert res2.valid is False
    assert any("issuer mismatch" in e.lower() for e in res2.errors)

    # Invalid audience
    v3 = ClaimsVerifier(expected_audience="admin.example.com")
    res3 = v3.verify(token)
    assert res3.valid is False
    assert any("audience mismatch" in e.lower() for e in res3.errors)
