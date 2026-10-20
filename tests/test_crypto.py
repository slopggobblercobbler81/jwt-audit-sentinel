"""Unit tests for cryptographic verification and signing."""

import pytest

from jwt_audit_sentinel.crypto import (
    HAS_CRYPTOGRAPHY,
    sign_token,
    verify_signature,
)
from jwt_audit_sentinel.decoder import decode_token


def test_hmac_sha256_signing_and_verification():
    secret = "a_very_secure_and_long_secret_key_32_bytes!!"
    token_str = sign_token(
        header={"alg": "HS256"},
        payload={"sub": "user_42", "scope": "read write"},
        key=secret,
    )
    token = decode_token(token_str)

    # Valid verification
    valid, reason = verify_signature(token, secret)
    assert valid is True
    assert "Valid HS256" in reason

    # Wrong secret
    valid, reason = verify_signature(token, "wrong_secret")
    assert valid is False

    # Tampered token (valid JSON payload with altered content against original signature)
    parts = token_str.split(".")
    from jwt_audit_sentinel.decoder import base64url_encode
    tampered_payload_b64 = base64url_encode(b'{"sub":"user_99","scope":"read write"}')
    tampered_token = decode_token(f"{parts[0]}.{tampered_payload_b64}.{parts[2]}")
    valid, reason = verify_signature(tampered_token, secret)
    assert valid is False


def test_hmac_sha384_and_sha512():
    secret = "strong_key_for_sha384_and_sha512_verification_12345"
    for alg in ("HS384", "HS512"):
        token_str = sign_token(
            header={"alg": alg},
            payload={"sub": "test"},
            key=secret,
            algorithm=alg,
        )
        token = decode_token(token_str)
        valid, reason = verify_signature(token, secret)
        assert valid is True
        assert f"Valid {alg}" in reason


def test_none_algorithm():
    # Valid none token
    token_str = sign_token(
        header={"alg": "none"},
        payload={"sub": "guest"},
        key="",
        algorithm="none",
    )
    token = decode_token(token_str)
    valid, reason = verify_signature(token, key="")
    assert valid is True

    # Malicious none token with attached signature
    fake_token = decode_token(f"{token.header_b64}.{token.payload_b64}.ZmFrZXNpZw")
    valid, reason = verify_signature(fake_token, key="")
    assert valid is False


def test_allowed_algorithms_restriction():
    secret = "secret"
    token_str = sign_token(header={"alg": "HS256"}, payload={"sub": "1"}, key=secret)
    token = decode_token(token_str)

    # Only allow RS256
    valid, reason = verify_signature(token, key=secret, allowed_algorithms=["RS256"])
    assert valid is False
    assert "not in allowed list" in reason

    # Allow HS256
    valid, reason = verify_signature(token, key=secret, allowed_algorithms=["HS256", "RS256"])
    assert valid is True


@pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography library not installed")
def test_rsa_verification():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # Generate RSA keypair for testing
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    token_str = sign_token(
        header={"alg": "RS256"},
        payload={"sub": "rsa_user"},
        key=private_pem,
        algorithm="RS256",
    )
    token = decode_token(token_str)

    # Verify with public key
    valid, reason = verify_signature(token, public_pem)
    assert valid is True
    assert "Valid RS256" in reason

    # Verification with wrong public key
    other_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pub = other_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    valid_bad, _ = verify_signature(token, other_pub)
    assert valid_bad is False
