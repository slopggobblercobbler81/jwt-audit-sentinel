"""Unit tests for JWT decoder and base64url parsing."""

import json
import pytest

from jwt_audit_sentinel.decoder import (
    JWTDecodeError,
    JWTToken,
    base64url_decode,
    base64url_encode,
    decode_token,
)


def test_base64url_roundtrip():
    data = b"Hello world! Testing base64url with characters + / and padding ==="
    encoded = base64url_encode(data)
    assert "+" not in encoded
    assert "/" not in encoded
    assert "=" not in encoded

    decoded = base64url_decode(encoded)
    assert decoded == data


def test_decode_standard_token():
    header = {"alg": "HS256", "typ": "JWT", "kid": "key_1"}
    payload = {"sub": "user_123", "name": "Alice", "admin": True}

    h_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    p_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    s_b64 = base64url_encode(b"dummy_signature_32_bytes_long_ok")

    token_str = f"{h_b64}.{p_b64}.{s_b64}"

    token = decode_token(token_str)
    assert token.algorithm == "HS256"
    assert token.token_type == "JWT"
    assert token.key_id == "key_1"
    assert token.has_signature is True
    assert token.payload["sub"] == "user_123"
    assert token.payload["admin"] is True
    assert token.signing_input == f"{h_b64}.{p_b64}".encode("ascii")

    token_dict = token.to_dict()
    assert token_dict["algorithm"] == "HS256"
    assert token_dict["has_signature"] is True


def test_decode_bearer_prefix():
    header = {"alg": "none"}
    payload = {"sub": "test"}
    h_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    p_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))

    token_str = f"Bearer {h_b64}.{p_b64}."
    token = decode_token(token_str)
    assert token.algorithm == "none"
    assert token.has_signature is False


def test_decode_invalid_tokens():
    # Only 1 part
    with pytest.raises(JWTDecodeError):
        decode_token("just_one_part")

    # 4 parts
    with pytest.raises(JWTDecodeError):
        decode_token("part1.part2.part3.part4")

    # Non-json header
    bad_header = base64url_encode(b"not json")
    with pytest.raises(JWTDecodeError):
        decode_token(f"{bad_header}.eyJuYW1lIjoidGVzdCJ9.sig")

    # Non-json payload
    good_header = base64url_encode(b'{"alg":"none"}')
    bad_payload = base64url_encode(b"not json")
    with pytest.raises(JWTDecodeError):
        decode_token(f"{good_header}.{bad_payload}.")
