"""JWT decoding and base64url serialization utilities."""

import base64
from dataclasses import dataclass, field
import json
from typing import Any, Dict, Optional, Tuple, Union


def base64url_decode(data: Union[str, bytes]) -> bytes:
    """Decode a base64url-encoded string or bytes, adding required padding."""
    if isinstance(data, str):
        data_str = data.strip()
    else:
        data_str = data.decode("ascii").strip()

    # URL-safe conversion
    data_str = data_str.replace("-", "+").replace("_", "/")
    # Add padding
    missing_padding = len(data_str) % 4
    if missing_padding:
        data_str += "=" * (4 - missing_padding)

    return base64.b64decode(data_str.encode("ascii"))


def base64url_encode(data: Union[str, bytes]) -> str:
    """Encode bytes or string into a base64url string without padding."""
    if isinstance(data, str):
        raw_bytes = data.encode("utf-8")
    else:
        raw_bytes = data

    encoded = base64.urlsafe_b64encode(raw_bytes).decode("ascii")
    return encoded.rstrip("=")


class JWTDecodeError(ValueError):
    """Raised when JWT token string cannot be decoded or parsed."""
    pass


@dataclass
class JWTToken:
    """Parsed representation of a JSON Web Token."""
    raw_token: str
    header_b64: str
    payload_b64: str
    signature_b64: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature_bytes: bytes
    raw_header_bytes: bytes
    raw_payload_bytes: bytes

    @property
    def signing_input(self) -> bytes:
        """The ASCII bytes representing `header_b64.payload_b64` used for signing."""
        return f"{self.header_b64}.{self.payload_b64}".encode("ascii")

    @property
    def algorithm(self) -> str:
        """The 'alg' claim from the header, defaults to 'none' if absent."""
        return str(self.header.get("alg", "none"))

    @property
    def token_type(self) -> Optional[str]:
        """The 'typ' claim from the header."""
        return self.header.get("typ")

    @property
    def key_id(self) -> Optional[str]:
        """The 'kid' claim from the header."""
        return self.header.get("kid")

    @property
    def has_signature(self) -> bool:
        """Whether the token contains a non-empty signature component."""
        return len(self.signature_b64) > 0 and len(self.signature_bytes) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header,
            "payload": self.payload,
            "algorithm": self.algorithm,
            "token_type": self.token_type,
            "key_id": self.key_id,
            "has_signature": self.has_signature,
            "signature_hex": self.signature_bytes.hex() if self.signature_bytes else "",
        }


def decode_token(raw_token: str) -> JWTToken:
    """Parse and decode a JWT string.
    
    Accepts raw token strings or 'Bearer <token>' headers.
    """
    token_str = raw_token.strip()
    if token_str.lower().startswith("bearer "):
        token_str = token_str[7:].strip()

    parts = token_str.split(".")
    if len(parts) == 2:
        # Unsigned / alg=none token with trailing dot omitted
        header_b64, payload_b64 = parts
        sig_b64 = ""
    elif len(parts) == 3:
        header_b64, payload_b64, sig_b64 = parts
    else:
        raise JWTDecodeError(
            f"Invalid JWT format: expected 2 or 3 dot-separated segments, got {len(parts)}"
        )

    # Decode Header
    try:
        header_bytes = base64url_decode(header_b64)
    except Exception as e:
        raise JWTDecodeError(f"Failed to base64url-decode token header: {e}") from e

    try:
        header = json.loads(header_bytes.decode("utf-8"))
        if not isinstance(header, dict):
            raise JWTDecodeError("JWT header is not a JSON object")
    except Exception as e:
        raise JWTDecodeError(f"Failed to parse JWT header JSON: {e}") from e

    # Decode Payload
    try:
        payload_bytes = base64url_decode(payload_b64)
    except Exception as e:
        raise JWTDecodeError(f"Failed to base64url-decode token payload: {e}") from e

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
        if not isinstance(payload, dict):
            raise JWTDecodeError("JWT payload is not a JSON object")
    except Exception as e:
        raise JWTDecodeError(f"Failed to parse JWT payload JSON: {e}") from e

    # Decode Signature
    sig_bytes = b""
    if sig_b64:
        try:
            sig_bytes = base64url_decode(sig_b64)
        except Exception as e:
            raise JWTDecodeError(f"Failed to base64url-decode token signature: {e}") from e

    return JWTToken(
        raw_token=token_str,
        header_b64=header_b64,
        payload_b64=payload_b64,
        signature_b64=sig_b64,
        header=header,
        payload=payload,
        signature_bytes=sig_bytes,
        raw_header_bytes=header_bytes,
        raw_payload_bytes=payload_bytes,
    )
