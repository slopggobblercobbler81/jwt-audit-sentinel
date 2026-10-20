"""Cryptographic signature generation and verification for JWTs."""

import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional, Tuple, Union

from .decoder import JWTToken, base64url_decode, base64url_encode

# Optional cryptography support for asymmetric algorithms (RSA/ECDSA/EdDSA)
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, ec, ed25519, utils
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


HMAC_HASH_MAP = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _ensure_bytes(data: Union[str, bytes]) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    return data


def verify_signature(
    token: JWTToken,
    key: Union[str, bytes],
    allowed_algorithms: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """Verify cryptographic signature of a JWTToken against a secret or public key.
    
    Args:
        token: Decoded JWTToken object
        key: HMAC secret (string/bytes) or PEM-encoded public key
        allowed_algorithms: Explicit list of permitted algorithms (e.g. ['HS256'])
        
    Returns:
        (is_valid, reason)
    """
    alg = token.algorithm.upper()

    # Algorithm restriction check
    if allowed_algorithms is not None:
        allowed_upper = [a.upper() for a in allowed_algorithms]
        if alg not in allowed_upper:
            return (
                False,
                f"Algorithm '{token.algorithm}' is not in allowed list: {allowed_algorithms}",
            )

    # 1. Unsigned / 'none' algorithm
    if alg == "NONE":
        if token.has_signature:
            return False, "Algorithm is 'none' but signature segment is not empty"
        return True, "Valid unsigned token (alg='none')"

    if not token.has_signature:
        return False, f"Missing signature for algorithm '{token.algorithm}'"

    # 2. Symmetric HMAC (HS256, HS384, HS512)
    if alg in HMAC_HASH_MAP:
        key_bytes = _ensure_bytes(key)
        hash_mod = HMAC_HASH_MAP[alg]
        expected_sig = hmac.new(key_bytes, token.signing_input, hash_mod).digest()

        if hmac.compare_digest(token.signature_bytes, expected_sig):
            return True, f"Valid {alg} signature"
        return False, f"Signature verification failed for {alg}"

    # 3. Asymmetric RSA / ECDSA / EdDSA
    if not HAS_CRYPTOGRAPHY:
        return (
            False,
            f"Algorithm '{alg}' requires the 'cryptography' library (pip install cryptography)",
        )

    try:
        key_bytes = _ensure_bytes(key)
        pub_key = load_pem_public_key(key_bytes)
    except Exception as e:
        return False, f"Failed to parse public key as PEM: {e}"

    signing_input = token.signing_input
    sig = token.signature_bytes

    try:
        if alg == "RS256":
            pub_key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return True, "Valid RS256 signature"
        elif alg == "RS384":
            pub_key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA384())
            return True, "Valid RS384 signature"
        elif alg == "RS512":
            pub_key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA512())
            return True, "Valid RS512 signature"
        elif alg == "PS256":
            pub_key.verify(
                sig,
                signing_input,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True, "Valid PS256 signature"
        elif alg == "PS384":
            pub_key.verify(
                sig,
                signing_input,
                padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA384(),
            )
            return True, "Valid PS384 signature"
        elif alg == "PS512":
            pub_key.verify(
                sig,
                signing_input,
                padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA512(),
            )
            return True, "Valid PS512 signature"
        elif alg == "ES256":
            pub_key.verify(sig, signing_input, ec.ECDSA(hashes.SHA256()))
            return True, "Valid ES256 signature"
        elif alg == "ES384":
            pub_key.verify(sig, signing_input, ec.ECDSA(hashes.SHA384()))
            return True, "Valid ES384 signature"
        elif alg == "ES512":
            pub_key.verify(sig, signing_input, ec.ECDSA(hashes.SHA512()))
            return True, "Valid ES512 signature"
        elif alg == "EDDSA":
            pub_key.verify(sig, signing_input)
            return True, "Valid EdDSA signature"
        else:
            return False, f"Unsupported algorithm '{alg}'"
    except Exception as e:
        return False, f"Cryptographic verification failed: {e}"


def sign_token(
    header: Dict[str, Any],
    payload: Dict[str, Any],
    key: Union[str, bytes],
    algorithm: Optional[str] = None,
) -> str:
    """Create a signed or unsigned JWT string."""
    hdr = dict(header)
    alg = (algorithm or hdr.get("alg", "HS256")).upper()
    hdr["alg"] = alg
    if "typ" not in hdr:
        hdr["typ"] = "JWT"

    header_json = json.dumps(hdr, separators=(",", ":")).encode("utf-8")
    payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    header_b64 = base64url_encode(header_json)
    payload_b64 = base64url_encode(payload_json)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    if alg == "NONE":
        return f"{header_b64}.{payload_b64}."

    if alg in HMAC_HASH_MAP:
        key_bytes = _ensure_bytes(key)
        hash_mod = HMAC_HASH_MAP[alg]
        sig_bytes = hmac.new(key_bytes, signing_input, hash_mod).digest()
        sig_b64 = base64url_encode(sig_bytes)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    if not HAS_CRYPTOGRAPHY:
        raise ValueError(f"Signing with '{alg}' requires 'cryptography' library")

    key_bytes = _ensure_bytes(key)
    priv_key = load_pem_private_key(key_bytes, password=None)

    if alg == "RS256":
        sig_bytes = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "RS384":
        sig_bytes = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA384())
    elif alg == "RS512":
        sig_bytes = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA512())
    elif alg == "ES256":
        sig_bytes = priv_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Signing with algorithm '{alg}' not supported yet")

    sig_b64 = base64url_encode(sig_bytes)
    return f"{header_b64}.{payload_b64}.{sig_b64}"
