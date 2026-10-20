"""RFC 7519 standard claims validation and expiration checking."""

from dataclasses import dataclass, field
import datetime
import time
from typing import Any, Dict, List, Optional, Union

from .decoder import JWTToken


@dataclass
class ClaimsValidationResult:
    """Outcome of validating token claims."""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_expired: bool = False
    expires_in_seconds: Optional[float] = None
    claims_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "is_expired": self.is_expired,
            "expires_in_seconds": round(self.expires_in_seconds, 1) if self.expires_in_seconds is not None else None,
            "claims_info": self.claims_info,
        }


class ClaimsVerifier:
    """Verifies standard JWT claims (exp, nbf, iat, iss, aud)."""

    def __init__(
        self,
        leeway: float = 0.0,
        expected_issuer: Optional[str] = None,
        expected_audience: Optional[Union[str, List[str]]] = None,
        require_exp: bool = True,
        require_iat: bool = False,
    ):
        self.leeway = float(leeway)
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.require_exp = require_exp
        self.require_iat = require_iat

    def verify(
        self, token: JWTToken, current_time: Optional[float] = None
    ) -> ClaimsValidationResult:
        now = time.time() if current_time is None else float(current_time)
        payload = token.payload
        errors: List[str] = []
        warnings: List[str] = []
        is_expired = False
        expires_in: Optional[float] = None
        claims_info: Dict[str, Any] = {}

        # 1. Expiration (exp)
        if "exp" in payload:
            exp_val = payload["exp"]
            if not isinstance(exp_val, (int, float)):
                errors.append(f"'exp' claim must be a number, got {type(exp_val).__name__}")
            else:
                expires_in = exp_val - now
                claims_info["exp"] = {
                    "timestamp": exp_val,
                    "datetime": datetime.datetime.fromtimestamp(exp_val, datetime.timezone.utc).isoformat(),
                    "expires_in_seconds": expires_in,
                }
                if now > (exp_val + self.leeway):
                    is_expired = True
                    errors.append(
                        f"Token expired {abs(expires_in):.0f}s ago at "
                        f"{claims_info['exp']['datetime']}"
                    )
        elif self.require_exp:
            warnings.append("Token does not have an 'exp' (expiration) claim")

        # 2. Not Before (nbf)
        if "nbf" in payload:
            nbf_val = payload["nbf"]
            if not isinstance(nbf_val, (int, float)):
                errors.append(f"'nbf' claim must be a number, got {type(nbf_val).__name__}")
            else:
                claims_info["nbf"] = {
                    "timestamp": nbf_val,
                    "datetime": datetime.datetime.fromtimestamp(nbf_val, datetime.timezone.utc).isoformat(),
                }
                if now < (nbf_val - self.leeway):
                    diff = nbf_val - now
                    errors.append(
                        f"Token not valid yet (nbf is {diff:.0f}s in the future at {claims_info['nbf']['datetime']})"
                    )

        # 3. Issued At (iat)
        if "iat" in payload:
            iat_val = payload["iat"]
            if not isinstance(iat_val, (int, float)):
                errors.append(f"'iat' claim must be a number, got {type(iat_val).__name__}")
            else:
                claims_info["iat"] = {
                    "timestamp": iat_val,
                    "datetime": datetime.datetime.fromtimestamp(iat_val, datetime.timezone.utc).isoformat(),
                }
                # Check future iat
                if iat_val > (now + self.leeway + 1.0):
                    errors.append(
                        f"Token issued in the future (iat={claims_info['iat']['datetime']}, current={datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat()})"
                    )
        elif self.require_iat:
            warnings.append("Token does not have an 'iat' (issued at) claim")

        # 4. Issuer (iss)
        if "iss" in payload:
            claims_info["iss"] = payload["iss"]
        if self.expected_issuer is not None:
            actual_iss = payload.get("iss")
            if actual_iss != self.expected_issuer:
                errors.append(
                    f"Issuer mismatch: expected '{self.expected_issuer}', got '{actual_iss}'"
                )

        # 5. Audience (aud)
        if "aud" in payload:
            claims_info["aud"] = payload["aud"]
        if self.expected_audience is not None:
            actual_aud = payload.get("aud")
            valid_aud = False
            expected_list = (
                [self.expected_audience]
                if isinstance(self.expected_audience, str)
                else list(self.expected_audience)
            )

            if isinstance(actual_aud, str):
                valid_aud = actual_aud in expected_list
            elif isinstance(actual_aud, list):
                valid_aud = any(a in expected_list for a in actual_aud)

            if not valid_aud:
                errors.append(
                    f"Audience mismatch: expected one of {expected_list}, got '{actual_aud}'"
                )

        # 6. Subject (sub)
        if "sub" in payload:
            claims_info["sub"] = str(payload["sub"])

        # 7. JWT ID (jti)
        if "jti" in payload:
            claims_info["jti"] = str(payload["jti"])

        is_valid = len(errors) == 0
        return ClaimsValidationResult(
            valid=is_valid,
            errors=errors,
            warnings=warnings,
            is_expired=is_expired,
            expires_in_seconds=expires_in,
            claims_info=claims_info,
        )
