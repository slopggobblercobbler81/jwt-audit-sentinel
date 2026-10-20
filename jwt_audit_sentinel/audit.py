"""Comprehensive JWT security auditing engine."""

from dataclasses import dataclass, field
import datetime
from enum import Enum
import ipaddress
import re
import time
from typing import Any, Dict, List, Optional, Union
import urllib.parse

from .claims import ClaimsVerifier
from .decoder import JWTToken

COMMON_WEAK_SECRETS = {
    "secret",
    "jwt",
    "password",
    "123456",
    "12345678",
    "admin",
    "development",
    "test",
    "dev",
    "prod",
    "production",
    "jwtsecret",
    "mysecret",
    "default",
    "changeme",
    "qwerty",
    "secretkey",
    "supersecret",
    "app_secret",
    "api_secret",
    "token",
}

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"password|passwd|pwd", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"secret|private[_-]?key", re.IGNORECASE),
    re.compile(r"credit[_-]?card|card[_-]?number|cvv", re.IGNORECASE),
    re.compile(r"ssn|social[_-]?security", re.IGNORECASE),
]


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AuditFinding:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
            "details": self.details,
        }


@dataclass
class AuditReport:
    token_summary: Dict[str, Any]
    score: int
    grade: str
    findings: List[AuditFinding]
    passed_checks: List[str]

    @property
    def is_secure(self) -> bool:
        has_critical_or_high = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings
        )
        return self.score >= 80 and not has_critical_or_high

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_summary": self.token_summary,
            "score": self.score,
            "grade": self.grade,
            "is_secure": self.is_secure,
            "findings": [f.to_dict() for f in self.findings],
            "passed_checks": self.passed_checks,
        }


class JWTAuditor:
    """Performs static and cryptographic security checks against JWT tokens."""

    def __init__(
        self,
        secret: Optional[Union[str, bytes]] = None,
        public_key: Optional[Union[str, bytes]] = None,
        expected_issuer: Optional[str] = None,
        expected_audience: Optional[str] = None,
        current_time: Optional[float] = None,
    ):
        self.secret = secret
        self.public_key = public_key
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.current_time = current_time

    def audit(self, token: JWTToken) -> AuditReport:
        findings: List[AuditFinding] = []
        passed_checks: List[str] = []

        now = self.current_time if self.current_time is not None else time.time()

        # Check 1: Algorithm 'none'
        self._check_algorithm_none(token, findings, passed_checks)

        # Check 2: Key / Algorithm confusion (CVE-2015-9235 pattern)
        self._check_algorithm_confusion(token, findings, passed_checks)

        # Check 3: Weak Secret Check
        self._check_weak_secret(token, findings, passed_checks)

        # Check 4: Expiration Claims
        self._check_expiration_claims(token, now, findings, passed_checks)

        # Check 5: Timestamp integrity (future iat, nbf)
        self._check_timestamp_integrity(token, now, findings, passed_checks)

        # Check 6: Sensitive Information in Payload
        self._check_sensitive_payload(token, findings, passed_checks)

        # Check 7: Suspicious Header Parameters (jku, x5u, jwk)
        self._check_suspicious_headers(token, findings, passed_checks)

        # Check 8: Token ID (jti) presence
        self._check_jti_claim(token, findings, passed_checks)

        # Check 9: Issuer and Audience
        self._check_iss_and_aud(token, findings, passed_checks)

        # Calculate Score and Grade
        score, grade = self._calculate_score(findings)

        token_summary = {
            "algorithm": token.algorithm,
            "token_type": token.token_type,
            "key_id": token.key_id,
            "has_signature": token.has_signature,
            "claims_count": len(token.payload),
            "payload_keys": list(token.payload.keys()),
        }

        return AuditReport(
            token_summary=token_summary,
            score=score,
            grade=grade,
            findings=findings,
            passed_checks=passed_checks,
        )

    def _check_algorithm_none(
        self, token: JWTToken, findings: List[AuditFinding], passed_checks: List[str]
    ) -> None:
        alg = token.algorithm.lower()
        if alg == "none":
            findings.append(
                AuditFinding(
                    id="SEC-ALG-NONE",
                    title="Insecure 'none' Algorithm Allowed",
                    severity=Severity.CRITICAL,
                    description=(
                        "The token header specifies 'alg': 'none'. This disables all "
                        "cryptographic signature verification, allowing anyone to forge claims."
                    ),
                    remediation=(
                        "Reject all tokens with alg='none' in production. Enforce strong algorithms "
                        "such as RS256, EdDSA, or HS256."
                    ),
                    details={"header_alg": token.header.get("alg")},
                )
            )
        else:
            passed_checks.append("Cryptographic signature algorithm is specified (not 'none')")

    def _check_algorithm_confusion(
        self, token: JWTToken, findings: List[AuditFinding], passed_checks: List[str]
    ) -> None:
        alg = token.algorithm.upper()
        # Check if public key was supplied but symmetric algorithm was used
        is_symmetric = alg.startswith("HS")
        has_pem_pubkey = False
        if self.public_key:
            pk_str = self.public_key if isinstance(self.public_key, str) else self.public_key.decode("utf-8", errors="ignore")
            if "BEGIN PUBLIC KEY" in pk_str or "BEGIN RSA PUBLIC KEY" in pk_str:
                has_pem_pubkey = True

        if is_symmetric and has_pem_pubkey:
            findings.append(
                AuditFinding(
                    id="SEC-ALG-CONFUSION",
                    title="Potential HMAC / RSA Key Confusion (CVE-2015-9235)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The token uses symmetric algorithm '{alg}', but an asymmetric RSA public key was provided. "
                        "Attackers exploit this by signing tokens using the server's public key as an HMAC secret."
                    ),
                    remediation=(
                        "Never trust the 'alg' header blindly. Explicitly whitelist the algorithm "
                        "(e.g. allowed_algorithms=['RS256']) and reject HMAC when an asymmetric key is expected."
                    ),
                    details={"token_algorithm": alg, "key_type": "RSA Public Key"},
                )
            )
        else:
            passed_checks.append("No algorithm confusion detected between symmetric and asymmetric keys")

    def _check_weak_secret(
        self, token: JWTToken, findings: List[AuditFinding], passed_checks: List[str]
    ) -> None:
        alg = token.algorithm.upper()
        if not alg.startswith("HS"):
            return

        if self.secret is not None:
            secret_str = (
                self.secret if isinstance(self.secret, str) else self.secret.decode("utf-8", errors="ignore")
            ).strip()

            if secret_str.lower() in COMMON_WEAK_SECRETS:
                findings.append(
                    AuditFinding(
                        id="SEC-SECRET-WEAK",
                        title="Trivially Weak HMAC Secret",
                        severity=Severity.HIGH,
                        description=(
                            f"The secret '{secret_str}' is a known common default password or dictionary word. "
                            "It can be cracked offline in seconds using tools like hashcat."
                        ),
                        remediation="Use a cryptographically secure random secret of at least 256 bits (32 bytes).",
                        details={"secret_preview": secret_str[:3] + "***"},
                    )
                )
            elif len(secret_str) < 16:
                findings.append(
                    AuditFinding(
                        id="SEC-SECRET-SHORT",
                        title="Critically Short HMAC Secret (< 16 characters)",
                        severity=Severity.HIGH,
                        description=f"Secret length is only {len(secret_str)} characters, making it vulnerable to brute force.",
                        remediation="Ensure the HMAC secret is at least 32 characters (256 bits) long.",
                        details={"length": len(secret_str)},
                    )
                )
            elif len(secret_str) < 32:
                findings.append(
                    AuditFinding(
                        id="SEC-SECRET-SUBOPTIMAL",
                        title="Suboptimal HMAC Secret Length (< 32 characters)",
                        severity=Severity.MEDIUM,
                        description=f"Secret length is {len(secret_str)} characters. Best practice for HS256 is >= 32 characters.",
                        remediation="Generate a 32-byte secret using: openssl rand -hex 32",
                        details={"length": len(secret_str)},
                    )
                )
            else:
                passed_checks.append(f"HMAC secret length meets recommendations ({len(secret_str)} characters)")

    def _check_expiration_claims(
        self, token: JWTToken, now: float, findings: List[AuditFinding], passed_checks: List[str]
    ) -> None:
        payload = token.payload
        if "exp" not in payload:
            findings.append(
                AuditFinding(
                    id="SEC-EXP-MISSING",
                    title="Missing Expiration Claim ('exp')",
                    severity=Severity.HIGH,
                    description=(
                        "The token lacks an 'exp' claim. This makes it immortal and impossible to invalidate "
                        "without maintaining a centralized revocation list."
                    ),
                    remediation="Always specify an 'exp' claim with an appropriate short lifespan (e.g., 15-60 minutes).",
                )
            )
        else:
            exp_val = payload["exp"]
            if isinstance(exp_val, (int, float)):
                if exp_val < now:
                    findings.append(
                        AuditFinding(
                            id="SEC-EXP-EXPIRED",
                            title="Token Has Expired",
                            severity=Severity.MEDIUM,
                            description=(
                                f"The token expired {abs(exp_val - now):.0f}s ago at "
                                f"{datetime.datetime.fromtimestamp(exp_val, datetime.timezone.utc).isoformat()}."
                            ),
                            remediation="Issue a new token via refresh token or re-authentication.",
                            details={"expired_at": exp_val, "current_time": now},
                        )
                    )
                else:
                    ttl_seconds = exp_val - now
                    # Check for excessively long lifespan (> 30 days)
                    if ttl_seconds > 30 * 86400:
                        findings.append(
                            AuditFinding(
                                id="SEC-EXP-LONG-LIVED",
                                title="Excessively Long Token Expiration (> 30 days)",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"Token remains valid for {ttl_seconds / 86400:.1f} days. Long-lived access tokens "
                                    "increase the window of risk if the token is stolen."
                                ),
                                remediation="Keep access token lifespans short (15-60 minutes) and use refresh tokens.",
                                details={"ttl_days": round(ttl_seconds / 86400, 1)},
                            )
                        )
                    else:
                        passed_checks.append(f"Token has valid unexpired 'exp' claim (TTL: {int(ttl_seconds)}s)")

    def _check_timestamp_integrity(
        self, token: JWTToken, now: float, findings: List[AuditFinding], passed_checks: List[str]
    ) -> None:
        payload = token.payload
        if "iat" in payload and isinstance(payload["iat"], (int, float)):
            iat = payload["iat"]
            if iat > (now + 60.0):
                findings.append(
                    AuditFinding(
                        id="SEC-IAT-FUTURE",
                        title="Token Issued In The Future",
                        severity=Severity.MEDIUM,
                        description=f"'iat' timestamp is {iat - now:.0f}s in the future.",
                        remediation="Synchronize server clocks with NTP.",
                        details={"iat": iat, "now": now},
                    )
                )
            else:
                passed_checks.append("Token 'iat' (issued-at) is valid and not in the future")

        if "nbf" in payload and isinstance(payload["nbf"], (int, float)):
            nbf = payload["nbf"]
            if nbf > (now + 60.0):
                findings.append(
                    AuditFinding(
                        id="SEC-NBF-FUTURE",
                        title="Token Not Yet Valid (nbf in future)",
                        severity=Severity.LOW,
                        description=f"'nbf' timestamp is {nbf - now:.0f}s in the future.",
                        remediation="Ensure client waits until the 'nbf' timestamp before presenting the token.",
                        details={"nbf": nbf, "now": now},
                    )
                )
            else:
                passed_checks.append("Token 'nbf' (not-before) is active")

    def _check_sensitive_payload(
        self, token: JWTToken, findings: List[AuditFinding], passed_checks: List[str]
    ) -> None:
        payload = token.payload
        sensitive_keys_found = []

        def inspect_dict(d: dict, prefix: str = ""):
            for k, v in d.items():
                full_key = f"{prefix}.{k}" if prefix else str(k)
                for pattern in SENSITIVE_KEY_PATTERNS:
                    if pattern.search(str(k)):
                        sensitive_keys_found.append(full_key)
                        break
                if isinstance(v, dict):
                    inspect_dict(v, full_key)

        inspect_dict(payload)

        if sensitive_keys_found:
            findings.append(
                AuditFinding(
                    id="SEC-PAYLOAD-SENSITIVE",
                    title="Potential Sensitive Data in Payload",
                    severity=Severity.HIGH,
                    description=(
                        f"Found claims that may contain sensitive credentials: {sensitive_keys_found}. "
                        "JWT payloads are only base64url encoded (not encrypted) and readable by anyone who inspects the token."
                    ),
                    remediation=(
                        "Never store passwords, secrets, or sensitive PII in unencrypted JWTs. "
                        "Use opaque tokens or encrypt the payload with JWE if confidential data is required."
                    ),
                    details={"sensitive_claims": sensitive_keys_found},
                )
            )
        else:
            passed_checks.append("No sensitive credential key patterns found in payload")

    def _check_suspicious_headers(
        self, token: JWTToken, findings: List[AuditFinding], passed_checks: List[str]
    ) -> None:
        header = token.header
        suspicious_urls: List[str] = []

        for url_key in ("jku", "x5u"):
            if url_key in header:
                val = str(header[url_key])
                parsed = urllib.parse.urlparse(val)
                hostname = parsed.hostname or ""

                is_local = False
                if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254"):
                    is_local = True
                else:
                    try:
                        ip = ipaddress.ip_address(hostname)
                        if ip.is_private or ip.is_loopback:
                            is_local = True
                    except ValueError:
                        pass

                if is_local:
                    findings.append(
                        AuditFinding(
                            id="SEC-HEADER-SSRF",
                            title=f"Potential SSRF via Header '{url_key}'",
                            severity=Severity.CRITICAL,
                            description=(
                                f"The '{url_key}' header points to a local or private address ({val}). "
                                "This is a common vector for Server-Side Request Forgery."
                            ),
                            remediation="Do not fetch JWK sets or certificates from untrusted, local, or arbitrary URLs.",
                            details={"header_key": url_key, "url": val},
                        )
                    )
                else:
                    suspicious_urls.append(f"{url_key}={val}")

        if suspicious_urls:
            findings.append(
                AuditFinding(
                    id="SEC-HEADER-EXTERNAL-URL",
                    title="External Key URL Header Present",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Token includes external key URL headers ({', '.join(suspicious_urls)}). "
                        "Verifiers must ensure strict host domain whitelisting."
                    ),
                    remediation="Validate external JWKS URLs against a strict domain whitelist.",
                )
            )
        else:
            passed_checks.append("No dangerous external key URLs (jku/x5u) in headers")

        if "jwk" in header:
            findings.append(
                AuditFinding(
                    id="SEC-HEADER-EMBEDDED-JWK",
                    title="Embedded JWK Public Key in Header",
                    severity=Severity.HIGH,
                    description=(
                        "The header contains an embedded 'jwk' key. If the server verifies signatures "
                        "using the embedded key without verification against a trusted source, an attacker can supply any key."
                    ),
                    remediation="Never verify JWTs using untrusted embedded 'jwk' header keys without validation.",
                )
            )

    def _check_jti_claim(
        self, token: JWTToken, findings: List[AuditFinding], passed_checks: List[str]
    ) -> None:
        if "jti" not in token.payload:
            findings.append(
                AuditFinding(
                    id="SEC-JTI-ABSENT",
                    title="Missing Token Identifier ('jti')",
                    severity=Severity.INFO,
                    description=(
                        "The token lacks a unique 'jti' claim. Replay attacks cannot be prevented "
                        "without a token identifier."
                    ),
                    remediation="Add a unique 'jti' (e.g. UUIDv4) if one-time use or replay protection is needed.",
                )
            )
        else:
            passed_checks.append("Token contains unique 'jti' identifier")

    def _check_iss_and_aud(
        self, token: JWTToken, findings: List[AuditFinding], passed_checks: List[str]
    ) -> None:
        payload = token.payload
        if "iss" not in payload:
            findings.append(
                AuditFinding(
                    id="SEC-ISS-ABSENT",
                    title="Missing Issuer ('iss') Claim",
                    severity=Severity.LOW,
                    description="The token does not specify an 'iss' (issuer) claim.",
                    remediation="Include an 'iss' claim identifying the authentication authority.",
                )
            )
        else:
            passed_checks.append(f"Token specifies issuer: '{payload['iss']}'")

        if "aud" not in payload:
            findings.append(
                AuditFinding(
                    id="SEC-AUD-ABSENT",
                    title="Missing Audience ('aud') Claim",
                    severity=Severity.LOW,
                    description="The token does not specify an 'aud' (audience) claim.",
                    remediation="Include an 'aud' claim to prevent tokens issued for one service being reused on another.",
                )
            )
        else:
            passed_checks.append(f"Token specifies audience: '{payload['aud']}'")

    def _calculate_score(self, findings: List[AuditFinding]) -> (int, str):
        penalty_map = {
            Severity.CRITICAL: 35,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
            Severity.INFO: 0,
        }

        total_penalty = sum(penalty_map.get(f.severity, 0) for f in findings)
        score = max(0, 100 - total_penalty)

        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 45:
            grade = "D"
        else:
            grade = "F"

        return score, grade
