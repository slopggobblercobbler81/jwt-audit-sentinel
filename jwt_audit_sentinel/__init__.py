"""JWT Audit Sentinel - Fast zero-dependency offline CLI and library for inspecting,
decoding, verifying cryptographic signatures, detecting algorithm confusion vulnerabilities,
checking claims/expirations, and generating formatted audit reports.
"""

__version__ = "0.1.0"
__author__ = "slopggobblercobbler81"

from .decoder import JWTToken, decode_token, base64url_decode, base64url_encode
from .claims import ClaimsVerifier, ClaimsValidationResult
from .crypto import verify_signature, sign_token
from .audit import JWTAuditor, AuditFinding, AuditReport, Severity
from .reporter import format_terminal_report, format_markdown_report, format_json_report

__all__ = [
    "JWTToken",
    "decode_token",
    "base64url_decode",
    "base64url_encode",
    "ClaimsVerifier",
    "ClaimsValidationResult",
    "verify_signature",
    "sign_token",
    "JWTAuditor",
    "AuditFinding",
    "AuditReport",
    "Severity",
    "format_terminal_report",
    "format_markdown_report",
    "format_json_report",
    "__version__",
]
