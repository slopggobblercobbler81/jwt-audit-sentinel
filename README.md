# JWT Audit Sentinel 🛡️🔍

[![CI](https://github.com/slopggobblercobbler81/jwt-audit-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/slopggobblercobbler81/jwt-audit-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20core-brightgreen.svg)](#features)

> A fast zero-dependency offline CLI and Python library for inspecting, decoding, verifying cryptographic signatures, detecting algorithm confusion vulnerabilities (such as `alg: "none"` or HS256/RS256 key mismatch), checking claims/expirations, and generating formatted audit reports for CI/CD gates.

---

## Key Features

- ⚡ **Zero Runtime Dependencies**: Core auditing, decoding, HMAC verification (HS256, HS384, HS512), and claims checking run entirely on Python's standard library.
- 🚨 **Vulnerability & Misconfiguration Detection**:
  - **Algorithm 'none' Vulnerabilities**: Flags tokens bypassing cryptographic signing.
  - **HMAC / RSA Key Confusion (CVE-2015-9235)**: Detects public keys being verified against symmetric algorithms.
  - **Weak & Short Secrets**: Detects dictionary words, common passwords (`secret`, `admin`, `123456`), and secrets `< 32 bytes`.
  - **SSRF & Header Injections**: Audits `jku`, `x5u`, and `jwk` headers for private IPs, loopback addresses (`127.0.0.1`), and untrusted key sets.
  - **Credential Leakage**: Scans payload claims for exposed passwords, private keys, API secrets, or PII.
  - **Claims & Lifespan Validation**: Checks expired tokens, missing `exp`, excessive validity windows (> 30 days), and future `iat`/`nbf` issues.
- 🚦 **CI/CD Quality Gate**: Set thresholds (`--min-grade A`) to block insecure or non-compliant tokens in your pipelines.
- 🎨 **Multi-Format Reports**: Beautiful colorized terminal reports, GitHub-flavored Markdown for PR summaries, and structured JSON for automated pipelines.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/slopggobblercobbler81/jwt-audit-sentinel.git
cd jwt-audit-sentinel

# Install package
pip install -e .

# (Optional) Install asymmetric cryptography support (RSA/ECDSA/EdDSA)
pip install cryptography
```

Or run directly without installation:

```bash
python -m jwt_audit_sentinel --help
```

---

## Security Audit Rules

| Rule ID | Check Name | Severity | Description |
|---|---|---|---|
| `SEC-ALG-NONE` | Insecure 'none' Algorithm | `CRITICAL` | Disables cryptographic signature verification, allowing claim forgery. |
| `SEC-ALG-CONFUSION` | HMAC / RSA Key Confusion | `CRITICAL` | Detects symmetric HS256 verification using an asymmetric RSA public key. |
| `SEC-HEADER-SSRF` | Local / Private Address in `jku`/`x5u` | `CRITICAL` | External key URL points to localhost or private network (SSRF). |
| `SEC-SECRET-WEAK` | Trivially Weak HMAC Secret | `HIGH` | Secret is in common dictionary / default password lists. |
| `SEC-SECRET-SHORT` | Short Secret (< 16 characters) | `HIGH` | Secret is vulnerable to rapid offline brute-force cracking. |
| `SEC-EXP-MISSING` | Missing Expiration (`exp`) Claim | `HIGH` | Tokens without expiration cannot be revoked. |
| `SEC-PAYLOAD-SENSITIVE` | Sensitive Information in Payload | `HIGH` | Found passwords, API keys, or private secrets in unencrypted payload. |
| `SEC-HEADER-EMBEDDED-JWK` | Untrusted Embedded `jwk` Key | `HIGH` | Header contains self-signed embedded key. |
| `SEC-EXP-LONG-LIVED` | Excessive Token Lifespan (> 30 days) | `MEDIUM` | Unnecessarily long exposure window if token is compromised. |
| `SEC-IAT-FUTURE` | Token Issued in the Future | `MEDIUM` | Clock skew or timestamp tampering detected. |
| `SEC-EXP-EXPIRED` | Expired Token | `MEDIUM` | Token expiration timestamp has elapsed. |
| `SEC-JTI-ABSENT` | Missing Token Identifier (`jti`) | `INFO` | Token cannot be checked against one-time use or replay caches. |

---

## Quickstart & CLI Usage

### 1. Security Audit a JWT Token

Run a comprehensive audit report:

```bash
jwt-audit-sentinel audit eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Audit with secret verification to detect weak passwords:

```bash
jwt-audit-sentinel audit eyJ... -s "secret"
```

Export report as JSON or Markdown:

```bash
jwt-audit-sentinel audit eyJ... -f markdown > audit-report.md
jwt-audit-sentinel audit eyJ... -f json > audit-report.json
```

Use as a CI/CD Quality Gate (fails with exit code `2` if grade is lower than `B`):

```bash
jwt-audit-sentinel audit @token.jwt --min-grade B
```

### 2. Inspect & Decode Tokens

Pretty-print decoded header, payload, and human-readable timestamps:

```bash
jwt-audit-sentinel inspect eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Inspect only payload or header as JSON:

```bash
jwt-audit-sentinel inspect @token.jwt --payload
jwt-audit-sentinel inspect @token.jwt --header
```

Pipe from standard input:

```bash
curl -s https://api.example.com/oauth/token | jq -r .access_token | jwt-audit-sentinel inspect
```

### 3. Verify Cryptographic Signatures & Claims

Verify signature with an HMAC secret:

```bash
jwt-audit-sentinel verify @token.jwt -s "my_secret_key"
```

Enforce permitted algorithms and validate claims:

```bash
jwt-audit-sentinel verify @token.jwt \
  -s "my_secret_key" \
  -a HS256 \
  --iss "https://auth.example.com" \
  --aud "https://api.example.com"
```

Verify asymmetric RSA / ECDSA token using public key:

```bash
jwt-audit-sentinel verify @token.jwt -k @public_key.pem -a RS256
```

### 4. Generate Test Tokens

Generate signed JWTs for testing or development:

```bash
jwt-audit-sentinel encode \
  -p '{"sub": "user_123", "role": "admin"}' \
  -s "my_strong_dev_secret_key_32_bytes_ok!" \
  --exp-mins 60 \
  --iss "https://dev.auth.local"
```

---

## Python Library API

You can use `jwt-audit-sentinel` directly in Python applications and automated test suites:

```python
from jwt_audit_sentinel import decode_token, JWTAuditor, verify_signature

token_string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 1. Decode token
token = decode_token(token_string)
print(f"Algorithm: {token.algorithm}, Subject: {token.payload.get('sub')}")

# 2. Verify signature
is_valid, reason = verify_signature(token, key="my_secret_key", allowed_algorithms=["HS256"])
print(f"Signature valid: {is_valid} ({reason})")

# 3. Perform security audit
auditor = JWTAuditor(secret="my_secret_key")
report = auditor.audit(token)

print(f"Security Grade: {report.grade} ({report.score}/100)")
print(f"Is Secure: {report.is_secure}")

for finding in report.findings:
    print(f"[{finding.severity}] {finding.title}: {finding.remediation}")
```

---

## Running Unit Tests

```bash
# Run tests
pytest -v

# Run tests with coverage
pytest --cov=jwt_audit_sentinel --cov-report=term
```

---

## License

This project is licensed under the [MIT License](LICENSE).
