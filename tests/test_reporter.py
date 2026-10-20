"""Unit tests for report formatters."""

import json
from jwt_audit_sentinel.audit import AuditFinding, AuditReport, Severity
from jwt_audit_sentinel.reporter import (
    format_json_report,
    format_markdown_report,
    format_terminal_report,
)


def _sample_report() -> AuditReport:
    finding = AuditFinding(
        id="SEC-TEST-01",
        title="Sample Finding",
        severity=Severity.HIGH,
        description="A test security issue.",
        remediation="Fix the test issue.",
        details={"test_key": "val"},
    )
    return AuditReport(
        token_summary={"algorithm": "HS256", "has_signature": True, "claims_count": 2},
        score=75,
        grade="B",
        findings=[finding],
        passed_checks=["Signature algorithm is secure"],
    )


def test_format_terminal_report():
    report = _sample_report()
    text = format_terminal_report(report)
    assert "JWT SECURITY AUDIT REPORT" in text
    assert "HS256" in text
    assert "Sample Finding" in text
    assert "Passed Security Checks" in text


def test_format_markdown_report():
    report = _sample_report()
    md = format_markdown_report(report)
    assert "# 🛡️ JWT Security Audit Report" in md
    assert "`B` (75/100)" in md
    assert "Sample Finding" in md
    assert "Fix the test issue." in md


def test_format_json_report():
    report = _sample_report()
    raw_json = format_json_report(report)
    data = json.loads(raw_json)
    assert data["score"] == 75
    assert data["grade"] == "B"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "SEC-TEST-01"
