"""Report formatters for terminal (ANSI colors), Markdown, and JSON."""

import json
import os
import sys
from typing import Any, Dict

from .audit import AuditReport, Severity


class TermColor:
    ENABLED = (
        sys.stdout.isatty()
        and "NO_COLOR" not in os.environ
        and os.environ.get("TERM") != "dumb"
    )

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    @classmethod
    def wrap(cls, text: str, code: str) -> str:
        if not cls.ENABLED:
            return text
        return f"{code}{text}{cls.RESET}"

    @classmethod
    def bold(cls, text: str) -> str:
        return cls.wrap(text, cls.BOLD)

    @classmethod
    def dim(cls, text: str) -> str:
        return cls.wrap(text, cls.DIM)

    @classmethod
    def red(cls, text: str) -> str:
        return cls.wrap(text, cls.RED)

    @classmethod
    def green(cls, text: str) -> str:
        return cls.wrap(text, cls.GREEN)

    @classmethod
    def yellow(cls, text: str) -> str:
        return cls.wrap(text, cls.YELLOW)

    @classmethod
    def cyan(cls, text: str) -> str:
        return cls.wrap(text, cls.CYAN)


def _severity_badge(severity: Severity) -> str:
    if severity == Severity.CRITICAL:
        return TermColor.wrap(" [CRITICAL] ", "\033[41;97;1m")  # Red bg, white bold text
    elif severity == Severity.HIGH:
        return TermColor.wrap(" [HIGH] ", "\033[1;31m")  # Bold red
    elif severity == Severity.MEDIUM:
        return TermColor.wrap(" [MEDIUM] ", "\033[1;33m")  # Bold yellow
    elif severity == Severity.LOW:
        return TermColor.wrap(" [LOW] ", "\033[33m")  # Yellow
    else:
        return TermColor.wrap(" [INFO] ", "\033[36m")  # Cyan


def _grade_badge(grade: str, score: int) -> str:
    if grade in ("A+", "A"):
        return TermColor.green(f"{grade} ({score}/100)")
    elif grade in ("B", "C"):
        return TermColor.yellow(f"{grade} ({score}/100)")
    else:
        return TermColor.red(f"{grade} ({score}/100)")


def format_terminal_report(report: AuditReport) -> str:
    lines = []
    lines.append(TermColor.bold("=================================================="))
    lines.append(TermColor.bold("             JWT SECURITY AUDIT REPORT            "))
    lines.append(TermColor.bold("=================================================="))

    # Token summary
    summary = report.token_summary
    lines.append(f"Algorithm:   {TermColor.bold(summary.get('algorithm', 'unknown'))}")
    lines.append(f"Type:        {summary.get('token_type', 'N/A')}")
    lines.append(f"Key ID:      {summary.get('key_id', 'N/A')}")
    lines.append(f"Signature:   {'Present' if summary.get('has_signature') else TermColor.red('None')}")
    lines.append(f"Claims:      {summary.get('claims_count', 0)} ({', '.join(summary.get('payload_keys', []))})")
    lines.append("")

    # Security score
    status_str = TermColor.green("PASSED AUDIT") if report.is_secure else TermColor.red("SECURITY RISKS DETECTED")
    lines.append(f"Security Grade:  {_grade_badge(report.grade, report.score)}")
    lines.append(f"Status:          {status_str}")
    lines.append(TermColor.dim("-" * 50))

    # Findings
    if report.findings:
        lines.append(TermColor.bold(f"\nFindings ({len(report.findings)}):"))
        for f in report.findings:
            badge = _severity_badge(f.severity)
            lines.append(f"\n{badge} {TermColor.bold(f.title)} ({TermColor.dim(f.id)})")
            lines.append(f"  Description: {f.description}")
            lines.append(f"  Remediation: {TermColor.cyan(f.remediation)}")
            if f.details:
                for k, v in f.details.items():
                    lines.append(f"  * {k}: {v}")
    else:
        lines.append(TermColor.green("\nNo security vulnerabilities or warnings found!"))

    # Passed checks
    if report.passed_checks:
        lines.append(TermColor.bold(f"\nPassed Security Checks ({len(report.passed_checks)}):"))
        for check in report.passed_checks:
            lines.append(f"  {TermColor.green('✓')} {check}")

    lines.append(TermColor.dim("\n" + "=" * 50))
    return "\n".join(lines)


def format_markdown_report(report: AuditReport) -> str:
    md = []
    md.append("# 🛡️ JWT Security Audit Report\n")

    status_icon = "✅ **Passed**" if report.is_secure else "⚠️ **Action Required**"
    md.append(f"**Security Grade**: `{report.grade}` ({report.score}/100) — {status_icon}\n")

    summary = report.token_summary
    md.append("## Token Overview\n")
    md.append("| Property | Value |")
    md.append("| --- | --- |")
    md.append(f"| Algorithm | `{summary.get('algorithm')}` |")
    md.append(f"| Token Type | `{summary.get('token_type') or 'N/A'}` |")
    md.append(f"| Key ID (kid) | `{summary.get('key_id') or 'N/A'}` |")
    md.append(f"| Signature | `{'Present' if summary.get('has_signature') else 'None'}` |")
    md.append(f"| Claims | {summary.get('claims_count', 0)} ({', '.join(f'`{k}`' for k in summary.get('payload_keys', []))}) |\n")

    if report.findings:
        md.append(f"## 🚨 Findings ({len(report.findings)})\n")
        for f in report.findings:
            severity_badge = f"**[{f.severity.value}]**"
            md.append(f"### {severity_badge} {f.title} (`{f.id}`)\n")
            md.append(f"- **Description**: {f.description}")
            md.append(f"- **Remediation**: {f.remediation}")
            if f.details:
                md.append(f"- **Details**: `{json.dumps(f.details)}`")
            md.append("")
    else:
        md.append("## ✅ No Findings\nToken passed all static and cryptographic security checks.\n")

    if report.passed_checks:
        md.append("## 📋 Passed Checks\n")
        for check in report.passed_checks:
            md.append(f"- [x] {check}")
        md.append("")

    return "\n".join(md)


def format_json_report(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2)
