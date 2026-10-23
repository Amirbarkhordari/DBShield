"""Terminal and plain-text report exporter for DBShield (Phase 8).

Formats security assessment reports for terminal presentation adhering to linux-cli-design-system standards.
"""

from __future__ import annotations

import os

from dbshield.reporting.exporters.base import BaseReportExporter
from dbshield.reporting.models import SecurityAssessmentReport


def _supports_color() -> bool:
    """Check NO_COLOR environment variable."""
    return os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"


def _color(text: str, code: str) -> str:
    """Format text with ANSI escape sequence if supported."""
    if not _supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


class TerminalReportExporter(BaseReportExporter):
    """Renders structured assessment results formatted for terminal consoles."""

    def export(self, report: SecurityAssessmentReport) -> str:
        """Render report as human-readable plain text or ANSI colored output."""
        meta = report.metadata
        width = 80
        lines: list[str] = [
            "=" * width,
            f"  {_color('DBSHIELD SECURITY ASSESSMENT REPORT', '1;36')}",
            f"  Target:     {meta.target_url}",
            f"  Generated:  {meta.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"  Report ID:  {meta.report_id}",
            "=" * width,
            "",
            _color("FINDING SUMMARY", "1;37"),
            "-" * width,
            f"  Total Findings:      {meta.total_findings}",
            f"  * Critical:          {meta.findings_by_severity.get('critical', 0)}",
            f"  * High:              {meta.findings_by_severity.get('high', 0)}",
            f"  * Medium:            {meta.findings_by_severity.get('medium', 0)}",
            f"  * Low:               {meta.findings_by_severity.get('low', 0)}",
            f"  * Info:              {meta.findings_by_severity.get('info', 0)}",
            "",
            _color("VERIFICATION LIFECYCLE BREAKDOWN", "1;37"),
            "-" * width,
            f"  * Verified:          {meta.findings_by_status.get('verified', 0)}",
            f"  * Corroborated:      {meta.findings_by_status.get('corroborated', 0)}",
            f"  * Potential:         {meta.findings_by_status.get('potential_indicator', 0)}",
            f"  * Inconclusive:      {meta.findings_by_status.get('inconclusive', 0)}",
            f"  * Rejected (FP):     {meta.findings_by_status.get('rejected', 0)}",
            f"  * Unverifiable:      {meta.findings_by_status.get('unverifiable', 0)}",
            "-" * width,
            "",
            _color("FINDING DETAILS", "1;37"),
            "-" * width,
        ]

        if not report.findings:
            lines.append("  [+] No security findings identified in this assessment.")
        else:
            for i, f in enumerate(report.findings, start=1):
                sev_color = (
                    "1;31"
                    if f.severity in {"critical", "high"}
                    else "1;33"
                    if f.severity == "medium"
                    else "1;34"
                )
                sev_tag = _color(f"[{f.severity.value.upper()}]", sev_color)
                lines.extend(
                    [
                        f"  {i}. {sev_tag} {f.title}",
                        f"     ID:           {f.id}",
                        f"     Category:     {f.category.value} ({f.subtype})",
                        f"     Status:       {f.verification_status.value} (Confidence: {f.confidence_level.value}, {f.confidence_score:.2f})",
                        f"     Endpoint:     {f.endpoint} [{f.http_method}]",
                        f"     Parameter:    {f.parameter_name} ({f.parameter_location.value})",
                        f"     CWE:          {f.cwe_id or 'N/A'}",
                        f"     Evidence:     {f.evidence_summary}",
                        f"     Remediation:  {f.remediation}",
                        "",
                    ]
                )

        lines.extend(
            [
                "-" * width,
                _color("SAFETY BOUNDARIES & LIMITATIONS", "1;37"),
                "-" * width,
            ]
        )
        if meta.limitations:
            for lim in meta.limitations:
                lines.append(f"  * {lim}")
        else:
            lines.append(
                "  * Passive and non-destructive automated testing within defined target scope."
            )

        lines.append("=" * width)
        return "\n".join(lines)
