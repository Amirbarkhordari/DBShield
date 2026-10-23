"""Unit tests for DBShield report exporters (JSON, Markdown, Terminal) (Phase 8)."""

import json

from dbshield.reporting.exporters.json_exporter import JSONReportExporter
from dbshield.reporting.exporters.markdown_exporter import MarkdownReportExporter
from dbshield.reporting.exporters.terminal_exporter import TerminalReportExporter
from dbshield.reporting.models import (
    FindingSeverity,
    NormalizedSecurityFinding,
    ReportMetadata,
    SecurityAssessmentReport,
    VulnerabilityCategory,
)
from dbshield.sqli.models import ParameterLocation
from dbshield.verification.models import ConfidenceLevel, VerificationStatus


def _build_sample_report() -> SecurityAssessmentReport:
    """Helper to construct a representative SecurityAssessmentReport."""
    meta = ReportMetadata(
        target_url="http://target.local/app",
        total_findings=2,
        findings_by_severity={"high": 1, "medium": 1},
        findings_by_status={"verified": 1, "potential_indicator": 1},
        findings_by_category={"sql_injection": 1, "nosql_injection": 1},
        assessment_scope=["http://target.local/app"],
        limitations=["Scope bounded to /app endpoints."],
    )
    f1 = NormalizedSecurityFinding(
        id="DBS-SQLI-01",
        title="Verified SQL Injection in query parameter 'id'",
        category=VulnerabilityCategory.SQL_INJECTION,
        subtype="error_based",
        target_url="http://target.local/app/items",
        endpoint="/app/items",
        http_method="GET",
        parameter_name="id",
        parameter_location=ParameterLocation.QUERY,
        engine="sqli",
        technique="error_based",
        verification_status=VerificationStatus.VERIFIED,
        confidence_level=ConfidenceLevel.VERIFIED,
        confidence_score=0.95,
        severity=FindingSeverity.HIGH,
        severity_rationale="Database syntax error confirmed in test response.",
        description="Observed MySQL error indicating direct query injection.",
        evidence_summary="syntax error near '1'",
        evidence_count=2,
        remediation="Apply parameterized SQL queries.",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
    )
    f2 = NormalizedSecurityFinding(
        id="DBS-NOSQLI-01",
        title="Potential NoSQL Injection in body parameter 'query'",
        category=VulnerabilityCategory.NOSQL_INJECTION,
        subtype="operator_injection",
        target_url="http://target.local/app/filter",
        endpoint="/app/filter",
        http_method="POST",
        parameter_name="query",
        parameter_location=ParameterLocation.BODY_JSON,
        engine="nosqli",
        technique="operator_injection",
        verification_status=VerificationStatus.POTENTIAL_INDICATOR,
        confidence_level=ConfidenceLevel.MEDIUM,
        confidence_score=0.55,
        severity=FindingSeverity.MEDIUM,
        severity_rationale="Unexpected operator evaluation behavior.",
        description="Response variance observed during operator testing.",
        evidence_summary="different status code returned",
        evidence_count=1,
        remediation="Validate input types against query selectors.",
        cwe_id="CWE-943",
        cwe_name="NoSQL Injection",
    )
    return SecurityAssessmentReport(metadata=meta, findings=[f1, f2])


def test_json_exporter_structure_and_schema_version() -> None:
    """Verify JSONReportExporter produces valid JSON with schema envelope."""
    report = _build_sample_report()
    json_output = JSONReportExporter().export(report)
    parsed = json.loads(json_output)

    assert "schema_version" in parsed
    assert parsed["schema_version"] == "1.0.0"
    assert "metadata" in parsed
    assert "summary" in parsed
    assert parsed["summary"]["total_findings"] == 2
    assert "findings" in parsed
    assert len(parsed["findings"]) == 2
    assert parsed["findings"][0]["id"] == "DBS-SQLI-01"


def test_json_exporter_empty_findings() -> None:
    """Verify JSONReportExporter handles empty findings."""
    meta = ReportMetadata(target_url="http://target.local", total_findings=0)
    report = SecurityAssessmentReport(metadata=meta, findings=[])
    json_output = JSONReportExporter().export(report)
    parsed = json.loads(json_output)

    assert parsed["summary"]["total_findings"] == 0
    assert parsed["findings"] == []


def test_markdown_exporter_contains_all_sections() -> None:
    """Verify MarkdownReportExporter renders executive summary, tables, and finding details."""
    report = _build_sample_report()
    md = MarkdownReportExporter().export(report)

    # Executive summary
    assert "## 1. Executive Summary" in md
    assert "http://target.local/app" in md
    assert "Finding Breakdown by Severity" in md
    assert "Finding Breakdown by Verification Lifecycle Status" in md

    # Finding details
    assert "## 2. Detailed Findings" in md
    assert "DBS-SQLI-01" in md
    assert "CWE-89" in md
    assert "DBS-NOSQLI-01" in md
    assert "CWE-943" in md

    # Actionable remediation & limitations
    assert "Actionable Remediation" in md
    assert "## 3. Scope and Limitations" in md


def test_terminal_exporter_presentation() -> None:
    """Verify TerminalReportExporter outputs formatted tables and borders."""
    report = _build_sample_report()
    out = TerminalReportExporter().export(report)

    assert "DBSHIELD SECURITY ASSESSMENT REPORT" in out
    assert "FINDING SUMMARY" in out
    assert "Total Findings:      2" in out
    assert "DBS-SQLI-01" in out
    assert "DBS-NOSQLI-01" in out
    assert "SAFETY BOUNDARIES & LIMITATIONS" in out
