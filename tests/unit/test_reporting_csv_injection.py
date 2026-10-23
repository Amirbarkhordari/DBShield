"""Unit tests for DBShield CSV formula injection (DDE) protection and formatting (Phase 8)."""

import csv
import io

from dbshield.reporting.exporters.csv_exporter import CSV_COLUMNS, CSVReportExporter
from dbshield.reporting.models import (
    FindingSeverity,
    NormalizedSecurityFinding,
    ReportMetadata,
    SecurityAssessmentReport,
    VulnerabilityCategory,
)
from dbshield.reporting.redaction import escape_csv_formula
from dbshield.sqli.models import ParameterLocation
from dbshield.verification.models import ConfidenceLevel, VerificationStatus


def test_escape_csv_formula_neutralizes_dangerous_prefixes() -> None:
    """Verify formula injection characters are neutralized with leading single quote."""
    # Excel / Calc formula injection characters: '=', '+', '-', '@', '\t', '\r'
    assert escape_csv_formula("=1+1") == "'=1+1"
    assert escape_csv_formula("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert escape_csv_formula("-2+3") == "'-2+3"
    assert escape_csv_formula("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert escape_csv_formula("\tcalc") == "'\tcalc"
    assert escape_csv_formula("\rcalc") == "'\rcalc"

    # Leading whitespace before formula char is also protected
    assert escape_csv_formula("   =cmd") == "'   =cmd"

    # Leading newlines and control characters before formula char
    assert escape_csv_formula("\n=1+1") == "'\n=1+1"
    assert escape_csv_formula("\r\n=1+1") == "'\r\n=1+1"
    assert escape_csv_formula("\t=1+1") == "'\t=1+1"
    assert escape_csv_formula(" \n\t=1+1") == "' \n\t=1+1"

    # Multiline cell values with formula triggers after newline
    assert escape_csv_formula("Description\n=1+1") == "'Description\n=1+1"
    assert escape_csv_formula("Header\r\n@SUM(A1:A5)") == "'Header\r\n@SUM(A1:A5)"

    # Benign text without formula prefix is unchanged
    assert escape_csv_formula("normal text") == "normal text"
    assert escape_csv_formula("parameter_name") == "parameter_name"
    assert escape_csv_formula("http://target.local") == "http://target.local"
    assert escape_csv_formula(123) == "123"
    assert escape_csv_formula("") == ""
    assert escape_csv_formula(None) == ""


def test_csv_exporter_escapes_malicious_cells_in_full_report() -> None:
    """Verify CSVReportExporter applies formula injection protection to all finding fields."""
    meta = ReportMetadata(
        target_url="http://target.local",
        total_findings=1,
    )
    # Finding with malicious formula payloads in multiple fields
    finding = NormalizedSecurityFinding(
        id="=cmd|' /C calc'!A0",
        title="+2+5 formula title",
        category=VulnerabilityCategory.SQL_INJECTION,
        subtype="-error",
        target_url="http://target.local/vuln",
        endpoint="/vuln",
        http_method="GET",
        parameter_name="@param",
        parameter_location=ParameterLocation.QUERY,
        engine="sqli",
        technique="=formula",
        verification_status=VerificationStatus.VERIFIED,
        confidence_level=ConfidenceLevel.VERIFIED,
        confidence_score=0.99,
        severity=FindingSeverity.HIGH,
        severity_rationale="+high impact",
        description="=description formula",
        evidence_summary="=1+1 evidence",
        remediation="@remediation formula",
        cwe_id="CWE-89",
    )
    report = SecurityAssessmentReport(metadata=meta, findings=[finding])
    csv_text = CSVReportExporter().export(report)

    # Parse exported CSV using standard csv reader
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)

    assert len(rows) == 2  # header + 1 data row
    headers = rows[0]
    data = rows[1]

    assert headers == CSV_COLUMNS

    # Check each malicious field is safely quoted with leading single quote
    id_idx = headers.index("finding_id")
    title_idx = headers.index("title")
    subtype_idx = headers.index("subtype")
    param_idx = headers.index("parameter_name")
    ev_idx = headers.index("evidence_summary")
    rem_idx = headers.index("remediation")

    assert data[id_idx].startswith("'=")
    assert data[title_idx].startswith("'+")
    assert data[subtype_idx].startswith("'-")
    assert data[param_idx].startswith("'@")
    assert data[ev_idx].startswith("'=")
    assert data[rem_idx].startswith("'@")


def test_csv_exporter_handles_empty_findings_gracefully() -> None:
    """Verify CSVReportExporter handles empty findings collections without error."""
    meta = ReportMetadata(target_url="http://target.local", total_findings=0)
    report = SecurityAssessmentReport(metadata=meta, findings=[])
    csv_text = CSVReportExporter().export(report)

    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0] == CSV_COLUMNS


def test_csv_exporter_handles_commas_newlines_and_unicode() -> None:
    """Verify CSV escaping with quotes, commas, newlines, and Unicode symbols."""
    meta = ReportMetadata(target_url="http://target.local", total_findings=1)
    finding = NormalizedSecurityFinding(
        id="DBS-UNICODE",
        title='Quote, "with comma", and newline \n inside title',
        category=VulnerabilityCategory.SQL_INJECTION,
        subtype="error_based",
        target_url="http://target.local/üñîçødé",
        endpoint="/üñîçødé",
        http_method="GET",
        parameter_name="term",
        parameter_location=ParameterLocation.QUERY,
        engine="sqli",
        technique="error_based",
        verification_status=VerificationStatus.VERIFIED,
        confidence_level=ConfidenceLevel.VERIFIED,
        confidence_score=0.90,
        severity=FindingSeverity.HIGH,
        severity_rationale="Database error detected: 'syntax error near \"1\"'",
        description="Line 1\nLine 2\nLine 3 with, comma",
        evidence_summary='Excerpts: "error in SQL", table: user_data',
        remediation="Use bound parameters; avoid string concatenation.",
        cwe_id="CWE-89",
    )
    report = SecurityAssessmentReport(metadata=meta, findings=[finding])
    csv_text = CSVReportExporter().export(report)

    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 2
    assert rows[1][1] == 'Quote, "with comma", and newline \n inside title'
    assert "/üñîçødé" in rows[1][9]


def test_csv_exporter_escapes_multiline_and_newline_formula_cells() -> None:
    """Verify serialized CSV output properly escapes multiline and newline formula injection payloads."""
    meta = ReportMetadata(target_url="http://target.local", total_findings=1)
    finding = NormalizedSecurityFinding(
        id="DBS-FORMULA-ML",
        title="\n=1+1 title with leading newline",
        category=VulnerabilityCategory.SQL_INJECTION,
        subtype="error_based",
        target_url="http://target.local/vuln",
        endpoint="/vuln",
        http_method="GET",
        parameter_name="id",
        parameter_location=ParameterLocation.QUERY,
        engine="sqli",
        technique="error_based",
        verification_status=VerificationStatus.VERIFIED,
        confidence_level=ConfidenceLevel.VERIFIED,
        confidence_score=0.90,
        severity=FindingSeverity.HIGH,
        severity_rationale="High impact",
        description="Line 1\n=cmd|' /C calc'!A0\nLine 3",
        evidence_summary="\r\n+2+2 evidence",
        remediation="Remediation guidance",
        cwe_id="CWE-89",
    )
    report = SecurityAssessmentReport(metadata=meta, findings=[finding])
    csv_text = CSVReportExporter().export(report)

    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 2
    data = rows[1]
    title_idx = CSV_COLUMNS.index("title")
    desc_idx = CSV_COLUMNS.index("evidence_summary")

    # Title must start with single quote before the newline
    assert data[title_idx].startswith("'\n=")
    assert data[desc_idx].startswith("'\r\n+")
