"""Unit tests for DBShield evidence redaction and credential protection in reports (Phase 8)."""

from dbshield.reporting.exporters.csv_exporter import CSVReportExporter
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
from dbshield.reporting.redaction import (
    redact_parameter,
    redact_text,
    redact_url,
)
from dbshield.sqli.models import ParameterLocation
from dbshield.verification.models import ConfidenceLevel, VerificationStatus


def test_redact_parameter_masks_sensitive_names() -> None:
    """Verify sensitive parameter names are masked while preserving safe names."""
    assert "REDACTED" in redact_parameter("password")
    assert "REDACTED" in redact_parameter("user_token")
    assert "REDACTED" in redact_parameter("api_key")
    assert "REDACTED" in redact_parameter("csrf_token")
    assert redact_parameter("username") == "username"
    assert redact_parameter("query") == "query"
    assert redact_parameter("page") == "page"


def test_redact_text_masks_credentials_and_headers() -> None:
    """Verify secret headers, database connection strings, and tokens are scrubbed."""
    raw = (
        "Server debug output:\n"
        "Authorization: Bearer my_secret_token_abc\n"
        "Cookie: session=active_session_cookie_123\n"
        "db_password = 'super_secret_db_pass'\n"
        "mysql://admin:secretpass123@db.internal:3306/production\n"
        "Error near password='injected_val'"
    )
    scrubbed = redact_text(raw)
    assert "my_secret_token_abc" not in scrubbed
    assert "active_session_cookie_123" not in scrubbed
    assert "super_secret_db_pass" not in scrubbed
    assert "secretpass123" not in scrubbed
    assert "Bearer [REDACTED]" in scrubbed
    assert "Cookie: [REDACTED]" in scrubbed


def test_zero_secret_leakage_across_all_exporters() -> None:
    """Verify synthetic secrets do not leak through JSON, CSV, Markdown, or Terminal exports."""
    # Synthetic token constructed via concatenation to prevent static secret scan false alarms
    synthetic_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
    raw_snippet = f"Header Authorization: Bearer {synthetic_token} on query"
    clean_snippet = redact_text(raw_snippet)

    meta = ReportMetadata(target_url="http://target.local", total_findings=1)
    finding = NormalizedSecurityFinding(
        id="DBS-SECRET-TEST",
        title="SQL Injection Finding",
        category=VulnerabilityCategory.SQL_INJECTION,
        subtype="error_based",
        target_url="http://target.local/vuln",
        endpoint="/vuln",
        http_method="POST",
        parameter_name=redact_parameter("password"),
        parameter_location=ParameterLocation.BODY_URLENCODED,
        engine="sqli",
        technique="error_based",
        verification_status=VerificationStatus.VERIFIED,
        confidence_level=ConfidenceLevel.VERIFIED,
        confidence_score=0.90,
        severity=FindingSeverity.HIGH,
        severity_rationale="Database error detected.",
        description=f"Evidence collected: {clean_snippet}",
        evidence_summary=clean_snippet,
        remediation="Ensure input validation and prepared statements.",
        cwe_id="CWE-89",
    )
    report = SecurityAssessmentReport(metadata=meta, findings=[finding])

    # 1. JSON Exporter
    json_out = JSONReportExporter().export(report)
    assert synthetic_token not in json_out
    assert finding.parameter_name != "password"
    assert "REDACTED" in json_out

    # 2. CSV Exporter
    csv_out = CSVReportExporter().export(report)
    assert synthetic_token not in csv_out
    assert "REDACTED" in csv_out

    # 3. Markdown Exporter
    md_out = MarkdownReportExporter().export(report)
    assert synthetic_token not in md_out
    assert "REDACTED" in md_out

    # 4. Terminal Exporter
    term_out = TerminalReportExporter().export(report)
    assert synthetic_token not in term_out
    assert "REDACTED" in term_out


def test_redact_url_masks_sensitive_query_parameters() -> None:
    """Verify redact_url masks sensitive query parameters while preserving URL structure and non-sensitive params."""
    # 1. Sensitive query parameters
    url = "https://target.local:8080/api/v1/search?q=test&token=secret_tok_123&access_token=acc_tok_456&key=api_key_789&secret=my_sec&page=2&item=a&item=b#section1"
    cleaned = redact_url(url)
    assert "secret_tok_123" not in cleaned
    assert "acc_tok_456" not in cleaned
    assert "api_key_789" not in cleaned
    assert "my_sec" not in cleaned
    assert "token=[REDACTED]" in cleaned
    assert "access_token=[REDACTED]" in cleaned
    assert "key=[REDACTED]" in cleaned
    assert "secret=[REDACTED]" in cleaned
    # Non-sensitive preserved
    assert "q=test" in cleaned
    assert "page=2" in cleaned
    assert "item=a&item=b" in cleaned  # Repeated parameters preserved
    # Structure preserved
    assert cleaned.startswith("https://target.local:8080/api/v1/search?")
    assert cleaned.endswith("#section1")

    # 2. Additional sensitive parameter names (password, passwd, authorization, api_key)
    url2 = "http://target.local/auth?user=alice&password=mypassword&passwd=oldpass&authorization=bearer_token&api_key=mykey"
    cleaned2 = redact_url(url2)
    assert "mypassword" not in cleaned2
    assert "oldpass" not in cleaned2
    assert "bearer_token" not in cleaned2
    assert "mykey" not in cleaned2
    assert "user=alice" in cleaned2
    assert "password=[REDACTED]" in cleaned2
    assert "passwd=[REDACTED]" in cleaned2
    assert "authorization=[REDACTED]" in cleaned2
    assert "api_key=[REDACTED]" in cleaned2

    # 3. URL authority credential masking
    url3 = "https://admin:super_secret_auth@target.local/dashboard"
    cleaned3 = redact_url(url3)
    assert "super_secret_auth" not in cleaned3
    assert "admin:[REDACTED]@target.local" in cleaned3

    # 4. URLs without query or non-sensitive URLs
    assert redact_url("https://target.local/home") == "https://target.local/home"
    assert (
        redact_url("https://target.local/search?q=apple&page=1")
        == "https://target.local/search?q=apple&page=1"
    )
    assert redact_url("") == ""
