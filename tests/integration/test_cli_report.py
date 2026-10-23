"""Integration tests for DBShield CLI report command (Phase 8)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from dbshield.cli import app

runner = CliRunner()


def _create_sample_findings_file(tmp_path: Path) -> Path:
    """Create a sample valid findings JSON file."""
    findings_data = {
        "target_url": "http://target.local/api",
        "findings": [
            {
                "id": "DBS-FINDING-01",
                "title": "Verified SQL Injection in query parameter 'id'",
                "category": "sql_injection",
                "subtype": "error_based",
                "target_url": "http://target.local/api/items",
                "endpoint": "/api/items",
                "http_method": "GET",
                "parameter_name": "id",
                "parameter_location": "query",
                "engine": "sqli",
                "technique": "error_based",
                "verification_status": "verified",
                "confidence_level": "verified",
                "confidence_score": 0.95,
                "severity": "high",
                "severity_rationale": "Database error verified in response.",
                "description": "SQL syntax error observed near parameter.",
                "evidence_summary": "syntax error near quote",
                "evidence_count": 1,
                "evidence_ids": ["ev-001"],
                "remediation": "Use parameterized queries.",
                "cwe_id": "CWE-89",
                "cwe_name": "SQL Injection",
                "execution_references": {},
                "first_observed_at": "2026-10-23T12:00:00Z",
                "metadata": {},
            },
            {
                "id": "DBS-FINDING-02",
                "title": "Potential NoSQL Injection in body parameter 'filter'",
                "category": "nosql_injection",
                "subtype": "operator_injection",
                "target_url": "http://target.local/api/search",
                "endpoint": "/api/search",
                "http_method": "POST",
                "parameter_name": "filter",
                "parameter_location": "body_json",
                "engine": "nosqli",
                "technique": "operator_injection",
                "verification_status": "potential_indicator",
                "confidence_level": "medium",
                "confidence_score": 0.50,
                "severity": "medium",
                "severity_rationale": "Preliminary variance observed.",
                "description": "Response variance during testing.",
                "evidence_summary": "Status code changed from 200 to 500",
                "evidence_count": 1,
                "evidence_ids": ["ev-002"],
                "remediation": "Validate input types against query selectors.",
                "cwe_id": "CWE-943",
                "cwe_name": "NoSQL Injection",
                "execution_references": {},
                "first_observed_at": "2026-10-23T12:05:00Z",
                "metadata": {},
            },
        ],
    }
    file_path = tmp_path / "sample_findings.json"
    file_path.write_text(json.dumps(findings_data), encoding="utf-8")
    return file_path


def test_cli_report_help() -> None:
    """Verify dbshield report --help displays usage and options."""
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
    assert "--input" in result.stdout
    assert "--format" in result.stdout
    assert "--output" in result.stdout
    assert "--severity" in result.stdout
    assert "--status" in result.stdout


def test_cli_report_text_format(tmp_path: Path) -> None:
    """Verify report text format output."""
    in_file = _create_sample_findings_file(tmp_path)
    result = runner.invoke(app, ["report", "-i", str(in_file), "-f", "text"])
    assert result.exit_code == 0
    assert "DBSHIELD SECURITY ASSESSMENT REPORT" in result.stdout
    assert "DBS-FINDING-01" in result.stdout


def test_cli_report_json_format(tmp_path: Path) -> None:
    """Verify report json format output."""
    in_file = _create_sample_findings_file(tmp_path)
    result = runner.invoke(app, ["report", "-i", str(in_file), "-f", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["schema_version"] == "1.0.0"
    assert parsed["summary"]["total_findings"] == 2


def test_cli_report_csv_format(tmp_path: Path) -> None:
    """Verify report csv format output."""
    in_file = _create_sample_findings_file(tmp_path)
    result = runner.invoke(app, ["report", "-i", str(in_file), "-f", "csv"])
    assert result.exit_code == 0
    assert "finding_id,title,category" in result.stdout
    assert "DBS-FINDING-01" in result.stdout


def test_cli_report_markdown_format(tmp_path: Path) -> None:
    """Verify report markdown format output."""
    in_file = _create_sample_findings_file(tmp_path)
    result = runner.invoke(app, ["report", "-i", str(in_file), "-f", "markdown"])
    assert result.exit_code == 0
    assert "# DBShield Security Assessment Report" in result.stdout
    assert "## 1. Executive Summary" in result.stdout
    assert "## 2. Detailed Findings" in result.stdout


def test_cli_report_export_to_file(tmp_path: Path) -> None:
    """Verify report exported to file destination."""
    in_file = _create_sample_findings_file(tmp_path)
    out_file = tmp_path / "assessment.md"
    result = runner.invoke(
        app, ["report", "-i", str(in_file), "-f", "markdown", "-o", str(out_file)]
    )
    assert result.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "Executive Summary" in content


def test_cli_report_overwrite_safeguard(tmp_path: Path) -> None:
    """Verify existing output file is not overwritten without --overwrite."""
    in_file = _create_sample_findings_file(tmp_path)
    existing = tmp_path / "existing.json"
    existing.write_text("pre-existing content", encoding="utf-8")

    # Without --overwrite -> exit code 1
    fail_result = runner.invoke(
        app, ["report", "-i", str(in_file), "-f", "json", "-o", str(existing)]
    )
    assert fail_result.exit_code == 1
    assert "already exists" in fail_result.stderr
    assert existing.read_text(encoding="utf-8") == "pre-existing content"

    # With --overwrite -> exit code 0
    success_result = runner.invoke(
        app,
        ["report", "-i", str(in_file), "-f", "json", "-o", str(existing), "--overwrite"],
    )
    assert success_result.exit_code == 0
    assert "pre-existing" not in existing.read_text(encoding="utf-8")


def test_cli_report_invalid_format(tmp_path: Path) -> None:
    """Verify invalid format specification produces error code 2."""
    in_file = _create_sample_findings_file(tmp_path)
    result = runner.invoke(app, ["report", "-i", str(in_file), "-f", "pdf"])
    assert result.exit_code == 2
    assert "Invalid format" in result.stderr


def test_cli_report_missing_file() -> None:
    """Verify non-existent input file produces error code 1."""
    result = runner.invoke(app, ["report", "-i", "non_existent_file_xyz.json"])
    assert result.exit_code == 1
    assert "not found" in result.stderr


def test_cli_report_severity_filtering(tmp_path: Path) -> None:
    """Verify --severity filters findings by minimum severity."""
    in_file = _create_sample_findings_file(tmp_path)
    # Filter by High -> only the high finding should be included
    result = runner.invoke(app, ["report", "-i", str(in_file), "-f", "json", "-s", "high"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["findings"][0]["severity"] == "high"


def test_cli_report_status_filtering(tmp_path: Path) -> None:
    """Verify --status filters findings by verification status."""
    in_file = _create_sample_findings_file(tmp_path)
    # Filter by verified status
    result = runner.invoke(
        app, ["report", "-i", str(in_file), "-f", "json", "--status", "verified"]
    )
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["findings"][0]["verification_status"] == "verified"
