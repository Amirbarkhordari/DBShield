"""Integration tests for dbshield verify CLI command (Phase 7)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from dbshield.cli import app

runner = CliRunner()


def test_cli_verify_help() -> None:
    """Verify dbshield verify --help prints options and exits 0."""
    result = runner.invoke(app, ["verify", "--help"])
    assert result.exit_code == 0
    assert "Analyze security test findings, reduce false positives" in result.stdout
    assert "--input" in result.stdout
    assert "--fixture" in result.stdout
    assert "--url" in result.stdout
    assert "--engine" in result.stdout
    assert "--format" in result.stdout
    assert "--output" in result.stdout
    assert "--overwrite" in result.stdout


def test_cli_verify_missing_all_inputs() -> None:
    """Verify dbshield verify without --input, --fixture, or --url exits with 2."""
    result = runner.invoke(app, ["verify"])
    assert result.exit_code == 2
    assert "Neither --input, --fixture, nor --url was provided" in result.stderr


def test_cli_verify_invalid_format() -> None:
    """Verify invalid --format option exits with code 2."""
    result = runner.invoke(app, ["verify", "--input", "any.json", "--format", "yaml"])
    assert result.exit_code == 2
    assert "Invalid format 'yaml'" in result.stderr


def test_cli_verify_invalid_engine() -> None:
    """Verify invalid --engine option exits with code 2."""
    result = runner.invoke(app, ["verify", "--input", "any.json", "--engine", "ldap"])
    assert result.exit_code == 2
    assert "Invalid engine 'ldap'" in result.stderr


def test_cli_verify_nonexistent_input_file() -> None:
    """Verify missing input file path exits with code 2."""
    result = runner.invoke(app, ["verify", "--input", "missing_file_xyz.json"])
    assert result.exit_code == 2
    assert "not found" in result.stderr


def test_cli_verify_input_file_true_positive(tmp_path: Path) -> None:
    """Verify analyzing an existing execution results JSON file with an SQLi finding."""
    input_file = tmp_path / "execution_run.json"
    execution_data = {
        "run_id": "run-test-001",
        "target_url": "http://laboratory.local/products",
        "engine_name": "sqli",
        "execution_status": "completed",
        "summary": {
            "total_test_cases": 1,
            "executed_test_cases": 1,
            "skipped_test_cases": 0,
            "failed_test_cases": 0,
            "cancelled_test_cases": 0,
            "total_requests": 2,
            "duration_seconds": 0.05,
        },
        "records": [
            {
                "execution_id": "exec-001",
                "test_case_id": "TC_SQLI_QUOTE",
                "payload_id": "SQLI_ERR_QUOTE",
                "parameter_name": "cat_id",
                "parameter_location": "query",
                "status": "executed",
                "request_count": 2,
                "elapsed_seconds": 0.05,
                "status_code": 500,
                "findings": [
                    {
                        "finding_id": "find-001",
                        "test_id": "TC_SQLI_QUOTE",
                        "technique": "error_based",
                        "target_url": "http://laboratory.local/products",
                        "http_method": "GET",
                        "parameter": {
                            "name": "cat_id",
                            "location": "query",
                            "endpoint": "http://laboratory.local/products",
                        },
                        "status": "potential_indicator",
                        "confidence": "high",
                        "evidence_summary": "MySQL syntax error detected",
                        "evidence_records": [
                            {
                                "technique": "error_based",
                                "rule_id": "SQLI_MYSQL_SYNTAX",
                                "matched_pattern": "You have an error in your SQL syntax",
                                "snippet": 'You have an error in your SQL syntax near "\'"',
                                "description": "MySQL syntax error",
                                "db_family_hint": "mysql",
                                "confirmed": False,
                            }
                        ],
                        "baseline_metadata": {"status_code": 200, "is_stable": True},
                        "test_response_metadata": {"status_code": 500},
                        "request_count": 2,
                    }
                ],
            }
        ],
        "findings": [],
    }
    input_file.write_text(json.dumps(execution_data), encoding="utf-8")

    result = runner.invoke(app, ["verify", "--input", str(input_file)])
    assert result.exit_code == 0
    assert "DBShield Evidence Analysis and Vulnerability Verification" in result.stdout
    assert "Verified Vulnerabilities:          1" in result.stdout
    assert "Parameter 'cat_id' [VERIFIED]" in result.stdout
    assert "Confidence: HIGH" in result.stdout or "Confidence: VERIFIED" in result.stdout
    assert "mysql" in result.stdout.lower()


def test_cli_verify_input_file_json_format(tmp_path: Path) -> None:
    """Verify --format json outputs valid machine-readable VerificationResult JSON on stdout."""
    input_file = tmp_path / "findings_input.json"
    findings_data = {
        "target_url": "http://laboratory.local/api",
        "findings": [
            {
                "finding_id": "f-123",
                "target_url": "http://laboratory.local/api",
                "param_name": "id",
                "location": "query",
                "technique": "error_based",
                "rule_id": "SQLI_SQLITE",
                "matched_pattern": "unclosed quotation mark",
                "description": "SQLite error",
                "db_family": "sqlite",
                "baseline_metadata": {"status_code": 200, "is_stable": True},
                "test_response_metadata": {"status_code": 500},
                "evidence_records": [
                    {
                        "rule_id": "SQLI_SQLITE",
                        "matched_pattern": "unclosed quotation mark",
                        "snippet": "unclosed quotation mark after the character string",
                        "description": "SQLite syntax error",
                        "db_family_hint": "sqlite",
                    }
                ],
            }
        ],
    }
    input_file.write_text(json.dumps(findings_data), encoding="utf-8")

    result = runner.invoke(app, ["verify", "--input", str(input_file), "--format", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["verified_count"] == 1
    assert parsed["findings"][0]["parameter_name"] == "id"
    assert parsed["findings"][0]["status"] == "verified"


def test_cli_verify_file_export_and_overwrite_protection(tmp_path: Path) -> None:
    """Verify file export protects against accidental overwrite unless --overwrite is given."""
    input_file = tmp_path / "simple_input.json"
    input_file.write_text(json.dumps({"target_url": "http://test.local", "findings": []}))

    out_file = tmp_path / "report.json"
    out_file.write_text("existing content")

    # Should fail without --overwrite
    result_fail = runner.invoke(
        app, ["verify", "--input", str(input_file), "--output", str(out_file)]
    )
    assert result_fail.exit_code == 1
    assert "already exists" in result_fail.stderr

    # Should succeed with --overwrite
    result_ok = runner.invoke(
        app,
        [
            "verify",
            "--input",
            str(input_file),
            "--output",
            str(out_file),
            "--overwrite",
            "--format",
            "json",
        ],
    )
    assert result_ok.exit_code == 0
    assert "successfully exported" in result_ok.stderr
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert "summary" in content


def test_cli_verify_offline_fixture(tmp_path: Path) -> None:
    """Verify dbshield verify --fixture analyzes offline response fixtures end-to-end."""
    fixture_file = tmp_path / "fixture.json"
    fixture_data = {
        "target_url": "http://lab.local/item?id=1",
        "parameter": "id",
        "location": "query",
        "payload_id": "SQLI_ERR_QUOTE",
        "baseline": {
            "status_code": 200,
            "body": "<html><body>Clean Response</body></html>",
        },
        "test": {
            "status_code": 500,
            "body": "<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</body></html>",
        },
    }
    fixture_file.write_text(json.dumps(fixture_data), encoding="utf-8")

    result = runner.invoke(app, ["verify", "--fixture", str(fixture_file)])
    assert result.exit_code == 0
    assert "DBShield Evidence Analysis and Vulnerability Verification" in result.stdout
    assert "Verified Vulnerabilities:          1" in result.stdout
    assert "Parameter 'id' [VERIFIED]" in result.stdout


def test_cli_verify_out_of_scope_url_blocked() -> None:
    """Verify live target URL out of authorized scope is blocked with exit code 2."""
    result = runner.invoke(
        app,
        ["verify", "--url", "https://unauthorized-evil.com/app?id=1"],
        env={"DBSHIELD_ALLOWED_HOSTS": "authorized.example.com"},
    )
    assert result.exit_code == 2
    assert "not within authorized scope" in result.stderr
