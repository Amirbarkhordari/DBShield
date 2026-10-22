"""Integration tests for DBShield CLI payloads and execute commands (Phase 6)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from dbshield.cli import app

runner = CliRunner()


def test_cli_payloads_help() -> None:
    """Verify dbshield payloads --help."""
    result = runner.invoke(app, ["payloads", "--help"])
    assert result.exit_code == 0
    assert "Inspect, filter, and validate DBShield's centralized test payload" in result.stdout
    assert "--engine" in result.stdout
    assert "--category" in result.stdout
    assert "--technique" in result.stdout
    assert "--location" in result.stdout
    assert "--risk" in result.stdout
    assert "--info" in result.stdout
    assert "--validate" in result.stdout
    assert "--format" in result.stdout


def test_cli_payloads_listing_default() -> None:
    """Verify default table listing of registered payloads."""
    result = runner.invoke(app, ["payloads"])
    assert result.exit_code == 0
    assert "DBShield Security Payload Catalog" in result.stdout
    assert "SQLI_ERR_QUOTE" in result.stdout
    assert "NOSQLI_ERR_OP_JSON" in result.stdout


def test_cli_payloads_validate() -> None:
    """Verify --validate flag verifies catalog integrity."""
    result = runner.invoke(app, ["payloads", "--validate"])
    assert result.exit_code == 0
    assert "Payload catalog validation passed" in result.stderr


def test_cli_payloads_filter_by_engine() -> None:
    """Verify filtering payloads by engine."""
    result = runner.invoke(app, ["payloads", "--engine", "sqli"])
    assert result.exit_code == 0
    assert "SQLI_ERR_QUOTE" in result.stdout
    assert "NOSQLI_ERR_OP_JSON" not in result.stdout


def test_cli_payloads_filter_by_category() -> None:
    """Verify filtering payloads by category."""
    result = runner.invoke(app, ["payloads", "--category", "nosqli"])
    assert result.exit_code == 0
    assert "NOSQLI_ERR_OP_JSON" in result.stdout
    assert "SQLI_ERR_QUOTE" not in result.stdout


def test_cli_payloads_filter_invalid_category() -> None:
    """Verify error on invalid category."""
    result = runner.invoke(app, ["payloads", "--category", "invalid_cat"])
    assert result.exit_code == 2
    assert "Invalid category 'invalid_cat'" in result.stderr


def test_cli_payloads_info_success() -> None:
    """Verify inspecting detailed payload metadata."""
    result = runner.invoke(app, ["payloads", "--info", "SQLI_ERR_QUOTE"])
    assert result.exit_code == 0
    assert "DBShield Security Payload Specification" in result.stdout
    assert "Payload ID:           SQLI_ERR_QUOTE" in result.stdout
    assert "Technique:            error_based" in result.stdout
    assert "Safety Constraints:" in result.stdout


def test_cli_payloads_info_not_found() -> None:
    """Verify error when requested payload ID does not exist."""
    result = runner.invoke(app, ["payloads", "--info", "NONEXISTENT_PAYLOAD"])
    assert result.exit_code == 2
    assert "Payload 'NONEXISTENT_PAYLOAD' not found" in result.stderr


def test_cli_payloads_json_format() -> None:
    """Verify JSON output format."""
    result = runner.invoke(app, ["payloads", "--format", "json", "--engine", "sqli"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert any(p["payload_id"] == "SQLI_ERR_QUOTE" for p in data)


def test_cli_payloads_export_to_file(tmp_path: Path) -> None:
    """Verify exporting payload catalog to file."""
    out_file = tmp_path / "catalog_export.json"
    result = runner.invoke(
        app,
        ["payloads", "--format", "json", "--output", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data) >= 10

    # Overwrite check without --overwrite fails
    res_dup = runner.invoke(
        app,
        ["payloads", "--output", str(out_file)],
    )
    assert res_dup.exit_code == 1
    assert "already exists" in res_dup.stderr

    # With --overwrite succeeds
    res_overwrite = runner.invoke(
        app,
        ["payloads", "--output", str(out_file), "--overwrite"],
    )
    assert res_overwrite.exit_code == 0


def test_cli_execute_help() -> None:
    """Verify dbshield execute --help."""
    result = runner.invoke(app, ["execute", "--help"])
    assert result.exit_code == 0
    assert "Execute controlled security test cases across engines" in result.stdout
    assert "--url" in result.stdout
    assert "--engine" in result.stdout
    assert "--param" in result.stdout
    assert "--fixture" in result.stdout
    assert "--max-budget" in result.stdout


def test_cli_execute_missing_target() -> None:
    """Verify error when neither --url nor --fixture is provided to execute."""
    result = runner.invoke(app, ["execute"])
    assert result.exit_code == 2
    assert "Missing target specification" in result.stderr


def test_cli_execute_out_of_scope_target() -> None:
    """Verify scope violation rejection with exit code 2."""
    result = runner.invoke(
        app,
        ["execute", "--url", "https://unauthorized-domain.com/item?id=1"],
        env={"DBSHIELD_ALLOWED_HOSTS": "authorized.example.com"},
    )
    assert result.exit_code == 2
    assert "not within authorized scope" in result.stderr


def test_cli_execute_offline_fixture(tmp_path: Path) -> None:
    """Verify offline fixture execution via dbshield execute."""
    fixture_path = tmp_path / "sqli_fixture.json"
    fixture_data = {
        "target_url": "http://laboratory.local/app",
        "parameter": "id",
        "location": "query",
        "payload_id": "SQLI_ERR_QUOTE",
        "baseline": {"status_code": 200, "body": "Normal baseline page"},
        "test": {
            "status_code": 500,
            "body": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        },
    }
    fixture_path.write_text(json.dumps(fixture_data), encoding="utf-8")

    result = runner.invoke(
        app,
        ["execute", "--fixture", str(fixture_path), "--engine", "sqli"],
    )
    assert result.exit_code == 0
    assert "DBShield Test Execution Orchestrator Report" in result.stdout
    assert "SQLI" in result.stdout
    assert "Total Requests:         0" in result.stdout


def test_cli_execute_offline_fixture_json_export(tmp_path: Path) -> None:
    """Verify exporting offline fixture execution to JSON file."""
    fixture_path = tmp_path / "fix.json"
    fixture_data = {
        "target_url": "http://laboratory.local/app",
        "parameter": "id",
        "baseline": {"status_code": 200, "body": "ok"},
        "test": {"status_code": 200, "body": "ok"},
    }
    fixture_path.write_text(json.dumps(fixture_data), encoding="utf-8")
    out_file = tmp_path / "exec_result.json"

    result = runner.invoke(
        app,
        [
            "execute",
            "--fixture",
            str(fixture_path),
            "--format",
            "json",
            "--output",
            str(out_file),
        ],
    )
    assert result.exit_code == 0
    assert out_file.is_file()
    res_data = json.loads(out_file.read_text(encoding="utf-8"))
    assert res_data["execution_status"] == "completed"
