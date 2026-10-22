"""Integration tests for dbshield nosqli CLI command (Phase 5)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from dbshield.cli import app

runner = CliRunner()


def test_cli_nosqli_help() -> None:
    """Verify nosqli --help output."""
    result = runner.invoke(app, ["nosqli", "--help"])
    assert result.exit_code == 0
    assert "Assess web application targets or offline response fixtures for NoSQL" in result.stdout
    assert "--url" in result.stdout
    assert "--fixture" in result.stdout
    assert "--param" in result.stdout
    assert "--json" in result.stdout
    assert "--format" in result.stdout


def test_cli_nosqli_missing_target_and_fixture() -> None:
    """Verify error when neither --url nor --fixture is provided."""
    result = runner.invoke(app, ["nosqli"])
    assert result.exit_code == 2
    assert "Neither --url nor --fixture was provided" in result.stderr


def test_cli_nosqli_invalid_url_scheme() -> None:
    """Verify rejection of invalid URL scheme."""
    result = runner.invoke(app, ["nosqli", "--url", "ftp://example.com/item"])
    assert result.exit_code == 2
    assert "Unsupported scheme" in result.stderr


def test_cli_nosqli_out_of_scope_target() -> None:
    """Verify scope violation rejection with exit code 2."""
    result = runner.invoke(
        app,
        ["nosqli", "--url", "https://unauthorized-domain.com/item?id=1"],
        env={"DBSHIELD_ALLOWED_HOSTS": "authorized.example.com"},
    )
    assert result.exit_code == 2
    assert "not within authorized scope" in result.stderr


def test_cli_nosqli_fixture_missing_file() -> None:
    """Verify error on nonexistent fixture file."""
    result = runner.invoke(app, ["nosqli", "--fixture", "non_existent_fixture.json"])
    assert result.exit_code == 2
    assert "Fixture file 'non_existent_fixture.json' not found" in result.stderr


def test_cli_nosqli_fixture_text_format(tmp_path: Path) -> None:
    """Verify offline fixture assessment in text report format."""
    fixture_file = tmp_path / "nosqli_sample.json"
    fixture_data = {
        "target_url": "http://lab.local/api/users?user=admin",
        "parameter": "user",
        "baseline": {
            "status_code": 200,
            "body": '{"user": "admin", "role": "root"}',
        },
        "test": {
            "status_code": 500,
            "body": '{"error": "MongoServerError: unknown operator: $invalid_nosql_op"}',
        },
        "true_response": {
            "status_code": 200,
            "body": '{"user": "admin", "role": "root"}',
        },
        "false_response": {
            "status_code": 404,
            "body": '{"error": "User not found"}',
        },
    }
    fixture_file.write_text(json.dumps(fixture_data), encoding="utf-8")

    result = runner.invoke(app, ["nosqli", "--fixture", str(fixture_file)])
    assert result.exit_code == 0
    assert "NoSQL INJECTION DETECTION REPORT" in result.stdout
    assert "Target URL:             http://lab.local/api/users?user=admin" in result.stdout
    assert "POTENTIAL_INDICATOR" in result.stdout
    assert "Analyzing offline NoSQL response fixtures" in result.stderr


def test_cli_nosqli_fixture_json_format(tmp_path: Path) -> None:
    """Verify offline fixture assessment in JSON output format."""
    fixture_file = tmp_path / "nosqli_sample.json"
    fixture_data = {
        "target_url": "http://lab.local/items?cat=electronics",
        "parameter": "cat",
        "baseline": {"status_code": 200, "body": '{"items": ["TV"]}'},
        "test": {"status_code": 200, "body": '{"items": ["TV"]}'},
    }
    fixture_file.write_text(json.dumps(fixture_data), encoding="utf-8")

    result = runner.invoke(app, ["nosqli", "--fixture", str(fixture_file), "--format", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["target_url"] == "http://lab.local/items?cat=electronics"
    assert parsed["execution_status"] == "completed"
    assert parsed["summary"]["clean_parameters"] == 1


def test_cli_nosqli_output_file_and_overwrite(tmp_path: Path) -> None:
    """Verify file output export and --overwrite safeguards."""
    fixture_file = tmp_path / "fixture.json"
    fixture_file.write_text(
        json.dumps(
            {
                "target_url": "http://lab.local/data?id=1",
                "parameter": "id",
                "baseline": {"status_code": 200, "body": "Normal"},
                "test": {"status_code": 200, "body": "Normal"},
            }
        ),
        encoding="utf-8",
    )
    output_file = tmp_path / "nosqli_report.json"

    # First write should succeed
    res1 = runner.invoke(
        app,
        [
            "nosqli",
            "--fixture",
            str(fixture_file),
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )
    assert res1.exit_code == 0
    assert output_file.exists()

    # Second write without --overwrite should fail
    res2 = runner.invoke(
        app,
        [
            "nosqli",
            "--fixture",
            str(fixture_file),
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )
    assert res2.exit_code == 1
    assert "already exists" in res2.stderr

    # Third write with --overwrite should succeed
    res3 = runner.invoke(
        app,
        [
            "nosqli",
            "--fixture",
            str(fixture_file),
            "--format",
            "json",
            "--output",
            str(output_file),
            "--overwrite",
        ],
    )
    assert res3.exit_code == 0
    assert "successfully exported" in res3.stderr
