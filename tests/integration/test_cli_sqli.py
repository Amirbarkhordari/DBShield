"""Integration tests for dbshield sqli CLI command (Phase 4)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from dbshield.cli import app

runner = CliRunner()


def test_cli_sqli_help() -> None:
    result = runner.invoke(app, ["sqli", "--help"])
    assert result.exit_code == 0
    assert "Assess web application targets or offline response fixtures" in result.stdout
    assert "--url" in result.stdout
    assert "--fixture" in result.stdout
    assert "--param" in result.stdout
    assert "--format" in result.stdout


def test_cli_sqli_missing_target_and_fixture() -> None:
    result = runner.invoke(app, ["sqli"])
    assert result.exit_code == 2
    assert "Neither --url nor --fixture was provided" in result.stderr


def test_cli_sqli_invalid_url_scheme() -> None:
    result = runner.invoke(app, ["sqli", "--url", "ftp://example.com/item"])
    assert result.exit_code == 2
    assert "Unsupported scheme" in result.stderr


def test_cli_sqli_out_of_scope_target() -> None:
    result = runner.invoke(
        app,
        ["sqli", "--url", "https://unauthorized-domain.com/item?id=1"],
        env={"DBSHIELD_ALLOWED_HOSTS": "authorized.example.com"},
    )
    assert result.exit_code == 2
    assert "not within authorized scope" in result.stderr


def test_cli_sqli_fixture_missing_file() -> None:
    result = runner.invoke(app, ["sqli", "--fixture", "non_existent_file.json"])
    assert result.exit_code == 2
    assert "Fixture file 'non_existent_file.json' not found" in result.stderr


def test_cli_sqli_fixture_text_format(tmp_path: Path) -> None:
    fixture_file = tmp_path / "sqli_sample.json"
    fixture_data = {
        "target_url": "http://lab.local/books?id=1",
        "parameter": "id",
        "baseline": {
            "status_code": 200,
            "body": "<html><body><h1>Book Catalog</h1><p>Clean book 1</p></body></html>",
        },
        "test": {
            "status_code": 500,
            "body": "<html><body><h1>DB Error</h1><p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server</p></body></html>",
        },
        "true_response": {
            "status_code": 200,
            "body": "<html><body><h1>Book Catalog</h1><p>Clean book 1</p></body></html>",
        },
        "false_response": {
            "status_code": 200,
            "body": "<html><body><h1>Book Catalog</h1><p>0 books found</p></body></html>",
        },
    }
    fixture_file.write_text(json.dumps(fixture_data), encoding="utf-8")

    result = runner.invoke(app, ["sqli", "--fixture", str(fixture_file)])
    assert result.exit_code == 0
    assert "SQL INJECTION DETECTION REPORT" in result.stdout
    assert "Target URL:             http://lab.local/books?id=1" in result.stdout
    assert "POTENTIAL_INDICATOR" in result.stdout
    assert "Analyzing offline response fixtures" in result.stderr


def test_cli_sqli_fixture_json_format(tmp_path: Path) -> None:
    fixture_file = tmp_path / "sqli_sample.json"
    fixture_data = {
        "target_url": "http://lab.local/items?id=5",
        "parameter": "id",
        "baseline": {"status_code": 200, "body": "Product 5 details"},
        "test": {"status_code": 200, "body": "Product 5 details"},
    }
    fixture_file.write_text(json.dumps(fixture_data), encoding="utf-8")

    result = runner.invoke(app, ["sqli", "--fixture", str(fixture_file), "--format", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["target_url"] == "http://lab.local/items?id=5"
    assert parsed["execution_status"] == "completed"
    assert parsed["summary"]["clean_parameters"] == 1


def test_cli_sqli_output_file_and_overwrite(tmp_path: Path) -> None:
    fixture_file = tmp_path / "fixture.json"
    fixture_file.write_text(
        json.dumps(
            {
                "target_url": "http://lab.local/items?id=1",
                "parameter": "id",
                "baseline": {"status_code": 200, "body": "Normal"},
                "test": {"status_code": 200, "body": "Normal"},
            }
        ),
        encoding="utf-8",
    )
    output_file = tmp_path / "report.json"

    # First write should succeed
    res1 = runner.invoke(
        app,
        ["sqli", "--fixture", str(fixture_file), "--format", "json", "--output", str(output_file)],
    )
    assert res1.exit_code == 0
    assert output_file.exists()

    # Second write without --overwrite should fail
    res2 = runner.invoke(
        app,
        ["sqli", "--fixture", str(fixture_file), "--format", "json", "--output", str(output_file)],
    )
    assert res2.exit_code == 1
    assert "already exists" in res2.stderr

    # Third write with --overwrite should succeed
    res3 = runner.invoke(
        app,
        [
            "sqli",
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
