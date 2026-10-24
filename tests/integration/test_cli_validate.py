"""Integration tests for DBShield CLI validate command (Phase 9)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from dbshield.cli import app

runner = CliRunner()


def test_cli_validate_help() -> None:
    result = runner.invoke(app, ["validate", "--help"])
    assert result.exit_code == 0
    assert "Execute deterministic offline validation scenarios" in result.stdout
    assert "--suite" in result.stdout
    assert "--format" in result.stdout
    assert "--output" in result.stdout
    assert "--profile" in result.stdout


def test_cli_validate_all_default() -> None:
    result = runner.invoke(app, ["validate", "--quiet"])
    assert result.exit_code == 0
    assert "DBSHIELD DETECTION RELIABILITY & LAB VALIDATION REPORT" in result.stdout
    assert "CONFUSION MATRIX & ACCURACY METRICS:" in result.stdout
    assert "Total Scenarios:     20" in result.stdout
    assert "Passed:              20" in result.stdout
    assert "Failed:              0" in result.stdout


def test_cli_validate_suite_sqli() -> None:
    result = runner.invoke(app, ["validate", "--suite", "sqli", "--quiet"])
    assert result.exit_code == 0
    assert "Total Scenarios:     13" in result.stdout
    assert "Passed:              13" in result.stdout
    assert "SQLI-POS-MYSQL-ERR" in result.stdout


def test_cli_validate_suite_nosqli() -> None:
    result = runner.invoke(app, ["validate", "--suite", "nosqli", "--quiet"])
    assert result.exit_code == 0
    assert "Total Scenarios:     6" in result.stdout
    assert "Passed:              6" in result.stdout
    assert "NOSQLI-POS-MONGO-ERR" in result.stdout


def test_cli_validate_suite_safety() -> None:
    result = runner.invoke(app, ["validate", "--suite", "safety", "--quiet"])
    assert result.exit_code == 0
    assert "SAFETY-INELIGIBLE-PARAM" in result.stdout


def test_cli_validate_tag_filter() -> None:
    result = runner.invoke(app, ["validate", "--tag", "error", "--quiet"])
    assert result.exit_code == 0
    assert "Total Scenarios:" in result.stdout
    assert "SQLI-POS-MYSQL-ERR" in result.stdout


def test_cli_validate_json_format() -> None:
    result = runner.invoke(app, ["validate", "--suite", "nosqli", "--format", "json", "--quiet"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["schema_version"] == "1.0.0"
    assert "validation_report" in parsed
    assert parsed["validation_report"]["total_scenarios"] == 6
    assert parsed["validation_report"]["passed"] == 6
    assert parsed["validation_report"]["confusion_matrix"]["precision"] == 1.0


def test_cli_validate_output_file(tmp_path: Path) -> None:
    out_file = tmp_path / "val_report.json"
    result = runner.invoke(
        app,
        ["validate", "--suite", "nosqli", "--format", "json", "--output", str(out_file), "--quiet"],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["validation_report"]["passed"] == 6


def test_cli_validate_output_conflict_without_overwrite(tmp_path: Path) -> None:
    out_file = tmp_path / "conflict.txt"
    out_file.write_text("existing content", encoding="utf-8")

    result = runner.invoke(
        app,
        ["validate", "--suite", "safety", "--output", str(out_file)],
    )
    assert result.exit_code == 1
    assert "already exists" in result.stderr


def test_cli_validate_output_overwrite(tmp_path: Path) -> None:
    out_file = tmp_path / "overwrite.txt"
    out_file.write_text("old content", encoding="utf-8")

    result = runner.invoke(
        app,
        ["validate", "--suite", "safety", "--output", str(out_file), "--overwrite", "--quiet"],
    )
    assert result.exit_code == 0
    assert "old content" not in out_file.read_text(encoding="utf-8")


def test_cli_validate_invalid_suite() -> None:
    result = runner.invoke(app, ["validate", "--suite", "invalid_suite"])
    assert result.exit_code == 2
    assert "Invalid validation suite" in result.stderr


def test_cli_validate_invalid_format() -> None:
    result = runner.invoke(app, ["validate", "--format", "xml"])
    assert result.exit_code == 2
    assert "Invalid format" in result.stderr


def test_cli_validate_custom_input_file() -> None:
    result = runner.invoke(
        app,
        ["validate", "--input", "tests/fixtures/sample_lab_scenarios.json", "--quiet"],
    )
    assert result.exit_code == 0
    assert "CUSTOM-FIXTURE-SQLI" in result.stdout
    assert "CUSTOM-FIXTURE-CLEAN" in result.stdout
    assert "Total Scenarios:     2" in result.stdout
    assert "Passed:              2" in result.stdout


def test_cli_validate_custom_input_file_not_found() -> None:
    result = runner.invoke(app, ["validate", "--input", "tests/fixtures/non_existent.json"])
    assert result.exit_code == 1
    assert "does not exist" in result.stderr


def test_cli_validate_custom_input_file_invalid_json(tmp_path: Path) -> None:
    broken_file = tmp_path / "broken.json"
    broken_file.write_text("{not-valid-json", encoding="utf-8")

    result = runner.invoke(app, ["validate", "--input", str(broken_file)])
    assert result.exit_code == 2
    assert "Failed to parse scenario file" in result.stderr
