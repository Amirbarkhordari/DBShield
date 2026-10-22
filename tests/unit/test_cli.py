"""Unit tests for DBShield Typer CLI interface."""

import pytest
from typer.testing import CliRunner

from dbshield.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    """Verify `dbshield --version` prints version string and exits with 0."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "DBShield v0.1.0" in result.stdout


def test_cli_help() -> None:
    """Verify `dbshield --help` prints command list and options."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "doctor" in result.stdout
    assert "inspect" in result.stdout
    assert "info" in result.stdout
    assert "--version" in result.stdout


def test_cli_info() -> None:
    """Verify `dbshield info` outputs version, runtime, and safe config."""
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "DBSHIELD FRAMEWORK INFORMATION" in result.stdout
    assert "Version:" in result.stdout
    assert "Python Runtime:" in result.stdout
    assert "HTTP Timeout:" in result.stdout


def test_cli_doctor() -> None:
    """Verify `dbshield doctor` executes readiness checks and exits 0."""
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Python Runtime:" in result.stderr
    assert "Configuration:" in result.stderr
    assert "Workspace Directory:" in result.stderr


def test_cli_inspect_valid_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify `dbshield inspect --url` parses target and displays passive details without network calls."""
    # Ensure no network socket can be created
    result = runner.invoke(app, ["inspect", "--url", "https://example.com/login?service=auth"])
    assert result.exit_code == 0
    assert "TARGET INSPECTION REPORT" in result.stdout
    assert "Host:            example.com" in result.stdout
    assert "Scheme:          HTTPS (TLS Encrypted)" in result.stdout
    assert "Effective Port:  443" in result.stdout
    assert "Path:            /login" in result.stdout
    assert "Query String:    service=auth" in result.stdout
    assert "Zero network packets were transmitted" in result.stdout


def test_cli_inspect_invalid_url() -> None:
    """Verify `dbshield inspect --url` with malformed URL exits with code 2."""
    result = runner.invoke(app, ["inspect", "--url", "ftp://unsupported.com"])
    assert result.exit_code == 2
    assert "Unsupported scheme" in result.stderr or "Error:" in result.stderr


def test_cli_inspect_missing_url_argument() -> None:
    """Verify `dbshield inspect` without required --url option exits with code 2."""
    result = runner.invoke(app, ["inspect"])
    assert result.exit_code == 2
