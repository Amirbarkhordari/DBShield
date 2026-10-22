"""Integration tests for the `dbshield request` CLI command."""

import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from dbshield.cli import app

runner = CliRunner()


def test_cli_request_help() -> None:
    """Verify request command help displays all options."""
    result = runner.invoke(app, ["request", "--help"])
    assert result.exit_code == 0
    assert "--url" in result.stdout
    assert "--method" in result.stdout
    assert "--header" in result.stdout
    assert "--data" in result.stdout
    assert "--json" in result.stdout
    assert "--auth-type" in result.stdout
    assert "--token" in result.stdout
    assert "--username" in result.stdout
    assert "--password" in result.stdout
    assert "--cookie" in result.stdout
    assert "--format" in result.stdout
    assert "--output" in result.stdout
    assert "--overwrite" in result.stdout


def test_cli_request_missing_url() -> None:
    """Verify missing --url produces exit code 2."""
    result = runner.invoke(app, ["request"])
    assert result.exit_code == 2


def test_cli_request_invalid_url() -> None:
    """Verify invalid URL syntax produces exit code 2."""
    result = runner.invoke(app, ["request", "--url", "invalid-syntax-no-scheme"])
    assert result.exit_code == 2
    assert "Error:" in result.stderr


def test_cli_request_out_of_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify out-of-scope target produces exit code 2."""
    monkeypatch.setenv("DBSHIELD_ALLOWED_HOSTS", "allowed.example.com")
    result = runner.invoke(app, ["request", "--url", "https://unauthorized.com/api"])
    assert result.exit_code == 2
    assert "outside authorized scope" in result.stderr


def test_cli_request_invalid_method() -> None:
    """Verify invalid HTTP method produces exit code 2."""
    result = runner.invoke(
        app,
        ["request", "--url", "https://example.com/api", "--method", "INVALID_METHOD"],
    )
    assert result.exit_code == 2
    assert "Unsupported HTTP method" in result.stderr


def test_cli_request_invalid_header_format() -> None:
    """Verify header without colon produces exit code 2."""
    result = runner.invoke(
        app,
        ["request", "--url", "https://example.com/api", "--header", "InvalidHeaderFormat"],
    )
    assert result.exit_code == 2
    assert "Invalid header format" in result.stderr


def test_cli_request_invalid_cookie_format() -> None:
    """Verify cookie without equals produces exit code 2."""
    result = runner.invoke(
        app,
        ["request", "--url", "https://example.com/api", "--cookie", "InvalidCookieFormat"],
    )
    assert result.exit_code == 2
    assert "Invalid cookie format" in result.stderr


def test_cli_request_invalid_json() -> None:
    """Verify invalid JSON string in --json produces exit code 2."""
    result = runner.invoke(
        app,
        ["request", "--url", "https://example.com/api", "--json", "not valid json {["],
    )
    assert result.exit_code == 2
    assert "Invalid JSON payload" in result.stderr


def test_cli_request_missing_auth_parameters() -> None:
    """Verify missing bearer token produces exit code 2."""
    result = runner.invoke(
        app,
        ["request", "--url", "https://example.com/api", "--auth-type", "bearer"],
    )
    assert result.exit_code == 2
    assert "requires a non-empty 'token'" in result.stderr


@respx.mock
def test_cli_request_text_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify successful request text report formatting."""
    monkeypatch.setenv("DBSHIELD_ALLOWED_HOSTS", "example.com")
    respx.get("https://example.com/api/status").respond(
        200,
        headers={"Content-Type": "application/json"},
        text='{"status": "ready"}',
    )

    result = runner.invoke(app, ["request", "--url", "https://example.com/api/status"])
    assert result.exit_code == 0
    assert "DBShield HTTP Request Report" in result.stdout
    assert "Target URL       : https://example.com/api/status" in result.stdout
    assert "HTTP Status      : 200 (OK)" in result.stdout
    assert "status" in result.stdout


@respx.mock
def test_cli_request_json_output_and_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    """CRITICAL SECURITY TEST: Verify JSON output structure and ensure credentials are redacted."""
    monkeypatch.setenv("DBSHIELD_ALLOWED_HOSTS", "example.com")
    secret_token = "my-secret-jwt-token-xyz"

    def match_auth(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == f"Bearer {secret_token}"
        return httpx.Response(200, json={"auth": "confirmed"})

    respx.get("https://example.com/api/me").mock(side_effect=match_auth)

    result = runner.invoke(
        app,
        [
            "request",
            "--url",
            "https://example.com/api/me",
            "--auth-type",
            "bearer",
            "--token",
            secret_token,
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    # Must NOT contain raw secret token in stdout
    assert secret_token not in result.stdout

    parsed = json.loads(result.stdout)
    assert parsed["status_code"] == 200
    assert parsed["auth"]["auth_type"] == "bearer"
    assert parsed["auth"]["config"]["token"] == "[REDACTED]"


@respx.mock
def test_cli_request_file_output_and_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify output file creation and --overwrite guard."""
    monkeypatch.setenv("DBSHIELD_ALLOWED_HOSTS", "example.com")
    respx.get("https://example.com/health").respond(200, text="healthy")

    out_file = tmp_path / "req_output.json"

    # First write: creates file
    res1 = runner.invoke(
        app,
        [
            "request",
            "--url",
            "https://example.com/health",
            "--format",
            "json",
            "--output",
            str(out_file),
        ],
    )
    assert res1.exit_code == 0
    assert out_file.exists()

    # Second write without --overwrite: must fail
    res2 = runner.invoke(
        app,
        [
            "request",
            "--url",
            "https://example.com/health",
            "--format",
            "json",
            "--output",
            str(out_file),
        ],
    )
    assert res2.exit_code == 1
    assert "already exists" in res2.stderr

    # Third write with --overwrite: must succeed
    res3 = runner.invoke(
        app,
        [
            "request",
            "--url",
            "https://example.com/health",
            "--format",
            "json",
            "--output",
            str(out_file),
            "--overwrite",
        ],
    )
    assert res3.exit_code == 0
