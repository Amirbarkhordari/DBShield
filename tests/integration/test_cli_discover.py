"""Integration tests for the `dbshield discover` CLI command."""

import json
from pathlib import Path

import pytest
import respx
from typer.testing import CliRunner

from dbshield.cli import app

runner = CliRunner()


def test_cli_discover_help() -> None:
    result = runner.invoke(app, ["discover", "--help"])
    assert result.exit_code == 0
    assert "--url" in result.stdout
    assert "--format" in result.stdout
    assert "--output" in result.stdout
    assert "--overwrite" in result.stdout
    assert "--timeout" in result.stdout


def test_cli_discover_missing_url() -> None:
    result = runner.invoke(app, ["discover"])
    assert result.exit_code == 2


def test_cli_discover_invalid_url() -> None:
    result = runner.invoke(app, ["discover", "--url", "not-a-valid-url"])
    assert result.exit_code == 2
    assert "Error:" in result.stderr
    assert "missing a protocol scheme" in result.stderr


def test_cli_discover_unsupported_format() -> None:
    result = runner.invoke(
        app, ["discover", "--url", "https://example.com/login", "--format", "xml"]
    )
    assert result.exit_code == 2
    assert "Unsupported output format" in result.stderr


def test_cli_discover_out_of_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBSHIELD_ALLOWED_HOSTS", "internal.corp.com")
    result = runner.invoke(app, ["discover", "--url", "https://unauthorized.target.com/login"])
    assert result.exit_code == 2
    assert "outside authorized scope" in result.stderr


@respx.mock
def test_cli_discover_text_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBSHIELD_ALLOWED_HOSTS", "app.example.com")
    html_page = """
    <html>
    <head><title>Test App Login</title></head>
    <body>
        <form id="login-form" action="/auth/login" method="post">
            <input type="hidden" name="csrf" value="tok" />
            <input type="text" name="user_name" placeholder="User" required />
            <input type="password" name="password" placeholder="Pass" required />
            <input type="submit" value="Sign In" />
        </form>
    </body>
    </html>
    """
    respx.get("https://app.example.com/login").respond(
        status_code=200,
        headers={"Content-Type": "text/html; charset=utf-8"},
        text=html_page,
    )

    result = runner.invoke(app, ["discover", "--url", "https://app.example.com/login"])

    assert result.exit_code == 0
    assert "LOGIN PAGE DISCOVERY REPORT" in result.stdout
    assert "Target URL:             https://app.example.com/login" in result.stdout
    assert "Page Title:             Test App Login" in result.stdout
    assert "LOGIN_FORM_DETECTED" in result.stdout
    assert "Candidate Authentication Forms:    1" in result.stdout
    assert "Password Fields:                   1" in result.stdout
    assert "Username / Email Fields:           1" in result.stdout
    assert "Discovered HTML Forms:" in result.stdout
    assert "[LOGIN CANDIDATE]" in result.stdout
    assert "SECURITY NOTE:" in result.stdout


@respx.mock
def test_cli_discover_json_format(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DBSHIELD_ALLOWED_HOSTS", "app.example.com")
    html_page = """
    <html>
    <body>
        <form action="/login" method="post">
            <input type="password" name="pwd" />
        </form>
    </body>
    </html>
    """
    respx.get("https://app.example.com/login").respond(
        status_code=200,
        headers={"Content-Type": "text/html"},
        text=html_page,
    )

    result = runner.invoke(
        app,
        ["discover", "--url", "https://app.example.com/login", "--format", "json"],
    )

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["target_url"] == "https://app.example.com/login"
    assert parsed["status"] == "completed"
    assert parsed["summary"]["total_forms"] == 1
    assert parsed["summary"]["password_fields"] == 1


@respx.mock
def test_cli_discover_output_file_and_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DBSHIELD_ALLOWED_HOSTS", "app.example.com")
    html_page = "<form action='/auth' method='post'><input type='password' name='p'></form>"
    respx.get("https://app.example.com/login").respond(
        status_code=200,
        headers={"Content-Type": "text/html"},
        text=html_page,
    )

    output_file = tmp_path / "subdir" / "results.json"

    # First write: creates file
    result1 = runner.invoke(
        app,
        [
            "discover",
            "--url",
            "https://app.example.com/login",
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )
    assert result1.exit_code == 0
    assert output_file.exists()
    saved_data = json.loads(output_file.read_text(encoding="utf-8"))
    assert saved_data["target_url"] == "https://app.example.com/login"

    # Second write without --overwrite: should fail with exit code 1
    result2 = runner.invoke(
        app,
        [
            "discover",
            "--url",
            "https://app.example.com/login",
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )
    assert result2.exit_code == 1
    assert "already exists" in result2.stderr

    # Third write with --overwrite: should succeed
    result3 = runner.invoke(
        app,
        [
            "discover",
            "--url",
            "https://app.example.com/login",
            "--format",
            "json",
            "--output",
            str(output_file),
            "--overwrite",
        ],
    )
    assert result3.exit_code == 0
