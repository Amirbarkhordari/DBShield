"""Command-line interface for DBShield using Typer.

Follows linux-cli-design-system standards:
- Clear status prefixes ([+], [-], [!], [*])
- Proper exit codes (0: success, 1: operational error, 2: usage error)
- Strict stream separation (stderr for diagnostics, stdout for data)
- Respects NO_COLOR
"""

import os
import platform
import sys

import typer

from dbshield import __author__, __version__
from dbshield.config import get_settings
from dbshield.exceptions import DBShieldError, ScopeViolationError, URLValidationError
from dbshield.logging_config import configure_logging
from dbshield.models.target import Target
from dbshield.scope.manager import ScopeManager

app = typer.Typer(
    name="dbshield",
    help="DBShield: Modular CLI framework for testing database-related security vulnerabilities in web applications.",
    add_completion=False,
    no_args_is_help=True,
)


def _should_use_color() -> bool:
    """Check if terminal supports ANSI color output according to NO_COLOR and TTY rules."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stderr.isatty()


def _format_prefix(prefix: str, color_code: str) -> str:
    """Format status prefix with optional ANSI styling."""
    if not _should_use_color():
        return prefix
    return f"\033[{color_code}m{prefix}\033[0m"


def print_success(msg: str) -> None:
    """Print success message with [+] prefix."""
    prefix = _format_prefix("[+]", "1;32")
    sys.stderr.write(f"{prefix} {msg}\n")
    sys.stderr.flush()


def print_error(msg: str, cause: str | None = None, remedy: str | None = None) -> None:
    """Print structured 3-part error message with [-] prefix."""
    prefix = _format_prefix("[-]", "1;31")
    sys.stderr.write(f"{prefix} Error: {msg}\n")
    if cause:
        sys.stderr.write(f"    Cause: {cause}\n")
    if remedy:
        sys.stderr.write(f"    Remedy: {remedy}\n")
    sys.stderr.flush()


def print_warning(msg: str) -> None:
    """Print warning message with [!] prefix."""
    prefix = _format_prefix("[!]", "1;33")
    sys.stderr.write(f"{prefix} Warning: {msg}\n")
    sys.stderr.flush()


def print_info(msg: str) -> None:
    """Print informational notice with [*] prefix."""
    prefix = _format_prefix("[*]", "1;36")
    sys.stderr.write(f"{prefix} {msg}\n")
    sys.stderr.flush()


def version_callback(value: bool) -> None:
    """Callback for --version flag."""
    if value:
        sys.stdout.write(f"DBShield v{__version__}\n")
        raise typer.Exit(code=0)


@app.callback()
def main(
    _version: bool | None = typer.Option(
        None,
        "--version",
        "-V",
        help="Display DBShield version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose diagnostic logs.",
    ),
) -> None:
    """DBShield - Database Vulnerability Assessment CLI Framework."""
    log_level = "DEBUG" if verbose else "INFO"
    configure_logging(level=log_level)


@app.command(name="doctor")
def doctor_cmd() -> None:
    """Check Python runtime, configuration accessibility, and basic environment readiness."""
    print_info("Running DBShield environment and system readiness diagnostics...")

    issues_found = False

    # 1. Python version check
    py_version = sys.version_info
    py_ver_str = f"{py_version.major}.{py_version.minor}.{py_version.micro}"
    if py_version >= (3, 12):
        print_success(f"Python Runtime: {py_ver_str} (>= 3.12 required - OK)")
    else:
        print_error(
            f"Python Runtime: {py_ver_str} is unsupported.",
            cause="DBShield requires Python 3.12 or newer.",
            remedy="Upgrade your Python interpreter to version 3.12 or later.",
        )
        issues_found = True

    # 2. Configuration accessibility
    try:
        settings = get_settings()
        print_success(
            f"Configuration: Valid (Log level: {settings.log_level}, Timeout: {settings.http_timeout}s)"
        )
    except Exception as exc:
        print_error(
            "Configuration: Failed to load settings.",
            cause=str(exc),
            remedy="Check your .env file or environment variables.",
        )
        issues_found = True
        settings = None

    # 3. Data directory access check
    if settings:
        data_dir = settings.data_dir
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            test_file = data_dir / ".dbshield_write_test"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink()
            print_success(f"Workspace Directory: {data_dir} (Writable - OK)")
        except Exception as exc:
            print_error(
                f"Workspace Directory: {data_dir} is not writable.",
                cause=str(exc),
                remedy=f"Verify write permissions for directory: {data_dir}",
            )
            issues_found = True

    # Summary
    if issues_found:
        print_error(
            "Diagnostics completed with errors.",
            remedy="Resolve reported system issues before proceeding.",
        )
        raise typer.Exit(code=1)

    print_success("All diagnostic checks passed. DBShield environment is ready.")
    raise typer.Exit(code=0)


@app.command(name="inspect")
def inspect_cmd(
    url: str = typer.Option(
        ...,
        "--url",
        "-u",
        help="Target web application URL to inspect (passive syntax and scope validation only).",
    ),
) -> None:
    """Validate and display basic target information. Does NOT initiate any network requests."""
    print_info("Performing passive target syntax and scope inspection...")

    # Validate URL syntax and structure
    try:
        target = Target.from_url(url)
    except URLValidationError as exc:
        print_error(
            exc.message,
            cause=exc.cause,
            remedy=exc.remedy,
        )
        raise typer.Exit(code=2) from exc

    # Load configuration and evaluate scope
    try:
        settings = get_settings()
        scope_manager = ScopeManager(
            allowed_hosts=settings.allowed_hosts,
            allow_subdomains=settings.allow_subdomains,
            strict_mode=bool(settings.allowed_hosts),
        )
        in_scope = scope_manager.is_url_in_scope(target)
    except Exception as exc:
        print_error(
            "Failed to evaluate target scope.",
            cause=str(exc),
            remedy="Check DBSHIELD_ALLOWED_HOSTS configuration in settings.",
        )
        raise typer.Exit(code=1) from exc

    # Output inspection details (human-readable key-value presentation)
    output_lines = [
        "",
        "================================================================================",
        "                             TARGET INSPECTION REPORT                           ",
        "================================================================================",
        f"  Raw Input:       {target.raw_url}",
        f"  Scheme:          {target.scheme.upper()} ({'TLS Encrypted' if target.is_tls else 'Unencrypted'})",
        f"  Host:            {target.host}",
        f"  Effective Port:  {target.port}",
        f"  Path:            {target.path}",
        f"  Query String:    {target.query or '(none)'}",
        f"  Origin Base:     {target.origin}",
        "--------------------------------------------------------------------------------",
        f"  Scope Status:    {'[+] IN-SCOPE (Authorized)' if in_scope else '[-] OUT-OF-SCOPE (Not Authorized)'}",
        "================================================================================",
        "  NOTE: Phase 1 inspection is passive. Zero network packets were transmitted.   ",
        "================================================================================",
    ]
    sys.stdout.write("\n".join(output_lines) + "\n")
    sys.stdout.flush()

    if not in_scope and settings.allowed_hosts:
        print_warning(
            f"Host '{target.host}' is not listed in allowed_hosts ({settings.allowed_hosts})."
        )

    raise typer.Exit(code=0)


@app.command(name="info")
def info_cmd() -> None:
    """Display application version, Python runtime, and safe configuration status."""
    try:
        settings = get_settings()
        safe_config = settings.get_safe_dict()
    except Exception as exc:
        print_error("Failed to load configuration.", cause=str(exc))
        raise typer.Exit(code=1) from exc

    output_lines = [
        "",
        "================================================================================",
        "                           DBSHIELD FRAMEWORK INFORMATION                       ",
        "================================================================================",
        f"  Version:         v{__version__}",
        f"  Author:          {__author__}",
        f"  Python Runtime:  {platform.python_version()} ({platform.python_implementation()})",
        f"  Platform OS:     {platform.system()} {platform.release()} ({platform.machine()})",
        "--------------------------------------------------------------------------------",
        "  Active Configuration (Safe View):",
        f"    HTTP Timeout:     {safe_config['http_timeout']}s",
        f"    Max Redirects:    {safe_config['max_redirects']}",
        f"    User-Agent:       {safe_config['user_agent']}",
        f"    Logging Level:    {safe_config['log_level']}",
        f"    Log File:         {safe_config['log_file'] or '(none)'}",
        f"    Data Directory:   {safe_config['data_dir']}",
        f"    Allowed Hosts:    {safe_config['allowed_hosts'] or '(none configured)'}",
        f"    Subdomains:       {safe_config['allow_subdomains']}",
        f"    Rate Limit:       {safe_config['rate_limit']} req/s",
        "================================================================================",
    ]
    sys.stdout.write("\n".join(output_lines) + "\n")
    sys.stdout.flush()
    raise typer.Exit(code=0)


def run() -> None:
    """Application entrypoint with global exception handling."""
    try:
        app()
    except DBShieldError as err:
        print_error(err.message, cause=err.cause, remedy=err.remedy)
        sys.exit(2 if isinstance(err, (URLValidationError, ScopeViolationError)) else 1)
    except Exception as exc:
        print_error(f"Unexpected fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    run()
