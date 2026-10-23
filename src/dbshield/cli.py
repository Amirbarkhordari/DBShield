"""Command-line interface for DBShield using Typer.

Follows linux-cli-design-system standards:
- Clear status prefixes ([+], [-], [!], [*])
- Proper exit codes (0: success, 1: operational error, 2: usage error)
- Strict stream separation (stderr for diagnostics, stdout for data)
- Respects NO_COLOR
"""

import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

import typer

from dbshield import __author__, __version__
from dbshield.auth.manager import SessionManager
from dbshield.config import get_settings
from dbshield.discovery.engine import DiscoveryEngine
from dbshield.exceptions import (
    AuthenticationError,
    DBShieldError,
    HTTPClientError,
    NetworkError,
    ScopeViolationError,
    URLValidationError,
)
from dbshield.execution.adapters import (
    EngineAdapter,
    NoSQLiExecutionAdapter,
    SQLiExecutionAdapter,
)
from dbshield.execution.models import ExecutionRunResult
from dbshield.execution.orchestrator import TestExecutionOrchestrator
from dbshield.execution.policy import ExecutionPolicy
from dbshield.http.client import SafeHTTPClient
from dbshield.logging_config import configure_logging
from dbshield.models.auth import AuthConfig, AuthType
from dbshield.models.discovery import DiscoveryResult, DiscoveryStatus
from dbshield.models.http import HTTPMethod, HTTPResponse
from dbshield.models.target import Target
from dbshield.nosqli.engine import NoSQLiEngine
from dbshield.nosqli.models import NoSQLScanResult
from dbshield.payloads.catalog import PayloadCatalog
from dbshield.payloads.models import (
    PayloadCategory,
    PayloadRiskLevel,
    SecurityPayload,
)
from dbshield.reporting import (
    CSVReportExporter,
    FindingNormalizer,
    JSONReportExporter,
    MarkdownReportExporter,
    SecurityAssessmentReport,
    TerminalReportExporter,
)
from dbshield.scope.manager import ScopeManager
from dbshield.sqli.engine import SQLiEngine
from dbshield.sqli.models import ParameterLocation, SQLiScanResult
from dbshield.verification import VerificationEngine, VerificationResult

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


def _format_discovery_report(result: DiscoveryResult) -> str:
    """Format discovery results into a structured terminal presentation."""
    status_display = result.status.value.upper()
    classification_display = result.page_classification.value.upper()

    lines = [
        "",
        "=" * 80,
        "                         LOGIN PAGE DISCOVERY REPORT                            ",
        "=" * 80,
        f"  Target URL:             {result.target_url}",
        f"  Final Resolved URL:     {result.final_url or '(unresolved)'}",
        f"  HTTP Response:          {result.http_status_code or 'N/A'} ({result.content_type or 'unknown'})",
        f"  Page Title:             {result.page_title or '(no title tag)'}",
        f"  Discovery Status:       {status_display}",
        f"  Page Classification:    {classification_display}",
    ]
    if result.page_query_params:
        lines.append(f"  Page Query Params:      {', '.join(result.page_query_params)}")

    lines.extend(
        [
            "-" * 80,
            "  Discovery Inventory & Summary Metrics:",
            f"    Total Forms Discovered:            {result.summary.total_forms}",
            f"    Candidate Authentication Forms:    {result.summary.login_forms}",
            f"    Interactive Candidate Fields:      {result.summary.candidate_fields}",
            f"    Hidden / Anti-CSRF Fields:         {result.summary.hidden_fields}",
            f"    Username / Email Fields:           {result.summary.username_fields}",
            f"    Password Fields:                   {result.summary.password_fields}",
            f"    Anti-CSRF / Verification Tokens:   {result.summary.csrf_fields}",
            f"    Action URLs In-Scope:              {result.summary.action_urls_in_scope}",
            f"    Action URLs Out-of-Scope:          {result.summary.action_urls_out_of_scope}",
        ]
    )

    if result.page_evidence:
        lines.extend(
            [
                "-" * 80,
                "  Page Classification Evidence:",
            ]
        )
        for ev in result.page_evidence:
            lines.append(f"    * {ev}")

    if result.forms:
        lines.extend(
            [
                "-" * 80,
                "  Discovered HTML Forms:",
            ]
        )
        for idx, form in enumerate(result.forms, start=1):
            auth_badge = "[LOGIN CANDIDATE]" if form.is_login_candidate else "[NON-LOGIN]"
            scope_badge = "IN-SCOPE" if form.is_action_in_scope else "OUT-OF-SCOPE"
            lines.extend(
                [
                    f"    Form #{idx}: '{form.form_id}' {auth_badge}",
                    f"      Method:           {form.method}",
                    f"      Declared Action:  {form.declared_action or '(omitted - defaults to page URL)'}",
                    f"      Resolved Action:  {form.resolved_action} [{scope_badge}]",
                    f"      Encoding Type:    {form.enctype}",
                    f"      Same-Origin:      {form.is_same_origin}",
                    f"      Controls ({len(form.controls)}):",
                ]
            )
            for ctrl in form.controls:
                name_str = f"name='{ctrl.name}'" if ctrl.name else "(unnamed)"
                id_str = f" id='{ctrl.id_attr}'" if ctrl.id_attr else ""
                req_str = " [required]" if ctrl.required else ""
                lines.append(
                    f"        - <{ctrl.element_type}> {name_str}{id_str} type='{ctrl.input_type}' "
                    f"-> {ctrl.classification.value.upper()} (conf: {ctrl.confidence:.2f}){req_str}"
                )
            if form.evidence:
                lines.append("      Form Evidence:")
                for ev in form.evidence:
                    lines.append(f"        * {ev}")

    if result.orphan_inputs:
        lines.extend(
            [
                "-" * 80,
                f"  Formless / Orphan Controls Outside Forms ({len(result.orphan_inputs)}):",
            ]
        )
        for ctrl in result.orphan_inputs:
            name_str = f"name='{ctrl.name}'" if ctrl.name else "(unnamed)"
            lines.append(
                f"    - <{ctrl.element_type}> {name_str} type='{ctrl.input_type}' "
                f"-> {ctrl.classification.value.upper()} (conf: {ctrl.confidence:.2f})"
            )

    lines.extend(
        [
            "=" * 80,
            "  SECURITY NOTE: Discovered inputs are candidate points for database security  ",
            "  testing; DBShield has NOT submitted credentials nor confirmed vulnerabilities.",
            "=" * 80,
        ]
    )
    return "\n".join(lines)


@app.command(name="discover")
def discover_cmd(
    url: str = typer.Option(
        ...,
        "--url",
        "-u",
        help="Target login page URL to discover and analyze.",
    ),
    format_opt: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: 'text' (human-readable summary) or 'json' (machine-readable data).",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="File path to save the discovery results.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite existing output file if it already exists.",
    ),
    timeout: float | None = typer.Option(
        None,
        "--timeout",
        "-t",
        help="HTTP timeout budget in seconds (overrides configuration).",
    ),
) -> None:
    """Retrieve and analyze an authorized login page to identify forms and input controls."""
    fmt = format_opt.strip().lower()
    if fmt not in {"text", "json"}:
        print_error(
            f"Unsupported output format: '{format_opt}'.",
            cause=f"Format must be 'text' or 'json', received '{format_opt}'.",
            remedy="Specify --format text or --format json.",
        )
        raise typer.Exit(code=2)

    # 1. Target Validation
    try:
        target = Target.from_url(url)
    except URLValidationError as exc:
        print_error(exc.message, cause=exc.cause, remedy=exc.remedy)
        raise typer.Exit(code=2) from exc

    # 2. Scope Manager & Authorization Pre-flight Check
    try:
        settings = get_settings()
        scope_manager = ScopeManager(
            allowed_hosts=settings.allowed_hosts,
            allow_subdomains=settings.allow_subdomains,
            strict_mode=bool(settings.allowed_hosts),
        )
    except Exception as exc:
        print_error("Failed to load configuration.", cause=str(exc))
        raise typer.Exit(code=1) from exc

    if not scope_manager.is_url_in_scope(target):
        print_error(
            f"Target URL '{target.full_url}' is outside authorized scope.",
            cause=f"Host '{target.host}' is not listed in allowed_hosts ({settings.allowed_hosts}).",
            remedy="Update DBSHIELD_ALLOWED_HOSTS in your environment or .env file before scanning.",
        )
        raise typer.Exit(code=2)

    if fmt == "text":
        print_info(f"Initiating login page discovery against '{target.full_url}'...")

    # 3. Execute Discovery Engine
    effective_timeout = timeout if timeout is not None else settings.http_timeout
    engine = DiscoveryEngine(
        scope_manager=scope_manager,
        timeout=effective_timeout,
        max_redirects=settings.max_redirects,
        user_agent=settings.user_agent,
    )
    with engine:
        result = engine.discover(target)

    # 4. Handle Output Export
    rendered_text = _format_discovery_report(result)
    json_output = result.model_dump_json(indent=2)

    if output is not None:
        out_path = Path(output)
        if out_path.exists() and not overwrite:
            print_error(
                f"Output destination '{output}' already exists.",
                cause="Target file exists and --overwrite was not specified.",
                remedy="Provide a different output path or specify --overwrite to replace it.",
            )
            raise typer.Exit(code=1)

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if fmt == "json" or out_path.suffix.lower() == ".json":
                out_path.write_text(json_output, encoding="utf-8")
            else:
                out_path.write_text(rendered_text, encoding="utf-8")
            print_success(f"Discovery results successfully exported to '{out_path}'.")
        except Exception as exc:
            print_error(
                f"Failed to write discovery results to '{out_path}'.",
                cause=str(exc),
                remedy="Verify write permissions and disk space for destination path.",
            )
            raise typer.Exit(code=1) from exc

    # 5. Render Output to Terminal
    if fmt == "json":
        sys.stdout.write(json_output + "\n")
    else:
        sys.stdout.write(rendered_text + "\n")
    sys.stdout.flush()

    # 6. Report Warnings and Errors to stderr
    for warning in result.warnings:
        print_warning(warning)
    for err in result.errors:
        print_error(err)

    # 7. Exit Code Discipline
    if result.status == DiscoveryStatus.BLOCKED_BY_SCOPE:
        raise typer.Exit(code=2)
    if result.status == DiscoveryStatus.FAILED:
        raise typer.Exit(code=1)


def _format_request_report(
    response: HTTPResponse,
    session_manager: SessionManager,
    auth_config: AuthConfig,
) -> str:
    """Format structured HTTP response and session status for human-readable terminal output."""
    status_phrase = {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        303: "See Other",
        304: "Not Modified",
        307: "Temporary Redirect",
        308: "Permanent Redirect",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }.get(response.status_code, "HTTP Response")

    redirect_info = (
        f"{len(response.redirect_history)} hop(s) -> {', '.join(response.redirect_history)}"
        if response.redirect_history
        else "None (0 hops)"
    )

    lines = [
        "=" * 80,
        "DBShield HTTP Request Report",
        "=" * 80,
        f"Target URL       : {response.url}",
        f"Request Method   : {response.request_method}",
        f"HTTP Status      : {response.status_code} ({status_phrase})",
        f"Elapsed Time     : {response.elapsed_seconds:.4f}s",
        f"Auth Configured  : {auth_config.auth_type.value.upper()}",
        f"Session State    : {session_manager.state.value.upper()}",
        f"Redirect History : {redirect_info}",
        f"Content-Type     : {response.content_type or 'None'}",
        f"Content-Length   : {response.content_length} bytes",
        f"Truncated        : {response.truncated}",
        "-" * 80,
        "Response Headers",
        "-" * 80,
    ]
    for k, v in response.headers.items():
        masked_val = "[REDACTED]" if k.lower() in {"authorization", "set-cookie"} else v
        lines.append(f"{k}: {masked_val}")

    lines.extend(
        [
            "-" * 80,
            "Response Body Preview",
            "-" * 80,
        ]
    )
    snippet = response.body[:500] if len(response.body) > 500 else response.body
    if not snippet:
        lines.append("(empty body)")
    else:
        lines.append(snippet)
        if len(response.body) > 500:
            lines.append(f"... [Truncated {len(response.body) - 500} bytes in preview]")

    lines.extend(
        [
            "=" * 80,
            "NOTICE: This HTTP request was performed passively for operational",
            "  verification; DBShield has NOT executed injection payloads.",
            "=" * 80,
        ]
    )
    return "\n".join(lines)


@app.command(name="request")
def request_cmd(
    url: str = typer.Option(
        ...,
        "--url",
        "-u",
        help="Target URL endpoint to send HTTP request to.",
    ),
    method: str = typer.Option(
        "GET",
        "--method",
        "-m",
        help="HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).",
    ),
    headers: list[str] | None = typer.Option(
        None,
        "--header",
        "-H",
        help="Custom HTTP header in 'Name: Value' format (repeatable).",
    ),
    data: str | None = typer.Option(
        None,
        "--data",
        "-d",
        help="Form or raw text request body.",
    ),
    json_data: str | None = typer.Option(
        None,
        "--json",
        "-j",
        help="Raw JSON request body string.",
    ),
    auth_type: str = typer.Option(
        "none",
        "--auth-type",
        "-a",
        help="Authentication type: 'none', 'bearer', 'basic', 'header', 'cookie'.",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="Bearer authentication token (can also be read from DBSHIELD_AUTH_TOKEN).",
    ),
    username: str | None = typer.Option(
        None,
        "--username",
        "-U",
        help="Basic authentication username (can also be read from DBSHIELD_AUTH_USERNAME).",
    ),
    password: str | None = typer.Option(
        None,
        "--password",
        "-P",
        help="Basic authentication password (can also be read from DBSHIELD_AUTH_PASSWORD).",
    ),
    cookies: list[str] | None = typer.Option(
        None,
        "--cookie",
        "-C",
        help="Session cookie in 'name=value' format (repeatable).",
    ),
    timeout: float | None = typer.Option(
        None,
        "--timeout",
        "-t",
        help="HTTP timeout budget in seconds (overrides configuration).",
    ),
    follow_redirects: bool = typer.Option(
        True,
        "--follow-redirects/--no-follow-redirects",
        help="Whether to follow in-scope redirects.",
    ),
    max_redirects: int | None = typer.Option(
        None,
        "--max-redirects",
        help="Maximum redirect hops allowed (overrides configuration).",
    ),
    format_opt: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: 'text' (human-readable summary) or 'json' (machine-readable data).",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="File path to save the request output.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite existing output file if it already exists.",
    ),
) -> None:
    """Send a controlled, scope-verified HTTP request and report response/auth status."""
    fmt = format_opt.strip().lower()
    if fmt not in {"text", "json"}:
        print_error(
            f"Unsupported output format: '{format_opt}'.",
            cause=f"Format must be 'text' or 'json', received '{format_opt}'.",
            remedy="Specify --format text or --format json.",
        )
        raise typer.Exit(code=2)

    # 1. Method Validation
    m_upper = method.strip().upper()
    try:
        http_method = HTTPMethod(m_upper)
    except ValueError as exc:
        valid_methods = [m.value for m in HTTPMethod]
        print_error(
            f"Unsupported HTTP method: '{method}'.",
            cause=f"Method must be one of: {', '.join(valid_methods)}.",
            remedy="Specify a valid standard HTTP method (e.g. GET, POST).",
        )
        raise typer.Exit(code=2) from exc

    # 2. Parse Custom Headers
    parsed_headers: dict[str, str] = {}
    if headers:
        for h in headers:
            if ":" not in h:
                print_error(
                    f"Invalid header format: '{h}'.",
                    cause="Header must be formatted as 'Name: Value'.",
                    remedy="Provide headers in the format --header 'Header-Name: Value'.",
                )
                raise typer.Exit(code=2)
            k, _, v = h.partition(":")
            parsed_headers[k.strip()] = v.strip()

    # 3. Parse Cookies
    parsed_cookies: dict[str, str] = {}
    if cookies:
        for c in cookies:
            if "=" not in c:
                print_error(
                    f"Invalid cookie format: '{c}'.",
                    cause="Cookie must be formatted as 'name=value'.",
                    remedy="Provide cookies in the format --cookie 'name=value'.",
                )
                raise typer.Exit(code=2)
            k, _, v = c.partition("=")
            parsed_cookies[k.strip()] = v.strip()

    # 4. Parse JSON Body if provided
    parsed_json_body: Any = None
    if json_data is not None:
        try:
            parsed_json_body = json.loads(json_data)
        except json.JSONDecodeError as exc:
            print_error(
                "Invalid JSON payload provided in --json.",
                cause=str(exc),
                remedy="Ensure the payload passed to --json is valid JSON string.",
            )
            raise typer.Exit(code=2) from exc

    # 5. Authentication Configuration
    auth_type_norm = auth_type.strip().lower()
    try:
        auth_enum = AuthType(auth_type_norm)
    except ValueError as exc:
        valid_auth = [a.value for a in AuthType]
        print_error(
            f"Unsupported authentication type: '{auth_type}'.",
            cause=f"Must be one of: {', '.join(valid_auth)}.",
            remedy="Select a valid authentication type via --auth-type.",
        )
        raise typer.Exit(code=2) from exc

    effective_token = token or os.environ.get("DBSHIELD_AUTH_TOKEN")
    effective_username = username or os.environ.get("DBSHIELD_AUTH_USERNAME")
    effective_password = password or os.environ.get("DBSHIELD_AUTH_PASSWORD")

    try:
        auth_config = AuthConfig(
            auth_type=auth_enum,
            token=effective_token,
            username=effective_username,
            password=effective_password,
            custom_headers=parsed_headers if auth_enum == AuthType.HEADER else {},
            cookies=parsed_cookies if auth_enum == AuthType.COOKIE else {},
        )
    except ValueError as exc:
        print_error(
            f"Invalid authentication configuration for '{auth_enum.value}': {exc}",
            cause=str(exc),
            remedy="Supply all required credentials for the chosen authentication type.",
        )
        raise typer.Exit(code=2) from exc

    session_manager = SessionManager(auth_config=auth_config)

    # 6. Target Validation
    try:
        target = Target.from_url(url)
    except URLValidationError as exc:
        print_error(exc.message, cause=exc.cause, remedy=exc.remedy)
        raise typer.Exit(code=2) from exc

    # 7. Scope Boundary Pre-flight Check
    try:
        settings = get_settings()
        scope_manager = ScopeManager(
            allowed_hosts=settings.allowed_hosts,
            allow_subdomains=settings.allow_subdomains,
            strict_mode=bool(settings.allowed_hosts),
        )
    except Exception as exc:
        print_error(
            "Failed to load settings.",
            cause=str(exc),
            remedy="Check your environment configuration.",
        )
        raise typer.Exit(code=1) from exc

    if not scope_manager.is_url_in_scope(target):
        print_error(
            f"Target URL '{target.full_url}' is outside authorized scope.",
            cause=f"Host '{target.host}' is not listed in allowed_hosts ({settings.allowed_hosts}).",
            remedy="Update DBSHIELD_ALLOWED_HOSTS in your environment or .env file before scanning.",
        )
        raise typer.Exit(code=2)

    if fmt == "text":
        print_info(f"Dispatching HTTP {http_method.value} request to '{target.full_url}'...")

    # 8. Safe HTTP Request Execution
    effective_timeout = timeout if timeout is not None else settings.http_timeout
    effective_max_redirects = max_redirects if max_redirects is not None else settings.max_redirects

    client = SafeHTTPClient(
        scope_manager=scope_manager,
        timeout=effective_timeout,
        max_redirects=effective_max_redirects,
        user_agent=settings.user_agent,
        session_manager=session_manager,
    )

    try:
        with client:
            response = client.request(
                method=http_method,
                url=target,
                headers=parsed_headers if auth_enum != AuthType.HEADER else None,
                cookies=parsed_cookies if auth_enum != AuthType.COOKIE else None,
                data=data,
                json=parsed_json_body,
                follow_redirects=follow_redirects,
            )
    except ScopeViolationError as exc:
        print_error(exc.message, cause=exc.cause, remedy=exc.remedy)
        raise typer.Exit(code=2) from exc
    except AuthenticationError as exc:
        print_error(exc.message, cause=exc.cause, remedy=exc.remedy)
        raise typer.Exit(code=2) from exc
    except (NetworkError, HTTPClientError) as exc:
        print_error(exc.message, cause=exc.cause, remedy=exc.remedy)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        print_error(f"Unexpected request failure: {exc}")
        raise typer.Exit(code=1) from exc

    # 9. Format Output
    rendered_text = _format_request_report(response, session_manager, auth_config)
    safe_result_dict = {
        "url": response.url,
        "request_method": response.request_method,
        "status_code": response.status_code,
        "is_success": response.is_success,
        "elapsed_seconds": response.elapsed_seconds,
        "headers": dict(response.headers),
        "content_type": response.content_type,
        "content_length": response.content_length,
        "redirect_history": response.redirect_history,
        "truncated": response.truncated,
        "auth": {
            "auth_type": auth_config.auth_type.value,
            "state": session_manager.state.value,
            "config": auth_config.to_safe_dict(),
        },
        "body": response.body,
    }
    json_output = json.dumps(safe_result_dict, indent=2)

    # 10. File Output if requested
    if output is not None:
        out_path = Path(output)
        if out_path.exists() and not overwrite:
            print_error(
                f"Output destination '{output}' already exists.",
                cause="Target file exists and --overwrite was not specified.",
                remedy="Provide a different output path or specify --overwrite to replace it.",
            )
            raise typer.Exit(code=1)

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if fmt == "json" or out_path.suffix.lower() == ".json":
                out_path.write_text(json_output, encoding="utf-8")
            else:
                out_path.write_text(rendered_text, encoding="utf-8")
            print_success(f"Request results successfully exported to '{out_path}'.")
        except Exception as exc:
            print_error(
                f"Failed to write request results to '{out_path}'.",
                cause=str(exc),
                remedy="Verify write permissions and disk space for destination path.",
            )
            raise typer.Exit(code=1) from exc

    # 11. Render Output to Terminal
    if fmt == "json":
        sys.stdout.write(json_output + "\n")
    else:
        sys.stdout.write(rendered_text + "\n")
    sys.stdout.flush()

    raise typer.Exit(code=0)


def _format_sqli_report(result: SQLiScanResult) -> str:
    """Format structured SQL injection assessment results for terminal output."""
    lines = [
        "=" * 80,
        "                      SQL INJECTION DETECTION REPORT                            ",
        "=" * 80,
        f"  Target URL:             {result.target_url}",
        f"  Scan ID:                {result.scan_id}",
        f"  Execution Status:       {result.execution_status.upper()}",
        f"  Total Duration:         {result.summary.duration_seconds:.3f}s",
        f"  Total Requests:         {result.summary.total_requests}",
        "-" * 80,
        "  Parameter & Finding Metrics:",
        f"    Total Parameters Evaluated:        {result.summary.total_parameters}",
        f"    Parameters Actively Tested:        {result.summary.tested_parameters}",
        f"    Parameters Skipped (Safety/Rules): {result.summary.skipped_parameters}",
        f"    Potential Indicators Flagged:      {result.summary.potential_indicators}",
        f"    Clean Parameters (No Indicator):   {result.summary.clean_parameters}",
        f"    Inconclusive Tests:                {result.summary.inconclusive_parameters}",
        f"    Blocked by Scope:                  {result.summary.blocked_parameters}",
        f"    Transport / Operational Errors:    {result.summary.error_parameters}",
    ]

    if result.findings:
        lines.extend(["-" * 80, "  Detailed Finding Records:"])
        for idx, finding in enumerate(result.findings, start=1):
            badge = f"[{finding.status.value.upper()}]"
            conf = (
                f" (Confidence: {finding.confidence.value.upper()})" if finding.confidence else ""
            )
            lines.append(
                f"    {idx}. Parameter '{finding.parameter.name}' ({finding.parameter.location.value}) {badge}{conf}"
            )
            lines.append(f"       Technique:    {finding.technique.value}")
            if finding.evidence_summary:
                lines.append(f"       Summary:      {finding.evidence_summary}")
            if finding.evidence_records:
                for ev in finding.evidence_records:
                    lines.append(f"       * Match [{ev.rule_id}]: {ev.description}")
                    if ev.snippet:
                        lines.append(f'         Snippet: "{ev.snippet}"')
            if finding.error_or_skip_reason:
                lines.append(f"       Reason:       {finding.error_or_skip_reason}")

    if result.limitations:
        lines.extend(["-" * 80, "  Framework Analytical Limitations:"])
        for lim in result.limitations:
            lines.append(f"    * {lim}")

    lines.append("=" * 80)
    return "\n".join(lines)


@app.command(name="sqli")
def sqli_cmd(
    url: str | None = typer.Option(
        None,
        "--url",
        "-u",
        help="Target web application URL to assess.",
    ),
    param: str | None = typer.Option(
        None,
        "--param",
        "-p",
        help="Specific candidate parameter to test (defaults to all eligible parameters).",
    ),
    method: str = typer.Option(
        "GET",
        "--method",
        "-m",
        help="HTTP request method (GET, POST, PUT, PATCH, DELETE).",
    ),
    data: str | None = typer.Option(
        None,
        "--data",
        "-d",
        help="Raw or URL-encoded form data body.",
    ),
    json_data: str | None = typer.Option(
        None,
        "--json",
        "-j",
        help="JSON formatted request body (evaluates top-level keys; nested structures deferred to Phase 6).",
    ),
    fixture: str | None = typer.Option(
        None,
        "--fixture",
        help="Path to JSON file containing captured baseline and test responses for offline testing.",
    ),
    auth_type: str = typer.Option(
        "none",
        "--auth-type",
        help="Authentication method: none, bearer, basic, header, cookie.",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="Bearer token (or DBSHIELD_AUTH_TOKEN env var).",
    ),
    username: str | None = typer.Option(
        None,
        "--username",
        help="HTTP Basic username (or DBSHIELD_AUTH_USERNAME env var).",
    ),
    password: str | None = typer.Option(
        None,
        "--password",
        help="HTTP Basic password (or DBSHIELD_AUTH_PASSWORD env var).",
    ),
    cookie: str | None = typer.Option(
        None,
        "--cookie",
        help="Session cookie string (e.g., 'session=xyz').",
    ),
    timeout: float | None = typer.Option(
        None,
        "--timeout",
        help="Per-request timeout budget in seconds.",
    ),
    max_budget: int = typer.Option(
        50,
        "--max-budget",
        help="Maximum total request budget across entire scan.",
    ),
    max_param_budget: int = typer.Option(
        8,
        "--max-param-budget",
        help="Maximum request budget per candidate parameter.",
    ),
    disable_differential: bool = typer.Option(
        False,
        "--disable-differential",
        help="Disable boolean differential testing (run error-based only).",
    ),
    fmt: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text (human-readable table) or json.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional file path to export assessment results.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite destination output file if it already exists.",
    ),
) -> None:
    """Assess web application targets or offline response fixtures for SQL injection indicators."""
    fmt_clean = fmt.lower().strip()
    if fmt_clean not in {"text", "json"}:
        print_error(
            f"Unsupported format '{fmt}'.",
            cause="DBShield supports only 'text' or 'json' output formats.",
            remedy="Specify --format text or --format json.",
        )
        raise typer.Exit(code=2)

    # 1. Handle Offline Fixture Assessment Mode
    if fixture is not None:
        fixture_path = Path(fixture)
        if not fixture_path.is_file():
            print_error(
                f"Fixture file '{fixture}' not found.",
                cause="The specified fixture path does not point to an existing readable file.",
                remedy="Provide a valid path to a JSON response fixture file.",
            )
            raise typer.Exit(code=2)

        try:
            fixture_data = json.loads(fixture_path.read_text(encoding="utf-8"))
            target_url = fixture_data.get("target_url", "http://laboratory.local/fixture")
            p_name = fixture_data.get("parameter", param or "id")

            base_info = fixture_data.get("baseline", {})
            test_info = fixture_data.get("test", {})

            base_resp = HTTPResponse(
                url=target_url,
                status_code=base_info.get("status_code", 200),
                body=base_info.get("body", ""),
            )
            test_resp = HTTPResponse(
                url=target_url,
                status_code=test_info.get("status_code", 200),
                body=test_info.get("body", ""),
            )

            true_resp = None
            false_resp = None
            if "true_response" in fixture_data and "false_response" in fixture_data:
                true_info = fixture_data["true_response"]
                false_info = fixture_data["false_response"]
                true_resp = HTTPResponse(
                    url=target_url,
                    status_code=true_info.get("status_code", 200),
                    body=true_info.get("body", ""),
                )
                false_resp = HTTPResponse(
                    url=target_url,
                    status_code=false_info.get("status_code", 200),
                    body=false_info.get("body", ""),
                )

            print_info(f"Analyzing offline response fixtures from '{fixture_path}'...")
            result = SQLiEngine.analyze_fixture_records(
                target_url=target_url,
                param_name=p_name,
                baseline_response=base_resp,
                test_response=test_resp,
                true_response=true_resp,
                false_response=false_resp,
            )
        except Exception as exc:
            print_error(
                "Failed to process fixture file.",
                cause=str(exc),
                remedy="Verify that the fixture file contains valid JSON matching DBShield fixture structure.",
            )
            raise typer.Exit(code=1) from exc

    # 2. Handle Online Target Assessment Mode
    else:
        if not url:
            print_error(
                "Missing required target specification.",
                cause="Neither --url nor --fixture was provided.",
                remedy="Specify target URL via --url <URL> or offline fixture via --fixture <PATH>.",
            )
            raise typer.Exit(code=2)

        # Validate URL
        try:
            target = Target.from_url(url)
        except URLValidationError as exc:
            print_error(exc.message, cause=exc.cause, remedy=exc.remedy)
            raise typer.Exit(code=2) from exc

        # Initialize ScopeManager and assert scope
        settings = get_settings()
        scope_manager = ScopeManager(
            allowed_hosts=settings.allowed_hosts,
            allow_subdomains=settings.allow_subdomains,
            strict_mode=bool(settings.allowed_hosts),
        )
        try:
            scope_manager.assert_in_scope(target)
        except ScopeViolationError as exc:
            print_error(
                f"Target host '{target.host}' is not within authorized scope.",
                cause=exc.cause or "Host does not match any entry in allowed_hosts.",
                remedy=exc.remedy
                or "Configure DBSHIELD_ALLOWED_HOSTS to authorize target before scanning.",
            )
            raise typer.Exit(code=2) from exc

        # Authentication Configuration
        effective_token = token or os.environ.get("DBSHIELD_AUTH_TOKEN")
        effective_username = username or os.environ.get("DBSHIELD_AUTH_USERNAME")
        effective_password = password or os.environ.get("DBSHIELD_AUTH_PASSWORD")

        try:
            auth_mode = AuthType(auth_type.lower())
        except ValueError:
            print_error(
                f"Invalid auth-type '{auth_type}'.",
                cause=f"'{auth_type}' is not a recognized authentication method.",
                remedy="Supported methods: none, bearer, basic, header, cookie.",
            )
            raise typer.Exit(code=2) from None

        try:
            auth_config = AuthConfig(
                auth_type=auth_mode,
                token=effective_token,
                username=effective_username,
                password=effective_password,
                cookies={"session": cookie} if cookie else {},
            )
        except ValueError as exc:
            print_error(
                "Invalid authentication configuration parameters.",
                cause=str(exc),
                remedy="Check required credentials for the chosen auth mode.",
            )
            raise typer.Exit(code=2) from exc

        session_mgr = SessionManager(auth_config=auth_config)
        session_mgr.bind_target(target)

        effective_timeout = timeout if timeout is not None else settings.http_timeout
        http_client = SafeHTTPClient(
            scope_manager=scope_manager,
            timeout=effective_timeout,
            session_manager=session_mgr,
        )

        engine = SQLiEngine(
            scope_manager=scope_manager,
            http_client=http_client,
            session_manager=session_mgr,
            max_requests_per_parameter=max_param_budget,
            total_request_budget=max_budget,
            enable_differential=not disable_differential,
        )

        print_info(f"Initiating controlled SQL injection assessment on: {target.full_url}")
        try:
            result = engine.scan(
                target_url=target,
                method=method,
                selected_param=param,
                data=data,
                json_data=json_data,
            )
        except Exception as exc:
            print_error(
                "Operational failure during SQL injection scan.",
                cause=str(exc),
                remedy="Review network connectivity, target availability, and configuration.",
            )
            raise typer.Exit(code=1) from exc

    # 3. Format Output
    rendered_text = _format_sqli_report(result)
    json_output = result.model_dump_json(indent=2)

    # 4. Handle Output Export
    if output is not None:
        out_path = Path(output)
        if out_path.exists() and not overwrite:
            print_error(
                f"Output destination '{output}' already exists.",
                cause="Target file exists and --overwrite was not specified.",
                remedy="Provide a different output path or specify --overwrite to replace it.",
            )
            raise typer.Exit(code=1)

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if fmt_clean == "json" or out_path.suffix.lower() == ".json":
                out_path.write_text(json_output, encoding="utf-8")
            else:
                out_path.write_text(rendered_text, encoding="utf-8")
            print_success(
                f"SQL injection assessment results successfully exported to '{out_path}'."
            )
        except Exception as exc:
            print_error(
                f"Failed to write assessment results to '{out_path}'.",
                cause=str(exc),
                remedy="Verify write permissions and disk space for destination path.",
            )
            raise typer.Exit(code=1) from exc

    # 5. Render Output to Terminal
    if fmt_clean == "json":
        sys.stdout.write(json_output + "\n")
    else:
        sys.stdout.write(rendered_text + "\n")
    sys.stdout.flush()

    raise typer.Exit(code=0)


def _format_nosqli_report(result: NoSQLScanResult) -> str:
    """Format structured NoSQL injection assessment results for terminal output."""
    lines = [
        "=" * 80,
        "                    NoSQL INJECTION DETECTION REPORT                            ",
        "=" * 80,
        f"  Target URL:             {result.target_url}",
        f"  Scan ID:                {result.scan_id}",
        f"  Execution Status:       {result.execution_status.upper()}",
        f"  Total Duration:         {result.summary.duration_seconds:.3f}s",
        f"  Total Requests:         {result.summary.total_requests}",
        "-" * 80,
        "  Parameter & Finding Metrics:",
        f"    Total Parameters Evaluated:        {result.summary.total_parameters}",
        f"    Parameters Actively Tested:        {result.summary.tested_parameters}",
        f"    Parameters Skipped (Safety/Rules): {result.summary.skipped_parameters}",
        f"    Potential Indicators Flagged:      {result.summary.potential_indicators}",
        f"    Clean Parameters (No Indicator):   {result.summary.clean_parameters}",
        f"    Inconclusive Tests:                {result.summary.inconclusive_parameters}",
        f"    Blocked by Scope:                  {result.summary.blocked_parameters}",
        f"    Transport / Operational Errors:    {result.summary.error_parameters}",
    ]

    if result.findings:
        lines.extend(["-" * 80, "  Detailed Finding Records:"])
        for idx, finding in enumerate(result.findings, start=1):
            badge = f"[{finding.status.value.upper()}]"
            conf = (
                f" (Confidence: {finding.confidence.value.upper()})" if finding.confidence else ""
            )
            param_display = finding.parameter.name
            if finding.parameter.key_path and len(finding.parameter.key_path) > 1:
                param_display = (
                    f"{finding.parameter.name} (path: {' -> '.join(finding.parameter.key_path)})"
                )
            lines.append(
                f"    {idx}. Parameter '{param_display}' ({finding.parameter.location.value}) {badge}{conf}"
            )
            lines.append(f"       Technique:    {finding.technique.value}")
            if finding.evidence_summary:
                lines.append(f"       Summary:      {finding.evidence_summary}")
            if finding.evidence_records:
                for ev in finding.evidence_records:
                    lines.append(f"       * Match [{ev.rule_id}]: {ev.description}")
                    if ev.snippet:
                        lines.append(f'         Snippet: "{ev.snippet}"')
            if finding.error_or_skip_reason:
                lines.append(f"       Reason:       {finding.error_or_skip_reason}")

    if result.limitations:
        lines.extend(["-" * 80, "  Framework Analytical Limitations:"])
        for lim in result.limitations:
            lines.append(f"    * {lim}")

    lines.append("=" * 80)
    return "\n".join(lines)


@app.command(name="nosqli")
def nosqli_cmd(
    url: str | None = typer.Option(
        None,
        "--url",
        "-u",
        help="Target web application URL to assess.",
    ),
    param: str | None = typer.Option(
        None,
        "--param",
        "-p",
        help="Specific candidate parameter to test (defaults to all eligible parameters).",
    ),
    method: str = typer.Option(
        "GET",
        "--method",
        "-m",
        help="HTTP request method (GET, POST, PUT, PATCH, DELETE).",
    ),
    data: str | None = typer.Option(
        None,
        "--data",
        "-d",
        help="Raw or URL-encoded form data body.",
    ),
    json_data: str | None = typer.Option(
        None,
        "--json",
        "-j",
        help="JSON formatted request body (supports nested keys and object structures).",
    ),
    fixture: str | None = typer.Option(
        None,
        "--fixture",
        help="Path to JSON file containing captured baseline and test responses for offline testing.",
    ),
    auth_type: str = typer.Option(
        "none",
        "--auth-type",
        help="Authentication method: none, bearer, basic, header, cookie.",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="Bearer token (or DBSHIELD_AUTH_TOKEN env var).",
    ),
    username: str | None = typer.Option(
        None,
        "--username",
        help="HTTP Basic username (or DBSHIELD_AUTH_USERNAME env var).",
    ),
    password: str | None = typer.Option(
        None,
        "--password",
        help="HTTP Basic password (or DBSHIELD_AUTH_PASSWORD env var).",
    ),
    cookie: str | None = typer.Option(
        None,
        "--cookie",
        help="Session cookie string (e.g., 'session=xyz').",
    ),
    timeout: float | None = typer.Option(
        None,
        "--timeout",
        help="Per-request timeout budget in seconds.",
    ),
    max_budget: int = typer.Option(
        50,
        "--max-budget",
        help="Maximum total request budget across entire scan.",
    ),
    max_param_budget: int = typer.Option(
        8,
        "--max-param-budget",
        help="Maximum request budget per candidate parameter.",
    ),
    disable_differential: bool = typer.Option(
        False,
        "--disable-differential",
        help="Disable boolean differential testing (run error-based only).",
    ),
    fmt: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text (human-readable table) or json.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional file path to export assessment results.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite destination output file if it already exists.",
    ),
) -> None:
    """Assess web application targets or offline response fixtures for NoSQL injection indicators."""
    fmt_clean = fmt.lower().strip()
    if fmt_clean not in {"text", "json"}:
        print_error(
            f"Unsupported format '{fmt}'.",
            cause="DBShield supports only 'text' or 'json' output formats.",
            remedy="Specify --format text or --format json.",
        )
        raise typer.Exit(code=2)

    # 1. Handle Offline Fixture Assessment Mode
    if fixture is not None:
        fixture_path = Path(fixture)
        if not fixture_path.is_file():
            print_error(
                f"Fixture file '{fixture}' not found.",
                cause="The specified fixture path does not point to an existing readable file.",
                remedy="Provide a valid path to a JSON response fixture file.",
            )
            raise typer.Exit(code=2)

        try:
            fixture_data = json.loads(fixture_path.read_text(encoding="utf-8"))
            target_url = fixture_data.get("target_url", "http://laboratory.local/fixture")
            p_name = fixture_data.get("parameter", param or "id")

            base_info = fixture_data.get("baseline", {})
            test_info = fixture_data.get("test", {})

            base_resp = HTTPResponse(
                url=target_url,
                status_code=base_info.get("status_code", 200),
                body=base_info.get("body", ""),
            )
            test_resp = HTTPResponse(
                url=target_url,
                status_code=test_info.get("status_code", 200),
                body=test_info.get("body", ""),
            )

            true_resp = None
            false_resp = None
            if "true_response" in fixture_data and "false_response" in fixture_data:
                true_info = fixture_data["true_response"]
                false_info = fixture_data["false_response"]
                true_resp = HTTPResponse(
                    url=target_url,
                    status_code=true_info.get("status_code", 200),
                    body=true_info.get("body", ""),
                )
                false_resp = HTTPResponse(
                    url=target_url,
                    status_code=false_info.get("status_code", 200),
                    body=false_info.get("body", ""),
                )

            print_info(f"Analyzing offline NoSQL response fixtures from '{fixture_path}'...")
            result = NoSQLiEngine.analyze_fixture_records(
                target_url=target_url,
                param_name=p_name,
                baseline_response=base_resp,
                test_response=test_resp,
                true_response=true_resp,
                false_response=false_resp,
            )
        except Exception as exc:
            print_error(
                "Failed to process fixture file.",
                cause=str(exc),
                remedy="Verify that the fixture file contains valid JSON matching DBShield fixture structure.",
            )
            raise typer.Exit(code=1) from exc

    # 2. Handle Online Target Assessment Mode
    else:
        if not url:
            print_error(
                "Missing required target specification.",
                cause="Neither --url nor --fixture was provided.",
                remedy="Specify target URL via --url <URL> or offline fixture via --fixture <PATH>.",
            )
            raise typer.Exit(code=2)

        # Validate URL
        try:
            target = Target.from_url(url)
        except URLValidationError as exc:
            print_error(exc.message, cause=exc.cause, remedy=exc.remedy)
            raise typer.Exit(code=2) from exc

        # Initialize ScopeManager and assert scope
        settings = get_settings()
        scope_manager = ScopeManager(
            allowed_hosts=settings.allowed_hosts,
            allow_subdomains=settings.allow_subdomains,
            strict_mode=bool(settings.allowed_hosts),
        )
        try:
            scope_manager.assert_in_scope(target)
        except ScopeViolationError as exc:
            print_error(
                f"Target host '{target.host}' is not within authorized scope.",
                cause=exc.cause or "Host does not match any entry in allowed_hosts.",
                remedy=exc.remedy
                or "Configure DBSHIELD_ALLOWED_HOSTS to authorize target before scanning.",
            )
            raise typer.Exit(code=2) from exc

        # Authentication Configuration
        effective_token = token or os.environ.get("DBSHIELD_AUTH_TOKEN")
        effective_username = username or os.environ.get("DBSHIELD_AUTH_USERNAME")
        effective_password = password or os.environ.get("DBSHIELD_AUTH_PASSWORD")

        try:
            auth_mode = AuthType(auth_type.lower())
        except ValueError:
            print_error(
                f"Invalid auth-type '{auth_type}'.",
                cause=f"'{auth_type}' is not a recognized authentication method.",
                remedy="Supported methods: none, bearer, basic, header, cookie.",
            )
            raise typer.Exit(code=2) from None

        try:
            auth_config = AuthConfig(
                auth_type=auth_mode,
                token=effective_token,
                username=effective_username,
                password=effective_password,
                cookies={"session": cookie} if cookie else {},
            )
        except ValueError as exc:
            print_error(
                "Invalid authentication configuration parameters.",
                cause=str(exc),
                remedy="Check required credentials for the chosen auth mode.",
            )
            raise typer.Exit(code=2) from exc

        session_mgr = SessionManager(auth_config=auth_config)
        session_mgr.bind_target(target)

        effective_timeout = timeout if timeout is not None else settings.http_timeout
        http_client = SafeHTTPClient(
            scope_manager=scope_manager,
            timeout=effective_timeout,
            session_manager=session_mgr,
        )

        engine = NoSQLiEngine(
            scope_manager=scope_manager,
            http_client=http_client,
            session_manager=session_mgr,
            max_requests_per_parameter=max_param_budget,
            total_request_budget=max_budget,
            enable_differential=not disable_differential,
        )

        print_info(f"Initiating controlled NoSQL injection assessment on: {target.full_url}")
        try:
            result = engine.scan(
                target_url=target,
                method=method,
                selected_param=param,
                data=data,
                json_data=json_data,
            )
        except Exception as exc:
            print_error(
                "Operational failure during NoSQL injection scan.",
                cause=str(exc),
                remedy="Review network connectivity, target availability, and configuration.",
            )
            raise typer.Exit(code=1) from exc

    # 3. Format Output
    rendered_text = _format_nosqli_report(result)
    json_output = result.model_dump_json(indent=2)

    # 4. Handle Output Export
    if output is not None:
        out_path = Path(output)
        if out_path.exists() and not overwrite:
            print_error(
                f"Output destination '{output}' already exists.",
                cause="Target file exists and --overwrite was not specified.",
                remedy="Provide a different output path or specify --overwrite to replace it.",
            )
            raise typer.Exit(code=1)

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if fmt_clean == "json" or out_path.suffix.lower() == ".json":
                out_path.write_text(json_output, encoding="utf-8")
            else:
                out_path.write_text(rendered_text, encoding="utf-8")
            print_success(
                f"NoSQL injection assessment results successfully exported to '{out_path}'."
            )
        except Exception as exc:
            print_error(
                f"Failed to write assessment results to '{out_path}'.",
                cause=str(exc),
                remedy="Verify write permissions and disk space for destination path.",
            )
            raise typer.Exit(code=1) from exc

    # 5. Render Output to Terminal
    if fmt_clean == "json":
        sys.stdout.write(json_output + "\n")
    else:
        sys.stdout.write(rendered_text + "\n")
    sys.stdout.flush()

    raise typer.Exit(code=0)


def _format_payloads_report(payloads: list[SecurityPayload]) -> str:
    """Format structured payload catalog listing for terminal presentation."""
    lines = [
        "=" * 80,
        "                     DBShield Security Payload Catalog                          ",
        "=" * 80,
        f"  Total Registered Payloads: {len(payloads)}",
        "-" * 80,
        f"  {'ID':<24} {'CATEGORY':<10} {'TECHNIQUE':<16} {'RISK':<12} {'LOCATIONS'}",
        "-" * 80,
    ]
    for p in payloads:
        locs = ",".join(loc.value for loc in p.applicable_locations)
        lines.append(
            f"  {p.payload_id:<24} {p.category.value:<10} {p.technique:<16} {p.risk_level.value:<12} {locs}"
        )
    lines.append("=" * 80)
    return "\n".join(lines)


def _format_payload_detail(payload: SecurityPayload) -> str:
    """Format single payload detailed metadata for terminal presentation."""
    lines = [
        "=" * 80,
        "                    DBShield Security Payload Specification                      ",
        "=" * 80,
        f"  Payload ID:           {payload.payload_id}",
        f"  Name:                 {payload.name}",
        f"  Description:          {payload.description}",
        f"  Category:             {payload.category.value.upper()}",
        f"  Technique:            {payload.technique}",
        f"  Risk Level:           {payload.risk_level.value.upper()}",
        f"  Value:                {payload.payload_value!r}",
        f"  Applicable Locations: {', '.join(loc.value for loc in payload.applicable_locations)}",
        f"  Applicable Engines:   {', '.join(payload.applicable_engines) if payload.applicable_engines else 'all'}",
        f"  Target Providers:     {', '.join(payload.target_providers) if payload.target_providers else 'all'}",
        f"  Paired Payload ID:    {payload.paired_with_id or 'none'}",
        f"  Pair Role:            {payload.pair_role or 'none'}",
        f"  Safety Constraints:   {', '.join(payload.safety_constraints) if payload.safety_constraints else 'standard'}",
        f"  Tags:                 {', '.join(payload.tags) if payload.tags else 'none'}",
        "=" * 80,
    ]
    return "\n".join(lines)


def _format_execution_report(result: ExecutionRunResult) -> str:
    """Format structured test execution orchestrator run results for terminal presentation."""
    lines = [
        "=" * 80,
        "                 DBShield Test Execution Orchestrator Report                    ",
        "=" * 80,
        f"  Target URL:             {result.target_url}",
        f"  Run ID:                 {result.run_id}",
        f"  Engine:                 {result.engine_name.upper()}",
        f"  Execution Status:       {result.execution_status.upper()}",
        f"  Total Duration:         {result.summary.duration_seconds:.3f}s",
        f"  Total Requests:         {result.summary.total_requests}",
        "-" * 80,
        "  Execution Test Metrics:",
        f"    Total Test Cases:                  {result.summary.total_test_cases}",
        f"    Executed Test Cases:               {result.summary.executed_test_cases}",
        f"    Skipped Test Cases:                {result.summary.skipped_test_cases}",
        f"    Failed Test Cases:                 {result.summary.failed_test_cases}",
        f"    Findings Generated:                {len(result.findings)}",
    ]
    if result.findings:
        lines.extend(["-" * 80, "  Detected Findings:"])
        for idx, finding in enumerate(result.findings, start=1):
            status = getattr(finding, "status", None)
            badge = f"[{status.value.upper()}]" if status else "[FINDING]"
            param = getattr(finding, "parameter", None)
            param_name = getattr(param, "name", "unknown") if param else "unknown"
            tech = getattr(finding, "technique", None)
            tech_val = getattr(tech, "value", str(tech)) if tech else "unknown"
            summary_txt = getattr(finding, "evidence_summary", "")
            lines.append(f"    {idx}. Parameter '{param_name}' {badge} ({tech_val})")
            if summary_txt:
                lines.append(f"       Summary: {summary_txt}")
    if result.records:
        lines.extend(["-" * 80, "  Test Case Execution Records (Sample):"])
        for rec in result.records[:15]:
            status_badge = f"[{rec.status.value.upper()}]"
            lines.append(
                f"    * {rec.test_case_id:<36} {status_badge:<11} {rec.elapsed_seconds:.3f}s"
            )
            if rec.error_or_skip_reason:
                lines.append(f"      Reason: {rec.error_or_skip_reason}")
        if len(result.records) > 15:
            lines.append(f"    ... and {len(result.records) - 15} more test records.")
    lines.append("=" * 80)
    return "\n".join(lines)


@app.command(name="payloads")
def payloads_cmd(
    engine: str | None = typer.Option(
        None,
        "--engine",
        "-e",
        help="Filter payloads by target engine ('sqli', 'nosqli').",
    ),
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter payloads by category ('sqli', 'nosqli', 'generic').",
    ),
    technique: str | None = typer.Option(
        None,
        "--technique",
        "-t",
        help="Filter payloads by testing technique ('error_based', 'differential', etc.).",
    ),
    location: str | None = typer.Option(
        None,
        "--location",
        "-l",
        help="Filter payloads by applicable parameter location ('query', 'body', 'json').",
    ),
    risk: str | None = typer.Option(
        None,
        "--risk",
        "-r",
        help="Filter payloads by risk level ('safe_probe', 'read_only').",
    ),
    info: str | None = typer.Option(
        None,
        "--info",
        "-i",
        help="Inspect detailed metadata for a specific payload identifier.",
    ),
    validate_catalog: bool = typer.Option(
        False,
        "--validate",
        help="Validate payload catalog integrity and paired payload consistency.",
    ),
    fmt: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text (human-readable table) or json.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional file path to export payload catalog or metadata.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite destination output file if it already exists.",
    ),
) -> None:
    """Inspect, filter, and validate DBShield's centralized test payload catalog."""
    fmt_clean = fmt.lower().strip()
    if fmt_clean not in {"text", "json"}:
        print_error(
            f"Invalid format '{fmt}'.",
            cause="The --format option must be either 'text' or 'json'.",
            remedy="Specify '--format text' or '--format json'.",
        )
        raise typer.Exit(code=2)

    catalog = PayloadCatalog()

    # 1. Validation mode
    if validate_catalog:
        try:
            catalog.validate_catalog()
        except Exception as exc:
            print_error(
                "Payload catalog validation failed.",
                cause=str(exc),
                remedy="Review payload definitions for missing pairs or invalid attributes.",
            )
            raise typer.Exit(code=1) from exc

        print_success(
            f"Payload catalog validation passed. All {len(catalog.get_all())} definitions are consistent."
        )
        raise typer.Exit(code=0)

    # 2. Detailed info mode
    if info:
        payload = catalog.get_payload(info.strip())
        if not payload:
            print_error(
                f"Payload '{info}' not found.",
                cause=f"No registered payload definition matching identifier '{info}'.",
                remedy="Run 'dbshield payloads' to list valid payload identifiers.",
            )
            raise typer.Exit(code=2)

        rendered_text = _format_payload_detail(payload)
        json_output = payload.model_dump_json(indent=2)

        if output:
            out_path = Path(output)
            if out_path.exists() and not overwrite:
                print_error(
                    f"Output destination '{output}' already exists.",
                    cause="Target file exists and --overwrite was not specified.",
                    remedy="Provide a different output path or specify --overwrite to replace it.",
                )
                raise typer.Exit(code=1)
            try:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(
                    json_output if fmt_clean == "json" else rendered_text, encoding="utf-8"
                )
                print_success(f"Payload details exported to '{out_path}'.")
            except Exception as exc:
                print_error(f"Failed to write to '{output}'.", cause=str(exc))
                raise typer.Exit(code=1) from exc

        if fmt_clean == "json":
            sys.stdout.write(json_output + "\n")
        else:
            sys.stdout.write(rendered_text + "\n")
        sys.stdout.flush()
        raise typer.Exit(code=0)

    # 3. Filtering and listing mode
    cat_enum = None
    if category:
        try:
            cat_enum = PayloadCategory(category.lower().strip())
        except ValueError:
            valid_cats = [c.value for c in PayloadCategory]
            print_error(
                f"Invalid category '{category}'.",
                cause=f"Must be one of: {', '.join(valid_cats)}.",
                remedy="Provide a valid payload category.",
            )
            raise typer.Exit(code=2) from None

    risk_enum = None
    if risk:
        try:
            risk_enum = PayloadRiskLevel(risk.lower().strip())
        except ValueError:
            valid_risks = [r.value for r in PayloadRiskLevel]
            print_error(
                f"Invalid risk level '{risk}'.",
                cause=f"Must be one of: {', '.join(valid_risks)}.",
                remedy="Provide a valid risk level.",
            )
            raise typer.Exit(code=2) from None

    loc_enum = None
    if location:
        try:
            loc_enum = ParameterLocation(location.lower().strip())
        except ValueError:
            valid_locs = [loc.value for loc in ParameterLocation]
            print_error(
                f"Invalid parameter location '{location}'.",
                cause=f"Must be one of: {', '.join(valid_locs)}.",
                remedy="Provide a valid parameter location.",
            )
            raise typer.Exit(code=2) from None

    payloads = catalog.filter(
        category=cat_enum,
        technique=technique.strip() if technique else None,
        engine=engine.strip() if engine else None,
        location=loc_enum,
        risk_level=risk_enum,
    )

    rendered_text = _format_payloads_report(payloads)
    json_output = json.dumps([p.model_dump(mode="json") for p in payloads], indent=2)

    if output:
        out_path = Path(output)
        if out_path.exists() and not overwrite:
            print_error(
                f"Output destination '{output}' already exists.",
                cause="Target file exists and --overwrite was not specified.",
                remedy="Provide a different output path or specify --overwrite to replace it.",
            )
            raise typer.Exit(code=1)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json_output if fmt_clean == "json" else rendered_text, encoding="utf-8"
            )
            print_success(f"Payload catalog listing exported to '{out_path}'.")
        except Exception as exc:
            print_error(f"Failed to write to '{output}'.", cause=str(exc))
            raise typer.Exit(code=1) from exc

    if fmt_clean == "json":
        sys.stdout.write(json_output + "\n")
    else:
        sys.stdout.write(rendered_text + "\n")
    sys.stdout.flush()
    raise typer.Exit(code=0)


@app.command(name="execute")
def execute_cmd(
    url: str | None = typer.Option(
        None,
        "--url",
        "-u",
        help="Target web application URL to assess.",
    ),
    engine: str = typer.Option(
        "all",
        "--engine",
        "-e",
        help="Target detection engine to orchestrate ('sqli', 'nosqli', or 'all').",
    ),
    param: str | None = typer.Option(
        None,
        "--param",
        "-p",
        help="Specific candidate parameter to test (defaults to all eligible parameters).",
    ),
    method: str = typer.Option(
        "GET",
        "--method",
        "-m",
        help="HTTP request method (GET, POST, PUT, PATCH, DELETE).",
    ),
    data: str | None = typer.Option(
        None,
        "--data",
        "-d",
        help="Raw or URL-encoded form data body.",
    ),
    json_data: str | None = typer.Option(
        None,
        "--json",
        "-j",
        help="JSON formatted request body (supports nested paths and array mutation).",
    ),
    fixture: str | None = typer.Option(
        None,
        "--fixture",
        help="Path to JSON file containing captured baseline and test responses for offline testing.",
    ),
    auth_type: str = typer.Option(
        "none",
        "--auth-type",
        help="Authentication method: none, bearer, basic, header, cookie.",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="Bearer token (or DBSHIELD_AUTH_TOKEN env var).",
    ),
    username: str | None = typer.Option(
        None,
        "--username",
        help="HTTP Basic username (or DBSHIELD_AUTH_USERNAME env var).",
    ),
    password: str | None = typer.Option(
        None,
        "--password",
        help="HTTP Basic password (or DBSHIELD_AUTH_PASSWORD env var).",
    ),
    cookie: str | None = typer.Option(
        None,
        "--cookie",
        help="Session cookie in 'name=value' format.",
    ),
    max_budget: int = typer.Option(
        50,
        "--max-budget",
        help="Maximum total HTTP requests allowed for the execution run.",
    ),
    max_param_budget: int = typer.Option(
        15,
        "--max-param-budget",
        help="Maximum HTTP requests allowed per individual parameter.",
    ),
    timeout: float | None = typer.Option(
        None,
        "--timeout",
        help="HTTP request timeout in seconds.",
    ),
    fmt: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text or json.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional file path to export execution run results.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite destination output file if it already exists.",
    ),
) -> None:
    """Execute controlled security test cases across engines using the Phase 6 execution engine."""
    fmt_clean = fmt.lower().strip()
    if fmt_clean not in {"text", "json"}:
        print_error(
            f"Invalid format '{fmt}'.",
            cause="The --format option must be either 'text' or 'json'.",
            remedy="Specify '--format text' or '--format json'.",
        )
        raise typer.Exit(code=2)

    engine_clean = engine.lower().strip()
    if engine_clean not in {"sqli", "nosqli", "all"}:
        print_error(
            f"Invalid engine '{engine}'.",
            cause="Supported engines are 'sqli', 'nosqli', or 'all'.",
            remedy="Specify '--engine sqli', '--engine nosqli', or '--engine all'.",
        )
        raise typer.Exit(code=2)

    # 1. Offline fixture mode
    if fixture:
        fix_path = Path(fixture)
        if not fix_path.is_file():
            print_error(
                f"Fixture file '{fixture}' not found.",
                cause="The specified fixture path does not exist or is not a readable file.",
                remedy="Provide a valid path to a JSON response fixture file.",
            )
            raise typer.Exit(code=2)

        try:
            fix_content = json.loads(fix_path.read_text(encoding="utf-8"))
            t_url = fix_content.get("target_url", "http://laboratory.local/fixture")
            p_name = fix_content.get("parameter", param or "id")
            p_loc_str = fix_content.get("location", "query")
            p_loc = ParameterLocation(p_loc_str)
            p_id = fix_content.get("payload_id", "SQLI_ERR_QUOTE")

            base_info = fix_content.get("baseline", {})
            test_info = fix_content.get("test", {})
            base_resp = HTTPResponse(
                url=t_url,
                status_code=base_info.get("status_code", 200),
                body=base_info.get("body", ""),
            )
            test_resp = HTTPResponse(
                url=t_url,
                status_code=test_info.get("status_code", 200),
                body=test_info.get("body", ""),
            )

            true_resp = None
            false_resp = None
            if "true_response" in fix_content and "false_response" in fix_content:
                true_info = fix_content["true_response"]
                false_info = fix_content["false_response"]
                true_resp = HTTPResponse(
                    url=t_url,
                    status_code=true_info.get("status_code", 200),
                    body=true_info.get("body", ""),
                )
                false_resp = HTTPResponse(
                    url=t_url,
                    status_code=false_info.get("status_code", 200),
                    body=false_info.get("body", ""),
                )

            adapter = (
                NoSQLiExecutionAdapter() if engine_clean == "nosqli" else SQLiExecutionAdapter()
            )
            print_info(
                f"Analyzing offline fixture from '{fix_path}' via {adapter.engine_name.upper()}..."
            )
            result = TestExecutionOrchestrator.execute_offline_fixture(
                target_url=t_url,
                param_name=p_name,
                param_location=p_loc,
                payload_id=p_id,
                baseline_response=base_resp,
                test_response=test_resp,
                adapter=adapter,
                true_response=true_resp,
                false_response=false_resp,
            )
        except Exception as exc:
            print_error(
                "Failed to process offline fixture.",
                cause=str(exc),
                remedy="Ensure fixture file is valid JSON matching DBShield fixture specifications.",
            )
            raise typer.Exit(code=1) from exc

    # 2. Live online target execution mode
    else:
        if not url:
            print_error(
                "Missing target specification.",
                cause="Neither --url nor --fixture was provided.",
                remedy="Specify a target via --url <URL> or offline fixture via --fixture <PATH>.",
            )
            raise typer.Exit(code=2)

        try:
            target = Target.from_url(url)
        except URLValidationError as exc:
            print_error(exc.message, cause=exc.cause, remedy=exc.remedy)
            raise typer.Exit(code=2) from exc

        settings = get_settings()
        scope_manager = ScopeManager(
            allowed_hosts=settings.allowed_hosts,
            allow_subdomains=settings.allow_subdomains,
            strict_mode=bool(settings.allowed_hosts),
        )
        try:
            scope_manager.assert_in_scope(target)
        except ScopeViolationError as exc:
            print_error(
                f"Target host '{target.host}' is not within authorized scope.",
                cause=exc.cause or "Host does not match any entry in allowed_hosts.",
                remedy=exc.remedy
                or "Configure DBSHIELD_ALLOWED_HOSTS to authorize target before scanning.",
            )
            raise typer.Exit(code=2) from exc

        # Authentication Configuration
        effective_token = token or os.environ.get("DBSHIELD_AUTH_TOKEN")
        effective_username = username or os.environ.get("DBSHIELD_AUTH_USERNAME")
        effective_password = password or os.environ.get("DBSHIELD_AUTH_PASSWORD")

        try:
            auth_mode = AuthType(auth_type.lower().strip())
        except ValueError:
            print_error(
                f"Invalid auth-type '{auth_type}'.",
                cause=f"'{auth_type}' is not a recognized authentication method.",
                remedy="Supported methods: none, bearer, basic, header, cookie.",
            )
            raise typer.Exit(code=2) from None

        try:
            auth_config = AuthConfig(
                auth_type=auth_mode,
                token=effective_token,
                username=effective_username,
                password=effective_password,
                cookies={"session": cookie} if cookie else {},
            )
        except ValueError as exc:
            print_error(
                "Invalid authentication configuration parameters.",
                cause=str(exc),
                remedy="Check required credentials for the chosen auth mode.",
            )
            raise typer.Exit(code=2) from exc

        session_mgr = SessionManager(auth_config=auth_config)
        session_mgr.bind_target(target)

        effective_timeout = timeout if timeout is not None else settings.http_timeout
        http_client = SafeHTTPClient(
            scope_manager=scope_manager,
            timeout=effective_timeout,
            session_manager=session_mgr,
        )

        policy = ExecutionPolicy(
            max_total_requests=max_budget,
            max_requests_per_parameter=max_param_budget,
            timeout_seconds=effective_timeout,
        )

        adapters: list[EngineAdapter] = []
        if engine_clean in {"sqli", "all"}:
            adapters.append(SQLiExecutionAdapter())
        if engine_clean in {"nosqli", "all"}:
            adapters.append(NoSQLiExecutionAdapter())

        orchestrator = TestExecutionOrchestrator(
            scope_manager=scope_manager,
            http_client=http_client,
            session_manager=session_mgr,
            policy=policy,
        )

        print_info(f"Initiating orchestrated execution test run on: {target.full_url}")
        results: list[ExecutionRunResult] = []
        for adp in adapters:
            try:
                res = orchestrator.execute_suite(
                    target_url=target,
                    adapter=adp,
                    selected_param=param,
                    method=method,
                    data=data,
                    json_data=json_data,
                )
                results.append(res)
            except Exception as exc:
                print_error(
                    f"Operational failure during {adp.engine_name.upper()} execution run.",
                    cause=str(exc),
                    remedy="Review target connectivity and configuration.",
                )
                raise typer.Exit(code=1) from exc

        result = results[0] if len(results) == 1 else results[0]
        # If multiple adapters, merge records and findings into single result for display
        if len(results) > 1:
            all_records = []
            all_findings = []
            total_reqs = sum(r.summary.total_requests for r in results)
            total_cases = sum(r.summary.total_test_cases for r in results)
            exec_cases = sum(r.summary.executed_test_cases for r in results)
            skip_cases = sum(r.summary.skipped_test_cases for r in results)
            fail_cases = sum(r.summary.failed_test_cases for r in results)
            duration = sum(r.summary.duration_seconds for r in results)
            for r in results:
                all_records.extend(r.records)
                all_findings.extend(r.findings)
            from dbshield.execution.models import ExecutionSummary

            merged_summary = ExecutionSummary(
                total_test_cases=total_cases,
                executed_test_cases=exec_cases,
                skipped_test_cases=skip_cases,
                failed_test_cases=fail_cases,
                total_requests=total_reqs,
                duration_seconds=round(duration, 3),
            )
            result = ExecutionRunResult(
                target_url=target.full_url,
                engine_name="sqli+nosqli",
                execution_status="completed",
                summary=merged_summary,
                records=all_records,
                findings=all_findings,
            )

    rendered_text = _format_execution_report(result)
    json_output = result.model_dump_json(indent=2)

    if output is not None:
        out_path = Path(output)
        if out_path.exists() and not overwrite:
            print_error(
                f"Output destination '{output}' already exists.",
                cause="Target file exists and --overwrite was not specified.",
                remedy="Provide a different output path or specify --overwrite to replace it.",
            )
            raise typer.Exit(code=1)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json_output if fmt_clean == "json" else rendered_text, encoding="utf-8"
            )
            print_success(f"Execution run results successfully exported to '{out_path}'.")
        except Exception as exc:
            print_error(
                f"Failed to write results to '{out_path}'.",
                cause=str(exc),
                remedy="Verify write permissions for destination path.",
            )
            raise typer.Exit(code=1) from exc

    if fmt_clean == "json":
        sys.stdout.write(json_output + "\n")
    else:
        sys.stdout.write(rendered_text + "\n")
    sys.stdout.flush()
    raise typer.Exit(code=0)


def _format_verification_report(result: VerificationResult) -> str:
    """Format structured evidence analysis and verification results for terminal presentation."""
    lines = [
        "=" * 80,
        "           DBShield Evidence Analysis and Vulnerability Verification            ",
        "=" * 80,
        f"  Target Scope:           {result.target_url}",
        f"  Result ID:              {result.result_id}",
        f"  Engine Spec Version:    {result.assessment_version}",
        f"  Evaluation Timestamp:   {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "-" * 80,
        "  Verification Summary Metrics:",
        f"    Total Findings Evaluated:          {result.summary.total_evaluated}",
        f"    Verified Vulnerabilities:          {result.summary.verified_count}",
        f"    Corroborated Signals:              {result.summary.corroborated_count}",
        f"    Potential Indicators:              {result.summary.potential_indicator_count}",
        f"    Inconclusive Assessments:          {result.summary.inconclusive_count}",
        f"    Rejected (False Positives):        {result.summary.rejected_count}",
        f"    Unverifiable (Execution Failures): {result.summary.unverifiable_count}",
    ]
    if result.findings:
        lines.extend(["-" * 80, "  Verified Findings & Analysis Details:"])
        for idx, finding in enumerate(result.findings, start=1):
            status_badge = f"[{finding.status.value.upper()}]"
            conf = finding.confidence
            conf_str = f"{conf.level.value.upper()} (score: {conf.score:.2f})"
            lines.append(
                f"    {idx}. Parameter '{finding.parameter_name}' {status_badge} "
                f"({finding.vulnerability_class.value.upper()} via {finding.parameter_location.value})"
            )
            lines.append(f"       Confidence: {conf_str}")
            lines.append(f"       Rationale:  {finding.verification_rationale}")
            if finding.rejection_or_downgrade_reason:
                lines.append(f"       Down/Reject Reason: {finding.rejection_or_downgrade_reason}")
            if finding.recommended_next_step:
                lines.append(f"       Next Step:  {finding.recommended_next_step}")
            if finding.corroborating_evidence:
                first_ev = finding.corroborating_evidence[0]
                lines.append(
                    f"       Evidence:   {first_ev.evidence_type.value} [Rule: {first_ev.rule_id}] "
                    f"(Provider: {first_ev.provider_or_family})"
                )
                if first_ev.safe_snippet:
                    lines.append(f'       Snippet:    "{first_ev.safe_snippet[:100]}"')
            if finding.state_history:
                transitions = " -> ".join(
                    [h.from_status.value for h in finding.state_history]
                    + [finding.state_history[-1].to_status.value]
                )
                lines.append(f"       Lifecycle:  {transitions}")
    if result.limitations:
        lines.extend(["-" * 80, "  Verification Safety Boundaries & Limitations:"])
        for lim in result.limitations:
            lines.append(f"    * {lim}")
    lines.append("=" * 80)
    return "\n".join(lines)


@app.command(name="verify")
def verify_cmd(
    input_file: str | None = typer.Option(
        None,
        "--input",
        "-i",
        help="Path to JSON file containing previous scan findings or execution results to verify.",
    ),
    fixture: str | None = typer.Option(
        None,
        "--fixture",
        help="Path to JSON file containing captured baseline and test responses for offline testing.",
    ),
    url: str | None = typer.Option(
        None,
        "--url",
        "-u",
        help="Target web application URL to assess and verify.",
    ),
    engine: str = typer.Option(
        "all",
        "--engine",
        "-e",
        help="Target detection engine to orchestrate ('sqli', 'nosqli', or 'all').",
    ),
    param: str | None = typer.Option(
        None,
        "--param",
        "-p",
        help="Specific candidate parameter to test and verify (defaults to all eligible parameters).",
    ),
    method: str = typer.Option(
        "GET",
        "--method",
        "-m",
        help="HTTP request method (GET, POST, PUT, PATCH, DELETE).",
    ),
    data: str | None = typer.Option(
        None,
        "--data",
        "-d",
        help="Raw or URL-encoded form data body.",
    ),
    json_data: str | None = typer.Option(
        None,
        "--json",
        "-j",
        help="JSON formatted request body.",
    ),
    auth_type: str = typer.Option(
        "none",
        "--auth-type",
        help="Authentication method: none, bearer, basic, header, cookie.",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="Bearer token (or DBSHIELD_AUTH_TOKEN env var).",
    ),
    username: str | None = typer.Option(
        None,
        "--username",
        help="HTTP Basic username (or DBSHIELD_AUTH_USERNAME env var).",
    ),
    password: str | None = typer.Option(
        None,
        "--password",
        help="HTTP Basic password (or DBSHIELD_AUTH_PASSWORD env var).",
    ),
    cookie: str | None = typer.Option(
        None,
        "--cookie",
        help="Session cookie in 'name=value' format.",
    ),
    max_budget: int = typer.Option(
        50,
        "--max-budget",
        help="Maximum total HTTP requests allowed for the execution run.",
    ),
    max_param_budget: int = typer.Option(
        15,
        "--max-param-budget",
        help="Maximum HTTP requests allowed per individual parameter.",
    ),
    timeout: float | None = typer.Option(
        None,
        "--timeout",
        help="HTTP request timeout in seconds.",
    ),
    fmt: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text or json.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional file path to export verification results.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite destination output file if it already exists.",
    ),
) -> None:
    """Analyze security test findings, reduce false positives, and produce verified results."""
    fmt_clean = fmt.lower().strip()
    if fmt_clean not in {"text", "json"}:
        print_error(
            f"Invalid format '{fmt}'.",
            cause="The --format option must be either 'text' or 'json'.",
            remedy="Specify '--format text' or '--format json'.",
        )
        raise typer.Exit(code=2)

    engine_clean = engine.lower().strip()
    if engine_clean not in {"sqli", "nosqli", "all"}:
        print_error(
            f"Invalid engine '{engine}'.",
            cause="Supported engines are 'sqli', 'nosqli', or 'all'.",
            remedy="Specify '--engine sqli', '--engine nosqli', or '--engine all'.",
        )
        raise typer.Exit(code=2)

    v_engine = VerificationEngine()

    # 1. Input file mode (existing findings or execution run results)
    if input_file:
        in_path = Path(input_file)
        if not in_path.is_file():
            print_error(
                f"Input file '{input_file}' not found.",
                cause="The specified input path does not exist or is not a readable file.",
                remedy="Provide a valid path to an existing JSON results file.",
            )
            raise typer.Exit(code=2)
        try:
            raw_content = json.loads(in_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print_error(
                f"Failed to parse input file '{input_file}'.",
                cause=str(exc),
                remedy="Ensure the file contains valid JSON formatted data.",
            )
            raise typer.Exit(code=1) from exc

        print_info(f"Analyzing and verifying security findings from '{in_path}'...")
        if isinstance(raw_content, dict):
            if "records" in raw_content and "target_url" in raw_content:
                try:
                    run_res = ExecutionRunResult.model_validate(raw_content)
                    result = v_engine.verify_execution_run(run_res)
                except Exception:
                    result = v_engine.verify_dict_records(
                        [raw_content],
                        target_url=raw_content.get("target_url", "http://laboratory.local"),
                    )
            elif "findings" in raw_content:
                t_url = raw_content.get("target_url", "http://laboratory.local")
                findings_data = raw_content["findings"]
                result = v_engine.verify_dict_records(findings_data, target_url=t_url)
            else:
                result = v_engine.verify_dict_records([raw_content])
        elif isinstance(raw_content, list):
            result = v_engine.verify_dict_records(raw_content)
        else:
            print_error(
                "Unsupported JSON root structure in input file.",
                cause="Input JSON root must be an object or an array of finding objects.",
                remedy="Provide standard DBShield scan or execution results.",
            )
            raise typer.Exit(code=2)

    # 2. Offline fixture mode
    elif fixture:
        fix_path = Path(fixture)
        if not fix_path.is_file():
            print_error(
                f"Fixture file '{fixture}' not found.",
                cause="The specified fixture path does not exist or is not a readable file.",
                remedy="Provide a valid path to a JSON response fixture file.",
            )
            raise typer.Exit(code=2)

        try:
            fix_content = json.loads(fix_path.read_text(encoding="utf-8"))
            t_url = fix_content.get("target_url", "http://laboratory.local/fixture")
            p_name = fix_content.get("parameter", param or "id")
            p_loc_str = fix_content.get("location", "query")
            p_loc = ParameterLocation(p_loc_str)
            p_id = fix_content.get("payload_id", "SQLI_ERR_QUOTE")

            base_info = fix_content.get("baseline", {})
            test_info = fix_content.get("test", {})
            base_resp = HTTPResponse(
                url=t_url,
                status_code=base_info.get("status_code", 200),
                body=base_info.get("body", ""),
            )
            test_resp = HTTPResponse(
                url=t_url,
                status_code=test_info.get("status_code", 200),
                body=test_info.get("body", ""),
            )

            true_resp = None
            false_resp = None
            if "true_response" in fix_content and "false_response" in fix_content:
                true_info = fix_content["true_response"]
                false_info = fix_content["false_response"]
                true_resp = HTTPResponse(
                    url=t_url,
                    status_code=true_info.get("status_code", 200),
                    body=true_info.get("body", ""),
                )
                false_resp = HTTPResponse(
                    url=t_url,
                    status_code=false_info.get("status_code", 200),
                    body=false_info.get("body", ""),
                )

            adapter = (
                NoSQLiExecutionAdapter() if engine_clean == "nosqli" else SQLiExecutionAdapter()
            )
            print_info(
                f"Analyzing offline fixture from '{fix_path}' via {adapter.engine_name.upper()}..."
            )
            exec_res = TestExecutionOrchestrator.execute_offline_fixture(
                target_url=t_url,
                param_name=p_name,
                param_location=p_loc,
                payload_id=p_id,
                baseline_response=base_resp,
                test_response=test_resp,
                adapter=adapter,
                true_response=true_resp,
                false_response=false_resp,
            )
            result = v_engine.verify_execution_run(exec_res)
        except Exception as exc:
            print_error(
                "Failed to process offline fixture.",
                cause=str(exc),
                remedy="Ensure fixture file is valid JSON matching DBShield fixture specifications.",
            )
            raise typer.Exit(code=1) from exc

    # 3. Live online target execution and verification
    elif url:
        try:
            target = Target.from_url(url)
        except URLValidationError as exc:
            print_error(exc.message, cause=exc.cause, remedy=exc.remedy)
            raise typer.Exit(code=2) from exc

        settings = get_settings()
        scope_manager = ScopeManager(
            allowed_hosts=settings.allowed_hosts,
            allow_subdomains=settings.allow_subdomains,
            strict_mode=bool(settings.allowed_hosts),
        )
        try:
            scope_manager.assert_in_scope(target)
        except ScopeViolationError as exc:
            print_error(
                f"Target host '{target.host}' is not within authorized scope.",
                cause=exc.cause or "Host does not match any entry in allowed_hosts.",
                remedy=exc.remedy
                or "Configure DBSHIELD_ALLOWED_HOSTS to authorize target before scanning.",
            )
            raise typer.Exit(code=2) from exc

        effective_token = token or os.environ.get("DBSHIELD_AUTH_TOKEN")
        effective_username = username or os.environ.get("DBSHIELD_AUTH_USERNAME")
        effective_password = password or os.environ.get("DBSHIELD_AUTH_PASSWORD")

        try:
            auth_mode = AuthType(auth_type.lower().strip())
        except ValueError:
            print_error(
                f"Invalid auth-type '{auth_type}'.",
                cause=f"'{auth_type}' is not a recognized authentication method.",
                remedy="Supported methods: none, bearer, basic, header, cookie.",
            )
            raise typer.Exit(code=2) from None

        try:
            auth_config = AuthConfig(
                auth_type=auth_mode,
                token=effective_token,
                username=effective_username,
                password=effective_password,
                cookies={"session": cookie} if cookie else {},
            )
        except ValueError as exc:
            print_error(
                "Invalid authentication configuration parameters.",
                cause=str(exc),
                remedy="Check required credentials for the chosen auth mode.",
            )
            raise typer.Exit(code=2) from exc

        session_mgr = SessionManager(auth_config=auth_config)
        session_mgr.bind_target(target)

        effective_timeout = timeout if timeout is not None else settings.http_timeout
        http_client = SafeHTTPClient(
            scope_manager=scope_manager,
            timeout=effective_timeout,
            session_manager=session_mgr,
        )

        policy = ExecutionPolicy(
            max_total_requests=max_budget,
            max_requests_per_parameter=max_param_budget,
            timeout_seconds=effective_timeout,
        )

        adapters: list[EngineAdapter] = []
        if engine_clean in {"sqli", "all"}:
            adapters.append(SQLiExecutionAdapter())
        if engine_clean in {"nosqli", "all"}:
            adapters.append(NoSQLiExecutionAdapter())

        orchestrator = TestExecutionOrchestrator(
            scope_manager=scope_manager,
            http_client=http_client,
            session_manager=session_mgr,
            policy=policy,
        )

        print_info(f"Initiating orchestrated execution test run on: {target.full_url}")
        results: list[ExecutionRunResult] = []
        for adp in adapters:
            try:
                res = orchestrator.execute_suite(
                    target_url=target,
                    adapter=adp,
                    selected_param=param,
                    method=method,
                    data=data,
                    json_data=json_data,
                )
                results.append(res)
            except Exception as exc:
                print_error(
                    f"Operational failure during {adp.engine_name.upper()} execution run.",
                    cause=str(exc),
                    remedy="Review target connectivity and configuration.",
                )
                raise typer.Exit(code=1) from exc

        exec_res = results[0]
        if len(results) > 1:
            all_records = []
            all_findings = []
            total_reqs = sum(r.summary.total_requests for r in results)
            total_cases = sum(r.summary.total_test_cases for r in results)
            exec_cases = sum(r.summary.executed_test_cases for r in results)
            skip_cases = sum(r.summary.skipped_test_cases for r in results)
            fail_cases = sum(r.summary.failed_test_cases for r in results)
            duration = sum(r.summary.duration_seconds for r in results)
            for r in results:
                all_records.extend(r.records)
                all_findings.extend(r.findings)
            from dbshield.execution.models import ExecutionSummary

            merged_summary = ExecutionSummary(
                total_test_cases=total_cases,
                executed_test_cases=exec_cases,
                skipped_test_cases=skip_cases,
                failed_test_cases=fail_cases,
                total_requests=total_reqs,
                duration_seconds=round(duration, 3),
            )
            exec_res = ExecutionRunResult(
                target_url=target.full_url,
                engine_name="sqli+nosqli",
                execution_status="completed",
                summary=merged_summary,
                records=all_records,
                findings=all_findings,
            )

        print_info("Analyzing execution results through verification engine...")
        result = v_engine.verify_execution_run(exec_res)

    else:
        print_error(
            "Missing target or input specification.",
            cause="Neither --input, --fixture, nor --url was provided.",
            remedy="Provide an input file via '--input <PATH>', an offline fixture via '--fixture <PATH>', or a target via '--url <URL>'.",
        )
        raise typer.Exit(code=2)

    rendered_text = _format_verification_report(result)
    json_output = result.model_dump_json(indent=2)

    if output is not None:
        out_path = Path(output)
        if out_path.exists() and not overwrite:
            print_error(
                f"Output destination '{output}' already exists.",
                cause="Target file exists and --overwrite was not specified.",
                remedy="Provide a different output path or specify --overwrite to replace it.",
            )
            raise typer.Exit(code=1)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json_output if fmt_clean == "json" else rendered_text, encoding="utf-8"
            )
            print_success(f"Verification results successfully exported to '{out_path}'.")
        except Exception as exc:
            print_error(
                f"Failed to write results to '{out_path}'.",
                cause=str(exc),
                remedy="Verify write permissions for destination path.",
            )
            raise typer.Exit(code=1) from exc

    if fmt_clean == "json":
        sys.stdout.write(json_output + "\n")
    else:
        sys.stdout.write(rendered_text + "\n")


@app.command(name="report")
def report_cmd(
    input_file: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to JSON file containing findings or assessment results to generate report from.",
    ),
    fmt: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Report output format: text, json, csv, markdown.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional file path to export formatted report.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite destination output file if it already exists.",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Minimum severity filter: info, low, medium, high, critical.",
    ),
    status: str | None = typer.Option(
        None,
        "--status",
        help="Filter by verification status (e.g., verified, potential_indicator, inconclusive).",
    ),
) -> None:
    """Generate professional, structured security assessment reports across multiple formats."""
    fmt_clean = fmt.lower().strip()
    valid_formats = {"text", "json", "csv", "markdown"}
    if fmt_clean not in valid_formats:
        print_error(
            f"Invalid format '{fmt}'.",
            cause=f"'{fmt}' is not a recognized report format.",
            remedy=f"Supported formats: {', '.join(sorted(valid_formats))}.",
        )
        raise typer.Exit(code=2)

    in_path = Path(input_file)
    if not in_path.exists() or not in_path.is_file():
        print_error(
            f"Input file '{input_file}' not found.",
            cause="The specified path does not exist or is not a readable regular file.",
            remedy="Check the file path and verify read permissions.",
        )
        raise typer.Exit(code=1)

    try:
        raw_text = in_path.read_text(encoding="utf-8")
        parsed_data = json.loads(raw_text)
    except Exception as exc:
        print_error(
            f"Failed to parse input file '{input_file}'.",
            cause=str(exc),
            remedy="Ensure input file is valid JSON matching DBShield finding schemas.",
        )
        raise typer.Exit(code=1) from exc

    report = FindingNormalizer.from_dict_payload(parsed_data)

    # Apply optional severity filter
    if severity:
        sev_clean = severity.lower().strip()
        sev_order = {
            "info": 1,
            "low": 2,
            "medium": 3,
            "high": 4,
            "critical": 5,
        }
        if sev_clean not in sev_order:
            print_error(
                f"Invalid severity filter '{severity}'.",
                cause=f"'{severity}' is not a valid severity level.",
                remedy="Supported severities: info, low, medium, high, critical.",
            )
            raise typer.Exit(code=2)
        min_rank = sev_order[sev_clean]
        filtered = [f for f in report.findings if sev_order.get(f.severity.value, 0) >= min_rank]
        meta = FindingNormalizer.build_report_metadata(
            target_url=report.metadata.target_url,
            findings=filtered,
            scope=report.metadata.assessment_scope,
            limitations=report.metadata.limitations,
        )
        report = SecurityAssessmentReport(metadata=meta, findings=filtered)

    # Apply optional status filter
    if status:
        stat_clean = status.lower().strip()
        filtered = [f for f in report.findings if f.verification_status.value == stat_clean]
        meta = FindingNormalizer.build_report_metadata(
            target_url=report.metadata.target_url,
            findings=filtered,
            scope=report.metadata.assessment_scope,
            limitations=report.metadata.limitations,
        )
        report = SecurityAssessmentReport(metadata=meta, findings=filtered)

    # Render selected format
    if fmt_clean == "json":
        rendered = JSONReportExporter().export(report)
    elif fmt_clean == "csv":
        rendered = CSVReportExporter().export(report)
    elif fmt_clean == "markdown":
        rendered = MarkdownReportExporter().export(report)
    else:
        rendered = TerminalReportExporter().export(report)

    # Output file handling
    if output is not None:
        out_path = Path(output)
        if out_path.exists() and not overwrite:
            print_error(
                f"Output destination '{output}' already exists.",
                cause="Target file exists and --overwrite was not specified.",
                remedy="Provide a different output path or specify --overwrite to replace it.",
            )
            raise typer.Exit(code=1)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
            print_success(f"Report successfully exported to '{out_path}'.")
        except Exception as exc:
            print_error(
                f"Failed to write report to '{out_path}'.",
                cause=str(exc),
                remedy="Verify write permissions for destination path.",
            )
            raise typer.Exit(code=1) from exc

    sys.stdout.write(rendered + ("\n" if not rendered.endswith("\n") else ""))
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
