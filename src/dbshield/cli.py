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
from dbshield.http.client import SafeHTTPClient
from dbshield.logging_config import configure_logging
from dbshield.models.auth import AuthConfig, AuthType
from dbshield.models.discovery import DiscoveryResult, DiscoveryStatus
from dbshield.models.http import HTTPMethod, HTTPResponse
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
