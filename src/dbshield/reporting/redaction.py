"""Centralized redaction and safe output utilities (Phase 8).

Ensures sensitive credentials, authorization tokens, cookies, and secrets are
redacted across all reporting channels (JSON, CSV, Markdown, Terminal).
Provides protection against CSV formula injection (DDE injection).
"""

from __future__ import annotations

import re
from typing import Any

from dbshield.verification.normalizer import (
    is_sensitive_parameter_name,
    sanitize_snippet,
)

# Additional output redaction patterns for JSON/CSV/Text reports
_EXTENDED_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Generic key=value or "key": "value" for sensitive terms
    (
        re.compile(
            r'(?i)(["\']?(?:db_password|database_password|db_pass|secret_token|private_key)["\']?\s*[:=]\s*["\']?)([^"\'\s&,;]+)(["\']?)'
        ),
        r"\1[REDACTED]\3",
    ),
    # Connection strings: mysql://user:pass@host/db or mongodb://user:pass@host
    (
        re.compile(r"(?i)([a-z0-9+.-]+://[^:]+:)([^@]+)(@[^\s/]+)"),
        r"\1[REDACTED]\3",
    ),
]

# Dangerous leading characters in spreadsheets that can trigger formula execution (CSV Injection)
_FORMULA_INJECTION_CHARS: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r", "\n")
_WHITESPACE_AND_CONTROL: str = " \t\r\n\v\f"

# Parameter names considered sensitive in query strings
_SENSITIVE_QUERY_PARAM_NAMES: set[str] = {
    "token",
    "access_token",
    "refresh_token",
    "auth_token",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "key",
    "password",
    "passwd",
    "pwd",
    "authorization",
    "auth",
    "session",
    "session_id",
    "sessionid",
    "csrf",
    "otp",
}


def redact_text(text: str) -> str:
    """Sanitize secrets, tokens, passwords, and sensitive credentials from any text."""
    if not text:
        return ""
    # Run Phase 7 baseline snippet redactions
    cleaned = sanitize_snippet(text)
    # Run extended secret pattern filters
    for pattern, replacement in _EXTENDED_SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def escape_csv_formula(value: Any) -> str:
    """Neutralize potential CSV formula injection in spreadsheet applications.

    If a string value begins with dangerous spreadsheet formula characters
    ('=', '+', '-', '@', tab, carriage return, or newline), or contains
    whitespace/control prefixes before formula triggers, prepend a single quote (')
    to instruct spreadsheet parsers (Excel, LibreOffice, Google Sheets) to treat
    the cell as literal text rather than executable formula/DDE code.
    Also protects multiline cell values containing formula triggers after line breaks.
    """
    if value is None:
        return ""
    str_val = str(value)
    if not str_val:
        return ""
    # Already escaped with text marker
    if str_val.startswith("'"):
        return str_val
    # Check if value begins with formula characters after stripping leading whitespace and control chars
    stripped = str_val.lstrip(_WHITESPACE_AND_CONTROL)
    if stripped.startswith(("=", "+", "-", "@")) or str_val.startswith(("\t", "\r", "\n")):
        return f"'{str_val}"
    # Check multiline values where subsequent lines could trigger formula execution
    if "\n" in str_val or "\r" in str_val:
        lines = str_val.splitlines()
        if any(
            line.lstrip(_WHITESPACE_AND_CONTROL).startswith(("=", "+", "-", "@")) for line in lines
        ):
            return f"'{str_val}"
    return str_val


def is_sensitive_query_param(name: str) -> bool:
    """Check if query parameter key matches known sensitive tokens, passwords, or secrets."""
    clean = name.lower().strip().replace("-", "_").replace(".", "_")
    if clean in _SENSITIVE_QUERY_PARAM_NAMES:
        return True
    if clean == "key":
        return True
    return any(
        p in clean
        for p in (
            "token",
            "secret",
            "password",
            "passwd",
            "apikey",
            "api_key",
            "authorization",
        )
    )


def redact_url(url: str) -> str:
    """Mask sensitive query parameter values in target URL while preserving structure and non-sensitive params.

    Preserves scheme, host, port, path, URL encoding, non-sensitive query values,
    repeated parameters, and fragments. Also masks basic auth credentials in URL authority.
    """
    import urllib.parse

    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
        netloc = parsed.netloc
        if "@" in netloc and ":" in netloc.split("@")[0]:
            netloc = re.sub(r":[^@]+@", ":[REDACTED]@", netloc)

        if not parsed.query:
            if netloc != parsed.netloc:
                return urllib.parse.urlunsplit(
                    (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
                )
            return url

        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            return url

        redacted_pairs: list[tuple[str, str]] = []
        has_redactions = False
        for k, v in pairs:
            if is_sensitive_query_param(k):
                redacted_pairs.append((k, "[REDACTED]"))
                has_redactions = True
            else:
                redacted_pairs.append((k, v))

        if not has_redactions and netloc == parsed.netloc:
            return url

        new_query = urllib.parse.urlencode(redacted_pairs, doseq=True, safe="[]:")
        return urllib.parse.urlunsplit(
            (parsed.scheme, netloc, parsed.path, new_query, parsed.fragment)
        )
    except Exception:
        return url


def redact_parameter(name: str) -> str:
    """Return a sanitized parameter reference."""
    if is_sensitive_parameter_name(name):
        return f"[REDACTED_PARAM:{name[:3]}***]" if len(name) > 3 else "[REDACTED_PARAM]"
    return name
