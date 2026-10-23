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
_FORMULA_INJECTION_CHARS: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


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
    ('=', '+', '-', '@', tab, or carriage return), prepend a single quote (')
    to instruct spreadsheet parsers (Excel, LibreOffice, Google Sheets) to treat
    the cell as literal text rather than executable formula/DDE code.
    """
    if value is None:
        return ""
    str_val = str(value)
    if not str_val:
        return ""
    # Strip leading whitespace before checking for formula triggers
    stripped = str_val.lstrip(" ")
    if stripped.startswith(_FORMULA_INJECTION_CHARS):
        return f"'{str_val}"
    return str_val


def redact_parameter(name: str) -> str:
    """Return a sanitized parameter reference."""
    if is_sensitive_parameter_name(name):
        return f"[REDACTED_PARAM:{name[:3]}***]" if len(name) > 3 else "[REDACTED_PARAM]"
    return name
