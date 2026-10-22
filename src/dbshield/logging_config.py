"""Centralized logging infrastructure and sensitive-data redaction.

Ensures structured, timestamped logs across DBShield while strictly redacting
credentials, tokens, cookies, authorization headers, and sensitive query parameters.
"""

import logging
import re
from contextvars import ContextVar
from pathlib import Path

# Context variable for request / operation correlation ID
correlation_id_ctx: ContextVar[str | None] = ContextVar("correlation_id", default=None)

# Regular expressions for detecting and redacting sensitive data
_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Authorization header values
    (
        re.compile(r"(?i)(authorization\s*:\s*)(bearer|basic|token)\s+[^\s,;]+"),
        r"\1\2 [REDACTED]",
    ),
    # Cookies
    (
        re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(set-cookie\s*:\s*)[^\r\n]+"),
        r"\1[REDACTED]",
    ),
    # Specific token signatures (matched before generic key-value pairs)
    (
        re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b"),
        "[REDACTED_JWT]",
    ),
    # Common token / password key-value patterns (JSON or query strings)
    (
        re.compile(
            r'(?i)(["\']?(?:password|passwd|pwd|token|access_token|refresh_token|api_key|secret|client_secret)["\']?\s*[:=]\s*["\']?)(?!\[REDACTED)([^"\'\s&]+)(["\']?)'
        ),
        r"\1[REDACTED]\3",
    ),
]


class SensitiveDataFilter(logging.Filter):
    """Logging filter that scrubs sensitive credentials from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Inject correlation ID if available
        cid = correlation_id_ctx.get()
        record.correlation_id = cid or "-"

        # Redact message if string
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)

        # Redact args if present
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._scrub_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._scrub_value(v) for v in record.args)

        return True

    @classmethod
    def redact(cls, text: str) -> str:
        """Apply all redaction patterns to the provided text."""
        if not text:
            return text
        sanitized = text
        for pattern, replacement in _REDACTION_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    @classmethod
    def _scrub_value(cls, val: object) -> object:
        if isinstance(val, str):
            return cls.redact(val)
        return val


def configure_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    correlation_id: str | None = None,
) -> None:
    """Configure DBShield root logger with standardized formatting and redaction.

    Args:
        level: Logging severity string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path to write persistent log output.
        correlation_id: Optional correlation ID to bind to the current context.
    """
    if correlation_id:
        correlation_id_ctx.set(correlation_id)

    root_logger = logging.getLogger()
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    log_format = "%(asctime)s [%(levelname)s] [%(name)s] [corr:%(correlation_id)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt=log_format, datefmt=date_format)

    redaction_filter = SensitiveDataFilter()

    # Console handler (stderr to keep stdout pure for machine data)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(redaction_filter)
    root_logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redaction_filter)
        root_logger.addHandler(file_handler)
