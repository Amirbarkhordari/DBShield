"""Unit tests for logging infrastructure and sensitive-data redaction."""

import logging

from dbshield.logging_config import SensitiveDataFilter, configure_logging, correlation_id_ctx


def test_sensitive_data_filter_redaction() -> None:
    """Verify various sensitive secrets are properly masked."""
    filter_ = SensitiveDataFilter()

    # Bearer token in header
    msg1 = "Request Header: Authorization: Bearer secret-token-xyz123"
    assert filter_.redact(msg1) == "Request Header: Authorization: Bearer [REDACTED]"

    # Basic auth
    msg2 = "Header: Authorization: Basic dXNlcjpwYXNz"
    assert filter_.redact(msg2) == "Header: Authorization: Basic [REDACTED]"

    # Cookie
    msg3 = "Cookie: session_id=abc123xyz; auth=true"
    assert filter_.redact(msg3) == "Cookie: [REDACTED]"

    # Password in JSON or key-value
    msg4 = 'User submitted {"username": "admin", "password": "supersecretpassword123"}'
    assert filter_.redact(msg4) == 'User submitted {"username": "admin", "password": "[REDACTED]"}'

    # API Key parameter
    msg5 = "Query string: api_key=ab395028491048591"
    assert filter_.redact(msg5) == "Query string: api_key=[REDACTED]"

    # GitHub token (constructed dynamically to avoid scanner false positives)
    sample_gh_token = "ghp_" + ("1234567890" * 3) + "123456"
    msg6 = f"Using token {sample_gh_token} to clone"
    assert filter_.redact(msg6) == "Using token [REDACTED_GITHUB_TOKEN] to clone"


def test_log_record_filtering_with_correlation_id() -> None:
    """Verify SensitiveDataFilter modifies LogRecord and injects correlation_id."""
    correlation_id_ctx.set("corr-uuid-12345")
    filter_ = SensitiveDataFilter()
    sample_gh_token = "ghp_" + ("1234567890" * 3) + "123456"

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=f"Connecting with token: {sample_gh_token}",
        args=(),
        exc_info=None,
    )

    result = filter_.filter(record)
    assert result is True
    assert record.correlation_id == "corr-uuid-12345"
    assert "[REDACTED_GITHUB_TOKEN]" in record.msg
    assert "ghp_" not in record.msg


def test_configure_logging_integration() -> None:
    """Verify configure_logging configures root logger without exceptions."""
    configure_logging(level="DEBUG", correlation_id="test-run-1")
    logger = logging.getLogger("dbshield.test")
    assert logger.getEffectiveLevel() == logging.DEBUG
