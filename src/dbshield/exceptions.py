"""DBShield exception hierarchy.

Provides structured, actionable exceptions distinguishing configuration,
scope violations, URL validation, network, and CLI errors.
"""

from typing import Any


class DBShieldError(Exception):
    """Base exception for all DBShield framework errors."""

    def __init__(
        self,
        message: str,
        cause: str | None = None,
        remedy: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.cause = cause
        self.remedy = remedy
        self.context = context or {}

    def format_detailed(self) -> str:
        """Format a 3-part structured error message following Linux CLI standards."""
        lines = [f"[-] Error: {self.message}"]
        if self.cause:
            lines.append(f"    Cause: {self.cause}")
        if self.remedy:
            lines.append(f"    Remedy: {self.remedy}")
        return "\n".join(lines)


class ConfigurationError(DBShieldError):
    """Raised when configuration values, environment variables, or config files are invalid."""


class URLValidationError(DBShieldError):
    """Raised when a target URL is malformed, uses an unsupported scheme, or cannot be parsed."""


class ScopeViolationError(DBShieldError):
    """Raised when a request, target, or redirect destination falls outside authorized scope."""


class NetworkError(DBShieldError):
    """Raised when a network-level transmission error occurs (e.g., DNS failure, timeout)."""


class HTTPClientError(DBShieldError):
    """Raised when an HTTP client protocol, redirect limit, or connection failure occurs."""


class DiscoveryError(DBShieldError):
    """Raised when an error occurs during login page retrieval, HTML parsing, or input analysis."""


class AuthenticationError(DBShieldError):
    """Raised when authentication configuration is invalid, credentials fail, or session errors occur."""


class CLIExecutionError(DBShieldError):
    """Raised when CLI command execution fails due to invalid parameters or runtime conditions."""
