"""Authentication configuration and state models for DBShield.

Defines explicit authentication profiles, credentials representations with
zero-leak redaction guarantees, and authentication lifecycle states.
"""

import base64
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AuthType(StrEnum):
    """Supported authentication mechanisms."""

    NONE = "none"
    BEARER = "bearer"
    BASIC = "basic"
    HEADER = "header"
    COOKIE = "cookie"


class AuthState(StrEnum):
    """Authentication and session lifecycle states."""

    NOT_CONFIGURED = "not_configured"
    CONFIGURED = "configured"
    AUTHENTICATED = "authenticated"
    UNAUTHENTICATED = "unauthenticated"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class AuthConfig(BaseModel):
    """Configuration model for selecting and parameterizing an authentication method."""

    model_config = ConfigDict(frozen=True)

    auth_type: AuthType = Field(
        default=AuthType.NONE, description="Selected authentication mechanism."
    )
    token: str | None = Field(default=None, description="Bearer token string.")
    username: str | None = Field(default=None, description="Basic authentication username.")
    password: str | None = Field(default=None, description="Basic authentication password.")
    custom_headers: dict[str, str] = Field(
        default_factory=dict, description="Custom authentication headers (e.g., X-API-Key)."
    )
    cookies: dict[str, str] = Field(
        default_factory=dict, description="Explicit initial session cookies."
    )

    @model_validator(mode="after")
    def validate_auth_parameters(self) -> "AuthConfig":
        """Validate that required parameters exist for the chosen authentication type."""
        if self.auth_type == AuthType.BEARER:
            if not self.token or not self.token.strip():
                raise ValueError("Bearer authentication requires a non-empty 'token'.")

        elif self.auth_type == AuthType.BASIC:
            if not self.username or not self.username.strip():
                raise ValueError("Basic authentication requires a non-empty 'username'.")
            if self.password is None:
                raise ValueError("Basic authentication requires a 'password'.")

        elif self.auth_type == AuthType.HEADER and not self.custom_headers:
            raise ValueError("Header authentication requires 'custom_headers' to be configured.")

        elif self.auth_type == AuthType.COOKIE and not self.cookies:
            raise ValueError("Cookie authentication requires 'cookies' to be configured.")

        return self

    def build_headers(self) -> dict[str, str]:
        """Construct authentication headers to attach to outbound requests."""
        headers: dict[str, str] = {}

        if self.auth_type == AuthType.BEARER and self.token:
            headers["Authorization"] = f"Bearer {self.token.strip()}"

        elif self.auth_type == AuthType.BASIC and self.username and self.password is not None:
            user_pass = f"{self.username}:{self.password}".encode()
            b64_val = base64.b64encode(user_pass).decode("ascii")
            headers["Authorization"] = f"Basic {b64_val}"

        elif self.auth_type == AuthType.HEADER:
            headers.update(self.custom_headers)

        return headers

    def to_safe_dict(self) -> dict[str, Any]:
        """Return a serialized dictionary representation safe for logs and reports (secrets masked)."""
        safe_custom_headers = dict.fromkeys(self.custom_headers, "[REDACTED]")
        safe_cookies = dict.fromkeys(self.cookies, "[REDACTED]")

        return {
            "auth_type": self.auth_type.value,
            "token": "[REDACTED]" if self.token else None,
            "username": self.username,
            "password": "[REDACTED]" if self.password is not None else None,
            "custom_headers": safe_custom_headers,
            "cookies": safe_cookies,
        }

    def __repr__(self) -> str:
        safe_view = self.to_safe_dict()
        return (
            f"AuthConfig(auth_type={safe_view['auth_type']}, "
            f"username={safe_view['username']!r}, "
            f"token={safe_view['token']!r}, "
            f"custom_headers={list(self.custom_headers.keys())}, "
            f"cookies={list(self.cookies.keys())})"
        )
