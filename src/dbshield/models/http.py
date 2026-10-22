"""HTTP request and response data models for DBShield.

Provides structured, immutable, and validated representations of outbound
HTTP requests and safe, bounded HTTP responses with complete metadata.
"""

import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class HTTPMethod(StrEnum):
    """Supported standard HTTP request methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class HTTPRequest(BaseModel):
    """Structured representation of an outbound HTTP request."""

    model_config = ConfigDict(frozen=True)

    url: str = Field(description="Target URL endpoint.")
    method: HTTPMethod = Field(default=HTTPMethod.GET, description="HTTP request method.")
    headers: dict[str, str] = Field(default_factory=dict, description="Request HTTP headers.")
    params: dict[str, Any] = Field(default_factory=dict, description="URL query parameters.")
    data: Any = Field(default=None, description="Form or raw body data.")
    json_data: Any = Field(default=None, description="JSON body payload.")
    timeout: float = Field(default=10.0, gt=0.0, le=300.0, description="Timeout budget in seconds.")
    follow_redirects: bool = Field(
        default=True, description="Whether to follow in-scope redirects."
    )
    max_redirects: int = Field(default=5, ge=0, le=30, description="Maximum redirect hops allowed.")
    verify_ssl: bool = Field(default=True, description="Whether to verify TLS certificates.")


class CaseInsensitiveDict(dict[str, str]):
    """Dictionary mapping keys case-insensitively while preserving string values."""

    def __init__(self, data: Any = None, **kwargs: Any) -> None:
        super().__init__()
        if data:
            if hasattr(data, "items"):
                for k, v in data.items():
                    super().__setitem__(str(k).lower(), str(v))
            else:
                for k, v in data:
                    super().__setitem__(str(k).lower(), str(v))
        for k, v in kwargs.items():
            super().__setitem__(str(k).lower(), str(v))

    def __getitem__(self, key: str) -> str:
        return super().__getitem__(key.lower())

    def __setitem__(self, key: str, value: str) -> None:
        super().__setitem__(key.lower(), value)

    def __contains__(self, key: object) -> bool:
        return super().__contains__(str(key).lower()) if isinstance(key, str) else False

    def get(self, key: str, default: Any = None) -> Any:
        return super().get(key.lower(), default)


class HTTPResponse(BaseModel):
    """Structured, bounded representation of an HTTP response with operational metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    url: str = Field(description="Final resolved URL following any in-scope redirects.")
    status_code: int = Field(description="HTTP status code.")
    headers: CaseInsensitiveDict = Field(
        default_factory=CaseInsensitiveDict, description="Case-insensitive response headers."
    )
    body: str = Field(default="", description="Safe, bounded response body text.")
    content_bytes: bytes = Field(default=b"", repr=False, description="Raw response content bytes.")
    content_type: str | None = Field(
        default=None, description="Response Content-Type header value."
    )
    content_length: int | None = Field(
        default=None, description="Response Content-Length in bytes."
    )
    redirect_history: list[str] = Field(
        default_factory=list, description="List of followed redirect URLs."
    )
    elapsed_seconds: float = Field(
        default=0.0, ge=0.0, description="Total request elapsed time in seconds."
    )
    request_method: str = Field(default="GET", description="HTTP method used for request.")
    truncated: bool = Field(
        default=False, description="Whether response body exceeded limit and was truncated."
    )
    error_message: str | None = Field(
        default=None, description="Operational or transport error description."
    )

    @field_validator("headers", mode="before")
    @classmethod
    def _validate_headers(cls, v: Any) -> CaseInsensitiveDict:
        return CaseInsensitiveDict(v)

    def get_header(self, name: str, default: str | None = None) -> str | None:
        """Lookup response header case-insensitively."""
        val = self.headers.get(name.lower(), default)
        return str(val) if val is not None else default

    @property
    def is_success(self) -> bool:
        """Return True if status code indicates success (2xx)."""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """Return True if status code is an HTTP redirect (3xx)."""
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        """Return True if status code indicates client error (4xx)."""
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        """Return True if status code indicates server error (5xx)."""
        return 500 <= self.status_code < 600

    @property
    def text(self) -> str:
        """Duck-typing property matching httpx.Response.text."""
        return self.body

    @property
    def content(self) -> bytes:
        """Duck-typing property matching httpx.Response.content."""
        return self.content_bytes

    def json(self, *_args: Any, **_kwargs: Any) -> Any:
        """Parse response body as JSON.

        Raises:
            ValueError: If body is empty or not valid JSON.
        """
        if not self.body:
            raise ValueError("Response body is empty.")
        return json.loads(self.body)

    def to_safe_dict(self) -> dict[str, Any]:
        """Return a serialized dictionary representation safe for reporting."""
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": self.headers,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "redirect_history": self.redirect_history,
            "elapsed_seconds": self.elapsed_seconds,
            "request_method": self.request_method,
            "is_success": self.is_success,
            "truncated": self.truncated,
            "error_message": self.error_message,
            "body_snippet": self.body[:500] if len(self.body) > 500 else self.body,
        }
