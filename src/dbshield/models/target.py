"""Target URL data model with strict normalization and validation."""

from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from dbshield.exceptions import URLValidationError

SUPPORTED_SCHEMES = {"http", "https"}
DEFAULT_PORTS = {"http": 80, "https": 443}


class Target(BaseModel):
    """Validated, normalized target web application endpoint for DBShield."""

    model_config = ConfigDict(frozen=True)

    raw_url: str = Field(description="Original user-supplied URL string.")
    scheme: str = Field(description="Normalized protocol scheme (http or https).")
    host: str = Field(description="Normalized lowercase hostname or IP address.")
    port: int = Field(description="Effective TCP port number.")
    path: str = Field(default="/", description="URL path component.")
    query: str | None = Field(default=None, description="URL query string component.")

    @classmethod
    def from_url(cls, url: str) -> "Target":
        """Parse, validate, and normalize a URL into a Target model.

        Raises:
            URLValidationError: If URL is malformed, missing host, or uses an unsupported scheme.
        """
        if not url or not isinstance(url, str):
            raise URLValidationError(
                message="Target URL cannot be empty.",
                cause="An empty or non-string URL was provided.",
                remedy="Provide a valid HTTP or HTTPS URL (e.g., https://example.com/login).",
            )

        stripped_url = url.strip()
        parsed = urlparse(stripped_url)

        # Require explicit scheme
        if not parsed.scheme:
            raise URLValidationError(
                message=f"Target URL '{url}' is missing a protocol scheme.",
                cause="No scheme component found in URL.",
                remedy="Prefix the URL with 'https://' or 'http://' (e.g., https://example.com).",
            )

        scheme = parsed.scheme.lower()
        if scheme not in SUPPORTED_SCHEMES:
            raise URLValidationError(
                message=f"Unsupported scheme '{scheme}' in URL '{url}'.",
                cause=f"Scheme '{scheme}' is not supported. DBShield only tests web applications via HTTP/HTTPS.",
                remedy=f"Use one of the supported schemes: {', '.join(sorted(SUPPORTED_SCHEMES))}.",
            )

        if not parsed.hostname:
            raise URLValidationError(
                message=f"Target URL '{url}' is missing a valid hostname.",
                cause="Hostname could not be extracted from URL authority.",
                remedy="Ensure the URL contains a valid domain name or IP address (e.g., https://example.com).",
            )

        host = parsed.hostname.lower()
        try:
            port = parsed.port if parsed.port is not None else DEFAULT_PORTS[scheme]
        except ValueError as exc:
            raise URLValidationError(
                message=f"Invalid port in URL '{url}'.",
                cause=str(exc),
                remedy="Specify a valid TCP port between 1 and 65535.",
            ) from exc

        if not (1 <= port <= 65535):
            raise URLValidationError(
                message=f"Invalid port number '{port}' in URL '{url}'.",
                cause="Port number is outside valid TCP port range (1-65535).",
                remedy="Specify a valid TCP port between 1 and 65535.",
            )

        path = parsed.path if parsed.path else "/"
        query = parsed.query if parsed.query else None

        return cls(
            raw_url=stripped_url,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            query=query,
        )

    @field_validator("scheme")
    @classmethod
    def validate_scheme(cls, v: str) -> str:
        if v not in SUPPORTED_SCHEMES:
            raise ValueError(f"Scheme must be one of {SUPPORTED_SCHEMES}")
        return v

    @property
    def is_tls(self) -> bool:
        """Return True if target uses HTTPS."""
        return self.scheme == "https"

    @property
    def origin(self) -> str:
        """Return origin string (e.g. 'https://example.com:8443' or 'https://example.com')."""
        default_port = DEFAULT_PORTS.get(self.scheme)
        if self.port == default_port:
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def base_url(self) -> str:
        """Return base URL with origin and path."""
        return f"{self.origin}{self.path}"

    @property
    def full_url(self) -> str:
        """Return fully qualified URL string with path and query."""
        if self.query:
            return f"{self.origin}{self.path}?{self.query}"
        return f"{self.origin}{self.path}"
