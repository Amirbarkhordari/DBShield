"""Safe, scope-aware HTTP client built on httpx.

Enforces pre-request scope authorization, strict redirect destination revalidation,
explicit timeout budgets, error translation, sensitive-data redaction in logs,
session management, and cross-origin credential isolation.
"""

import logging
import time
from typing import Any

import httpx

from dbshield.auth.manager import SessionManager
from dbshield.exceptions import (
    HTTPClientError,
    NetworkError,
    ScopeViolationError,
)
from dbshield.logging_config import SensitiveDataFilter
from dbshield.models.http import CaseInsensitiveDict, HTTPMethod, HTTPResponse
from dbshield.models.target import Target
from dbshield.scope.manager import ScopeManager

logger = logging.getLogger("dbshield.http")

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


class SafeHTTPClient:
    """HTTP client wrapper enforcing scope boundaries, redirect validation, and resource safety."""

    def __init__(
        self,
        scope_manager: ScopeManager,
        timeout: float = 10.0,
        max_redirects: int = 5,
        user_agent: str = "DBShield/0.1.0 (Database Vulnerability Assessment Framework)",
        verify_ssl: bool = True,
        max_response_size_bytes: int = 5 * 1024 * 1024,
        session_manager: SessionManager | None = None,
        client: httpx.Client | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Initialize SafeHTTPClient.

        Args:
            scope_manager: Authoritative ScopeManager instance.
            timeout: Maximum connection and read timeout in seconds.
            max_redirects: Maximum number of redirects to follow.
            user_agent: Custom User-Agent string.
            verify_ssl: Whether to verify TLS/SSL certificates.
            max_response_size_bytes: Configurable limit on response body size (default: 5MB).
            session_manager: Optional SessionManager for managing cookies and credentials.
            client: Optional pre-configured httpx.Client (for dependency injection).
            transport: Optional custom transport (for mock testing).
        """
        self.scope_manager = scope_manager
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.max_response_size_bytes = max_response_size_bytes
        self.session_manager = session_manager

        headers = {"User-Agent": self.user_agent}

        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                timeout=httpx.Timeout(self.timeout),
                headers=headers,
                verify=self.verify_ssl,
                transport=transport,
                follow_redirects=False,  # Redirects handled manually for scope safety
            )
            self._owns_client = True

    @property
    def is_closed(self) -> bool:
        """Check if underlying client is closed."""
        return self._client.is_closed

    def close(self) -> None:
        """Close underlying HTTP client and release resources."""
        if self._owns_client and not self._client.is_closed:
            self._client.close()

    def __enter__(self) -> "SafeHTTPClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def request(
        self,
        method: str | HTTPMethod,
        url: str | Target,
        follow_redirects: bool = True,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: Any | None = None,
        json: Any | None = None,
        cookies: dict[str, str] | None = None,
        session_manager: SessionManager | None = None,
        **kwargs: Any,
    ) -> HTTPResponse:
        """Execute an HTTP request after enforcing scope validation and redirect safety.

        Raises:
            ScopeViolationError: If target URL or any redirect destination is out of scope.
            NetworkError: If connection fails, times out, or DNS fails.
            HTTPClientError: If maximum redirect hops are exceeded or protocol error occurs.
            AuthenticationError: If request attempts cross-origin credential transmission.
        """
        # Resolve active session manager (call-level takes precedence over client-level)
        active_session = session_manager if session_manager is not None else self.session_manager

        # 1. Pre-flight Scope Check
        target = self.scope_manager.assert_in_scope(url)
        current_url = target.full_url
        current_method = method.value if isinstance(method, HTTPMethod) else str(method).upper()

        redirect_count = 0
        redirect_history: list[str] = []
        req_headers = dict(headers or {})
        req_cookies = dict(cookies or {})

        # Bind session origin and apply auth if session active
        if active_session is not None:
            active_session.bind_target(target)
            req_headers, req_cookies = active_session.apply_auth(
                target, headers=req_headers, cookies=req_cookies
            )

        initial_origin = SessionManager._normalize_origin(target.full_url)
        start_time = time.monotonic()

        while True:
            # Re-verify scope on every hop
            self.scope_manager.assert_in_scope(current_url)

            scrubbed_url = SensitiveDataFilter.redact(current_url)
            logger.debug("Dispatching HTTP %s to %s", current_method, scrubbed_url)

            hop_start = time.monotonic()
            try:
                # Use follow_redirects=False to intercept every redirect hop
                raw_response = self._client.request(
                    method=current_method,
                    url=current_url,
                    headers=req_headers,
                    cookies=req_cookies if req_cookies else None,
                    params=params if redirect_count == 0 else None,
                    data=data if redirect_count == 0 else None,
                    json=json if redirect_count == 0 else None,
                    follow_redirects=False,
                    **kwargs,
                )
            except httpx.TimeoutException as exc:
                duration = time.monotonic() - hop_start
                raise NetworkError(
                    message=f"Request to '{scrubbed_url}' timed out after {duration:.2f}s.",
                    cause=str(exc),
                    remedy=f"Verify network connectivity or increase timeout beyond {self.timeout}s via DBSHIELD_HTTP_TIMEOUT.",
                    context={"url": scrubbed_url, "timeout": self.timeout},
                ) from exc
            except httpx.ConnectError as exc:
                raise NetworkError(
                    message=f"Failed to connect to host '{target.host}'.",
                    cause=str(exc),
                    remedy="Check if the destination service is running, ports are open, and DNS resolves properly.",
                    context={"host": target.host, "url": scrubbed_url},
                ) from exc
            except httpx.HTTPError as exc:
                raise HTTPClientError(
                    message=f"HTTP protocol error occurred while querying '{scrubbed_url}'.",
                    cause=str(exc),
                    remedy="Check request formatting, headers, or server status.",
                    context={"url": scrubbed_url},
                ) from exc

            # 2. Check for Redirect
            if (
                follow_redirects
                and raw_response.status_code in REDIRECT_STATUS_CODES
                and "location" in raw_response.headers
            ):
                redirect_count += 1
                redirect_history.append(current_url)
                if redirect_count > self.max_redirects:
                    raise HTTPClientError(
                        message=f"Exceeded maximum redirect limit of {self.max_redirects} hops.",
                        cause=f"Server returned circular or excessive redirects at '{scrubbed_url}'.",
                        remedy=f"Increase max_redirects limit beyond {self.max_redirects} if deep redirect chains are expected.",
                        context={"hops": redirect_count, "url": scrubbed_url},
                    )

                raw_location = raw_response.headers["location"]

                # 3. CRITICAL: Validate redirect destination BEFORE following
                try:
                    new_target = self.scope_manager.validate_redirect(current_url, raw_location)
                except ScopeViolationError as exc:
                    logger.warning(
                        "Blocked redirect to out-of-scope destination: %s",
                        SensitiveDataFilter.redact(raw_location),
                    )
                    raise exc

                # Check for cross-origin redirect credential leakage
                new_origin = SessionManager._normalize_origin(new_target.full_url)
                if new_origin != initial_origin:
                    logger.debug(
                        "Redirect origin (%s) differs from initial origin (%s); stripping credentials.",
                        new_origin,
                        initial_origin,
                    )
                    # Strip Authorization and Cookie headers to prevent cross-origin leaks
                    req_headers = {
                        k: v for k, v in req_headers.items() if k.lower() != "authorization"
                    }
                    if active_session is not None:
                        for custom_header in active_session.auth_config.custom_headers:
                            req_headers.pop(custom_header, None)
                    req_cookies = {}

                # Adjust method per HTTP RFC specs (303 -> GET)
                if raw_response.status_code == 303 and current_method != "HEAD":
                    current_method = "GET"

                current_url = new_target.full_url
                target = new_target
                continue

            # Request complete: construct bounded HTTPResponse
            total_elapsed = time.monotonic() - start_time
            raw_content = raw_response.content
            truncated = False

            if len(raw_content) > self.max_response_size_bytes:
                content_bytes = raw_content[: self.max_response_size_bytes]
                truncated = True
                encoding = raw_response.encoding or "utf-8"
                text_body = content_bytes.decode(encoding, errors="replace")
                logger.warning(
                    "Response from %s exceeded %d bytes limit; truncated to %d bytes.",
                    scrubbed_url,
                    self.max_response_size_bytes,
                    len(content_bytes),
                )
            else:
                content_bytes = raw_content
                text_body = raw_response.text

            content_length_header = raw_response.headers.get("content-length")
            content_length = (
                int(content_length_header)
                if content_length_header and content_length_header.isdigit()
                else len(content_bytes)
            )

            http_response = HTTPResponse(
                url=str(raw_response.url),
                status_code=raw_response.status_code,
                headers=CaseInsensitiveDict(raw_response.headers),
                body=text_body,
                content_bytes=content_bytes,
                content_type=raw_response.headers.get("content-type"),
                content_length=content_length,
                redirect_history=redirect_history,
                elapsed_seconds=round(total_elapsed, 4),
                request_method=current_method,
                truncated=truncated,
            )

            # Update session state if session manager attached
            if active_session is not None:
                active_session.update_from_response(http_response)

            return http_response

    def get(self, url: str | Target, **kwargs: Any) -> HTTPResponse:
        """Convenience method for GET requests."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str | Target, **kwargs: Any) -> HTTPResponse:
        """Convenience method for POST requests."""
        return self.request("POST", url, **kwargs)

    def put(self, url: str | Target, **kwargs: Any) -> HTTPResponse:
        """Convenience method for PUT requests."""
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str | Target, **kwargs: Any) -> HTTPResponse:
        """Convenience method for PATCH requests."""
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str | Target, **kwargs: Any) -> HTTPResponse:
        """Convenience method for DELETE requests."""
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str | Target, **kwargs: Any) -> HTTPResponse:
        """Convenience method for HEAD requests."""
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str | Target, **kwargs: Any) -> HTTPResponse:
        """Convenience method for OPTIONS requests."""
        return self.request("OPTIONS", url, **kwargs)
