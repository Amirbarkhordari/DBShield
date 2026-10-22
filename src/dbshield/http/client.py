"""Safe, scope-aware HTTP client built on httpx.

Enforces pre-request scope authorization, strict redirect destination revalidation,
explicit timeout budgets, error translation, and sensitive-data redaction in logs.
"""

import logging
import time
from typing import Any

import httpx

from dbshield.exceptions import (
    HTTPClientError,
    NetworkError,
    ScopeViolationError,
)
from dbshield.logging_config import SensitiveDataFilter
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
            client: Optional pre-configured httpx.Client (for dependency injection).
            transport: Optional custom transport (for mock testing).
        """
        self.scope_manager = scope_manager
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl

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
        method: str,
        url: str | Target,
        follow_redirects: bool = True,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: Any | None = None,
        json: Any | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute an HTTP request after enforcing scope validation and redirect safety.

        Raises:
            ScopeViolationError: If target URL or any redirect destination is out of scope.
            NetworkError: If connection fails, times out, or DNS fails.
            HTTPClientError: If maximum redirect hops are exceeded or protocol error occurs.
        """
        # 1. Pre-flight Scope Check
        target = self.scope_manager.assert_in_scope(url)
        current_url = target.full_url
        current_method = method.upper()

        redirect_count = 0
        req_headers = headers.copy() if headers else {}

        while True:
            # Re-verify scope on every hop
            self.scope_manager.assert_in_scope(current_url)

            scrubbed_url = SensitiveDataFilter.redact(current_url)
            logger.debug("Dispatching HTTP %s to %s", current_method, scrubbed_url)

            start_time = time.monotonic()
            try:
                # Use follow_redirects=False to intercept every redirect hop
                response = self._client.request(
                    method=current_method,
                    url=current_url,
                    headers=req_headers,
                    params=params if redirect_count == 0 else None,
                    data=data if redirect_count == 0 else None,
                    json=json if redirect_count == 0 else None,
                    follow_redirects=False,
                    **kwargs,
                )
            except httpx.TimeoutException as exc:
                duration = time.monotonic() - start_time
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
                and response.status_code in REDIRECT_STATUS_CODES
                and "location" in response.headers
            ):
                redirect_count += 1
                if redirect_count > self.max_redirects:
                    raise HTTPClientError(
                        message=f"Exceeded maximum redirect limit of {self.max_redirects} hops.",
                        cause=f"Server returned circular or excessive redirects at '{scrubbed_url}'.",
                        remedy=f"Increase max_redirects limit beyond {self.max_redirects} if deep redirect chains are expected.",
                        context={"hops": redirect_count, "url": scrubbed_url},
                    )

                raw_location = response.headers["location"]

                # 3. CRITICAL: Validate redirect destination BEFORE following
                try:
                    new_target = self.scope_manager.validate_redirect(current_url, raw_location)
                except ScopeViolationError as exc:
                    logger.warning(
                        "Blocked redirect to out-of-scope destination: %s",
                        SensitiveDataFilter.redact(raw_location),
                    )
                    raise exc

                # Adjust method per HTTP RFC specs (303 -> GET)
                if response.status_code == 303 and current_method != "HEAD":
                    current_method = "GET"

                current_url = new_target.full_url
                target = new_target
                continue

            # Request complete without further redirects
            return response

    def get(self, url: str | Target, **kwargs: Any) -> httpx.Response:
        """Convenience method for GET requests."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str | Target, **kwargs: Any) -> httpx.Response:
        """Convenience method for POST requests."""
        return self.request("POST", url, **kwargs)
