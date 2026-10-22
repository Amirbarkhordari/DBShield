"""Integration tests for SafeHTTPClient using mock transport."""

import httpx
import pytest

from dbshield.exceptions import (
    HTTPClientError,
    NetworkError,
    ScopeViolationError,
)
from dbshield.http.client import SafeHTTPClient
from dbshield.scope.manager import ScopeManager


def test_in_scope_request_success() -> None:
    """Verify in-scope GET request succeeds and parses response."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok", "app": "test"})

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    with SafeHTTPClient(scope_manager=scope, transport=transport) as client:
        response = client.get("https://example.com/api/status")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_out_of_scope_request_blocked_before_transmission() -> None:
    """CRITICAL SECURITY TEST: Client must refuse out-of-scope requests before hitting transport."""
    mock_called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal mock_called
        mock_called = True
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    with SafeHTTPClient(scope_manager=scope, transport=transport) as client:
        with pytest.raises(ScopeViolationError) as exc_info:
            client.get("https://unauthorized-target.com/login")

        assert "out of authorized scope" in exc_info.value.message
        assert not mock_called, "Network transport was contacted for out-of-scope target!"


def test_in_scope_redirect_followed() -> None:
    """Verify in-scope redirect (302) is followed correctly."""
    request_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_urls.append(str(request.url))
        if str(request.url) == "https://example.com/login":
            return httpx.Response(302, headers={"Location": "/dashboard"})
        return httpx.Response(200, text="Dashboard content")

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    with SafeHTTPClient(scope_manager=scope, transport=transport) as client:
        response = client.get("https://example.com/login", follow_redirects=True)
        assert response.status_code == 200
        assert response.text == "Dashboard content"
        assert len(request_urls) == 2
        assert request_urls[1] == "https://example.com/dashboard"


def test_out_of_scope_redirect_blocked() -> None:
    """CRITICAL SECURITY TEST: Redirect to out-of-scope destination must be blocked before following."""
    visited_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        visited_urls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://evil-attacker.com/steal"})

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    with SafeHTTPClient(scope_manager=scope, transport=transport) as client:
        with pytest.raises(ScopeViolationError) as exc_info:
            client.get("https://example.com/login", follow_redirects=True)

        assert "prohibited by scope policy" in exc_info.value.message
        assert len(visited_urls) == 1
        assert "evil-attacker.com" not in visited_urls[0]


def test_max_redirects_exceeded() -> None:
    """Verify exceeding max_redirects raises HTTPClientError."""

    def handler(request: httpx.Request) -> httpx.Response:
        # Endless circular redirect
        return httpx.Response(302, headers={"Location": "https://example.com/loop"})

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    with SafeHTTPClient(scope_manager=scope, max_redirects=3, transport=transport) as client:
        with pytest.raises(HTTPClientError) as exc_info:
            client.get("https://example.com/loop", follow_redirects=True)

        assert "Exceeded maximum redirect limit" in exc_info.value.message


def test_timeout_handling() -> None:
    """Verify timeout translates to NetworkError."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Mocked read timeout")

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    with SafeHTTPClient(scope_manager=scope, transport=transport) as client:
        with pytest.raises(NetworkError) as exc_info:
            client.get("https://example.com/slow")

        assert "timed out" in exc_info.value.message


def test_connection_error_handling() -> None:
    """Verify connection failure translates to NetworkError."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Failed to establish TCP connection")

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    with SafeHTTPClient(scope_manager=scope, transport=transport) as client:
        with pytest.raises(NetworkError) as exc_info:
            client.get("https://example.com/offline")

        assert "Failed to connect" in exc_info.value.message


def test_resource_cleanup() -> None:
    """Verify client properly closes and manages is_closed state."""
    scope = ScopeManager(allowed_hosts=["example.com"])
    client = SafeHTTPClient(scope_manager=scope)
    assert not client.is_closed
    client.close()
    assert client.is_closed
