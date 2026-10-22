"""Integration tests for SafeHTTPClient Phase 3 capabilities: auth, methods, sessions, and redirects."""

import httpx

from dbshield.auth.manager import SessionManager
from dbshield.http.client import SafeHTTPClient
from dbshield.models.auth import AuthConfig, AuthType
from dbshield.scope.manager import ScopeManager


def test_http_methods_dispatch() -> None:
    """Verify all supported HTTP methods are dispatched correctly."""
    recorded_methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded_methods.append(request.method)
        return httpx.Response(200, json={"status": "ok"})

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    with SafeHTTPClient(scope_manager=scope, transport=transport) as client:
        client.get("https://example.com/api")
        client.post("https://example.com/api", json={"a": 1})
        client.put("https://example.com/api", json={"b": 2})
        client.patch("https://example.com/api", data="test")
        client.delete("https://example.com/api")
        client.head("https://example.com/api")
        client.options("https://example.com/api")

    assert recorded_methods == ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def test_bearer_token_authentication_flow() -> None:
    """Verify Bearer token is attached to outbound requests and session state updates."""
    auth_headers_received: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        auth_header = request.headers.get("authorization", "")
        auth_headers_received.append(auth_header)
        if auth_header == "Bearer test-jwt-token":
            return httpx.Response(200, json={"user": "alice"})
        return httpx.Response(401, json={"error": "unauthorized"})

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    auth = AuthConfig(auth_type=AuthType.BEARER, token="test-jwt-token")
    session = SessionManager(auth_config=auth)

    with SafeHTTPClient(
        scope_manager=scope, transport=transport, session_manager=session
    ) as client:
        resp = client.get("https://example.com/protected")
        assert resp.status_code == 200
        assert resp.json()["user"] == "alice"
        assert auth_headers_received == ["Bearer test-jwt-token"]


def test_basic_authentication_flow() -> None:
    """Verify Basic authentication header is attached to outbound requests."""
    auth_headers_received: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        auth_headers_received.append(request.headers.get("authorization", ""))
        return httpx.Response(200, text="admin area")

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    auth = AuthConfig(auth_type=AuthType.BASIC, username="admin", password="password123")
    session = SessionManager(auth_config=auth)

    with SafeHTTPClient(
        scope_manager=scope, transport=transport, session_manager=session
    ) as client:
        resp = client.get("https://example.com/admin")
        assert resp.status_code == 200
        assert auth_headers_received == ["Basic YWRtaW46cGFzc3dvcmQxMjM="]


def test_cookie_issuance_and_reuse() -> None:
    """Verify server Set-Cookie header is captured and retransmitted on subsequent requests."""
    request_cookies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_cookies.append(request.headers.get("cookie", ""))
        if str(request.url) == "https://example.com/login":
            return httpx.Response(
                200,
                headers={"Set-Cookie": "auth_session=secret_token_123; Path=/"},
                text="Logged in",
            )
        return httpx.Response(200, text="Dashboard")

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])
    session = SessionManager()

    with SafeHTTPClient(
        scope_manager=scope, transport=transport, session_manager=session
    ) as client:
        # Request 1: hits /login and receives Set-Cookie
        r1 = client.get("https://example.com/login")
        assert r1.status_code == 200
        assert session.cookies.get("auth_session") == "secret_token_123"

        # Request 2: hits /dashboard; should automatically include cookie
        r2 = client.get("https://example.com/dashboard")
        assert r2.status_code == 200
        assert "auth_session=secret_token_123" in request_cookies[1]


def test_cross_origin_redirect_strips_credentials() -> None:
    """CRITICAL SECURITY TEST: Redirect to a different in-scope origin must strip Authorization & Cookies."""
    captured_headers: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.append(dict(request.headers))
        if str(request.url) == "https://example.com/login":
            # Redirect to another host in the same allowed domain
            return httpx.Response(
                302, headers={"Location": "https://api.example.com/oauth/callback"}
            )
        return httpx.Response(200, text="Oauth endpoint")

    transport = httpx.MockTransport(handler)
    # Scope allows both example.com and api.example.com
    scope = ScopeManager(allowed_hosts=["example.com"], allow_subdomains=True)

    auth = AuthConfig(auth_type=AuthType.BEARER, token="super-secret-bearer")
    session = SessionManager(auth_config=auth, target_origin="https://example.com")
    session.cookies["session_id"] = "cookie123"

    with SafeHTTPClient(
        scope_manager=scope, transport=transport, session_manager=session
    ) as client:
        resp = client.get("https://example.com/login", follow_redirects=True)
        assert resp.status_code == 200
        assert len(captured_headers) == 2

        # Hop 1 (example.com): Credentials included
        assert captured_headers[0].get("authorization") == "Bearer super-secret-bearer"
        assert "session_id=cookie123" in captured_headers[0].get("cookie", "")

        # Hop 2 (api.example.com): Credentials MUST be stripped!
        assert "authorization" not in captured_headers[1]
        assert "session_id=cookie123" not in captured_headers[1].get("cookie", "")


def test_response_size_limiting() -> None:
    """Verify response bodies exceeding max_response_size_bytes are safely truncated."""
    large_payload = "X" * 10000

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=large_payload)

    transport = httpx.MockTransport(handler)
    scope = ScopeManager(allowed_hosts=["example.com"])

    # Limit to 500 bytes
    with SafeHTTPClient(
        scope_manager=scope,
        transport=transport,
        max_response_size_bytes=500,
    ) as client:
        resp = client.get("https://example.com/large")
        assert resp.status_code == 200
        assert resp.truncated is True
        assert len(resp.content) == 500
        assert len(resp.body) == 500
