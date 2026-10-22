"""Integration tests for DiscoveryEngine with mocked HTTP transports."""

import httpx

from dbshield.discovery.engine import DiscoveryEngine
from dbshield.http.client import SafeHTTPClient
from dbshield.models.discovery import (
    DiscoveryStatus,
    PageClassification,
)
from dbshield.scope.manager import ScopeManager


def test_discovery_engine_successful_login_page() -> None:
    html_body = """
    <!DOCTYPE html>
    <html>
    <head><title>Secure Enterprise Portal</title></head>
    <body>
        <h2>Sign In</h2>
        <form id="portal-login" action="/v1/auth" method="post">
            <input type="hidden" name="csrf_token" value="dummy" />
            <input type="text" name="username" placeholder="Username" required />
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit">Log In</button>
        </form>
    </body>
    </html>
    """
    request_log: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_log.append(request)
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text=html_body,
        )

    scope_mgr = ScopeManager(allowed_hosts=["app.example.com"], strict_mode=True)
    transport = httpx.MockTransport(handler)
    client = SafeHTTPClient(scope_manager=scope_mgr, transport=transport)

    engine = DiscoveryEngine(scope_manager=scope_mgr, http_client=client)
    result = engine.discover("https://app.example.com/login")

    # Verify only 1 HTTP request made (zero crawling, zero form submissions)
    assert len(request_log) == 1
    assert request_log[0].url == "https://app.example.com/login"
    assert request_log[0].method == "GET"

    # Verify DiscoveryResult
    assert result.status == DiscoveryStatus.COMPLETED
    assert result.page_classification == PageClassification.LOGIN_FORM_DETECTED
    assert result.http_status_code == 200
    assert result.page_title == "Secure Enterprise Portal"
    assert result.summary.total_forms == 1
    assert result.summary.login_forms == 1
    assert result.summary.password_fields == 1
    assert result.summary.username_fields == 1
    assert result.summary.csrf_fields == 1

    form = result.forms[0]
    assert form.form_id == "portal-login"
    assert form.resolved_action == "https://app.example.com/v1/auth"
    assert form.is_action_in_scope is True
    assert form.is_login_candidate is True


def test_discovery_engine_out_of_scope_target_blocked() -> None:
    scope_mgr = ScopeManager(allowed_hosts=["authorized.example.com"], strict_mode=True)
    engine = DiscoveryEngine(scope_manager=scope_mgr)

    result = engine.discover("https://unauthorized.target.com/login")

    assert result.status == DiscoveryStatus.BLOCKED_BY_SCOPE
    assert result.page_classification == PageClassification.PAGE_INACCESSIBLE_OR_BLOCKED
    assert any("outside authorized scope" in err for err in result.errors)


def test_discovery_engine_redirect_to_out_of_scope_blocked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=302,
            headers={"Location": "https://attacker.evil.com/login"},
        )

    scope_mgr = ScopeManager(allowed_hosts=["app.example.com"], strict_mode=True)
    transport = httpx.MockTransport(handler)
    client = SafeHTTPClient(scope_manager=scope_mgr, transport=transport)

    engine = DiscoveryEngine(scope_manager=scope_mgr, http_client=client)
    result = engine.discover("https://app.example.com/login")

    assert result.status == DiscoveryStatus.BLOCKED_BY_SCOPE
    assert result.page_classification == PageClassification.PAGE_INACCESSIBLE_OR_BLOCKED
    assert any("out-of-scope" in err for err in result.errors)


def test_discovery_engine_out_of_scope_form_action_flagged_and_never_contacted() -> None:
    html_body = """
    <form action="https://external-auth.other.com/api/post" method="post">
        <input type="text" name="user" />
        <input type="password" name="pass" />
    </form>
    """
    request_log: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_log.append(request)
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            text=html_body,
        )

    scope_mgr = ScopeManager(allowed_hosts=["app.example.com"], strict_mode=True)
    transport = httpx.MockTransport(handler)
    client = SafeHTTPClient(scope_manager=scope_mgr, transport=transport)

    engine = DiscoveryEngine(scope_manager=scope_mgr, http_client=client)
    result = engine.discover("https://app.example.com/login")

    # Exactly 1 request made to app.example.com. Zero requests to external-auth.other.com!
    assert len(request_log) == 1
    assert "external-auth.other.com" not in str(request_log[0].url)

    assert result.status == DiscoveryStatus.COMPLETED_WITH_WARNINGS
    assert result.summary.action_urls_out_of_scope == 1
    assert result.forms[0].is_action_in_scope is False
    assert any("outside authorized scope and must not be contacted" in w for w in result.warnings)


def test_discovery_engine_non_html_content_type_warning() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            text='{"message": "API endpoint, not HTML"}',
        )

    scope_mgr = ScopeManager(allowed_hosts=["app.example.com"], strict_mode=True)
    transport = httpx.MockTransport(handler)
    client = SafeHTTPClient(scope_manager=scope_mgr, transport=transport)

    engine = DiscoveryEngine(scope_manager=scope_mgr, http_client=client)
    result = engine.discover("https://app.example.com/api/login")

    assert result.status == DiscoveryStatus.COMPLETED_WITH_WARNINGS
    assert result.summary.total_forms == 0
    assert any("not text/html" in w for w in result.warnings)


def test_discovery_engine_timeout_handling() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Socket timeout")

    scope_mgr = ScopeManager(allowed_hosts=["app.example.com"], strict_mode=True)
    transport = httpx.MockTransport(handler)
    client = SafeHTTPClient(scope_manager=scope_mgr, transport=transport)

    engine = DiscoveryEngine(scope_manager=scope_mgr, http_client=client)
    result = engine.discover("https://app.example.com/login")

    assert result.status == DiscoveryStatus.FAILED
    assert result.page_classification == PageClassification.PAGE_INACCESSIBLE_OR_BLOCKED
    assert any("timed out" in err for err in result.errors)
