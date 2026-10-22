"""Unit tests for SessionManager target binding, isolation, and lifecycle tracking."""

import pytest

from dbshield.auth.manager import SessionManager
from dbshield.exceptions import AuthenticationError
from dbshield.models.auth import AuthConfig, AuthState, AuthType
from dbshield.models.http import HTTPResponse


def test_session_manager_initial_state() -> None:
    """Verify session manager states based on auth profile."""
    unauth = SessionManager(AuthConfig(auth_type=AuthType.NONE))
    assert unauth.state == AuthState.NOT_CONFIGURED

    bearer = SessionManager(AuthConfig(auth_type=AuthType.BEARER, token="test-token"))
    assert bearer.state == AuthState.CONFIGURED


def test_session_manager_origin_normalization_and_binding() -> None:
    """Verify origin extraction and target binding."""
    sm = SessionManager()
    assert sm.target_origin is None

    sm.bind_target("https://example.com:443/login?q=1")
    assert sm.target_origin == "https://example.com"

    # Subsequent bind calls do not overwrite initial binding
    sm.bind_target("https://other.com")
    assert sm.target_origin == "https://example.com"


def test_session_manager_origin_isolation_prevents_credential_leakage() -> None:
    """CRITICAL SECURITY TEST: Ensure credentials cannot be applied to cross-origin targets."""
    auth = AuthConfig(auth_type=AuthType.BEARER, token="secret-auth-token")
    sm = SessionManager(auth_config=auth, target_origin="https://authorized.example.com")

    # In-origin destination succeeds
    headers, _ = sm.apply_auth("https://authorized.example.com/api/v1/profile")
    assert headers["Authorization"] == "Bearer secret-auth-token"

    # Cross-origin destination MUST raise AuthenticationError
    with pytest.raises(AuthenticationError) as exc_info:
        sm.apply_auth("https://unauthorized-destination.com/steal")

    assert "Refused to transmit session credentials" in exc_info.value.message
    assert exc_info.value.context["session_origin"] == "https://authorized.example.com"


def test_session_cookie_recording_and_persistence() -> None:
    """Verify Set-Cookie headers are parsed and persisted in session cookie store."""
    sm = SessionManager(target_origin="https://example.com")
    assert sm.cookies == {}

    # Simulate response with Set-Cookie header
    headers = {"Set-Cookie": "session_id=sess_abc123; Path=/; Secure; HttpOnly"}
    sm.record_cookies_from_headers(headers)
    assert sm.cookies.get("session_id") == "sess_abc123"

    # Merge caller cookies with stored cookies
    req_headers, req_cookies = sm.apply_auth(
        "https://example.com/data",
        cookies={"caller_flag": "1"},
    )
    assert req_cookies["session_id"] == "sess_abc123"
    assert req_cookies["caller_flag"] == "1"


def test_session_state_transitions() -> None:
    """Verify explainable authentication state transitions per requirements."""
    auth = AuthConfig(auth_type=AuthType.BEARER, token="token-1")
    sm = SessionManager(auth_config=auth)
    assert sm.state == AuthState.CONFIGURED

    # 1. HTTP 200 does NOT claim AUTHENTICATED; transitions to UNKNOWN
    resp_200 = HTTPResponse(url="https://example.com/api", status_code=200)
    sm.update_from_response(resp_200)
    assert sm.state == AuthState.UNKNOWN

    # 2. HTTP 401 transitions to UNAUTHENTICATED
    resp_401 = HTTPResponse(url="https://example.com/api", status_code=401)
    sm.update_from_response(resp_401)
    assert sm.state == AuthState.UNAUTHENTICATED

    # 3. HTTP 403 preserves state (does NOT assume expired session)
    resp_403 = HTTPResponse(url="https://example.com/api", status_code=403)
    sm.update_from_response(resp_403)
    assert sm.state == AuthState.UNAUTHENTICATED


def test_session_reset_and_invalidation() -> None:
    """Verify session reset and explicit invalidation lifecycle."""
    init_cookies = {"remember_token": "rem_123"}
    auth = AuthConfig(auth_type=AuthType.COOKIE, cookies=init_cookies)
    sm = SessionManager(auth_config=auth)

    # Ingest new cookies
    sm.record_cookies_from_headers({"Set-Cookie": "dynamic_token=dyn_456"})
    assert len(sm.cookies) == 2

    # Invalidate session
    sm.invalidate()
    assert len(sm.cookies) == 0
    assert sm.state == AuthState.EXPIRED

    # Reset session restores initial config
    sm.reset()
    assert sm.cookies == init_cookies
    assert sm.state == AuthState.CONFIGURED
