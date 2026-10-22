"""Unit tests for authentication models and credential redaction."""

import pytest

from dbshield.models.auth import AuthConfig, AuthState, AuthType


def test_auth_enums() -> None:
    """Verify supported auth types and lifecycle states."""
    assert AuthType.NONE == "none"
    assert AuthType.BEARER == "bearer"
    assert AuthType.BASIC == "basic"
    assert AuthType.HEADER == "header"
    assert AuthType.COOKIE == "cookie"

    assert AuthState.NOT_CONFIGURED == "not_configured"
    assert AuthState.CONFIGURED == "configured"
    assert AuthState.AUTHENTICATED == "authenticated"
    assert AuthState.UNAUTHENTICATED == "unauthenticated"
    assert AuthState.EXPIRED == "expired"
    assert AuthState.UNKNOWN == "unknown"


def test_auth_config_unauthenticated() -> None:
    """Verify default unauthenticated configuration."""
    config = AuthConfig(auth_type=AuthType.NONE)
    assert config.auth_type == AuthType.NONE
    assert config.build_headers() == {}
    assert config.to_safe_dict()["auth_type"] == "none"


def test_auth_config_bearer_validation_and_headers() -> None:
    """Verify Bearer token validation, header generation, and redaction."""
    valid = AuthConfig(auth_type=AuthType.BEARER, token="super-secret-token")
    headers = valid.build_headers()
    assert headers["Authorization"] == "Bearer super-secret-token"

    # Missing token raises ValueError
    with pytest.raises(ValueError, match="requires a non-empty 'token'"):
        AuthConfig(auth_type=AuthType.BEARER, token=None)

    with pytest.raises(ValueError, match="requires a non-empty 'token'"):
        AuthConfig(auth_type=AuthType.BEARER, token="   ")


def test_auth_config_basic_validation_and_headers() -> None:
    """Verify Basic authentication validation and Base64 header construction."""
    valid = AuthConfig(auth_type=AuthType.BASIC, username="admin", password="password123")
    headers = valid.build_headers()
    # base64("admin:password123") -> "YWRtaW46cGFzc3dvcmQxMjM="
    assert headers["Authorization"] == "Basic YWRtaW46cGFzc3dvcmQxMjM="

    # Missing username
    with pytest.raises(ValueError, match="requires a non-empty 'username'"):
        AuthConfig(auth_type=AuthType.BASIC, username="", password="pwd")

    # Missing password
    with pytest.raises(ValueError, match="requires a 'password'"):
        AuthConfig(auth_type=AuthType.BASIC, username="admin", password=None)


def test_auth_config_custom_headers_validation() -> None:
    """Verify custom header auth validation and header attachment."""
    valid = AuthConfig(
        auth_type=AuthType.HEADER,
        custom_headers={"X-API-Key": "key-secret-123", "X-Client-ID": "dbshield"},
    )
    headers = valid.build_headers()
    assert headers["X-API-Key"] == "key-secret-123"
    assert headers["X-Client-ID"] == "dbshield"

    # Missing custom headers
    with pytest.raises(ValueError, match="requires 'custom_headers'"):
        AuthConfig(auth_type=AuthType.HEADER, custom_headers={})


def test_auth_config_cookie_validation() -> None:
    """Verify explicit cookie auth validation."""
    valid = AuthConfig(auth_type=AuthType.COOKIE, cookies={"sessionid": "sess-secret-456"})
    assert valid.cookies["sessionid"] == "sess-secret-456"

    # Missing cookies
    with pytest.raises(ValueError, match="requires 'cookies'"):
        AuthConfig(auth_type=AuthType.COOKIE, cookies={})


def test_secret_redaction_guarantees() -> None:
    """CRITICAL SECURITY TEST: Ensure raw secrets are NEVER exposed in safe representations or repr."""
    secret_token = "secret-token-999"
    secret_pass = "super-secret-password"
    secret_cookie = "cookie-value-abc"
    secret_header = "api-key-xyz"

    config = AuthConfig(
        auth_type=AuthType.BASIC,
        username="dbadmin",
        password=secret_pass,
        token=secret_token,
        custom_headers={"X-API-Key": secret_header},
        cookies={"session": secret_cookie},
    )

    safe_view = config.to_safe_dict()
    assert safe_view["password"] == "[REDACTED]"
    assert safe_view["token"] == "[REDACTED]"
    assert safe_view["custom_headers"]["X-API-Key"] == "[REDACTED]"
    assert safe_view["cookies"]["session"] == "[REDACTED]"
    assert safe_view["username"] == "dbadmin"

    repr_str = repr(config)
    assert secret_pass not in repr_str
    assert secret_token not in repr_str
    assert secret_cookie not in repr_str
    assert secret_header not in repr_str
    assert "[REDACTED]" in repr_str
