"""Unit tests for Target Scope Management and boundary validation."""

import pytest

from dbshield.exceptions import ScopeViolationError
from dbshield.scope.manager import ScopeManager


def test_exact_hostname_matching() -> None:
    """Verify exact hostname matching when subdomains are disabled."""
    scope = ScopeManager(allowed_hosts=["example.com"], allow_subdomains=False)

    assert scope.is_host_in_scope("example.com") is True
    assert scope.is_host_in_scope("EXAMPLE.COM") is True  # case-insensitive
    assert scope.is_host_in_scope("example.com.") is True  # trailing dot normalized

    # Subdomains must be rejected when allow_subdomains=False
    assert scope.is_host_in_scope("sub.example.com") is False
    assert scope.is_host_in_scope("api.example.com") is False


def test_subdomain_matching_enabled() -> None:
    """Verify subdomain matching works properly when explicitly enabled."""
    scope = ScopeManager(allowed_hosts=["example.com"], allow_subdomains=True)

    assert scope.is_host_in_scope("example.com") is True
    assert scope.is_host_in_scope("sub.example.com") is True
    assert scope.is_host_in_scope("deep.api.example.com") is True


def test_rejection_of_similarly_named_domains() -> None:
    """CRITICAL SECURITY CHECK: Authorizing example.com must NEVER authorize attacker domains."""
    scope = ScopeManager(allowed_hosts=["example.com"], allow_subdomains=True)

    disallowed_hosts = [
        "example.com.attacker.invalid",
        "example.com.evil.com",
        "attacker-example.com",
        "fakeexample.com",
        "notexample.com",
        "example.org",
        "example.net",
        "192.168.1.1",
    ]

    for hostile_host in disallowed_hosts:
        assert scope.is_host_in_scope(hostile_host) is False, (
            f"Hostile host '{hostile_host}' was unexpectedly authorized!"
        )


def test_scope_port_and_scheme_restrictions() -> None:
    """Verify schemes and ports outside scope are rejected."""
    scope = ScopeManager(
        allowed_hosts=["example.com"],
        allowed_schemes={"https"},  # only HTTPS
        allowed_ports={443, 8443},
    )

    # HTTPS on 443 -> OK
    assert scope.is_url_in_scope("https://example.com/login") is True
    # HTTPS on 8443 -> OK
    assert scope.is_url_in_scope("https://example.com:8443/login") is True
    # HTTP (disallowed scheme) -> False
    assert scope.is_url_in_scope("http://example.com/login") is False
    # HTTPS on disallowed port 9443 -> False
    assert scope.is_url_in_scope("https://example.com:9443/login") is False


def test_assert_in_scope_raises_on_violation() -> None:
    """Verify assert_in_scope raises actionable ScopeViolationError."""
    scope = ScopeManager(allowed_hosts=["app.corp.internal"])

    with pytest.raises(ScopeViolationError) as exc_info:
        scope.assert_in_scope("https://unauthorized.com/login")
    assert "out of authorized scope" in exc_info.value.message
    assert "unauthorized.com" in exc_info.value.message


def test_validate_redirect_in_scope_relative() -> None:
    """Verify relative redirect on the same host succeeds."""
    scope = ScopeManager(allowed_hosts=["example.com"])
    target = scope.validate_redirect("https://example.com/login", "/dashboard?session=1")
    assert target.host == "example.com"
    assert target.path == "/dashboard"
    assert target.query == "session=1"


def test_validate_redirect_in_scope_absolute() -> None:
    """Verify absolute in-scope redirect succeeds."""
    scope = ScopeManager(allowed_hosts=["example.com"])
    target = scope.validate_redirect("https://example.com/login", "https://example.com/portal")
    assert target.host == "example.com"
    assert target.path == "/portal"


def test_validate_redirect_out_of_scope_blocked() -> None:
    """CRITICAL SECURITY CHECK: Out-of-scope redirect destination must raise ScopeViolationError."""
    scope = ScopeManager(allowed_hosts=["example.com"])

    with pytest.raises(ScopeViolationError) as exc_info:
        scope.validate_redirect(
            "https://example.com/login", "https://attacker.evil.com/oauth/steal"
        )
    assert "prohibited by scope policy" in exc_info.value.message
    assert "attacker.evil.com" in str(exc_info.value)


def test_empty_allowed_hosts_strict_mode() -> None:
    """Verify strict_mode rejects everything when allowed_hosts is empty."""
    strict_scope = ScopeManager(allowed_hosts=[], strict_mode=True)
    assert strict_scope.is_host_in_scope("example.com") is False

    open_scope = ScopeManager(allowed_hosts=[], strict_mode=False)
    assert open_scope.is_host_in_scope("example.com") is True
