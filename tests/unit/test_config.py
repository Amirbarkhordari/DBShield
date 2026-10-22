"""Unit tests for configuration management."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from dbshield.config import Settings, get_settings
from dbshield.exceptions import ConfigurationError


def test_default_settings() -> None:
    """Verify conservative baseline configuration defaults."""
    settings = Settings()
    assert settings.http_timeout == 10.0
    assert settings.max_redirects == 5
    assert "DBShield" in settings.user_agent
    assert settings.log_level == "INFO"
    assert settings.log_file is None
    assert isinstance(settings.data_dir, Path)
    assert settings.allowed_hosts == []
    assert settings.allow_subdomains is False
    assert settings.rate_limit == 10.0


def test_custom_valid_settings() -> None:
    """Test custom valid configuration settings."""
    settings = Settings(
        http_timeout=25.0,
        max_redirects=3,
        log_level="DEBUG",
        allowed_hosts=["example.com", "api.example.com"],
        allow_subdomains=True,
        rate_limit=5.0,
    )
    assert settings.http_timeout == 25.0
    assert settings.max_redirects == 3
    assert settings.log_level == "DEBUG"
    assert settings.allowed_hosts == ["example.com", "api.example.com"]
    assert settings.allow_subdomains is True
    assert settings.rate_limit == 5.0


def test_log_level_normalization() -> None:
    """Verify log_level normalizes lowercase and 'WARN' alias."""
    s1 = Settings(log_level="debug")
    assert s1.log_level == "DEBUG"

    s2 = Settings(log_level="warn")
    assert s2.log_level == "WARNING"


def test_invalid_log_level_rejected() -> None:
    """Verify invalid log level raises validation error."""
    with pytest.raises(ValidationError):
        Settings(log_level="VERBOSE_UNKNOWN")


def test_invalid_http_timeout_rejected() -> None:
    """Verify non-positive or extreme timeouts are rejected."""
    with pytest.raises(ValidationError):
        Settings(http_timeout=0.1)  # below 0.5s minimum

    with pytest.raises(ValidationError):
        Settings(http_timeout=500.0)  # above 300s maximum


def test_invalid_max_redirects_rejected() -> None:
    """Verify negative redirects are rejected."""
    with pytest.raises(ValidationError):
        Settings(max_redirects=-1)


def test_allowed_hosts_cleaning() -> None:
    """Verify schemes, ports, and paths are stripped from allowed_hosts."""
    settings = Settings(
        allowed_hosts=[
            "https://test.com/path",
            "http://api.test.com:8443",
            "admin.test.com",
            "test.com",  # duplicate should be deduplicated
        ]
    )
    assert settings.allowed_hosts == ["test.com", "api.test.com", "admin.test.com"]


def test_safe_dict_exposure() -> None:
    """Verify get_safe_dict returns non-sensitive parameter summary."""
    settings = Settings(allowed_hosts=["corp.internal"])
    safe = settings.get_safe_dict()
    assert safe["allowed_hosts"] == ["corp.internal"]
    assert "http_timeout" in safe
    assert "user_agent" in safe


def test_get_settings_factory_error() -> None:
    """Verify get_settings translates validation failure to ConfigurationError."""
    with pytest.raises(ConfigurationError) as exc_info:
        get_settings(http_timeout=-5.0)
    assert "ConfigurationError" in type(exc_info.value).__name__
