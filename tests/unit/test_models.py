"""Unit tests for Target and Scan data models."""

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from dbshield.exceptions import URLValidationError
from dbshield.models.scan import Scan, ScanProfile, ScanStatus
from dbshield.models.target import Target


def test_valid_target_url_parsing() -> None:
    """Test standard valid URL parsing and normalization."""
    t = Target.from_url("https://example.com/login?redirect=1")
    assert t.scheme == "https"
    assert t.host == "example.com"
    assert t.port == 443
    assert t.path == "/login"
    assert t.query == "redirect=1"
    assert t.is_tls is True
    assert t.origin == "https://example.com"
    assert t.base_url == "https://example.com/login"
    assert t.full_url == "https://example.com/login?redirect=1"


def test_target_custom_port() -> None:
    """Test custom port parsing."""
    t = Target.from_url("http://192.168.1.100:8080/api/v1")
    assert t.scheme == "http"
    assert t.host == "192.168.1.100"
    assert t.port == 8080
    assert t.path == "/api/v1"
    assert t.is_tls is False
    assert t.origin == "http://192.168.1.100:8080"


def test_target_missing_scheme_rejected() -> None:
    """Verify URL without scheme raises URLValidationError."""
    with pytest.raises(URLValidationError) as exc:
        Target.from_url("example.com/login")
    assert "missing a protocol scheme" in exc.value.message


def test_target_unsupported_scheme_rejected() -> None:
    """Verify non-HTTP schemes are rejected."""
    for bad_url in [
        "ftp://ftp.example.com/file.txt",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://example.com",
    ]:
        with pytest.raises(URLValidationError) as exc:
            Target.from_url(bad_url)
        assert "Unsupported scheme" in exc.value.message


def test_target_empty_url_rejected() -> None:
    """Verify empty or whitespace URL is rejected."""
    with pytest.raises(URLValidationError):
        Target.from_url("")

    with pytest.raises(URLValidationError):
        Target.from_url("   ")


def test_target_invalid_port_rejected() -> None:
    """Verify out-of-range port is rejected."""
    with pytest.raises(URLValidationError):
        Target.from_url("http://example.com:70000")

    with pytest.raises(URLValidationError):
        Target.from_url("http://example.com:0")


def test_scan_model_initialization() -> None:
    """Verify default scan model attributes."""
    scan = Scan(
        target_url="https://example.com/login",
        target_host="example.com",
    )
    assert isinstance(scan.id, uuid.UUID)
    assert scan.status == ScanStatus.PENDING
    assert scan.profile == ScanProfile.STANDARD
    assert isinstance(scan.created_at, datetime)
    assert scan.planned_test_count == 0
    assert scan.executed_test_count == 0


def test_scan_model_custom_attributes() -> None:
    """Verify customized scan profile and execution counts."""
    custom_id = uuid.uuid4()
    now = datetime.now(UTC)
    scan = Scan(
        id=custom_id,
        target_url="https://app.corp.internal",
        target_host="app.corp.internal",
        profile=ScanProfile.AGGRESSIVE,
        status=ScanStatus.INITIALIZED,
        created_at=now,
        planned_test_count=50,
        executed_test_count=10,
        metadata={"operator": "security-team", "environment": "staging"},
    )
    assert scan.id == custom_id
    assert scan.profile == ScanProfile.AGGRESSIVE
    assert scan.status == ScanStatus.INITIALIZED
    assert scan.planned_test_count == 50
    assert scan.executed_test_count == 10
    assert scan.metadata["operator"] == "security-team"


def test_scan_negative_counters_rejected() -> None:
    """Verify negative test count validation."""
    with pytest.raises(ValidationError):
        Scan(
            target_url="https://example.com",
            target_host="example.com",
            planned_test_count=-1,
        )
