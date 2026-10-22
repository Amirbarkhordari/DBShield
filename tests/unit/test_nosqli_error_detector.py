"""Unit tests for error-based NoSQL detector."""

from dbshield.nosqli.detectors.error_detector import NoSQLErrorDetector
from dbshield.nosqli.models import (
    NoSQLConfidenceRating,
    NoSQLDetectionStatus,
    NoSQLProviderFamily,
)


def test_clean_response_yields_no_indicator() -> None:
    """Verify clean response yields NO_INDICATOR."""
    status, conf, evidence, summary = NoSQLErrorDetector.analyze_response(
        test_body='{"status": "ok", "items": []}',
        test_status=200,
        baseline_body='{"status": "ok", "items": []}',
        baseline_status=200,
    )
    assert status == NoSQLDetectionStatus.NO_INDICATOR
    assert conf is None
    assert len(evidence) == 0


def test_generic_500_rejected_as_no_indicator() -> None:
    """Verify generic HTTP 500 error without NoSQL signatures is rejected."""
    status, conf, evidence, summary = NoSQLErrorDetector.analyze_response(
        test_body="500 Internal Server Error: General application failure.",
        test_status=500,
        baseline_body="200 OK",
        baseline_status=200,
    )
    assert status == NoSQLDetectionStatus.NO_INDICATOR
    assert conf is None
    assert len(evidence) == 0


def test_mongodb_error_yields_potential_indicator() -> None:
    """Verify MongoDB syntax/operator error absent in baseline yields POTENTIAL_INDICATOR."""
    test_body = "MongoError: unknown operator: $invalid at cursor execution"
    status, conf, evidence, summary = NoSQLErrorDetector.analyze_response(
        test_body=test_body,
        test_status=500,
        baseline_body='{"status": "ok"}',
        baseline_status=200,
    )
    assert status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
    assert conf == NoSQLConfidenceRating.HIGH
    assert len(evidence) >= 1
    assert evidence[0].provider_family_hint == NoSQLProviderFamily.MONGODB
    assert evidence[0].confirmed is False


def test_pre_existing_error_in_baseline_ignored() -> None:
    """Verify error already present in baseline is ignored as pre-existing."""
    err_body = "MongoError: unknown operator: $invalid at query"
    status, conf, evidence, summary = NoSQLErrorDetector.analyze_response(
        test_body=err_body,
        test_status=500,
        baseline_body=err_body,
        baseline_status=500,
    )
    assert status == NoSQLDetectionStatus.NO_INDICATOR
    assert len(evidence) == 0
    assert "pre-existing" in summary


def test_couchdb_error_yields_potential_indicator() -> None:
    """Verify CouchDB selector error yields POTENTIAL_INDICATOR."""
    test_body = '{"error": "invalid_selector", "reason": "Expected object in selector"}'
    status, conf, evidence, summary = NoSQLErrorDetector.analyze_response(
        test_body=test_body,
        test_status=400,
        baseline_body='{"docs": []}',
        baseline_status=200,
    )
    assert status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
    assert conf == NoSQLConfidenceRating.HIGH
    assert any(ev.provider_family_hint == NoSQLProviderFamily.COUCHDB for ev in evidence)
