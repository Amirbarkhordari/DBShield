"""Unit tests for error-based SQL injection detector (Phase 4)."""

from dbshield.sqli.detectors.error_detector import ErrorDetector
from dbshield.sqli.models import ConfidenceRating, DatabaseFamily, DetectionStatus


def test_clean_response_yields_no_indicator() -> None:
    baseline_body = "<html><body><h1>User Profile: John</h1><p>Active user</p></body></html>"
    test_body = "<html><body><h1>User Profile: John</h1><p>Active user</p></body></html>"

    status, conf, evidence, summary = ErrorDetector.analyze_response(
        test_body=test_body,
        test_status=200,
        baseline_body=baseline_body,
        baseline_status=200,
    )
    assert status == DetectionStatus.NO_INDICATOR
    assert conf is None
    assert len(evidence) == 0
    assert "No recognizable database error signatures" in summary


def test_generic_500_not_classified_as_sqli() -> None:
    baseline_body = "<html><body><h1>User Profile: John</h1></body></html>"
    test_body = "<html><body><h1>500 Internal Server Error</h1><p>An unexpected error occurred.</p></body></html>"

    status, conf, evidence, summary = ErrorDetector.analyze_response(
        test_body=test_body,
        test_status=500,
        baseline_body=baseline_body,
        baseline_status=200,
    )
    assert status == DetectionStatus.NO_INDICATOR
    assert conf is None
    assert len(evidence) == 0
    assert "generic server error" in summary.lower()


def test_mysql_error_yields_potential_indicator() -> None:
    baseline_body = "<html><body><h1>Search results</h1><p>0 items found</p></body></html>"
    test_body = (
        "<html><body><h1>Database error</h1><p>You have an error in your SQL syntax; "
        "check the manual that corresponds to your MySQL server version for the right syntax</p></body></html>"
    )

    status, conf, evidence, summary = ErrorDetector.analyze_response(
        test_body=test_body,
        test_status=500,
        baseline_body=baseline_body,
        baseline_status=200,
    )
    assert status == DetectionStatus.POTENTIAL_INDICATOR
    assert conf == ConfidenceRating.HIGH
    assert len(evidence) >= 1
    assert evidence[0].db_family_hint == DatabaseFamily.MYSQL
    assert evidence[0].confirmed is False
    assert "Potential SQL injection indicator" in summary


def test_pre_existing_error_in_baseline_ignored() -> None:
    # If the database error was already in the baseline response, it is NOT triggered by the test probe!
    baseline_body = "Warning: pg_query(): Query failed: relation does not exist"
    test_body = "Warning: pg_query(): Query failed: relation does not exist"

    status, conf, evidence, summary = ErrorDetector.analyze_response(
        test_body=test_body,
        test_status=500,
        baseline_body=baseline_body,
        baseline_status=500,
    )
    assert status == DetectionStatus.NO_INDICATOR
    assert conf is None
    assert len(evidence) == 0
    assert "already present in the baseline" in summary


def test_generic_sqlstate_yields_medium_confidence() -> None:
    baseline_body = "Welcome to our store"
    test_body = "Error encountered: SQLSTATE[42000]: Syntax error in SQL statement"

    status, conf, evidence, _ = ErrorDetector.analyze_response(
        test_body=test_body,
        test_status=500,
        baseline_body=baseline_body,
        baseline_status=200,
    )
    assert status == DetectionStatus.POTENTIAL_INDICATOR
    assert conf == ConfidenceRating.MEDIUM
    assert evidence[0].confirmed is False
