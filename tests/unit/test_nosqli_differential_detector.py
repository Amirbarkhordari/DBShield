"""Unit tests for NoSQL differential detector."""

from dbshield.nosqli.detectors.differential_detector import NoSQLDifferentialDetector
from dbshield.nosqli.models import (
    NoSQLConfidenceRating,
    NoSQLDetectionStatus,
    NoSQLProviderFamily,
)


def test_unstable_baseline_yields_inconclusive() -> None:
    """Verify unstable baseline results in INCONCLUSIVE."""
    res = NoSQLDifferentialDetector.analyze_pair(
        baseline_body="baseline",
        baseline_status=200,
        is_baseline_stable=False,
        true_body="true body",
        true_status=200,
        false_body="false body",
        false_status=200,
    )
    assert res.status == NoSQLDetectionStatus.INCONCLUSIVE
    assert "unstable" in res.explanation


def test_clean_differential_pair_yields_potential_indicator() -> None:
    """Verify True matching baseline while False diverging yields POTENTIAL_INDICATOR."""
    baseline = (
        '{"items": [{"id": "1", "name": "Item A"}, {"id": "2", "name": "Item B"}], "status": "ok"}'
    )
    true_body = (
        '{"items": [{"id": "1", "name": "Item A"}, {"id": "2", "name": "Item B"}], "status": "ok"}'
    )
    false_body = '{"items": [], "status": "not_found", "message": "No records matched the filter"}'

    res = NoSQLDifferentialDetector.analyze_pair(
        baseline_body=baseline,
        baseline_status=200,
        is_baseline_stable=True,
        true_body=true_body,
        true_status=200,
        false_body=false_body,
        false_status=200,
        provider_hint=NoSQLProviderFamily.MONGODB,
    )

    assert res.status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
    assert res.confidence is not None
    assert len(res.evidence) == 1
    assert res.evidence[0].confirmed is False
    assert res.similarity_true_baseline >= 0.85
    assert res.similarity_false_baseline <= 0.75


def test_status_code_differential_yields_high_confidence() -> None:
    """Verify distinct HTTP status codes (200 vs 404) yield HIGH confidence."""
    baseline = '{"user": "alice", "role": "admin"}'
    true_body = '{"user": "alice", "role": "admin"}'
    false_body = '{"error": "User not found"}'

    res = NoSQLDifferentialDetector.analyze_pair(
        baseline_body=baseline,
        baseline_status=200,
        is_baseline_stable=True,
        true_body=true_body,
        true_status=200,
        false_body=false_body,
        false_status=404,
    )

    assert res.status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
    assert res.confidence == NoSQLConfidenceRating.HIGH


def test_indistinguishable_responses_yields_no_indicator() -> None:
    """Verify indistinguishable responses yield NO_INDICATOR."""
    body = '{"results": ["a", "b", "c"]}'
    res = NoSQLDifferentialDetector.analyze_pair(
        baseline_body=body,
        baseline_status=200,
        is_baseline_stable=True,
        true_body=body,
        true_status=200,
        false_body=body,
        false_status=200,
    )
    assert res.status == NoSQLDetectionStatus.NO_INDICATOR


def test_both_conditions_return_500_yields_no_indicator() -> None:
    """Verify identical error status codes yield NO_INDICATOR."""
    res = NoSQLDifferentialDetector.analyze_pair(
        baseline_body="200 ok",
        baseline_status=200,
        is_baseline_stable=True,
        true_body="500 error",
        true_status=500,
        false_body="500 error",
        false_status=500,
    )
    assert res.status == NoSQLDetectionStatus.NO_INDICATOR
