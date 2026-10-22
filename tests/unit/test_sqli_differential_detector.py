"""Unit tests for boolean differential response detector (Phase 4)."""

from dbshield.sqli.detectors.differential_detector import DifferentialDetector
from dbshield.sqli.models import ConfidenceRating, DetectionStatus


def test_unstable_baseline_yields_inconclusive() -> None:
    res = DifferentialDetector.analyze_pair(
        baseline_body="Body content",
        baseline_status=200,
        is_baseline_stable=False,  # Unstable baseline!
        true_body="Body content",
        true_status=200,
        false_body="Different content",
        false_status=404,
    )
    assert res.status == DetectionStatus.INCONCLUSIVE
    assert "baseline response behavior is unstable" in res.explanation
    assert len(res.evidence) == 0


def test_clean_differential_pair_yields_potential_indicator() -> None:
    baseline = "<h1>User Profile</h1><p>Username: admin, Role: Administrator</p>"
    true_resp = "<h1>User Profile</h1><p>Username: admin, Role: Administrator</p>"
    false_resp = "<h1>User Profile</h1><p>User not found</p>"

    res = DifferentialDetector.analyze_pair(
        baseline_body=baseline,
        baseline_status=200,
        is_baseline_stable=True,
        true_body=true_resp,
        true_status=200,
        false_body=false_resp,
        false_status=200,
    )
    assert res.status == DetectionStatus.POTENTIAL_INDICATOR
    assert res.confidence in (ConfidenceRating.HIGH, ConfidenceRating.MEDIUM)
    assert res.similarity_true_baseline >= 0.85
    assert res.similarity_false_baseline < 0.75
    assert len(res.evidence) == 1
    assert res.evidence[0].confirmed is False
    assert "Differential signal detected" in res.explanation


def test_status_code_differential_yields_high_confidence() -> None:
    baseline = "<h1>Article 1</h1><p>Content of article</p>"
    true_resp = "<h1>Article 1</h1><p>Content of article</p>"
    false_resp = "<h1>404 Not Found</h1><p>The requested article does not exist</p>"

    res = DifferentialDetector.analyze_pair(
        baseline_body=baseline,
        baseline_status=200,
        is_baseline_stable=True,
        true_body=true_resp,
        true_status=200,
        false_body=false_resp,
        false_status=404,  # Status code split
    )
    assert res.status == DetectionStatus.POTENTIAL_INDICATOR
    assert res.confidence == ConfidenceRating.HIGH
    assert len(res.evidence) == 1


def test_indistinguishable_responses_yields_no_indicator() -> None:
    baseline = "<h1>Catalog</h1><p>Showing 20 items</p>"
    true_resp = "<h1>Catalog</h1><p>Showing 20 items</p>"
    false_resp = "<h1>Catalog</h1><p>Showing 20 items</p>"

    res = DifferentialDetector.analyze_pair(
        baseline_body=baseline,
        baseline_status=200,
        is_baseline_stable=True,
        true_body=true_resp,
        true_status=200,
        false_body=false_resp,
        false_status=200,
    )
    assert res.status == DetectionStatus.NO_INDICATOR
    assert "indistinguishable" in res.explanation.lower()
    assert len(res.evidence) == 0


def test_both_conditions_return_500_yields_no_indicator() -> None:
    baseline = "<h1>Catalog</h1>"
    true_resp = "Server Error"
    false_resp = "Server Error"

    res = DifferentialDetector.analyze_pair(
        baseline_body=baseline,
        baseline_status=200,
        is_baseline_stable=True,
        true_body=true_resp,
        true_status=500,
        false_body=false_resp,
        false_status=500,
    )
    assert res.status == DetectionStatus.NO_INDICATOR
    assert "Both paired probes returned HTTP 500" in res.explanation


def test_chaotic_divergence_yields_inconclusive() -> None:
    baseline = "Standard homepage layout"
    true_resp = "Completely different layout alpha"
    false_resp = "Completely different layout beta"

    res = DifferentialDetector.analyze_pair(
        baseline_body=baseline,
        baseline_status=200,
        is_baseline_stable=True,
        true_body=true_resp,
        true_status=200,
        false_body=false_resp,
        false_status=200,
    )
    assert res.status == DetectionStatus.INCONCLUSIVE
    assert "Neither probe matched the baseline" in res.explanation
