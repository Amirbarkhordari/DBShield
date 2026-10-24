"""Unit tests for Phase 9 validation models, confusion matrix, and reporting schemas."""

from dbshield.validation.models import (
    ConfusionMatrix,
    ExpectedClassification,
    ExpectedOutcome,
    LabScenario,
    MockHTTPResponse,
    ScenarioCategory,
    ScenarioExecutionResult,
    ScenarioOutcome,
    ValidationReport,
)


def test_scenario_enums() -> None:
    assert ScenarioCategory.SQL_INJECTION.value == "sql_injection"
    assert ScenarioCategory.NOSQL_INJECTION.value == "nosql_injection"
    assert ScenarioCategory.SAFETY_BUDGET.value == "safety_budget"
    assert ScenarioCategory.VERIFICATION_CONSISTENCY.value == "verification_consistency"

    assert ExpectedClassification.TRUE_POSITIVE.value == "true_positive"
    assert ExpectedClassification.TRUE_NEGATIVE.value == "true_negative"
    assert ExpectedClassification.AMBIGUOUS_INCONCLUSIVE.value == "ambiguous_inconclusive"
    assert ExpectedClassification.BLOCKED_OR_ERROR.value == "blocked_or_error"

    assert ScenarioOutcome.PASS.value == "pass"
    assert ScenarioOutcome.FAIL.value == "fail"
    assert ScenarioOutcome.INCONCLUSIVE.value == "inconclusive"
    assert ScenarioOutcome.SKIPPED.value == "skipped"


def test_mock_http_response_defaults() -> None:
    resp = MockHTTPResponse(url_pattern="http://lab.local/api")
    assert resp.url_pattern == "http://lab.local/api"
    assert resp.method is None
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/html; charset=utf-8"
    assert resp.body == ""
    assert resp.is_prefix is True


def test_expected_outcome_defaults() -> None:
    exp = ExpectedOutcome(classification=ExpectedClassification.TRUE_POSITIVE)
    assert exp.classification == ExpectedClassification.TRUE_POSITIVE
    assert exp.status is None
    assert exp.technique is None
    assert exp.family is None
    assert exp.min_evidence_count == 0


def test_lab_scenario_validation() -> None:
    sc = LabScenario(
        scenario_id="SCENARIO-01",
        name="Test Scenario",
        description="A deterministic test scenario.",
        category=ScenarioCategory.SQL_INJECTION,
        target_url="http://lab.local/test?q=1",
        parameter_name="q",
        parameter_location="query",
        mock_responses=[
            MockHTTPResponse(url_pattern="http://lab.local/test?q=1", status_code=200, body="OK"),
        ],
        expected=ExpectedOutcome(
            classification=ExpectedClassification.TRUE_NEGATIVE,
            status="no_indicator",
        ),
        tags=["test", "sqli"],
    )
    assert sc.scenario_id == "SCENARIO-01"
    assert sc.category == ScenarioCategory.SQL_INJECTION
    assert len(sc.mock_responses) == 1
    assert "test" in sc.tags


def test_confusion_matrix_perfect_metrics() -> None:
    cm = ConfusionMatrix(
        true_positives=10,
        false_positives=0,
        true_negatives=10,
        false_negatives=0,
        inconclusive=2,
        skipped=1,
        precision=1.0,
        recall=1.0,
        f1_score=1.0,
        accuracy=1.0,
    )
    assert cm.precision == 1.0
    assert cm.recall == 1.0
    assert cm.f1_score == 1.0
    assert cm.accuracy == 1.0
    assert cm.true_positives == 10
    assert cm.inconclusive == 2


def test_confusion_matrix_zero_division() -> None:
    cm = ConfusionMatrix(
        true_positives=0,
        false_positives=0,
        true_negatives=0,
        false_negatives=0,
        precision=None,
        recall=None,
        f1_score=None,
        accuracy=None,
    )
    assert cm.precision is None
    assert cm.recall is None
    assert cm.f1_score is None
    assert cm.accuracy is None


def test_validation_report_serialization() -> None:
    cm = ConfusionMatrix(
        true_positives=1,
        false_positives=0,
        true_negatives=1,
        false_negatives=0,
        precision=1.0,
        recall=1.0,
        f1_score=1.0,
        accuracy=1.0,
    )
    result = ScenarioExecutionResult(
        scenario_id="SC-01",
        scenario_name="Sample Scenario",
        category=ScenarioCategory.SQL_INJECTION,
        outcome=ScenarioOutcome.PASS,
        expected_classification=ExpectedClassification.TRUE_POSITIVE,
        actual_status="potential_indicator",
        actual_technique="error_based",
        actual_family="mysql",
        actual_evidence_count=1,
        discrepancies=[],
        execution_time_ms=12.5,
    )
    rep = ValidationReport(
        suite_name="Test Suite",
        total_scenarios=2,
        passed=2,
        failed=0,
        inconclusive=0,
        skipped=0,
        confusion_matrix=cm,
        dataset_limitations=["Local test mock fixture."],
        results=[result],
    )
    dumped = rep.model_dump(mode="json")
    assert dumped["suite_name"] == "Test Suite"
    assert dumped["passed"] == 2
    assert dumped["confusion_matrix"]["precision"] == 1.0
    assert len(dumped["results"]) == 1
    assert dumped["results"][0]["outcome"] == "pass"
