"""Unit tests for Phase 9 lab validation runner and offline execution."""

from dbshield.validation.models import (
    ExpectedClassification,
    ExpectedOutcome,
    LabScenario,
    MockHTTPResponse,
    ScenarioCategory,
    ScenarioOutcome,
)
from dbshield.validation.runner import LabValidationRunner
from dbshield.validation.scenarios import load_standard_scenarios


def test_runner_initialization() -> None:
    runner = LabValidationRunner()
    assert len(runner.dataset_limitations) >= 3


def test_runner_executes_sqli_error_positive() -> None:
    runner = LabValidationRunner()
    scenarios = load_standard_scenarios()
    sqli_pos = next(s for s in scenarios if s.scenario_id == "SQLI-POS-MYSQL-ERR")

    result = runner.run_scenario(sqli_pos)
    assert result.outcome == ScenarioOutcome.PASS
    assert result.actual_status == "potential_indicator"
    assert result.actual_technique == "error_based"
    assert result.actual_family == "mysql"
    assert result.actual_evidence_count >= 1
    assert len(result.discrepancies) == 0


def test_runner_executes_sqli_clean_negative() -> None:
    runner = LabValidationRunner()
    scenarios = load_standard_scenarios()
    sqli_neg = next(s for s in scenarios if s.scenario_id == "SQLI-NEG-CLEAN-QUERY")

    result = runner.run_scenario(sqli_neg)
    assert result.outcome == ScenarioOutcome.PASS
    assert result.actual_status == "no_indicator"
    assert len(result.discrepancies) == 0


def test_runner_executes_scope_blocked_scenario() -> None:
    runner = LabValidationRunner()
    scenarios = load_standard_scenarios()
    scope_sc = next(s for s in scenarios if s.scenario_id == "SQLI-AMB-SCOPE-BLOCKED")

    result = runner.run_scenario(scope_sc)
    assert result.outcome == ScenarioOutcome.PASS
    assert result.actual_status == "blocked_by_scope"


def test_runner_executes_safety_ineligible_param() -> None:
    runner = LabValidationRunner()
    scenarios = load_standard_scenarios()
    safety_sc = next(s for s in scenarios if s.scenario_id == "SAFETY-INELIGIBLE-PARAM")

    result = runner.run_scenario(safety_sc)
    assert result.outcome == ScenarioOutcome.PASS
    assert result.actual_status == "ineligible_skipped"


def test_runner_flags_discrepancy_on_divergent_behavior() -> None:
    # Author a scenario expecting a vulnerability where mock returns a clean response
    divergent_sc = LabScenario(
        scenario_id="TEST-DIVERGENT",
        name="Divergent Test Scenario",
        description="Expects finding but mock returns clean response.",
        category=ScenarioCategory.SQL_INJECTION,
        target_url="http://lab.local/clean?id=1",
        parameter_name="id",
        parameter_location="query",
        mock_responses=[
            MockHTTPResponse(
                url_pattern="http://lab.local/clean",
                status_code=200,
                body="<html><body>Clean</body></html>",
                is_prefix=True,
            )
        ],
        expected=ExpectedOutcome(
            classification=ExpectedClassification.TRUE_POSITIVE,
            status="potential_indicator",
            technique="error_based",
            family="mysql",
            min_evidence_count=1,
        ),
        tags=["test"],
    )

    runner = LabValidationRunner()
    result = runner.run_scenario(divergent_sc)
    assert result.outcome == ScenarioOutcome.FAIL
    assert len(result.discrepancies) >= 1
    assert any("Expected status 'potential_indicator'" in d for d in result.discrepancies)


def test_run_suite_filters_by_category() -> None:
    runner = LabValidationRunner()
    report = runner.run_suite(category_filter=ScenarioCategory.NOSQL_INJECTION)

    assert report.total_scenarios == 6
    assert all(r.category == ScenarioCategory.NOSQL_INJECTION for r in report.results)
    assert report.failed == 0
    assert report.passed == 6


def test_run_suite_filters_by_tag() -> None:
    runner = LabValidationRunner()
    report = runner.run_suite(tag_filter="differential")

    assert report.total_scenarios >= 2
    assert report.failed == 0
    assert report.passed == report.total_scenarios
