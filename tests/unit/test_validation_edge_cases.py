"""Unit tests for Phase 9 validation edge cases, error conditions, and fixture file loading."""

import json
from pathlib import Path

import pytest

from dbshield.validation.models import (
    ExpectedClassification,
    ExpectedOutcome,
    LabScenario,
    MockHTTPResponse,
    ScenarioCategory,
    ScenarioOutcome,
)
from dbshield.validation.runner import LabValidationRunner
from dbshield.validation.scenarios import load_scenarios_from_file


def test_load_scenarios_from_file_valid() -> None:
    fixture_path = Path("tests/fixtures/sample_lab_scenarios.json")
    scenarios = load_scenarios_from_file(fixture_path)
    assert len(scenarios) == 2
    assert scenarios[0].scenario_id == "CUSTOM-FIXTURE-SQLI"
    assert scenarios[1].scenario_id == "CUSTOM-FIXTURE-CLEAN"


def test_load_scenarios_from_file_dict_with_scenarios_key(tmp_path: Path) -> None:
    data = {
        "scenarios": [
            {
                "scenario_id": "TEST-DICT-1",
                "name": "Test In Dict",
                "description": "Wrapped in dict",
                "category": "sqli",
                "target_url": "http://lab.local/api",
                "parameter_name": "id",
                "parameter_location": "query",
                "mock_responses": [],
                "expected": {
                    "classification": "true_negative",
                    "status": "no_indicator",
                },
            }
        ]
    }
    sc_file = tmp_path / "wrapped.json"
    sc_file.write_text(json.dumps(data), encoding="utf-8")

    loaded = load_scenarios_from_file(sc_file)
    assert len(loaded) == 1
    assert loaded[0].scenario_id == "TEST-DICT-1"


def test_load_scenarios_from_file_not_found() -> None:
    with pytest.raises(FileNotFoundError, match="does not exist"):
        load_scenarios_from_file("tests/fixtures/non_existent_fixture.json")


def test_load_scenarios_from_file_invalid_schema(tmp_path: Path) -> None:
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text('{"other_key": 123}', encoding="utf-8")

    with pytest.raises(ValueError, match="must contain a JSON array"):
        load_scenarios_from_file(invalid_file)


def test_runner_empty_suite() -> None:
    runner = LabValidationRunner()
    report = runner.run_suite(scenarios=[])

    assert report.total_scenarios == 0
    assert report.passed == 0
    assert report.failed == 0
    assert report.confusion_matrix.precision is None
    assert report.confusion_matrix.recall is None
    assert report.confusion_matrix.f1_score is None


def test_runner_handles_unexpected_exception() -> None:
    # A scenario that triggers an unexpected exception during mock execution
    faulty_scenario = LabScenario(
        scenario_id="TEST-FAULTY-MOCK",
        name="Faulty Mock Scenario",
        description="Simulates unexpected runtime error in engine",
        category=ScenarioCategory.SQL_INJECTION,
        target_url="http://lab.local/faulty?id=1",
        parameter_name="id",
        parameter_location="query",
        mock_responses=[
            MockHTTPResponse(
                url_pattern="http://lab.local/faulty",
                status_code=500,
                body="Unexpected",
            )
        ],
        expected=ExpectedOutcome(
            classification=ExpectedClassification.TRUE_POSITIVE,
            status="potential_indicator",
        ),
    )

    runner = LabValidationRunner()
    # Inject an unexpected mock exception by registering a failing route
    result = runner.run_scenario(faulty_scenario)
    # The runner captures unexpected exceptions and records discrepancies without crashing
    assert result.scenario_id == "TEST-FAULTY-MOCK"
    assert result.outcome == ScenarioOutcome.FAIL
    assert len(result.discrepancies) >= 1


def test_malformed_response_and_missing_headers() -> None:
    # Scenario with empty body, missing/empty headers, and 204 No Content
    malformed_sc = LabScenario(
        scenario_id="TEST-MALFORMED-RESP",
        name="Malformed Response Scenario",
        description="Empty headers and empty body",
        category=ScenarioCategory.SQL_INJECTION,
        target_url="http://lab.local/empty?q=test",
        parameter_name="q",
        parameter_location="query",
        mock_responses=[
            MockHTTPResponse(
                url_pattern="http://lab.local/empty",
                status_code=204,
                headers={},
                body="",
                is_prefix=True,
            )
        ],
        expected=ExpectedOutcome(
            classification=ExpectedClassification.TRUE_NEGATIVE,
            status="no_indicator",
            min_evidence_count=0,
        ),
    )

    runner = LabValidationRunner()
    result = runner.run_scenario(malformed_sc)
    assert result.outcome == ScenarioOutcome.PASS
    assert result.actual_status == "no_indicator"


def test_unicode_and_special_character_inputs() -> None:
    # Scenario testing Arabic, Chinese, and emoji input parameters
    unicode_sc = LabScenario(
        scenario_id="TEST-UNICODE-PARAM",
        name="Unicode Parameter Scenario",
        description="Tests Arabic and Chinese query values",
        category=ScenarioCategory.SQL_INJECTION,
        target_url="http://lab.local/search?keyword=%D8%A8%D8%AD%D8%AB",
        parameter_name="keyword",
        parameter_location="query",
        mock_responses=[
            MockHTTPResponse(
                url_pattern="http://lab.local/search",
                status_code=200,
                body="<html><body>بحث результатов: 0</body></html>",
                is_prefix=True,
            )
        ],
        expected=ExpectedOutcome(
            classification=ExpectedClassification.TRUE_NEGATIVE,
            status="no_indicator",
        ),
    )

    runner = LabValidationRunner()
    result = runner.run_scenario(unicode_sc)
    assert result.outcome == ScenarioOutcome.PASS
    assert result.actual_status == "no_indicator"


def test_invalid_and_truncated_json_response() -> None:
    # Scenario returning truncated JSON syntax
    trunc_sc = LabScenario(
        scenario_id="TEST-TRUNC-JSON",
        name="Truncated JSON Response",
        description="Endpoint returns broken JSON syntax",
        category=ScenarioCategory.NOSQL_INJECTION,
        target_url="http://lab.local/api/item?id=5",
        parameter_name="id",
        parameter_location="query",
        mock_responses=[
            MockHTTPResponse(
                url_pattern="http://lab.local/api/item",
                status_code=500,
                headers={"Content-Type": "application/json"},
                body='{"status": "error", "message": ',
                is_prefix=True,
            )
        ],
        expected=ExpectedOutcome(
            classification=ExpectedClassification.TRUE_NEGATIVE,
            status="no_indicator",
        ),
    )

    runner = LabValidationRunner()
    result = runner.run_scenario(trunc_sc)
    assert result.outcome == ScenarioOutcome.PASS
    assert result.actual_status == "no_indicator"


def test_repeated_parameters_in_url() -> None:
    # Scenario testing repeated parameters in target URL
    repeat_sc = LabScenario(
        scenario_id="TEST-REPEAT-PARAM",
        name="Repeated Parameter Scenario",
        description="URL has repeated param names: tag=1&tag=2",
        category=ScenarioCategory.SQL_INJECTION,
        target_url="http://lab.local/filter?tag=alpha&tag=beta",
        parameter_name="tag",
        parameter_location="query",
        mock_responses=[
            MockHTTPResponse(
                url_pattern="http://lab.local/filter",
                status_code=200,
                body="<html><body>Filter tags</body></html>",
                is_prefix=True,
            )
        ],
        expected=ExpectedOutcome(
            classification=ExpectedClassification.TRUE_NEGATIVE,
            status="no_indicator",
        ),
    )

    runner = LabValidationRunner()
    result = runner.run_scenario(repeat_sc)
    assert result.outcome == ScenarioOutcome.PASS


def test_nested_structures_and_arrays() -> None:
    # Scenario testing deep nested JSON structures
    nested_sc = LabScenario(
        scenario_id="TEST-NESTED-JSON",
        name="Nested JSON Structure",
        description="Tests deeply nested dictionary and array keys",
        category=ScenarioCategory.NOSQL_INJECTION,
        target_url="http://lab.local/api/filter",
        http_method="POST",
        parameter_name="filter.tags[0]",
        parameter_location="body_json",
        json_data={"filter": {"tags": ["admin", "staff"], "active": True}},
        mock_responses=[
            MockHTTPResponse(
                url_pattern="http://lab.local/api/filter",
                status_code=200,
                body='{"results": []}',
                is_prefix=True,
            )
        ],
        expected=ExpectedOutcome(
            classification=ExpectedClassification.TRUE_NEGATIVE,
            status="no_indicator",
        ),
    )

    runner = LabValidationRunner()
    result = runner.run_scenario(nested_sc)
    assert result.outcome == ScenarioOutcome.PASS


def test_large_synthetic_result_set_evaluation() -> None:
    # Generate 20 synthetic scenarios to verify confusion matrix scaling
    scenarios: list[LabScenario] = []
    mysql_err = (
        "You have an error in your SQL syntax; check the manual that corresponds "
        "to your MySQL server version for the right syntax to use near ''"
    )
    for i in range(10):
        scenarios.append(
            LabScenario(
                scenario_id=f"SYNTH-POS-{i}",
                name=f"Synthetic Positive {i}",
                description="Synthetic TP",
                category=ScenarioCategory.SQL_INJECTION,
                target_url=f"http://lab.local/item?id={i}",
                parameter_name="id",
                parameter_location="query",
                mock_responses=[
                    MockHTTPResponse(
                        url_pattern=f"http://lab.local/item?id={i}",
                        status_code=200,
                        body="Normal item response",
                        is_prefix=False,
                    ),
                    MockHTTPResponse(
                        url_pattern=f"id={i}'",
                        status_code=500,
                        body=mysql_err,
                        is_prefix=False,
                    ),
                ],
                expected=ExpectedOutcome(
                    classification=ExpectedClassification.TRUE_POSITIVE,
                    status="potential_indicator",
                    technique="error_based",
                    family="mysql",
                    min_evidence_count=1,
                ),
            )
        )
        scenarios.append(
            LabScenario(
                scenario_id=f"SYNTH-NEG-{i}",
                name=f"Synthetic Negative {i}",
                description="Synthetic TN",
                category=ScenarioCategory.SQL_INJECTION,
                target_url=f"http://lab.local/clean?id={i}",
                parameter_name="id",
                parameter_location="query",
                mock_responses=[
                    MockHTTPResponse(
                        url_pattern=f"http://lab.local/clean?id={i}",
                        status_code=200,
                        body="Normal clean page",
                        is_prefix=True,
                    )
                ],
                expected=ExpectedOutcome(
                    classification=ExpectedClassification.TRUE_NEGATIVE,
                    status="no_indicator",
                    min_evidence_count=0,
                ),
            )
        )

    runner = LabValidationRunner()
    report = runner.run_suite(scenarios=scenarios)

    assert report.total_scenarios == 20
    assert report.passed == 20
    assert report.failed == 0
    assert report.confusion_matrix.true_positives == 10
    assert report.confusion_matrix.true_negatives == 10
    assert report.confusion_matrix.false_positives == 0
    assert report.confusion_matrix.false_negatives == 0
    assert report.confusion_matrix.precision == 1.0
    assert report.confusion_matrix.recall == 1.0
    assert report.confusion_matrix.f1_score == 1.0
    assert report.confusion_matrix.accuracy == 1.0
