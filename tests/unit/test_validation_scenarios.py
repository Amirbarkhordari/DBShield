"""Unit tests for Phase 9 standard validation scenario catalog."""

from dbshield.validation.models import (
    ExpectedClassification,
    ScenarioCategory,
)
from dbshield.validation.scenarios import load_standard_scenarios


def test_standard_scenarios_count_and_uniqueness() -> None:
    scenarios = load_standard_scenarios()
    assert len(scenarios) == 20

    ids = [s.scenario_id for s in scenarios]
    assert len(ids) == len(set(ids)), "All scenario IDs must be unique"


def test_standard_scenarios_category_coverage() -> None:
    scenarios = load_standard_scenarios()
    categories = {s.category for s in scenarios}

    assert ScenarioCategory.SQL_INJECTION in categories
    assert ScenarioCategory.NOSQL_INJECTION in categories
    assert ScenarioCategory.SAFETY_BUDGET in categories

    sqli_scenarios = [s for s in scenarios if s.category == ScenarioCategory.SQL_INJECTION]
    nosqli_scenarios = [s for s in scenarios if s.category == ScenarioCategory.NOSQL_INJECTION]
    safety_scenarios = [s for s in scenarios if s.category == ScenarioCategory.SAFETY_BUDGET]

    assert len(sqli_scenarios) >= 10
    assert len(nosqli_scenarios) >= 5
    assert len(safety_scenarios) >= 1


def test_standard_scenarios_classification_coverage() -> None:
    scenarios = load_standard_scenarios()
    classes = {s.expected.classification for s in scenarios}

    assert ExpectedClassification.TRUE_POSITIVE in classes
    assert ExpectedClassification.TRUE_NEGATIVE in classes
    assert ExpectedClassification.AMBIGUOUS_INCONCLUSIVE in classes
    assert ExpectedClassification.BLOCKED_OR_ERROR in classes


def test_scenario_target_urls_and_descriptions() -> None:
    scenarios = load_standard_scenarios()
    for s in scenarios:
        assert s.target_url.startswith("http://") or s.target_url.startswith("https://")
        assert len(s.name.strip()) > 5
        assert len(s.description.strip()) > 10
        assert len(s.tags) > 0
