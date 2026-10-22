"""Unit tests for NoSQLiEngine parameter handling, budget controls, and fixture analysis."""

from typing import Any

from dbshield.models.http import HTTPResponse
from dbshield.models.target import Target
from dbshield.nosqli.engine import NoSQLiEngine
from dbshield.nosqli.models import (
    NoSQLDetectionStatus,
    ParameterLocation,
)
from dbshield.scope.manager import ScopeManager


def test_extract_parameters_from_query() -> None:
    """Verify query parameter extraction."""
    scope = ScopeManager(allowed_hosts=["example.com"])
    engine = NoSQLiEngine(scope_manager=scope)
    target = Target.from_url("https://example.com/search?category=books&page=1")

    params = engine.extract_parameters(target=target)
    names = {p.name for p in params}
    assert "category" in names
    assert "page" in names
    for p in params:
        assert p.location == ParameterLocation.QUERY


def test_extract_parameters_from_nested_json() -> None:
    """Verify recursive extraction of nested JSON key paths."""
    scope = ScopeManager(allowed_hosts=["example.com"])
    engine = NoSQLiEngine(scope_manager=scope)
    target = Target.from_url("https://example.com/api/query")

    nested_json = {"filter": {"user_id": "123", "metadata": {"role": "editor"}}, "limit": 10}

    params = engine.extract_parameters(target=target, method="POST", json_data=nested_json)
    name_map = {p.name: p for p in params}

    assert "limit" in name_map
    assert "filter.user_id" in name_map
    assert "filter.metadata.role" in name_map

    p_nested = name_map["filter.user_id"]
    assert p_nested.key_path == ["filter", "user_id"]
    assert p_nested.original_value == "123"
    assert p_nested.location == ParameterLocation.BODY_JSON


def test_mutate_json_path_preserves_unrelated_keys() -> None:
    """Verify _mutate_json_path mutates isolated target path without modifying other keys."""
    original: dict[str, Any] = {
        "filter": {
            "user_id": "123",
            "role": "admin",
        },
        "tags": ["alpha", "beta"],
        "active": True,
    }

    mutated: dict[str, Any] = NoSQLiEngine._mutate_json_path(
        original, ["filter", "user_id"], {"$ne": "__sentinel__"}
    )

    # Targeted path has been mutated
    assert mutated["filter"]["user_id"] == {"$ne": "__sentinel__"}
    # Other keys remain untouched
    assert mutated["filter"]["role"] == "admin"
    assert mutated["tags"] == ["alpha", "beta"]
    assert mutated["active"] is True
    # Original object was not modified in-place
    assert original["filter"]["user_id"] == "123"


def test_sensitive_parameters_marked_ineligible() -> None:
    """Verify passwords, tokens, and nonces are skipped."""
    scope = ScopeManager(allowed_hosts=["example.com"])
    engine = NoSQLiEngine(scope_manager=scope)
    target = Target.from_url(
        "https://example.com/login?username=alice&password=secret&csrf_token=123"
    )

    params = engine.extract_parameters(target=target)
    param_map = {p.name: p for p in params}

    assert param_map["username"].is_eligible is True
    assert param_map["password"].is_eligible is False
    assert param_map["csrf_token"].is_eligible is False
    assert "sensitive" in (param_map["password"].skip_reason or "")


def test_selected_param_filter() -> None:
    """Verify --param limits candidate parameter testing."""
    scope = ScopeManager(allowed_hosts=["example.com"])
    engine = NoSQLiEngine(scope_manager=scope)
    target = Target.from_url("https://example.com/search?a=1&b=2&c=3")

    params = engine.extract_parameters(target=target, selected_param="b")
    assert len(params) == 1
    assert params[0].name == "b"


def test_out_of_scope_target_blocked_by_engine() -> None:
    """Verify out-of-scope targets are safely rejected without requests."""
    scope = ScopeManager(allowed_hosts=["allowed.com"], strict_mode=True)
    engine = NoSQLiEngine(scope_manager=scope)

    result = engine.scan(target_url="https://forbidden.com/api?id=1")
    assert result.execution_status == "blocked_by_scope"
    assert result.summary.blocked_parameters == 1
    assert result.summary.total_requests == 0
    assert result.findings[0].status == NoSQLDetectionStatus.BLOCKED_BY_SCOPE


def test_offline_fixture_records_analysis() -> None:
    """Verify offline response fixture assessment."""
    baseline = HTTPResponse(
        url="http://fixture.local/search", status_code=200, body='{"results": ["doc1"]}'
    )
    test = HTTPResponse(
        url="http://fixture.local/search",
        status_code=500,
        body="MongoServerError: unknown operator: $invalid at cursor",
    )
    true_resp = HTTPResponse(
        url="http://fixture.local/search", status_code=200, body='{"results": ["doc1"]}'
    )
    false_resp = HTTPResponse(
        url="http://fixture.local/search", status_code=200, body='{"results": []}'
    )

    result = NoSQLiEngine.analyze_fixture_records(
        target_url="http://fixture.local/search",
        param_name="category",
        baseline_response=baseline,
        test_response=test,
        true_response=true_resp,
        false_response=false_resp,
    )

    assert result.summary.total_requests == 0
    assert result.summary.potential_indicators >= 1
    assert len(result.findings) == 2
    err_finding = result.findings[0]
    assert err_finding.status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
    assert err_finding.evidence_records[0].confirmed is False
