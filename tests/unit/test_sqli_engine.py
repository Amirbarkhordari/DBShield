"""Unit tests for SQL injection testing engine orchestration and parameter handling (Phase 4)."""

from unittest.mock import MagicMock

from dbshield.models.http import CaseInsensitiveDict, HTTPResponse
from dbshield.models.target import Target
from dbshield.scope.manager import ScopeManager
from dbshield.sqli.engine import SQLiEngine
from dbshield.sqli.models import DetectionStatus, ParameterLocation


def _make_response(status_code: int = 200, body: str = "Clean page") -> HTTPResponse:
    return HTTPResponse(
        url="http://test.local/items?id=1",
        status_code=status_code,
        headers=CaseInsensitiveDict({"content-type": "text/html"}),
        body=body,
        content_bytes=body.encode("utf-8"),
        elapsed_seconds=0.05,
    )


def test_extract_parameters_from_query() -> None:
    scope = ScopeManager(allowed_hosts=["example.com"])
    engine = SQLiEngine(scope_manager=scope)
    target = Target.from_url("https://example.com/search?q=security&page=2")

    params = engine.extract_parameters(target)
    assert len(params) == 2
    names = {p.name for p in params}
    assert names == {"q", "page"}
    assert all(p.location == ParameterLocation.QUERY for p in params)
    assert all(p.is_eligible for p in params)


def test_extract_parameters_from_form_data() -> None:
    scope = ScopeManager(allowed_hosts=["example.com"])
    engine = SQLiEngine(scope_manager=scope)
    target = Target.from_url("https://example.com/login")

    params = engine.extract_parameters(
        target,
        method="POST",
        data="username=alice&password=secret123&csrf_token=tok123",
    )
    assert len(params) == 3
    param_map = {p.name: p for p in params}

    assert param_map["username"].is_eligible is True
    # Password and csrf_token must be flagged ineligible for safety!
    assert param_map["password"].is_eligible is False
    assert "credential" in str(param_map["password"].skip_reason).lower()
    assert param_map["csrf_token"].is_eligible is False


def test_extract_parameters_from_json_data() -> None:
    scope = ScopeManager(allowed_hosts=["example.com"])
    engine = SQLiEngine(scope_manager=scope)
    target = Target.from_url("https://example.com/api/user")

    params = engine.extract_parameters(
        target,
        method="POST",
        json_data={"user_id": 100, "session_token": "secret_xyz"},
    )
    assert len(params) == 2
    param_map = {p.name: p for p in params}
    assert param_map["user_id"].is_eligible is True
    assert param_map["session_token"].is_eligible is False


def test_selected_param_filter() -> None:
    scope = ScopeManager(allowed_hosts=["example.com"])
    engine = SQLiEngine(scope_manager=scope)
    target = Target.from_url("https://example.com/items?cat=books&page=1&sort=asc")

    params = engine.extract_parameters(target, selected_param="cat")
    assert len(params) == 1
    assert params[0].name == "cat"


def test_out_of_scope_target_blocked_by_engine() -> None:
    scope = ScopeManager(allowed_hosts=["authorized.example.com"], strict_mode=True)
    engine = SQLiEngine(scope_manager=scope)

    result = engine.scan("https://unauthorized.example.com/item?id=1")
    assert result.execution_status == "blocked_by_scope"
    assert result.summary.blocked_parameters == 1
    assert len(result.findings) == 1
    assert result.findings[0].status == DetectionStatus.BLOCKED_BY_SCOPE


def test_request_budget_enforcement() -> None:
    scope = ScopeManager(allowed_hosts=["example.com"])
    mock_client = MagicMock()
    mock_client.request.return_value = _make_response(200, "Normal response")

    # Set total request budget to a very small number (10)
    engine = SQLiEngine(
        scope_manager=scope,
        http_client=mock_client,
        max_requests_per_parameter=8,
        total_request_budget=10,
    )
    target = Target.from_url("https://example.com/test?p1=a&p2=b&p3=c&p4=d&p5=e")

    result = engine.scan(target)
    # Total requests must not exceed budget
    assert result.summary.total_requests <= 10
    # Later parameters should be marked skipped due to budget limit
    skipped = [f for f in result.findings if f.status == DetectionStatus.SKIPPED]
    assert len(skipped) >= 1
    assert any("budget" in str(s.error_or_skip_reason).lower() for s in skipped)


def test_offline_fixture_records_analysis() -> None:
    baseline = _make_response(200, "Clean catalog with 5 books")
    test_err = _make_response(
        500,
        "Server Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server",
    )
    true_resp = _make_response(200, "Clean catalog with 5 books")
    false_resp = _make_response(200, "Catalog is empty (0 books found)")

    result = SQLiEngine.analyze_fixture_records(
        target_url="http://lab.local/item?id=1",
        param_name="id",
        baseline_response=baseline,
        test_response=test_err,
        true_response=true_resp,
        false_response=false_resp,
    )

    assert result.summary.tested_parameters == 1
    assert result.summary.potential_indicators == 1  # 1 parameter with indicators
    assert len(result.findings) == 2
    assert result.findings[0].status == DetectionStatus.POTENTIAL_INDICATOR
    assert result.findings[1].status == DetectionStatus.POTENTIAL_INDICATOR
    assert result.summary.total_requests == 0  # Offline: 0 network requests
