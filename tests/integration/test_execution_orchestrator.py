"""Integration tests for TestExecutionOrchestrator (Phase 6)."""

import httpx
import respx

from dbshield.execution.adapters import NoSQLiExecutionAdapter, SQLiExecutionAdapter
from dbshield.execution.models import ExecutionStatus
from dbshield.execution.orchestrator import TestExecutionOrchestrator
from dbshield.execution.policy import ExecutionPolicy
from dbshield.http.client import SafeHTTPClient
from dbshield.models.http import HTTPResponse
from dbshield.models.target import Target
from dbshield.scope.manager import ScopeManager
from dbshield.sqli.models import DetectionStatus, ParameterLocation


def test_orchestrator_rejects_out_of_scope_target() -> None:
    """Verify out-of-scope targets are blocked before any HTTP dispatch."""
    scope = ScopeManager(allowed_hosts=["allowed.example.com"])
    orchestrator = TestExecutionOrchestrator(scope_manager=scope)
    adapter = SQLiExecutionAdapter()

    result = orchestrator.run(
        target_url="https://unauthorized.target.com/page?id=1",
        adapter=adapter,
    )

    assert result.execution_status == "blocked_by_scope"
    assert result.summary.total_requests == 0
    assert result.summary.skipped_test_cases >= 1
    assert len(result.records) >= 1
    assert result.records[0].status == ExecutionStatus.SKIPPED
    assert "out of authorized scope" in (result.records[0].error_or_skip_reason or "")
    assert len(result.findings) == 0


@respx.mock
def test_orchestrator_online_sqli_execution_and_finding() -> None:
    """Verify online test execution against mock HTTP server elicits SQLi indicator."""
    target_url = "http://app.internal/item?id=10"
    target = Target.from_url(target_url)

    def item_side_effect(request: httpx.Request) -> httpx.Response:
        if b"%27" in request.url.query:
            return httpx.Response(
                500,
                text="<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</body></html>",
            )
        return httpx.Response(200, text="<html><body>Welcome to Item 10</body></html>")

    respx.get(url__startswith="http://app.internal/item").mock(side_effect=item_side_effect)

    scope = ScopeManager(allowed_hosts=["app.internal"])
    client = SafeHTTPClient(scope_manager=scope)
    policy = ExecutionPolicy(max_total_requests=20, max_requests_per_parameter=10)
    orchestrator = TestExecutionOrchestrator(
        scope_manager=scope,
        http_client=client,
        policy=policy,
    )
    adapter = SQLiExecutionAdapter()

    result = orchestrator.run(target_url=target, adapter=adapter, selected_param="id")

    assert result.execution_status == "completed"
    assert result.summary.total_requests > 0
    assert result.summary.executed_test_cases > 0
    # Verified finding generated
    assert len(result.findings) >= 1
    indicator_findings = [
        f for f in result.findings if f.status == DetectionStatus.POTENTIAL_INDICATOR
    ]
    assert len(indicator_findings) >= 1


@respx.mock
def test_orchestrator_enforces_request_budgets() -> None:
    """Verify orchestrator respects policy request budgets and skips excess tests."""
    target_url = "http://app.internal/search?q=test"
    target = Target.from_url(target_url)

    respx.get(url__startswith="http://app.internal/search").respond(
        status_code=200,
        text="Search results",
    )

    scope = ScopeManager(allowed_hosts=["app.internal"])
    client = SafeHTTPClient(scope_manager=scope)
    # Set tight policy budget (min allowed is 5)
    policy = ExecutionPolicy(max_total_requests=5, max_requests_per_parameter=2)
    orchestrator = TestExecutionOrchestrator(
        scope_manager=scope,
        http_client=client,
        policy=policy,
    )
    adapter = SQLiExecutionAdapter()

    result = orchestrator.run(target_url=target, adapter=adapter, selected_param="q")

    assert result.execution_status == "completed"
    # Parameter budget was 2; multiple payloads exist for query param, so at least one should be skipped
    skipped = [r for r in result.records if r.status == ExecutionStatus.SKIPPED]
    assert len(skipped) > 0
    assert any("budget reached" in (r.error_or_skip_reason or "").lower() for r in skipped)


@respx.mock
def test_orchestrator_sensitive_parameter_protection() -> None:
    """Verify sensitive parameters are strictly skipped and never probed with injection payloads."""
    target_url = "http://app.internal/login?user=alice&password=secret&csrf_token=123"
    target = Target.from_url(target_url)

    respx.get(url__startswith="http://app.internal/login").respond(
        status_code=200,
        text="Login Page",
    )

    scope = ScopeManager(allowed_hosts=["app.internal"])
    client = SafeHTTPClient(scope_manager=scope)
    orchestrator = TestExecutionOrchestrator(scope_manager=scope, http_client=client)
    adapter = SQLiExecutionAdapter()

    result = orchestrator.run(target_url=target, adapter=adapter)

    # Password and csrf_token must be skipped
    records_by_param: dict[str, list[ExecutionStatus]] = {}
    for r in result.records:
        records_by_param.setdefault(r.parameter_name, []).append(r.status)

    if "password" in records_by_param:
        for st in records_by_param["password"]:
            assert st == ExecutionStatus.SKIPPED
    if "csrf_token" in records_by_param:
        for st in records_by_param["csrf_token"]:
            assert st == ExecutionStatus.SKIPPED

    # Non-sensitive parameter 'user' should have executed test cases
    assert "user" in records_by_param
    assert any(st == ExecutionStatus.EXECUTED for st in records_by_param["user"])


@respx.mock
def test_orchestrator_online_nosqli_execution() -> None:
    """Verify online NoSQL injection test execution using JSON parameter paths."""
    target_url = "http://app.internal/api/query"
    target = Target.from_url(target_url)

    # Baseline POST
    respx.post("http://app.internal/api/query").respond(
        status_code=200,
        text='{"status": "success", "results": [{"id": 1}]}',
    )

    scope = ScopeManager(allowed_hosts=["app.internal"])
    client = SafeHTTPClient(scope_manager=scope)
    orchestrator = TestExecutionOrchestrator(scope_manager=scope, http_client=client)
    adapter = NoSQLiExecutionAdapter()

    json_body = {"filter": {"account_id": "999"}}

    result = orchestrator.run(
        target_url=target,
        adapter=adapter,
        method="POST",
        json_data=json_body,
        selected_param="filter.account_id",
    )

    assert result.execution_status == "completed"
    assert result.summary.total_requests > 0
    assert result.summary.executed_test_cases > 0


def test_orchestrator_execute_offline_fixture() -> None:
    """Verify offline response fixture assessment without network activity."""
    base_resp = HTTPResponse(
        url="http://mock.local/offline",
        status_code=200,
        body="Normal catalog content",
    )
    test_resp = HTTPResponse(
        url="http://mock.local/offline?id=1'",
        status_code=500,
        body="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
    )
    true_resp = HTTPResponse(
        url="http://mock.local/offline?id=1+AND+1=1",
        status_code=200,
        body="Normal catalog content",
    )
    false_resp = HTTPResponse(
        url="http://mock.local/offline?id=1+AND+1=2",
        status_code=200,
        body="Zero items found",
    )

    adapter = SQLiExecutionAdapter()
    result = TestExecutionOrchestrator.execute_offline_fixture(
        target_url="http://mock.local/offline",
        param_name="id",
        param_location=ParameterLocation.QUERY,
        payload_id="SQLI_ERR_QUOTE",
        baseline_response=base_resp,
        test_response=test_resp,
        adapter=adapter,
        true_response=true_resp,
        false_response=false_resp,
    )

    assert result.execution_status == "completed"
    assert result.summary.total_requests == 0
    assert result.summary.total_test_cases == 2
    assert len(result.findings) >= 1
