"""Integration tests for SQL injection testing engine against simulated HTTP targets (Phase 4)."""

import httpx
import pytest
import respx

from dbshield.auth.manager import SessionManager
from dbshield.http.client import SafeHTTPClient
from dbshield.models.auth import AuthConfig, AuthType
from dbshield.models.target import Target
from dbshield.scope.manager import ScopeManager
from dbshield.sqli.engine import SQLiEngine
from dbshield.sqli.models import (
    ConfidenceRating,
    DatabaseFamily,
    DetectionStatus,
    ParameterLocation,
    TestTechnique,
)


@pytest.fixture
def in_scope_manager() -> ScopeManager:
    return ScopeManager(allowed_hosts=["lab.local", "api.lab.local"])


@respx.mock
def test_clean_endpoint_integration(in_scope_manager: ScopeManager) -> None:
    # All probes return standard 200 OK without errors or differential behavior
    respx.get(url__startswith="http://lab.local/catalog").respond(
        200,
        text="<html><body><h1>Product 42</h1><p>Clean book catalog item</p></body></html>",
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = SQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan("http://lab.local/catalog?item=42")

    assert result.execution_status == "completed"
    assert result.summary.total_parameters == 1
    assert result.summary.potential_indicators == 0
    assert result.summary.clean_parameters == 1
    assert result.summary.total_requests >= 2  # Baseline + probes
    for finding in result.findings:
        assert finding.status == DetectionStatus.NO_INDICATOR


@respx.mock
def test_error_based_sqli_signal_detected(in_scope_manager: ScopeManager) -> None:
    # Baseline returns normal catalog
    respx.get("http://lab.local/items?id=1").respond(
        200,
        text="<html><body><h1>Item 1</h1><p>Normal description</p></body></html>",
    )
    # Error probe with single quote triggers MySQL syntax error
    respx.get("http://lab.local/items?id=1%27").respond(
        500,
        text=(
            "<html><body><h1>Database Error</h1>"
            "<p>You have an error in your SQL syntax; check the manual that corresponds "
            "to your MySQL server version near ''' at line 1</p></body></html>"
        ),
    )
    # Differential probes also handled
    respx.get("http://lab.local/items?id=1+AND+1%3D1").respond(
        200,
        text="<html><body><h1>Item 1</h1><p>Normal description</p></body></html>",
    )
    respx.get("http://lab.local/items?id=1+AND+1%3D2").respond(
        200,
        text="<html><body><h1>Item 1</h1><p>Normal description</p></body></html>",
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = SQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan("http://lab.local/items?id=1")

    assert result.execution_status == "completed"
    assert result.summary.potential_indicators >= 1

    err_findings = [f for f in result.findings if f.technique == TestTechnique.ERROR_BASED]
    assert len(err_findings) == 1
    assert err_findings[0].status == DetectionStatus.POTENTIAL_INDICATOR
    assert err_findings[0].confidence == ConfidenceRating.HIGH
    assert err_findings[0].evidence_records[0].db_family_hint == DatabaseFamily.MYSQL
    assert err_findings[0].evidence_records[0].confirmed is False


@respx.mock
def test_boolean_differential_sqli_signal_detected(in_scope_manager: ScopeManager) -> None:
    # Baseline returns user
    respx.get("http://lab.local/user?uid=5").respond(
        200,
        text="<html><body><h1>Profile</h1><p>Name: Bob, Role: Editor</p></body></html>",
    )
    # Error probe returns standard profile (no DB error)
    respx.get("http://lab.local/user?uid=5%27").respond(
        200,
        text="<html><body><h1>Profile</h1><p>Name: Bob, Role: Editor</p></body></html>",
    )
    # True probe (5 AND 1=1) returns profile
    respx.get("http://lab.local/user?uid=5+AND+1%3D1").respond(
        200,
        text="<html><body><h1>Profile</h1><p>Name: Bob, Role: Editor</p></body></html>",
    )
    # False probe (5 AND 1=2) returns user not found
    respx.get("http://lab.local/user?uid=5+AND+1%3D2").respond(
        200,
        text="<html><body><h1>Error</h1><p>User record not found in system.</p></body></html>",
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = SQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan("http://lab.local/user?uid=5")

    assert result.summary.potential_indicators >= 1
    diff_findings = [
        f for f in result.findings if f.technique == TestTechnique.BOOLEAN_DIFFERENTIAL
    ]
    assert len(diff_findings) == 1
    assert diff_findings[0].status == DetectionStatus.POTENTIAL_INDICATOR
    assert diff_findings[0].confidence is not None


@respx.mock
def test_generic_500_not_classified_as_sqli(in_scope_manager: ScopeManager) -> None:
    # Baseline: 200
    respx.get("http://lab.local/api/item?id=10").respond(
        200,
        text="<html><body><h1>Item 10</h1></body></html>",
    )
    # Error probe returns generic 500 without database error
    respx.get("http://lab.local/api/item?id=10%27").respond(
        500,
        text="<html><body><h1>500 Internal Server Error</h1><p>An unexpected error occurred.</p></body></html>",
    )
    # True & False probes also return generic 500
    respx.get("http://lab.local/api/item?id=10+AND+1%3D1").respond(
        500,
        text="<html><body><h1>500 Internal Server Error</h1></body></html>",
    )
    respx.get("http://lab.local/api/item?id=10+AND+1%3D2").respond(
        500,
        text="<html><body><h1>500 Internal Server Error</h1></body></html>",
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = SQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan("http://lab.local/api/item?id=10")

    # Critical requirement: Generic 500 alone must NEVER be classified as SQL injection!
    assert result.summary.potential_indicators == 0
    for finding in result.findings:
        assert finding.status == DetectionStatus.NO_INDICATOR


@respx.mock
def test_unstable_baseline_marks_inconclusive(in_scope_manager: ScopeManager) -> None:
    # Baseline probe 1: 200 OK, Baseline probe 2: 503 Service Unavailable
    respx.get("http://lab.local/flaky?id=1").mock(
        side_effect=[
            httpx.Response(200, text="Clean page"),
            httpx.Response(503, text="503 Service Unavailable"),
        ]
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = SQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan("http://lab.local/flaky?id=1")

    assert result.summary.potential_indicators == 0
    assert result.summary.inconclusive_parameters == 1
    assert result.findings[0].status == DetectionStatus.INCONCLUSIVE
    assert "Status code varied" in str(result.findings[0].error_or_skip_reason)


@respx.mock
def test_authenticated_sqli_scan_integration(in_scope_manager: ScopeManager) -> None:
    auth_config = AuthConfig(
        auth_type=AuthType.BEARER,
        token="super_secret_auth_token_123",
    )
    session_mgr = SessionManager(auth_config=auth_config)
    session_mgr.bind_target(Target.from_url("http://lab.local/secure/data?q=test"))

    route = respx.get("http://lab.local/secure/data?q=test").respond(
        200,
        text="<h1>Secret Data</h1><p>Authorized view</p>",
    )
    respx.get("http://lab.local/secure/data?q=test%27").respond(
        200,
        text="<h1>Secret Data</h1><p>Authorized view</p>",
    )
    respx.get("http://lab.local/secure/data?q=test%27+AND+%271%27%3D%271").respond(
        200,
        text="<h1>Secret Data</h1><p>Authorized view</p>",
    )
    respx.get("http://lab.local/secure/data?q=test%27+AND+%271%27%3D%272").respond(
        200,
        text="<h1>Secret Data</h1><p>Authorized view</p>",
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager, session_manager=session_mgr)
    engine = SQLiEngine(
        scope_manager=in_scope_manager,
        http_client=client,
        session_manager=session_mgr,
    )

    result = engine.scan("http://lab.local/secure/data?q=test")

    assert result.execution_status == "completed"
    assert route.called is True
    # Verify Bearer token was transmitted in header
    last_req = route.calls.last.request
    assert last_req.headers.get("Authorization") == "Bearer super_secret_auth_token_123"


@respx.mock
def test_post_form_sqli_scan_integration(in_scope_manager: ScopeManager) -> None:
    # Handler for POST form requests
    def form_side_effect(request: httpx.Request) -> httpx.Response:
        body_text = request.content.decode("utf-8")
        if "keyword=database%27" in body_text or "keyword=database'" in body_text:
            return httpx.Response(
                500,
                text='<html><body>ERROR:  syntax error at or near "\'" at character 19</body></html>',
            )
        return httpx.Response(
            200,
            text="<html><body><h1>Search Results</h1><p>10 items matching keyword</p></body></html>",
        )

    route = respx.post("http://lab.local/api/search").mock(side_effect=form_side_effect)

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = SQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan(
        target_url="http://lab.local/api/search",
        method="POST",
        data="keyword=database&limit=10",
        selected_param="keyword",
    )

    assert result.execution_status == "completed"
    assert result.summary.potential_indicators == 1
    assert route.call_count >= 2

    # Check that Content-Type and request body were properly formatted
    first_req = route.calls[0].request
    assert first_req.method == "POST"
    assert "keyword=database" in first_req.content.decode("utf-8")

    finding = result.findings[0]
    assert finding.status == DetectionStatus.POTENTIAL_INDICATOR
    assert finding.parameter.name == "keyword"
    assert finding.parameter.location == ParameterLocation.BODY_URLENCODED
    assert finding.evidence_records[0].db_family_hint == DatabaseFamily.POSTGRESQL


@respx.mock
def test_post_json_sqli_scan_integration(in_scope_manager: ScopeManager) -> None:
    # Handler for JSON body POST requests
    def json_side_effect(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("content-type") == "application/json"
        body_text = request.content.decode("utf-8")
        if "42'" in body_text:
            return httpx.Response(
                500,
                text='sqlite3.OperationalError: near "\'": syntax error',
            )
        return httpx.Response(200, text='{"status": "ok", "items": [{"id": 42, "name": "widget"}]}')

    route = respx.post("http://lab.local/api/items").mock(side_effect=json_side_effect)

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = SQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan(
        target_url="http://lab.local/api/items",
        method="POST",
        json_data='{"item_id": 42, "category": "books"}',
        selected_param="item_id",
    )

    assert result.execution_status == "completed"
    assert result.summary.potential_indicators == 1
    assert route.call_count >= 2

    finding = result.findings[0]
    assert finding.status == DetectionStatus.POTENTIAL_INDICATOR
    assert finding.parameter.name == "item_id"
    assert finding.parameter.location == ParameterLocation.BODY_JSON
    assert finding.evidence_records[0].db_family_hint == DatabaseFamily.SQLITE


@respx.mock
def test_post_form_inconclusive_due_to_unstable_baseline(in_scope_manager: ScopeManager) -> None:
    # Baseline probe 1: 200 OK, Baseline probe 2: 502 Bad Gateway
    respx.post("http://lab.local/api/flaky_form").mock(
        side_effect=[
            httpx.Response(200, text="Clean page"),
            httpx.Response(502, text="Bad Gateway"),
        ]
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = SQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan(
        target_url="http://lab.local/api/flaky_form",
        method="POST",
        data="q=search_term",
    )

    assert result.summary.potential_indicators == 0
    assert result.summary.inconclusive_parameters == 1
    assert result.findings[0].status == DetectionStatus.INCONCLUSIVE
    assert "varied between baseline samples" in str(result.findings[0].error_or_skip_reason)


@respx.mock
def test_response_boundary_error_detection(in_scope_manager: ScopeManager) -> None:
    # Baseline response
    respx.get("http://lab.local/boundary?id=1").respond(
        200,
        text="<html><body><h1>Large Catalog</h1>"
        + ("<p>padding text</p>\n" * 500)
        + "</body></html>",
    )
    # Error probe: 100KB padded body with MSSQL error near the boundary
    padded_error = (
        "<html><body>"
        + ("x" * 80000)
        + "<p>Microsoft SQL Server: Unclosed quotation mark after the character string 'test'.</p>"
        + ("y" * 10000)
        + "</body></html>"
    )
    respx.get("http://lab.local/boundary?id=1%27").respond(500, text=padded_error)
    respx.get("http://lab.local/boundary?id=1+AND+1%3D1").respond(200, text="Normal")
    respx.get("http://lab.local/boundary?id=1+AND+1%3D2").respond(200, text="Normal")

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = SQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan("http://lab.local/boundary?id=1")

    assert result.summary.potential_indicators == 1
    err_finding = [f for f in result.findings if f.technique == TestTechnique.ERROR_BASED][0]
    assert err_finding.status == DetectionStatus.POTENTIAL_INDICATOR
    assert err_finding.evidence_records[0].db_family_hint == DatabaseFamily.MSSQL
    # Check that snippet is safely bounded (less than 300 characters, not full 90KB)
    assert len(err_finding.evidence_records[0].snippet) < 300
    assert "Unclosed quotation mark" in err_finding.evidence_records[0].snippet


@respx.mock
def test_repeated_query_parameters_handling(in_scope_manager: ScopeManager) -> None:
    respx.get(url__startswith="http://lab.local/filter").respond(
        200,
        text="<html><body><h1>Filtered items</h1><p>Results shown</p></body></html>",
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = SQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan("http://lab.local/filter?tag=news&tag=sports&page=1")

    assert result.execution_status == "completed"
    assert result.summary.total_parameters == 2  # 'tag' and 'page'
    assert result.summary.clean_parameters == 2
