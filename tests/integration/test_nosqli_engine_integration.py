"""Integration tests for NoSQL injection testing engine against simulated HTTP targets (Phase 5)."""

import httpx
import pytest
import respx

from dbshield.http.client import SafeHTTPClient
from dbshield.nosqli.engine import NoSQLiEngine
from dbshield.nosqli.models import (
    NoSQLConfidenceRating,
    NoSQLDetectionStatus,
    NoSQLProviderFamily,
    NoSQLTestTechnique,
)
from dbshield.scope.manager import ScopeManager


@pytest.fixture
def in_scope_manager() -> ScopeManager:
    return ScopeManager(allowed_hosts=["lab.local", "api.lab.local"])


@respx.mock
def test_nosql_clean_endpoint_integration(in_scope_manager: ScopeManager) -> None:
    """Verify clean endpoint produces no false positives."""
    respx.get(url__startswith="http://lab.local/catalog").respond(
        200,
        text='{"status": "ok", "items": [{"id": 1, "title": "Database Security"}]}',
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = NoSQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan("http://lab.local/catalog?category=books")

    assert result.execution_status == "completed"
    assert result.summary.total_parameters == 1
    assert result.summary.potential_indicators == 0
    assert result.summary.clean_parameters == 1
    for finding in result.findings:
        assert finding.status == NoSQLDetectionStatus.NO_INDICATOR


@respx.mock
def test_nosql_error_based_signal_detected(in_scope_manager: ScopeManager) -> None:
    """Verify MongoDB operator error is detected and classified with HIGH confidence."""
    # Baseline
    respx.get("http://lab.local/items?id=1").respond(
        200,
        text='{"status": "success", "data": {"id": 1, "name": "Document A"}}',
    )
    # Error probe: id[$invalid_nosql_op]=1 triggers MongoDB error
    respx.get(url__startswith="http://lab.local/items?id%5B%24invalid_nosql_op%5D=1").respond(
        500,
        text=(
            '{"error": "MongoServerError: unknown operator: $invalid_nosql_op", '
            '"code": 2, "codeName": "BadValue"}'
        ),
    )
    # Differential probes return clean responses
    respx.get(url__startswith="http://lab.local/items").respond(
        200,
        text='{"status": "success", "data": {"id": 1, "name": "Document A"}}',
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = NoSQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan("http://lab.local/items?id=1")

    assert result.execution_status == "completed"
    assert result.summary.potential_indicators >= 1

    err_findings = [f for f in result.findings if f.technique == NoSQLTestTechnique.ERROR_BASED]
    assert len(err_findings) == 1
    assert err_findings[0].status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
    assert err_findings[0].confidence == NoSQLConfidenceRating.HIGH
    assert err_findings[0].evidence_records[0].provider_family_hint == NoSQLProviderFamily.MONGODB
    assert err_findings[0].evidence_records[0].confirmed is False


@respx.mock
def test_nosql_boolean_differential_signal_detected(in_scope_manager: ScopeManager) -> None:
    """Verify boolean differential detection using MongoDB operator pairs."""
    # Baseline
    respx.get("http://lab.local/user?uid=5").respond(
        200,
        text='{"user": "alice", "role": "admin", "active": true}',
    )
    # Error probe returns standard profile
    respx.get(url__startswith="http://lab.local/user?uid%5B%24invalid_nosql_op%5D=1").respond(
        200,
        text='{"user": "alice", "role": "admin", "active": true}',
    )
    # True probe (uid[$ne]=sentinel) returns matching user document (matches baseline)
    respx.get(url__startswith="http://lab.local/user?uid%5B%24ne%5D=__dbshield_sentinel__").respond(
        200,
        text='{"user": "alice", "role": "admin", "active": true}',
    )
    # False probe (uid[$eq]=sentinel) returns not found (diverges)
    respx.get(url__startswith="http://lab.local/user?uid%5B%24eq%5D=__dbshield_sentinel__").respond(
        404,
        text='{"error": "User not found"}',
    )

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = NoSQLiEngine(scope_manager=in_scope_manager, http_client=client)

    result = engine.scan("http://lab.local/user?uid=5")

    diff_findings = [
        f for f in result.findings if f.technique == NoSQLTestTechnique.BOOLEAN_DIFFERENTIAL
    ]
    assert len(diff_findings) == 1
    assert diff_findings[0].status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
    assert diff_findings[0].evidence_records[0].confirmed is False


@respx.mock
def test_nosql_nested_json_post_integration(in_scope_manager: ScopeManager) -> None:
    """Verify testing parameters nested inside JSON bodies."""
    # Baseline
    respx.post("http://lab.local/api/search").respond(
        200,
        text='{"status": "ok", "results": [{"name": "Doc 1"}]}',
    )

    # Let's inspect request bodies in callback or route
    def handle_search(request: httpx.Request) -> httpx.Response:
        import json

        body = json.loads(request.content.decode("utf-8"))
        # If user_id is injected with operator, return MongoDB error
        user_val = body.get("filter", {}).get("user_id")
        if isinstance(user_val, dict) and "$invalid_nosql_op" in user_val:
            return httpx.Response(
                500,
                text="MongoServerError: unknown operator: $invalid_nosql_op",
            )
        return httpx.Response(200, text='{"status": "ok", "results": [{"name": "Doc 1"}]}')

    respx.post("http://lab.local/api/search").mock(side_effect=handle_search)

    client = SafeHTTPClient(scope_manager=in_scope_manager)
    engine = NoSQLiEngine(scope_manager=in_scope_manager, http_client=client)

    nested_payload = {"filter": {"user_id": "100"}}

    result = engine.scan(
        target_url="http://lab.local/api/search",
        method="POST",
        json_data=nested_payload,
    )

    assert result.execution_status == "completed"
    param_names = [p.name for p in result.parameters]
    assert "filter.user_id" in param_names
    err_finding = [f for f in result.findings if f.technique == NoSQLTestTechnique.ERROR_BASED][0]
    assert err_finding.status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
