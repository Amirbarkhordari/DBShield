"""Unit tests for SQLi and NoSQLi execution engine adapters (Phase 6)."""

from dbshield.execution.adapters import NoSQLiExecutionAdapter, SQLiExecutionAdapter
from dbshield.models.http import HTTPResponse
from dbshield.nosqli.models import (
    NoSQLConfidenceRating,
    NoSQLDetectionStatus,
    NoSQLFinding,
)
from dbshield.payloads.models import PayloadCategory, SecurityPayload
from dbshield.sqli.models import (
    ConfidenceRating,
    DetectionStatus,
    ParameterLocation,
    SQLiFinding,
)


def test_sqli_adapter_single_probe_detects_error() -> None:
    """Verify SQLi adapter evaluates single probe and flags SQL syntax errors."""
    adapter = SQLiExecutionAdapter()
    assert adapter.engine_name == "sqli"

    payload = SecurityPayload(
        payload_id="SQLI_ERR_QUOTE",
        name="Quote probe",
        description="Quote",
        category=PayloadCategory.SQLI,
        technique="error_based",
        applicable_locations=[ParameterLocation.QUERY],
        payload_value="'",
    )

    baseline_resp = HTTPResponse(
        url="https://example.com/item?id=1",
        status_code=200,
        body="<html><body>Welcome to item 1 page</body></html>",
    )
    test_resp = HTTPResponse(
        url="https://example.com/item?id=1'",
        status_code=500,
        body="<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</body></html>",
    )

    finding = adapter.evaluate_single_probe(
        target_url="https://example.com/item?id=1",
        param_name="id",
        param_location=ParameterLocation.QUERY,
        payload=payload,
        test_resp=test_resp,
        baseline_resp=baseline_resp,
    )

    assert isinstance(finding, SQLiFinding)
    assert finding.status == DetectionStatus.POTENTIAL_INDICATOR
    assert finding.confidence == ConfidenceRating.HIGH
    assert len(finding.evidence_records) > 0
    assert "syntax" in finding.evidence_records[0].description.lower()


def test_sqli_adapter_single_probe_clean_response() -> None:
    """Verify SQLi adapter marks clean responses as NO_INDICATOR."""
    adapter = SQLiExecutionAdapter()
    payload = SecurityPayload(
        payload_id="SQLI_ERR_QUOTE",
        name="Quote probe",
        description="Quote",
        category=PayloadCategory.SQLI,
        technique="error_based",
        applicable_locations=[ParameterLocation.QUERY],
        payload_value="'",
    )
    baseline_resp = HTTPResponse(
        url="https://example.com/item?id=1",
        status_code=200,
        body="Item details",
    )
    test_resp = HTTPResponse(
        url="https://example.com/item?id=1'",
        status_code=200,
        body="Item details",
    )

    finding = adapter.evaluate_single_probe(
        target_url="https://example.com/item?id=1",
        param_name="id",
        param_location=ParameterLocation.QUERY,
        payload=payload,
        test_resp=test_resp,
        baseline_resp=baseline_resp,
    )
    assert finding.status == DetectionStatus.NO_INDICATOR


def test_sqli_adapter_paired_probes_detects_differential() -> None:
    """Verify SQLi adapter evaluates paired true/false probes."""
    adapter = SQLiExecutionAdapter()
    p_true = SecurityPayload(
        payload_id="TRUE",
        name="T",
        description="T",
        category=PayloadCategory.SQLI,
        technique="differential",
        applicable_locations=[ParameterLocation.QUERY],
        payload_value=" AND 1=1",
        is_paired=True,
        pair_role="true",
        paired_with_id="FALSE",
    )
    p_false = SecurityPayload(
        payload_id="FALSE",
        name="F",
        description="F",
        category=PayloadCategory.SQLI,
        technique="differential",
        applicable_locations=[ParameterLocation.QUERY],
        payload_value=" AND 1=2",
        is_paired=True,
        pair_role="false",
        paired_with_id="TRUE",
    )

    baseline_resp = HTTPResponse(
        url="https://example.com/search?q=test",
        status_code=200,
        body="Items found: 10 results displayed here.",
    )
    true_resp = HTTPResponse(
        url="https://example.com/search?q=test+AND+1=1",
        status_code=200,
        body="Items found: 10 results displayed here.",
    )
    false_resp = HTTPResponse(
        url="https://example.com/search?q=test+AND+1=2",
        status_code=200,
        body="No results found matching your query.",
    )

    finding = adapter.evaluate_paired_probes(
        target_url="https://example.com/search?q=test",
        param_name="q",
        param_location=ParameterLocation.QUERY,
        true_payload=p_true,
        false_payload=p_false,
        true_resp=true_resp,
        false_resp=false_resp,
        baseline_resp=baseline_resp,
        is_baseline_stable=True,
    )
    assert isinstance(finding, SQLiFinding)
    assert finding.status == DetectionStatus.POTENTIAL_INDICATOR


def test_nosqli_adapter_single_probe_detects_error() -> None:
    """Verify NoSQLi adapter evaluates single probe and flags MongoDB error patterns."""
    adapter = NoSQLiExecutionAdapter()
    assert adapter.engine_name == "nosqli"

    payload = SecurityPayload(
        payload_id="NOSQLI_ERR_OP",
        name="Op probe",
        description="Op",
        category=PayloadCategory.NOSQLI,
        technique="error_based",
        applicable_locations=[ParameterLocation.BODY_JSON],
        payload_value={"$badOp": 1},
    )

    baseline_resp = HTTPResponse(
        url="https://example.com/api/users",
        status_code=200,
        body='{"users": ["alice", "bob"]}',
    )
    test_resp = HTTPResponse(
        url="https://example.com/api/users",
        status_code=500,
        body='{"error": "unknown operator: $badOp", "code": 2}',
    )

    finding = adapter.evaluate_single_probe(
        target_url="https://example.com/api/users",
        param_name="filter",
        param_location=ParameterLocation.BODY_JSON,
        payload=payload,
        test_resp=test_resp,
        baseline_resp=baseline_resp,
    )

    assert isinstance(finding, NoSQLFinding)
    assert finding.status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
    assert finding.confidence in (NoSQLConfidenceRating.HIGH, NoSQLConfidenceRating.MEDIUM)
    assert len(finding.evidence_records) > 0


def test_nosqli_adapter_paired_probes_detects_differential() -> None:
    """Verify NoSQLi adapter evaluates paired true/false probes."""
    adapter = NoSQLiExecutionAdapter()
    p_true = SecurityPayload(
        payload_id="T_JSON",
        name="T",
        description="T",
        category=PayloadCategory.NOSQLI,
        technique="differential",
        applicable_locations=[ParameterLocation.BODY_JSON],
        payload_value={"$ne": None},
        is_paired=True,
        pair_role="true",
        paired_with_id="F_JSON",
    )
    p_false = SecurityPayload(
        payload_id="F_JSON",
        name="F",
        description="F",
        category=PayloadCategory.NOSQLI,
        technique="differential",
        applicable_locations=[ParameterLocation.BODY_JSON],
        payload_value={"$in": []},
        is_paired=True,
        pair_role="false",
        paired_with_id="T_JSON",
    )

    baseline_resp = HTTPResponse(
        url="https://example.com/api/filter",
        status_code=200,
        body='{"status": "ok", "items": [{"id": 1}, {"id": 2}]}',
    )
    true_resp = HTTPResponse(
        url="https://example.com/api/filter",
        status_code=200,
        body='{"status": "ok", "items": [{"id": 1}, {"id": 2}]}',
    )
    false_resp = HTTPResponse(
        url="https://example.com/api/filter",
        status_code=200,
        body='{"status": "ok", "items": []}',
    )

    finding = adapter.evaluate_paired_probes(
        target_url="https://example.com/api/filter",
        param_name="filter",
        param_location=ParameterLocation.BODY_JSON,
        true_payload=p_true,
        false_payload=p_false,
        true_resp=true_resp,
        false_resp=false_resp,
        baseline_resp=baseline_resp,
        is_baseline_stable=True,
    )
    assert isinstance(finding, NoSQLFinding)
    assert finding.status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
