"""Unit tests for Phase 5 NoSQL models."""

import pytest
from pydantic import ValidationError

from dbshield.nosqli.models import (
    NoSQLBaselineProfile,
    NoSQLCandidateParameter,
    NoSQLConfidenceRating,
    NoSQLDetectionStatus,
    NoSQLEvidenceRecord,
    NoSQLFinding,
    NoSQLProviderFamily,
    NoSQLScanResult,
    NoSQLScanSummary,
    NoSQLTestTechnique,
    ParameterLocation,
)


def test_nosql_provider_family_enum() -> None:
    """Verify NoSQL provider family enum values."""
    assert NoSQLProviderFamily.MONGODB.value == "mongodb"
    assert NoSQLProviderFamily.COUCHDB.value == "couchdb"
    assert NoSQLProviderFamily.GENERIC_NOSQL.value == "generic_nosql"
    assert NoSQLProviderFamily.UNKNOWN.value == "unknown"


def test_nosql_candidate_parameter_immutability_and_nested_path() -> None:
    """Verify CandidateParameter immutability and nested key path representation."""
    param = NoSQLCandidateParameter(
        name="filter.user_id",
        location=ParameterLocation.BODY_JSON,
        key_path=["filter", "user_id"],
        original_value=12345,
        endpoint="https://example.com/api/users",
        method="POST",
        content_type="application/json",
        source="json_body",
        is_eligible=True,
    )

    assert param.name == "filter.user_id"
    assert param.key_path == ["filter", "user_id"]
    assert param.original_value == 12345

    with pytest.raises(ValidationError):
        # Frozen model prevents mutation
        param.name = "changed"  # type: ignore[misc]


def test_nosql_evidence_record_unconfirmed_guarantee() -> None:
    """Verify NoSQLEvidenceRecord defaults to confirmed=False."""
    record = NoSQLEvidenceRecord(
        technique=NoSQLTestTechnique.ERROR_BASED,
        rule_id="MONGO_ERR_UNKNOWN_OP",
        matched_pattern=r"unknown operator",
        snippet="MongoServerError: unknown operator: $invalid",
        description="Matched MongoDB unknown operator error",
        provider_family_hint=NoSQLProviderFamily.MONGODB,
    )

    assert record.confirmed is False
    assert record.provider_family_hint == NoSQLProviderFamily.MONGODB


def test_nosql_baseline_profile_attributes() -> None:
    """Verify NoSQLBaselineProfile initialization and immutability."""
    profile = NoSQLBaselineProfile(
        status_code=200,
        content_type="application/json",
        content_length=512,
        elapsed_seconds=0.042,
        is_stable=True,
        sample_count=2,
        body_hash="abc123hash",
    )

    assert profile.status_code == 200
    assert profile.is_stable is True
    assert profile.body_hash == "abc123hash"


def test_nosql_finding_serialization() -> None:
    """Verify NoSQLFinding Pydantic serialization round-trip."""
    param = NoSQLCandidateParameter(
        name="username",
        location=ParameterLocation.QUERY,
        key_path=["username"],
        endpoint="https://example.com/search",
    )
    evidence = NoSQLEvidenceRecord(
        technique=NoSQLTestTechnique.ERROR_BASED,
        rule_id="MONGO_SYNTAX_WHERE",
        matched_pattern="SyntaxError",
        snippet="SyntaxError: Unexpected token",
        description="MongoDB $where syntax error",
        provider_family_hint=NoSQLProviderFamily.MONGODB,
    )
    finding = NoSQLFinding(
        test_id="NOSQL_TEST_1",
        technique=NoSQLTestTechnique.ERROR_BASED,
        target_url="https://example.com/search",
        http_method="GET",
        parameter=param,
        status=NoSQLDetectionStatus.POTENTIAL_INDICATOR,
        confidence=NoSQLConfidenceRating.HIGH,
        evidence_summary="Found MongoDB syntax error",
        evidence_records=[evidence],
        limitations=["Laboratory test only."],
    )

    json_str = finding.model_dump_json()
    reconstituted = NoSQLFinding.model_validate_json(json_str)
    assert reconstituted.test_id == "NOSQL_TEST_1"
    assert reconstituted.status == NoSQLDetectionStatus.POTENTIAL_INDICATOR
    assert reconstituted.confidence == NoSQLConfidenceRating.HIGH
    assert len(reconstituted.evidence_records) == 1
    assert reconstituted.evidence_records[0].confirmed is False


def test_nosql_scan_result_and_summary() -> None:
    """Verify NoSQLScanResult and Summary structure."""
    summary = NoSQLScanSummary(
        total_parameters=3,
        tested_parameters=2,
        skipped_parameters=1,
        potential_indicators=1,
        clean_parameters=1,
        inconclusive_parameters=0,
        total_requests=7,
        duration_seconds=1.234,
    )
    result = NoSQLScanResult(
        target_url="https://example.com/login",
        execution_status="completed",
        summary=summary,
        findings=[],
        parameters=[],
        limitations=["Defensive assessment only."],
    )

    assert result.summary.potential_indicators == 1
    assert result.summary.total_requests == 7
    dumped = result.model_dump()
    assert dumped["execution_status"] == "completed"
