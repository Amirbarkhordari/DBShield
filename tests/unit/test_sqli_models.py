"""Unit tests for SQL injection data models and finding structures (Phase 4)."""

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from dbshield.sqli.models import (
    BaselineProfile,
    CandidateParameter,
    ConfidenceRating,
    DatabaseFamily,
    DetectionStatus,
    EvidenceRecord,
    ParameterLocation,
    SQLiFinding,
    SQLiScanResult,
    SQLiScanSummary,
    TestTechnique,
)


def test_parameter_location_enum() -> None:
    assert ParameterLocation.QUERY == "query"
    assert ParameterLocation.BODY_URLENCODED == "body_urlencoded"
    assert ParameterLocation.BODY_JSON == "body_json"
    assert ParameterLocation.HEADER == "header"
    assert ParameterLocation.COOKIE == "cookie"


def test_candidate_parameter_immutability() -> None:
    param = CandidateParameter(
        name="id",
        location=ParameterLocation.QUERY,
        original_value="123",
        endpoint="https://example.com/items",
        method="GET",
        is_eligible=True,
    )
    assert param.name == "id"
    assert param.location == ParameterLocation.QUERY
    assert param.original_value == "123"

    with pytest.raises(ValidationError):
        # Frozen model should reject mutation
        param.name = "other"  # type: ignore[misc]


def test_evidence_record_unconfirmed_guarantee() -> None:
    evidence = EvidenceRecord(
        technique=TestTechnique.ERROR_BASED,
        rule_id="ERR_MYSQL_SYNTAX",
        matched_pattern="You have an error in your SQL syntax",
        snippet="...syntax error near '' at line 1...",
        description="MySQL syntax error matched",
        db_family_hint=DatabaseFamily.MYSQL,
    )
    assert evidence.confirmed is False  # Phase 4 guarantee: never auto-confirmed
    assert evidence.db_family_hint == DatabaseFamily.MYSQL


def test_baseline_profile_attributes() -> None:
    profile = BaselineProfile(
        status_code=200,
        content_type="text/html; charset=utf-8",
        content_length=1024,
        elapsed_seconds=0.12,
        is_stable=True,
        instability_reason=None,
        sample_count=2,
        body_hash="abc123hash",
    )
    assert profile.status_code == 200
    assert profile.is_stable is True
    assert profile.body_hash == "abc123hash"


def test_sqli_finding_serialization() -> None:
    param = CandidateParameter(
        name="search",
        location=ParameterLocation.QUERY,
        original_value="books",
        endpoint="https://example.com/search",
    )
    evidence = EvidenceRecord(
        technique=TestTechnique.ERROR_BASED,
        rule_id="ERR_PG_SYNTAX",
        matched_pattern="syntax error at or near",
        snippet="ERROR: syntax error at or near 'books'",
        description="PostgreSQL syntax error",
        db_family_hint=DatabaseFamily.POSTGRESQL,
    )
    finding = SQLiFinding(
        test_id="SQLI_ERR_search",
        technique=TestTechnique.ERROR_BASED,
        target_url="https://example.com/search?search=books",
        http_method="GET",
        parameter=param,
        status=DetectionStatus.POTENTIAL_INDICATOR,
        confidence=ConfidenceRating.HIGH,
        evidence_summary="Detected PostgreSQL syntax error",
        evidence_records=[evidence],
        request_count=2,
    )
    assert finding.status == DetectionStatus.POTENTIAL_INDICATOR
    assert finding.confidence == ConfidenceRating.HIGH
    assert len(finding.evidence_records) == 1

    # Verify JSON serialization round-trip
    dumped_json = finding.model_dump_json()
    parsed = json.loads(dumped_json)
    assert parsed["test_id"] == "SQLI_ERR_search"
    assert parsed["status"] == "potential_indicator"
    assert parsed["confidence"] == "high"
    assert parsed["evidence_records"][0]["db_family_hint"] == "postgresql"


def test_sqli_scan_result_and_summary() -> None:
    summary = SQLiScanSummary(
        total_parameters=2,
        tested_parameters=2,
        potential_indicators=1,
        clean_parameters=1,
        total_requests=6,
        duration_seconds=0.45,
    )
    result = SQLiScanResult(
        target_url="https://example.com/api",
        execution_status="completed",
        summary=summary,
        findings=[],
        parameters=[],
        limitations=["Laboratory use only."],
    )
    assert result.summary.potential_indicators == 1
    assert result.summary.clean_parameters == 1
    assert "Laboratory use only." in result.limitations
    assert isinstance(result.timestamp, datetime)

    dumped = result.model_dump_json()
    assert "execution_status" in dumped
