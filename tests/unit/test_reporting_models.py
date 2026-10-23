"""Unit tests for DBShield structured reporting models (Phase 8)."""

import pytest
from pydantic import ValidationError

from dbshield.reporting.models import (
    FindingSeverity,
    NormalizedSecurityFinding,
    ReportMetadata,
    SecurityAssessmentReport,
    VulnerabilityCategory,
)
from dbshield.sqli.models import ParameterLocation
from dbshield.verification.models import ConfidenceLevel, VerificationStatus


def test_finding_severity_enum() -> None:
    """Verify finding severity enumeration values."""
    assert FindingSeverity.CRITICAL == "critical"
    assert FindingSeverity.HIGH == "high"
    assert FindingSeverity.MEDIUM == "medium"
    assert FindingSeverity.LOW == "low"
    assert FindingSeverity.INFO == "info"


def test_vulnerability_category_enum() -> None:
    """Verify vulnerability category enumeration values."""
    assert VulnerabilityCategory.SQL_INJECTION == "sql_injection"
    assert VulnerabilityCategory.NOSQL_INJECTION == "nosql_injection"
    assert VulnerabilityCategory.AUTHENTICATION_BYPASS == "authentication_bypass"
    assert VulnerabilityCategory.INFORMATION_DISCLOSURE == "information_disclosure"
    assert VulnerabilityCategory.CONFIGURATION_WEAKNESS == "configuration_weakness"
    assert VulnerabilityCategory.UNKNOWN == "unknown"


def test_deterministic_id_computation() -> None:
    """Verify deterministic finding ID generation is repeatable and canonical."""
    id1 = NormalizedSecurityFinding.compute_deterministic_id(
        target_url="http://target.local/search?q=1",
        category="sql_injection",
        parameter_location="query",
        parameter_name="q",
        technique="error_based",
    )
    id2 = NormalizedSecurityFinding.compute_deterministic_id(
        target_url="http://TARGET.local/search?q=1",
        category="SQL_INJECTION",
        parameter_location="QUERY",
        parameter_name="Q",
        technique="ERROR_BASED",
    )
    assert id1.startswith("DBS-")
    assert id1 == id2


def test_normalized_security_finding_immutability() -> None:
    """Verify NormalizedSecurityFinding rejects mutation once constructed."""
    finding = NormalizedSecurityFinding(
        id="DBS-TEST001",
        title="Verified SQL Injection",
        category=VulnerabilityCategory.SQL_INJECTION,
        subtype="error_based",
        target_url="http://target.local/products",
        endpoint="/products",
        http_method="GET",
        parameter_name="cat_id",
        parameter_location=ParameterLocation.QUERY,
        engine="sqli",
        technique="error_based",
        verification_status=VerificationStatus.VERIFIED,
        confidence_level=ConfidenceLevel.VERIFIED,
        confidence_score=0.95,
        severity=FindingSeverity.HIGH,
        severity_rationale="Formally verified database syntax error.",
        description="SQL syntax error observed near parameter.",
        evidence_summary="syntax error near quote",
        remediation="Use parameterized queries.",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
    )
    with pytest.raises(ValidationError):
        finding.severity = FindingSeverity.LOW  # type: ignore[misc]


def test_report_metadata_and_report_serialization() -> None:
    """Verify SecurityAssessmentReport serialization and deserialization."""
    meta = ReportMetadata(
        target_url="http://target.local",
        total_findings=1,
        findings_by_severity={"high": 1},
        findings_by_status={"verified": 1},
        findings_by_category={"sql_injection": 1},
        assessment_scope=["http://target.local"],
        limitations=["Automated non-destructive assessment."],
    )
    finding = NormalizedSecurityFinding(
        id="DBS-TEST002",
        title="Verified NoSQL Operator Injection",
        category=VulnerabilityCategory.NOSQL_INJECTION,
        subtype="operator_injection",
        target_url="http://target.local/login",
        endpoint="/login",
        http_method="POST",
        parameter_name="user",
        parameter_location=ParameterLocation.BODY_JSON,
        engine="nosqli",
        technique="operator_injection",
        verification_status=VerificationStatus.VERIFIED,
        confidence_level=ConfidenceLevel.VERIFIED,
        confidence_score=0.90,
        severity=FindingSeverity.HIGH,
        severity_rationale="MongoDB operator error triggered.",
        description="Unexpected query operator response.",
        evidence_summary="unknown operator: $invalidOp",
        remediation="Validate input types against query selectors.",
        cwe_id="CWE-943",
    )
    report = SecurityAssessmentReport(metadata=meta, findings=[finding])
    json_str = report.model_dump_json()
    assert "DBS-TEST002" in json_str
    assert "CWE-943" in json_str

    deserialized = SecurityAssessmentReport.model_validate_json(json_str)
    assert deserialized.metadata.total_findings == 1
    assert deserialized.findings[0].category == VulnerabilityCategory.NOSQL_INJECTION
