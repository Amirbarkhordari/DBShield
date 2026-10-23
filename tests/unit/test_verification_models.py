"""Unit tests for DBShield Verification Subsystem data models (Phase 7)."""

import pytest
from pydantic import ValidationError

from dbshield.sqli.models import ParameterLocation
from dbshield.verification.models import (
    ConfidenceAssessment,
    ConfidenceLevel,
    EvidenceProvenance,
    EvidenceType,
    NormalizedEvidence,
    StateTransitionRecord,
    VerificationFinding,
    VerificationResult,
    VerificationStatus,
    VerificationSummary,
    VulnerabilityClass,
)


def test_evidence_type_enum() -> None:
    """Verify all evidence types are recognized string enums."""
    assert EvidenceType.ERROR_SIGNATURE == "error_signature"
    assert EvidenceType.DIFFERENTIAL_PAIR == "differential_pair"
    assert EvidenceType.STATUS_CODE_DIFFERENCE == "status_code_difference"
    assert EvidenceType.BODY_SIMILARITY == "body_similarity"
    assert EvidenceType.BASELINE_COMPARISON == "baseline_comparison"
    assert EvidenceType.EXECUTION_TRACE == "execution_trace"


def test_verification_status_enum() -> None:
    """Verify all verification lifecycle states are defined."""
    assert VerificationStatus.POTENTIAL_INDICATOR == "potential_indicator"
    assert VerificationStatus.UNDER_ANALYSIS == "under_analysis"
    assert VerificationStatus.VERIFICATION_REQUIRED == "verification_required"
    assert VerificationStatus.CORROBORATED == "corroborated"
    assert VerificationStatus.VERIFIED == "verified"
    assert VerificationStatus.INCONCLUSIVE == "inconclusive"
    assert VerificationStatus.REJECTED == "rejected"
    assert VerificationStatus.UNVERIFIABLE == "unverifiable"


def test_normalized_evidence_immutability() -> None:
    """Verify NormalizedEvidence is frozen and rejects mutation."""
    prov = EvidenceProvenance(
        engine="sqli",
        vulnerability_class=VulnerabilityClass.SQLI,
        target_url="http://test.local/api",
        parameter_name="id",
        parameter_location=ParameterLocation.QUERY,
    )
    ev = NormalizedEvidence(
        evidence_type=EvidenceType.ERROR_SIGNATURE,
        provenance=prov,
        rule_id="SQLI_MYSQL_SYNTAX",
        matched_pattern="You have an error in your SQL syntax",
        safe_snippet="...error in your SQL syntax...",
        description="MySQL syntax error detected.",
        provider_or_family="mysql",
    )
    with pytest.raises(ValidationError):
        ev.provider_or_family = "sqlite"  # type: ignore[misc]


def test_confidence_assessment_bounds() -> None:
    """Verify ConfidenceAssessment scores enforce [0.0, 1.0] bounds."""
    # Valid assessment
    conf = ConfidenceAssessment(
        level=ConfidenceLevel.HIGH,
        score=0.85,
        observation_confidence=0.90,
        vulnerability_confidence=0.80,
        contributing_factors=["Stable baseline"],
        degrading_factors=[],
        explanation="High confidence finding.",
    )
    assert conf.score == 0.85
    assert conf.level == ConfidenceLevel.HIGH

    # Score > 1.0 should raise ValidationError
    with pytest.raises(ValidationError):
        ConfidenceAssessment(
            level=ConfidenceLevel.HIGH,
            score=1.5,
            observation_confidence=0.9,
            vulnerability_confidence=0.8,
            explanation="Invalid",
        )

    # Score < 0.0 should raise ValidationError
    with pytest.raises(ValidationError):
        ConfidenceAssessment(
            level=ConfidenceLevel.LOW,
            score=-0.1,
            observation_confidence=0.0,
            vulnerability_confidence=0.0,
            explanation="Invalid",
        )


def test_verification_finding_serialization() -> None:
    """Verify VerificationFinding serialization roundtrip."""
    prov = EvidenceProvenance(
        engine="sqli",
        vulnerability_class=VulnerabilityClass.SQLI,
        target_url="http://test.local/search",
        parameter_name="q",
        parameter_location=ParameterLocation.QUERY,
    )
    ev = NormalizedEvidence(
        evidence_type=EvidenceType.ERROR_SIGNATURE,
        provenance=prov,
        rule_id="SQLI_SQLITE_ERROR",
        matched_pattern="near syntax error",
        safe_snippet='near "\'": syntax error',
        description="SQLite syntax error",
        provider_or_family="sqlite",
    )
    conf = ConfidenceAssessment(
        level=ConfidenceLevel.VERIFIED,
        score=0.95,
        observation_confidence=0.95,
        vulnerability_confidence=0.95,
        contributing_factors=["Specific SQLite error pattern"],
        explanation="Verified SQLite syntax injection.",
    )
    transition = StateTransitionRecord(
        from_status=VerificationStatus.POTENTIAL_INDICATOR,
        to_status=VerificationStatus.VERIFIED,
        reason="Specific SQLite pattern matched on stable baseline.",
    )
    finding = VerificationFinding(
        vulnerability_class=VulnerabilityClass.SQLI,
        engine="sqli",
        target_url="http://test.local/search",
        parameter_name="q",
        parameter_location=ParameterLocation.QUERY,
        status=VerificationStatus.VERIFIED,
        confidence=conf,
        corroborating_evidence=[ev],
        all_evidence=[ev],
        state_history=[transition],
        verification_rationale="Verified SQLite syntax injection.",
    )

    json_str = finding.model_dump_json()
    reloaded = VerificationFinding.model_validate_json(json_str)

    assert reloaded.status == VerificationStatus.VERIFIED
    assert reloaded.parameter_name == "q"
    assert reloaded.confidence.score == 0.95
    assert len(reloaded.corroborating_evidence) == 1
    assert reloaded.corroborating_evidence[0].provider_or_family == "sqlite"


def test_verification_result_summary_counts() -> None:
    """Verify VerificationResult aggregation and summary consistency."""
    summary = VerificationSummary(
        total_evaluated=3,
        verified_count=1,
        corroborated_count=0,
        potential_indicator_count=0,
        inconclusive_count=1,
        rejected_count=1,
        unverifiable_count=0,
    )
    res = VerificationResult(
        target_url="http://example.local/app",
        summary=summary,
        findings=[],
        correlation_groups=[],
    )
    assert res.summary.total_evaluated == 3
    assert res.summary.verified_count == 1
    assert res.summary.inconclusive_count == 1
    assert res.summary.rejected_count == 1
