"""Unit tests for DBShield Confidence Assessor (Phase 7)."""

from dbshield.sqli.models import ParameterLocation
from dbshield.verification.confidence import ConfidenceAssessor
from dbshield.verification.models import (
    ConfidenceLevel,
    EvidenceProvenance,
    EvidenceType,
    NormalizedEvidence,
    VulnerabilityClass,
)


def _make_evidence(
    ev_type: EvidenceType = EvidenceType.ERROR_SIGNATURE,
    provider: str = "mysql",
    is_stable: bool = True,
    is_preexisting: bool = False,
    is_contradictory: bool = False,
    sim_score: float | None = None,
    base_status: int = 200,
    test_status: int = 500,
) -> NormalizedEvidence:
    prov = EvidenceProvenance(
        engine="sqli",
        vulnerability_class=VulnerabilityClass.SQLI,
        target_url="http://target.local/api",
        parameter_name="id",
        parameter_location=ParameterLocation.QUERY,
    )
    return NormalizedEvidence(
        evidence_type=ev_type,
        provenance=prov,
        rule_id="RULE_TEST",
        matched_pattern="pattern",
        safe_snippet="sample snippet",
        description="test description",
        provider_or_family=provider,
        baseline_status=base_status,
        test_status=test_status,
        similarity_score=sim_score,
        is_baseline_stable=is_stable,
        is_preexisting_in_baseline=is_preexisting,
        is_contradictory=is_contradictory,
    )


def test_confidence_specific_error_with_stable_baseline() -> None:
    """Verify specific database error signature with stable baseline yields high confidence."""
    ev = _make_evidence(ev_type=EvidenceType.ERROR_SIGNATURE, provider="mysql", is_stable=True)
    conf = ConfidenceAssessor.evaluate([ev], is_baseline_stable=True)

    assert conf.level in (ConfidenceLevel.HIGH, ConfidenceLevel.VERIFIED)
    assert conf.score >= 0.70
    assert conf.vulnerability_confidence >= 0.50
    assert any("Specific database engine error" in f for f in conf.contributing_factors)


def test_confidence_preexisting_baseline_error_yields_zero_vuln_confidence() -> None:
    """Verify pre-existing baseline error eliminates vulnerability confidence (false positive)."""
    ev = _make_evidence(ev_type=EvidenceType.ERROR_SIGNATURE, provider="mysql", is_preexisting=True)
    conf = ConfidenceAssessor.evaluate([ev], is_baseline_stable=True)

    assert conf.level == ConfidenceLevel.LOW
    assert conf.vulnerability_confidence == 0.0
    assert any("pre-existing" in f.lower() for f in conf.degrading_factors)
    assert "proven false positive" in conf.explanation.lower()


def test_confidence_unstable_baseline_penalizes_score() -> None:
    """Verify unstable baseline significantly degrades confidence."""
    ev_stable = _make_evidence(
        ev_type=EvidenceType.DIFFERENTIAL_PAIR, is_stable=True, sim_score=0.40
    )
    conf_stable = ConfidenceAssessor.evaluate([ev_stable], is_baseline_stable=True)

    ev_unstable = _make_evidence(
        ev_type=EvidenceType.DIFFERENTIAL_PAIR, is_stable=False, sim_score=0.40
    )
    conf_unstable = ConfidenceAssessor.evaluate([ev_unstable], is_baseline_stable=False)

    assert conf_unstable.score < conf_stable.score
    assert any("unstable" in f.lower() for f in conf_unstable.degrading_factors)


def test_confidence_corroboration_between_independent_detectors() -> None:
    """Verify agreement between error signature and differential detectors boosts confidence."""
    ev_err = _make_evidence(ev_type=EvidenceType.ERROR_SIGNATURE, provider="mysql")
    ev_diff = _make_evidence(
        ev_type=EvidenceType.DIFFERENTIAL_PAIR, provider="mysql", sim_score=0.35
    )

    conf = ConfidenceAssessor.evaluate([ev_err, ev_diff], is_baseline_stable=True)
    assert conf.level in (ConfidenceLevel.HIGH, ConfidenceLevel.VERIFIED)
    assert conf.score >= 0.80
    assert any("Agreement between independent" in f for f in conf.contributing_factors)


def test_confidence_contradictory_evidence_penalized() -> None:
    """Verify contradictory evidence degrades vulnerability confidence."""
    ev = _make_evidence(ev_type=EvidenceType.DIFFERENTIAL_PAIR, is_contradictory=True)
    conf = ConfidenceAssessor.evaluate([ev], is_baseline_stable=True)

    assert any("Contradictory" in f for f in conf.degrading_factors)
    assert conf.vulnerability_confidence < 0.50


def test_confidence_failed_execution_yields_zero() -> None:
    """Verify failed or cancelled executions yield zero confidence."""
    ev = _make_evidence()
    conf = ConfidenceAssessor.evaluate([ev], has_failed_execution=True)

    assert conf.level == ConfidenceLevel.LOW
    assert conf.score == 0.0
    assert conf.vulnerability_confidence == 0.0
    assert any("failed" in f.lower() for f in conf.degrading_factors)
