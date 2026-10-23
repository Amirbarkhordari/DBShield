"""Unit tests for DBShield finding normalization and deduplication layer (Phase 8)."""

from dbshield.reporting.models import FindingSeverity, VulnerabilityCategory
from dbshield.reporting.normalizer import FindingNormalizer
from dbshield.sqli.models import (
    CandidateParameter,
    DatabaseFamily,
    DetectionStatus,
    EvidenceRecord,
    ParameterLocation,
    SQLiFinding,
    SQLiScanResult,
    SQLiScanSummary,
    TestTechnique,
)
from dbshield.verification.models import (
    ConfidenceAssessment,
    ConfidenceLevel,
    EvidenceProvenance,
    NormalizedEvidence,
    VerificationFinding,
    VerificationResult,
    VerificationStatus,
    VerificationSummary,
)


def _make_dummy_evidence(param_name: str = "id") -> NormalizedEvidence:
    """Helper to create dummy normalized evidence record."""
    prov = EvidenceProvenance(
        engine="sqli",
        vulnerability_class="sqli",  # type: ignore[arg-type]
        target_url="http://target.local/products",
        parameter_name=param_name,
        parameter_location=ParameterLocation.QUERY,
    )
    return NormalizedEvidence(
        evidence_type="error_signature",  # type: ignore[arg-type]
        provenance=prov,
        rule_id="SQLI_MYSQL_SYNTAX",
        matched_pattern="syntax error",
        safe_snippet="...error in SQL syntax...",
        description="MySQL syntax error observed",
        provider_or_family="mysql",
    )


def test_from_verification_finding_conversion() -> None:
    """Verify conversion of VerificationFinding to NormalizedSecurityFinding."""
    ev = _make_dummy_evidence("cat_id")
    vf = VerificationFinding(
        verification_id="vf-123",
        vulnerability_class="sqli",  # type: ignore[arg-type]
        engine="sqli",
        target_url="http://target.local/products",
        parameter_name="cat_id",
        parameter_location=ParameterLocation.QUERY,
        status=VerificationStatus.VERIFIED,
        confidence=ConfidenceAssessment(
            level=ConfidenceLevel.VERIFIED,
            score=0.92,
            observation_confidence=0.95,
            vulnerability_confidence=0.90,
            explanation="Verified MySQL error pattern.",
        ),
        corroborating_evidence=[ev],
        verification_rationale="Formally verified MySQL error pattern.",
    )

    finding = FindingNormalizer.from_verification_finding(vf)
    assert finding.id.startswith("DBS-")
    assert finding.category == VulnerabilityCategory.SQL_INJECTION
    assert finding.severity == FindingSeverity.HIGH
    assert finding.verification_status == VerificationStatus.VERIFIED
    assert finding.parameter_name == "cat_id"
    assert finding.cwe_id == "CWE-89"
    assert finding.evidence_count == 1


def test_from_verification_result_conversion() -> None:
    """Verify conversion of complete VerificationResult to SecurityAssessmentReport."""
    ev = _make_dummy_evidence("q")
    vf = VerificationFinding(
        verification_id="vf-456",
        vulnerability_class="sqli",  # type: ignore[arg-type]
        engine="sqli",
        target_url="http://target.local/search",
        parameter_name="q",
        parameter_location=ParameterLocation.QUERY,
        status=VerificationStatus.VERIFIED,
        confidence=ConfidenceAssessment(
            level=ConfidenceLevel.VERIFIED,
            score=0.95,
            observation_confidence=0.98,
            vulnerability_confidence=0.92,
            explanation="Verified SQL syntax error.",
        ),
        corroborating_evidence=[ev],
        verification_rationale="Formally verified error pattern.",
    )
    vr = VerificationResult(
        result_id="res-789",
        target_url="http://target.local/search",
        summary=VerificationSummary(total_evaluated=1, verified_count=1),
        findings=[vf],
        limitations=["Scope bounded to /search."],
    )

    report = FindingNormalizer.from_verification_result(vr)
    assert report.metadata.total_findings == 1
    assert report.metadata.findings_by_severity["high"] == 1
    assert report.metadata.findings_by_status["verified"] == 1
    assert len(report.findings) == 1
    assert report.findings[0].endpoint == "/search"


def test_deduplication_promotes_higher_verification_status() -> None:
    """Verify deduplication groups identical coordinates and selects highest status."""
    ev = _make_dummy_evidence("id")
    # Finding 1: Potential Indicator
    vf1 = VerificationFinding(
        verification_id="vf-001",
        vulnerability_class="sqli",  # type: ignore[arg-type]
        engine="sqli",
        target_url="http://target.local/item",
        parameter_name="id",
        parameter_location=ParameterLocation.QUERY,
        status=VerificationStatus.POTENTIAL_INDICATOR,
        confidence=ConfidenceAssessment(
            level=ConfidenceLevel.LOW,
            score=0.40,
            observation_confidence=0.50,
            vulnerability_confidence=0.30,
            explanation="Initial error signal.",
        ),
        corroborating_evidence=[ev],
        verification_rationale="Raw signal observed.",
    )
    # Finding 2: Verified (same coordinates)
    vf2 = VerificationFinding(
        verification_id="vf-002",
        vulnerability_class="sqli",  # type: ignore[arg-type]
        engine="sqli",
        target_url="http://target.local/item",
        parameter_name="id",
        parameter_location=ParameterLocation.QUERY,
        status=VerificationStatus.VERIFIED,
        confidence=ConfidenceAssessment(
            level=ConfidenceLevel.VERIFIED,
            score=0.95,
            observation_confidence=0.95,
            vulnerability_confidence=0.95,
            explanation="Verified pattern.",
        ),
        corroborating_evidence=[ev],
        verification_rationale="Formally verified.",
    )

    f1 = FindingNormalizer.from_verification_finding(vf1)
    f2 = FindingNormalizer.from_verification_finding(vf2)

    assert f1.id == f2.id  # Same canonical coordinates

    deduped = FindingNormalizer.deduplicate_findings([f1, f2])
    assert len(deduped) == 1
    assert deduped[0].verification_status == VerificationStatus.VERIFIED
    assert deduped[0].severity == FindingSeverity.HIGH


def test_deduplication_preserves_distinct_parameters_and_endpoints() -> None:
    """Verify findings differing in parameter or endpoint remain separate."""
    ev1 = _make_dummy_evidence("user")
    ev2 = _make_dummy_evidence("page")

    vf1 = VerificationFinding(
        verification_id="vf-user",
        vulnerability_class="sqli",  # type: ignore[arg-type]
        engine="sqli",
        target_url="http://target.local/item",
        parameter_name="user",
        parameter_location=ParameterLocation.QUERY,
        status=VerificationStatus.VERIFIED,
        confidence=ConfidenceAssessment(
            level=ConfidenceLevel.VERIFIED,
            score=0.90,
            observation_confidence=0.90,
            vulnerability_confidence=0.90,
            explanation="Verified user parameter.",
        ),
        corroborating_evidence=[ev1],
        verification_rationale="Verified user parameter.",
    )
    vf2 = VerificationFinding(
        verification_id="vf-page",
        vulnerability_class="sqli",  # type: ignore[arg-type]
        engine="sqli",
        target_url="http://target.local/item",
        parameter_name="page",
        parameter_location=ParameterLocation.QUERY,
        status=VerificationStatus.VERIFIED,
        confidence=ConfidenceAssessment(
            level=ConfidenceLevel.VERIFIED,
            score=0.90,
            observation_confidence=0.90,
            vulnerability_confidence=0.90,
            explanation="Verified page parameter.",
        ),
        corroborating_evidence=[ev2],
        verification_rationale="Verified page parameter.",
    )

    f1 = FindingNormalizer.from_verification_finding(vf1)
    f2 = FindingNormalizer.from_verification_finding(vf2)
    assert f1.id != f2.id

    deduped = FindingNormalizer.deduplicate_findings([f1, f2])
    assert len(deduped) == 2


def test_from_sqli_scan_result_conversion() -> None:
    """Verify Phase 4 SQLiScanResult is converted to normalized report."""
    param = CandidateParameter(
        name="id",
        location=ParameterLocation.QUERY,
        endpoint="http://target.local/api",
    )
    ev_rec = EvidenceRecord(
        technique=TestTechnique.ERROR_BASED,
        rule_id="SQLI_MYSQL_SYNTAX",
        matched_pattern="syntax error",
        snippet="error in SQL syntax",
        description="MySQL syntax error observed",
        db_family_hint=DatabaseFamily.MYSQL,
    )
    finding = SQLiFinding(
        test_id="SQLI_001",
        technique=TestTechnique.ERROR_BASED,
        target_url="http://target.local/api",
        http_method="GET",
        parameter=param,
        status=DetectionStatus.POTENTIAL_INDICATOR,
        evidence_records=[ev_rec],
    )
    scan_res = SQLiScanResult(
        target_url="http://target.local/api",
        summary=SQLiScanSummary(
            total_parameters=1,
            tested_parameters=1,
            potential_indicators=1,
        ),
        findings=[finding],
    )

    report = FindingNormalizer.from_sqli_scan_result(scan_res)
    assert report.metadata.total_findings == 1
    assert report.findings[0].category == VulnerabilityCategory.SQL_INJECTION
    assert report.findings[0].cwe_id == "CWE-89"
