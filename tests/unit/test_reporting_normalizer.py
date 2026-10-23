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


def test_deduplication_preserves_distinct_sensitive_parameters() -> None:
    """Verify distinct sensitive parameters (e.g. password vs passwd) do not collide in finding ID."""
    conf = ConfidenceAssessment(
        level=ConfidenceLevel.VERIFIED,
        score=0.92,
        observation_confidence=0.95,
        vulnerability_confidence=0.90,
        explanation="Verified error pattern.",
    )
    vf1 = VerificationFinding(
        verification_id="vf-pass1",
        vulnerability_class="sqli",  # type: ignore[arg-type]
        engine="sqli",
        target_url="http://target.local/login",
        parameter_name="password",
        parameter_location=ParameterLocation.BODY_URLENCODED,
        status=VerificationStatus.VERIFIED,
        confidence=conf,
        verification_rationale="Vulnerable password field.",
    )
    vf2 = VerificationFinding(
        verification_id="vf-pass2",
        vulnerability_class="sqli",  # type: ignore[arg-type]
        engine="sqli",
        target_url="http://target.local/login",
        parameter_name="passwd",
        parameter_location=ParameterLocation.BODY_URLENCODED,
        status=VerificationStatus.VERIFIED,
        confidence=conf,
        verification_rationale="Vulnerable passwd field.",
    )

    f1 = FindingNormalizer.from_verification_finding(vf1)
    f2 = FindingNormalizer.from_verification_finding(vf2)

    # Deterministic IDs must be different for distinct raw parameters
    assert f1.id != f2.id
    # Redacted display parameter names remain masked
    assert "REDACTED" in f1.parameter_name
    assert "REDACTED" in f2.parameter_name
    assert "password" not in f1.parameter_name
    assert "passwd" not in f2.parameter_name

    # Deduplicating must preserve both distinct findings
    deduped = FindingNormalizer.deduplicate_findings([f1, f2])
    assert len(deduped) == 2

    # Equivalent observations of the same parameter must still deduplicate
    f1_dup = FindingNormalizer.from_verification_finding(vf1)
    assert f1.id == f1_dup.id
    assert len(FindingNormalizer.deduplicate_findings([f1, f1_dup])) == 1


def test_deduplication_does_not_inflate_evidence_count() -> None:
    """Verify deduplication does not inflate evidence counts across duplicate observations."""
    ev = _make_dummy_evidence("query_id")
    vf_base = VerificationFinding(
        verification_id="vf-ev-test",
        vulnerability_class="sqli",  # type: ignore[arg-type]
        engine="sqli",
        target_url="http://target.local/item",
        parameter_name="query_id",
        parameter_location=ParameterLocation.QUERY,
        status=VerificationStatus.VERIFIED,
        confidence=ConfidenceAssessment(
            level=ConfidenceLevel.VERIFIED,
            score=0.90,
            observation_confidence=0.90,
            vulnerability_confidence=0.90,
            explanation="Test confidence.",
        ),
        corroborating_evidence=[ev],
        verification_rationale="Test evidence.",
    )

    # 1. Duplicate observations with identical single evidence ID
    f_ev1 = FindingNormalizer.from_verification_finding(vf_base)
    f_ev2 = FindingNormalizer.from_verification_finding(vf_base)
    deduped_ev = FindingNormalizer.deduplicate_findings([f_ev1, f_ev2])
    assert len(deduped_ev) == 1
    assert deduped_ev[0].evidence_count == 1
    assert len(deduped_ev[0].evidence_ids) == 1

    # 2. Observations with empty evidence IDs (e.g. unindexed detector results)
    f_empty1 = f_ev1.model_copy(update={"evidence_ids": [], "evidence_count": 1})
    f_empty2 = f_ev1.model_copy(update={"evidence_ids": [], "evidence_count": 1})
    deduped_empty = FindingNormalizer.deduplicate_findings([f_empty1, f_empty2])
    assert len(deduped_empty) == 1
    # Must NOT sum (1+1=2); must take conservative max
    assert deduped_empty[0].evidence_count == 1
    assert deduped_empty[0].evidence_ids == []

    # 3. Observations with distinct evidence IDs must accumulate
    f_dist1 = f_ev1.model_copy(update={"evidence_ids": ["ev-101"], "evidence_count": 1})
    f_dist2 = f_ev1.model_copy(update={"evidence_ids": ["ev-102"], "evidence_count": 1})
    deduped_dist = FindingNormalizer.deduplicate_findings([f_dist1, f_dist2])
    assert len(deduped_dist) == 1
    assert deduped_dist[0].evidence_count == 2
    assert sorted(deduped_dist[0].evidence_ids) == ["ev-101", "ev-102"]


def test_target_url_sensitive_query_parameters_masked() -> None:
    """Verify target URLs with sensitive query parameters are masked across metadata and findings."""
    param = CandidateParameter(
        name="q",
        location=ParameterLocation.QUERY,
        endpoint="/search",
    )
    raw_url = "https://target.local:8443/search?q=test&token=synth_secret_123&api_key=synth_key_abc&item=1&item=2#frag"
    scan_res = SQLiScanResult(
        target_url=raw_url,
        candidate_parameters=[param],
        summary=SQLiScanSummary(
            total_parameters=1,
            tested_parameters=1,
            potential_indicators=0,
        ),
        findings=[],
    )

    # Default: redact_secrets=True
    report = FindingNormalizer.from_sqli_scan_result(scan_res)
    assert "synth_secret_123" not in report.metadata.target_url
    assert "synth_key_abc" not in report.metadata.target_url
    assert "token=[REDACTED]" in report.metadata.target_url
    assert "api_key=[REDACTED]" in report.metadata.target_url
    assert "q=test" in report.metadata.target_url
    assert "item=1&item=2" in report.metadata.target_url
    assert "#frag" in report.metadata.target_url

    # Disabled: redact_secrets=False
    report_unredacted = FindingNormalizer.from_sqli_scan_result(scan_res, redact_secrets=False)
    assert "synth_secret_123" in report_unredacted.metadata.target_url
    assert "synth_key_abc" in report_unredacted.metadata.target_url
