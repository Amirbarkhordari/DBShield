"""Unit tests for DBShield Verification Engine (Phase 7)."""

from dbshield.execution.models import (
    ExecutionRecord,
    ExecutionRunResult,
    ExecutionStatus,
    ExecutionSummary,
)
from dbshield.nosqli.models import (
    NoSQLCandidateParameter,
    NoSQLEvidenceRecord,
    NoSQLFinding,
    NoSQLProviderFamily,
    NoSQLTestTechnique,
)
from dbshield.sqli.models import (
    CandidateParameter,
    DatabaseFamily,
    DetectionStatus,
    EvidenceRecord,
    ParameterLocation,
    SQLiFinding,
    TestTechnique,
)
from dbshield.verification.engine import VerificationEngine
from dbshield.verification.models import ConfidenceLevel, VerificationStatus


def test_verify_sqli_true_positive() -> None:
    """Verify true positive SQLi finding produces VERIFIED status and high confidence."""
    param = CandidateParameter(
        name="id",
        location=ParameterLocation.QUERY,
        endpoint="http://target.local/item",
    )
    ev_rec = EvidenceRecord(
        technique=TestTechnique.ERROR_BASED,
        rule_id="SQLI_MYSQL_SYNTAX",
        matched_pattern="You have an error in your SQL syntax",
        snippet='You have an error in your SQL syntax near "\'" at line 1',
        description="MySQL syntax error observed",
        db_family_hint=DatabaseFamily.MYSQL,
    )
    finding = SQLiFinding(
        test_id="TC_SQLI_01",
        technique=TestTechnique.ERROR_BASED,
        target_url="http://target.local/item",
        http_method="GET",
        parameter=param,
        status=DetectionStatus.POTENTIAL_INDICATOR,
        evidence_records=[ev_rec],
        baseline_metadata={"status_code": 200, "is_stable": True},
        test_response_metadata={"status_code": 500},
        request_count=2,
    )

    engine = VerificationEngine()
    result = engine.verify_findings(sqli_findings=[finding], target_url="http://target.local/item")

    assert result.summary.total_evaluated == 1
    assert result.summary.verified_count == 1
    assert result.summary.rejected_count == 0

    vf = result.findings[0]
    assert vf.status == VerificationStatus.VERIFIED
    assert vf.confidence.level in (ConfidenceLevel.HIGH, ConfidenceLevel.VERIFIED)
    assert vf.confidence.score >= 0.70
    assert "mysql" in vf.verification_rationale.lower()
    assert len(vf.state_history) >= 2


def test_verify_baseline_error_false_positive_rejected() -> None:
    """Verify finding where database error pre-existed in baseline is REJECTED as false positive."""
    param = CandidateParameter(
        name="id",
        location=ParameterLocation.QUERY,
        endpoint="http://target.local/broken",
    )
    ev_rec = EvidenceRecord(
        technique=TestTechnique.ERROR_BASED,
        rule_id="SQLI_MYSQL_SYNTAX",
        matched_pattern="You have an error in your SQL syntax",
        snippet="Pre-existing MySQL error",
        description="MySQL error",
        db_family_hint=DatabaseFamily.MYSQL,
    )
    finding = SQLiFinding(
        test_id="TC_SQLI_FP_01",
        technique=TestTechnique.ERROR_BASED,
        target_url="http://target.local/broken",
        http_method="GET",
        parameter=param,
        status=DetectionStatus.POTENTIAL_INDICATOR,
        evidence_records=[ev_rec],
        baseline_metadata={"status_code": 500, "is_stable": True, "has_preexisting_error": True},
        test_response_metadata={"status_code": 500},
        request_count=2,
    )

    engine = VerificationEngine()
    result = engine.verify_findings(
        sqli_findings=[finding], target_url="http://target.local/broken"
    )

    assert result.summary.total_evaluated == 1
    assert result.summary.verified_count == 0
    assert result.summary.rejected_count == 1

    vf = result.findings[0]
    assert vf.status == VerificationStatus.REJECTED
    assert vf.confidence.vulnerability_confidence == 0.0
    assert vf.rejection_or_downgrade_reason is not None
    assert (
        "pre-existing" in vf.rejection_or_downgrade_reason.lower()
        or "baseline" in vf.rejection_or_downgrade_reason.lower()
    )


def test_verify_unstable_baseline_inconclusive() -> None:
    """Verify findings with unstable baseline are categorized as INCONCLUSIVE with next steps."""
    param = CandidateParameter(
        name="search",
        location=ParameterLocation.QUERY,
        endpoint="http://target.local/search",
    )
    finding = SQLiFinding(
        test_id="TC_SQLI_UNSTABLE",
        technique=TestTechnique.BOOLEAN_DIFFERENTIAL,
        target_url="http://target.local/search",
        http_method="GET",
        parameter=param,
        status=DetectionStatus.INCONCLUSIVE,
        baseline_metadata={"status_code": 200, "is_stable": False},
        test_response_metadata={"status_code": 200, "similarity": 0.40},
        request_count=4,
    )

    engine = VerificationEngine()
    result = engine.verify_findings(
        sqli_findings=[finding], target_url="http://target.local/search"
    )

    assert result.summary.inconclusive_count == 1
    vf = result.findings[0]
    assert vf.status == VerificationStatus.INCONCLUSIVE
    assert vf.recommended_next_step is not None
    assert "baseline" in vf.recommended_next_step.lower()


def test_verify_execution_run_result_failed_run() -> None:
    """Verify ExecutionRunResult with failed records produces UNVERIFIABLE findings."""
    rec = ExecutionRecord(
        test_case_id="TC_SQLI_TIMEOUT",
        payload_id="SQLI_BOOLEAN_TRUE",
        parameter_name="id",
        parameter_location=ParameterLocation.QUERY,
        status=ExecutionStatus.FAILED,
        error_or_skip_reason="Connection refused by remote host",
    )
    run_res = ExecutionRunResult(
        target_url="http://unreachable.local",
        engine_name="sqli",
        execution_status="failed",
        summary=ExecutionSummary(
            total_test_cases=1,
            executed_test_cases=0,
            failed_test_cases=1,
            total_requests=0,
        ),
        records=[rec],
    )

    engine = VerificationEngine()
    result = engine.verify_execution_run(run_res)

    assert result.summary.unverifiable_count == 1
    vf = result.findings[0]
    assert vf.status == VerificationStatus.UNVERIFIABLE
    assert vf.confidence.score == 0.0


def test_verify_nosqli_operator_true_positive() -> None:
    """Verify true positive NoSQL injection finding produces VERIFIED status."""
    param = NoSQLCandidateParameter(
        name="user",
        location=ParameterLocation.BODY_JSON,
        key_path=["user"],
        endpoint="http://target.local/auth",
    )
    ev_rec = NoSQLEvidenceRecord(
        technique=NoSQLTestTechnique.ERROR_BASED,
        rule_id="NOSQLI_MONGO_WHERE",
        matched_pattern="$where syntax error",
        snippet="MongoServerError: $where syntax error near invalid syntax",
        description="MongoDB $where syntax error",
        provider_family_hint=NoSQLProviderFamily.MONGODB,
    )
    finding = NoSQLFinding(
        test_id="TC_NOSQLI_01",
        technique=NoSQLTestTechnique.ERROR_BASED,
        target_url="http://target.local/auth",
        http_method="POST",
        parameter=param,
        status=DetectionStatus.POTENTIAL_INDICATOR,
        evidence_records=[ev_rec],
        baseline_metadata={"status_code": 401, "is_stable": True},
        test_response_metadata={"status_code": 500},
        request_count=2,
    )

    engine = VerificationEngine()
    result = engine.verify_findings(
        nosqli_findings=[finding], target_url="http://target.local/auth"
    )

    assert result.summary.verified_count == 1
    vf = result.findings[0]
    assert vf.status == VerificationStatus.VERIFIED
    assert "mongodb" in vf.verification_rationale.lower()
