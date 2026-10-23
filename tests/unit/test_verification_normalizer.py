"""Unit tests for DBShield Evidence Normalizer and Sensitive Data Redaction (Phase 7)."""

from dbshield.execution.models import ExecutionRecord, ExecutionStatus
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
from dbshield.verification.models import EvidenceType, VulnerabilityClass
from dbshield.verification.normalizer import (
    EvidenceNormalizer,
    is_sensitive_parameter_name,
    sanitize_snippet,
)


def test_sensitive_parameter_detection() -> None:
    """Verify detection and masking of sensitive credential parameters."""
    assert is_sensitive_parameter_name("password") is True
    assert is_sensitive_parameter_name("user_token") is True
    assert is_sensitive_parameter_name("api-key") is True
    assert is_sensitive_parameter_name("csrf_token") is True
    assert is_sensitive_parameter_name("id") is False
    assert is_sensitive_parameter_name("search_query") is False

    assert "REDACTED" in EvidenceNormalizer.redact_parameter_name("password")
    assert EvidenceNormalizer.redact_parameter_name("username") == "username"
    assert EvidenceNormalizer.redact_parameter_name("id") == "id"


def test_sanitize_snippet_redacts_credentials() -> None:
    """Verify evidence snippet sanitization scrubs tokens, keys, and authorization headers."""
    raw = (
        "HTTP/1.1 500 Internal Error\n"
        "Authorization: Bearer secret_token_xyz_987\n"
        "Cookie: session=super_secret_session_id_456\n"
        "Set-Cookie: auth=admin_token_999\n"
        "Error in query: password='unclosed_quote"
    )
    sanitized = sanitize_snippet(raw)
    assert "secret_token_xyz_987" not in sanitized
    assert "super_secret_session_id_456" not in sanitized
    assert "admin_token_999" not in sanitized
    assert "Bearer [REDACTED]" in sanitized
    assert "Cookie: [REDACTED]" in sanitized


def test_sanitize_snippet_redacts_jwt_and_github_tokens() -> None:
    """Verify specific token signatures are masked."""
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    gh_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
    raw = f"Token debug: {jwt} and {gh_token}"
    sanitized = sanitize_snippet(raw)
    assert "[REDACTED_JWT]" in sanitized
    assert "[REDACTED_GITHUB_TOKEN]" in sanitized
    assert jwt not in sanitized
    assert gh_token not in sanitized


def test_sanitize_snippet_length_truncation() -> None:
    """Verify snippet length is bounded to 500 characters for memory safety."""
    huge = "A" * 1000
    sanitized = sanitize_snippet(huge)
    assert len(sanitized) == 500
    assert sanitized.endswith("...")


def test_normalize_sqli_finding_error_based() -> None:
    """Verify normalization of error-based SQLiFinding into NormalizedEvidence."""
    param = CandidateParameter(
        name="cat_id",
        location=ParameterLocation.QUERY,
        endpoint="http://target.local/products",
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
        test_id="SQLI_TEST_001",
        technique=TestTechnique.ERROR_BASED,
        target_url="http://target.local/products",
        http_method="GET",
        parameter=param,
        status=DetectionStatus.POTENTIAL_INDICATOR,
        evidence_records=[ev_rec],
        baseline_metadata={"status_code": 200, "is_stable": True},
        test_response_metadata={"status_code": 500},
        request_count=2,
    )

    normalized = EvidenceNormalizer.normalize_sqli_finding(
        finding, execution_id="exec-123", run_id="run-456"
    )
    assert len(normalized) == 1
    ev = normalized[0]
    assert ev.evidence_type == EvidenceType.ERROR_SIGNATURE
    assert ev.provider_or_family == "mysql"
    assert ev.baseline_status == 200
    assert ev.test_status == 500
    assert ev.is_baseline_stable is True
    assert ev.provenance.parameter_name == "cat_id"
    assert ev.provenance.vulnerability_class == VulnerabilityClass.SQLI
    assert ev.provenance.execution_id == "exec-123"
    assert ev.provenance.run_id == "run-456"


def test_normalize_nosqli_finding_operator() -> None:
    """Verify normalization of NoSQLFinding into NormalizedEvidence."""
    param = NoSQLCandidateParameter(
        name="user",
        location=ParameterLocation.BODY_JSON,
        key_path=["credentials", "user"],
        endpoint="http://target.local/login",
    )
    ev_rec = NoSQLEvidenceRecord(
        technique=NoSQLTestTechnique.OPERATOR_INJECTION,
        rule_id="NOSQLI_MONGO_OP_ERR",
        matched_pattern="unknown operator",
        snippet="MongoServerError: unknown operator: $invalidOp",
        description="MongoDB operator error",
        provider_family_hint=NoSQLProviderFamily.MONGODB,
    )
    finding = NoSQLFinding(
        test_id="NOSQLI_TEST_001",
        technique=NoSQLTestTechnique.OPERATOR_INJECTION,
        target_url="http://target.local/login",
        http_method="POST",
        parameter=param,
        status=DetectionStatus.POTENTIAL_INDICATOR,
        evidence_records=[ev_rec],
        baseline_metadata={"status_code": 401, "is_stable": True},
        test_response_metadata={"status_code": 500, "similarity": 0.45},
        request_count=2,
    )

    normalized = EvidenceNormalizer.normalize_nosqli_finding(finding)
    assert len(normalized) == 1
    ev = normalized[0]
    assert ev.evidence_type == EvidenceType.DIFFERENTIAL_PAIR
    assert ev.provider_or_family == "mongodb"
    assert ev.provenance.vulnerability_class == VulnerabilityClass.NOSQLI
    assert ev.similarity_score == 0.45


def test_normalize_execution_record_failed_or_skipped() -> None:
    """Verify failed or skipped execution records are captured as execution traces."""
    rec = ExecutionRecord(
        test_case_id="TC_SQLI_TIMEOUT",
        payload_id="SQLI_BOOLEAN_TRUE",
        parameter_name="id",
        parameter_location=ParameterLocation.QUERY,
        status=ExecutionStatus.FAILED,
        error_or_skip_reason="HTTP transport timeout after 10.0s",
    )
    normalized = EvidenceNormalizer.normalize_execution_record(
        rec, target_url="http://target.local/api", engine_name="sqli"
    )
    assert len(normalized) == 1
    ev = normalized[0]
    assert ev.evidence_type == EvidenceType.EXECUTION_TRACE
    assert "timeout" in ev.safe_snippet.lower()
    assert ev.details["execution_status"] == "failed"


def test_normalize_dict_finding_fallback() -> None:
    """Verify robust parsing of arbitrary dictionary findings from JSON fixtures."""
    dict_data = {
        "target_url": "http://fixture.local/search",
        "engine": "sqli",
        "parameter": {"name": "query", "location": "query"},
        "technique": "error_based",
        "rule_id": "CUSTOM_SQL_ERR",
        "matched_pattern": "syntax error",
        "evidence_summary": "Detected syntax error in query",
        "baseline_metadata": {"status_code": 200, "is_stable": False},
        "test_response_metadata": {"status_code": 500},
    }
    normalized = EvidenceNormalizer.normalize_dict_finding(dict_data)
    assert len(normalized) == 1
    ev = normalized[0]
    assert ev.provenance.parameter_name == "query"
    assert ev.is_baseline_stable is False
    assert ev.baseline_status == 200
    assert ev.test_status == 500
