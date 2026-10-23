"""Unit tests for DBShield severity and prioritization assessment policy (Phase 8)."""

from dbshield.reporting.models import FindingSeverity, VulnerabilityCategory
from dbshield.reporting.severity import SeverityAssessor
from dbshield.verification.models import VerificationStatus


def test_severity_verified_sqli_is_high() -> None:
    """Verify formally verified SQLi is rated High with clear technical rationale."""
    sev, rationale = SeverityAssessor.evaluate_severity(
        category=VulnerabilityCategory.SQL_INJECTION,
        status=VerificationStatus.VERIFIED,
        technique="error_based",
    )
    assert sev == FindingSeverity.HIGH
    assert "verified" in rationale.lower()
    assert "database" in rationale.lower()


def test_severity_rejected_false_positive_is_info() -> None:
    """Verify false-positive / rejected finding is always assigned Info severity."""
    sev, rationale = SeverityAssessor.evaluate_severity(
        category=VulnerabilityCategory.SQL_INJECTION,
        status=VerificationStatus.REJECTED,
        technique="error_based",
    )
    assert sev == FindingSeverity.INFO
    assert "false-positive" in rationale.lower() or "benign" in rationale.lower()


def test_severity_inconclusive_is_low() -> None:
    """Verify inconclusive finding is downgraded to Low with uncertainty explanation."""
    sev, rationale = SeverityAssessor.evaluate_severity(
        category=VulnerabilityCategory.NOSQL_INJECTION,
        status=VerificationStatus.INCONCLUSIVE,
        technique="operator_injection",
    )
    assert sev == FindingSeverity.LOW
    assert "inconclusive" in rationale.lower()


def test_severity_potential_indicator_is_medium_or_low() -> None:
    """Verify potential indicators without formal verification are not exaggerated."""
    sev_err, _ = SeverityAssessor.evaluate_severity(
        category=VulnerabilityCategory.SQL_INJECTION,
        status=VerificationStatus.POTENTIAL_INDICATOR,
        technique="error_based",
    )
    assert sev_err == FindingSeverity.MEDIUM

    sev_diff, _ = SeverityAssessor.evaluate_severity(
        category=VulnerabilityCategory.SQL_INJECTION,
        status=VerificationStatus.POTENTIAL_INDICATOR,
        technique="differential_boolean",
    )
    assert sev_diff == FindingSeverity.LOW


def test_cwe_mapping_accuracy() -> None:
    """Verify documented CWE IDs and names for standard vulnerability categories."""
    sqli_cwe, sqli_name = SeverityAssessor.get_cwe_mapping(VulnerabilityCategory.SQL_INJECTION)
    assert sqli_cwe == "CWE-89"
    assert "SQL Command" in str(sqli_name)

    nosqli_cwe, nosqli_name = SeverityAssessor.get_cwe_mapping(
        VulnerabilityCategory.NOSQL_INJECTION
    )
    assert nosqli_cwe == "CWE-943"
    assert "Data Query Logic" in str(nosqli_name)

    unknown_cwe, unknown_name = SeverityAssessor.get_cwe_mapping(VulnerabilityCategory.UNKNOWN)
    assert unknown_cwe is None
    assert unknown_name is None


def test_remediation_guidance() -> None:
    """Verify remediation advice provides actionable, technical instructions."""
    rem_sqli = SeverityAssessor.get_remediation(VulnerabilityCategory.SQL_INJECTION)
    assert "parameterized queries" in rem_sqli.lower()

    rem_nosqli = SeverityAssessor.get_remediation(VulnerabilityCategory.NOSQL_INJECTION)
    assert "operator" in rem_nosqli.lower()
