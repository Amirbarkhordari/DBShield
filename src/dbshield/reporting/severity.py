"""Severity and prioritization assessment policy (Phase 8).

Provides transparent, evidence-based severity ratings and remediation guidance.
Decouples vulnerability impact (severity) from observation certainty (confidence),
ensuring no unverified indicator is exaggerated or falsely categorized.
"""

from __future__ import annotations

from dbshield.reporting.models import FindingSeverity, VulnerabilityCategory
from dbshield.verification.models import VerificationStatus

# Standard Common Weakness Enumeration mappings for verified classes
_CWE_CATALOG: dict[VulnerabilityCategory, tuple[str, str]] = {
    VulnerabilityCategory.SQL_INJECTION: (
        "CWE-89",
        "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    ),
    VulnerabilityCategory.NOSQL_INJECTION: (
        "CWE-943",
        "Improper Neutralization of Special Elements in Data Query Logic",
    ),
    VulnerabilityCategory.AUTHENTICATION_BYPASS: (
        "CWE-287",
        "Improper Authentication",
    ),
    VulnerabilityCategory.INFORMATION_DISCLOSURE: (
        "CWE-200",
        "Exposure of Sensitive Information to an Unauthorized Actor",
    ),
    VulnerabilityCategory.CONFIGURATION_WEAKNESS: (
        "CWE-16",
        "Configuration",
    ),
}

_REMEDIATION_CATALOG: dict[VulnerabilityCategory, str] = {
    VulnerabilityCategory.SQL_INJECTION: (
        "Use parameterized queries (prepared statements) or an object-relational mapping (ORM) layer "
        "with bound parameters for all database interactions. Ensure input validation is applied and "
        "database accounts operate with minimal required privileges."
    ),
    VulnerabilityCategory.NOSQL_INJECTION: (
        "Sanitize input against query operator injection by validating types (ensure parameters are strings, "
        "not arbitrary JSON objects or MongoDB query selectors). Use framework schema validation, "
        "avoid evaluating raw strings with $where or JavaScript engines, and apply strict type casting."
    ),
    VulnerabilityCategory.AUTHENTICATION_BYPASS: (
        "Enforce strict server-side authentication checks on all protected endpoints. Validate session "
        "tokens cryptographically and reject requests with missing, altered, or default credentials."
    ),
    VulnerabilityCategory.INFORMATION_DISCLOSURE: (
        "Disable detailed database and framework error messages in production environments. "
        "Log full diagnostic details securely server-side while presenting generic error messages to clients."
    ),
    VulnerabilityCategory.CONFIGURATION_WEAKNESS: (
        "Review server configuration against security hardening benchmarks. Restrict debug interfaces "
        "and enforce least-privilege access controls."
    ),
    VulnerabilityCategory.UNKNOWN: (
        "Conduct targeted manual code review and dynamic testing to determine root cause and implement "
        "appropriate input validation and defense-in-depth controls."
    ),
}


class SeverityAssessor:
    """Evaluates severity and remediation for normalized security findings."""

    @classmethod
    def evaluate_severity(
        cls,
        category: VulnerabilityCategory,
        status: VerificationStatus,
        technique: str = "",
    ) -> tuple[FindingSeverity, str]:
        """Determine qualitative severity rating and provide a documented rationale.

        Rules:
        - REJECTED: Always INFO (verified false positive/benign).
        - INCONCLUSIVE or UNVERIFIABLE: LOW or INFO (unresolved noise or incomplete tests).
        - POTENTIAL_INDICATOR or VERIFICATION_REQUIRED:
          - SQLi / NoSQLi error-based or operator: MEDIUM (indicates possible flaw, pending verification).
          - Other unverified signals: LOW.
        - CORROBORATED:
          - SQLi / NoSQLi corroborated by independent detector: HIGH or MEDIUM.
        - VERIFIED:
          - SQLi / NoSQLi formally verified: HIGH (impact: database access/tampering).
        """
        # Benign / False Positive
        if status == VerificationStatus.REJECTED:
            return (
                FindingSeverity.INFO,
                "Finding was evaluated and verified as a benign or false-positive indicator (e.g. pre-existing baseline error or generic HTTP status).",
            )

        # Inconclusive or Unverifiable
        if status == VerificationStatus.INCONCLUSIVE:
            return (
                FindingSeverity.LOW,
                "Inconclusive indicator due to baseline response instability or ambiguous differential behavior; requires manual confirmation before remediation.",
            )

        if status == VerificationStatus.UNVERIFIABLE:
            return (
                FindingSeverity.INFO,
                "Execution failed, timed out, or was skipped; security status could not be established from available evidence.",
            )

        # Verified Findings
        if status == VerificationStatus.VERIFIED:
            if category in {
                VulnerabilityCategory.SQL_INJECTION,
                VulnerabilityCategory.NOSQL_INJECTION,
            }:
                return (
                    FindingSeverity.HIGH,
                    f"Formally verified {category.value.replace('_', ' ')} vulnerability with documented database-specific evidence. High risk of unauthorized data access, manipulation, or integrity compromise.",
                )
            if category == VulnerabilityCategory.AUTHENTICATION_BYPASS:
                return (
                    FindingSeverity.CRITICAL,
                    "Verified authentication bypass vulnerability allowing unauthorized access to protected application resources.",
                )
            return (
                FindingSeverity.MEDIUM,
                f"Formally verified {category.value.replace('_', ' ')} finding with confirmed evidence.",
            )

        # Corroborated Findings
        if status == VerificationStatus.CORROBORATED:
            if category in {
                VulnerabilityCategory.SQL_INJECTION,
                VulnerabilityCategory.NOSQL_INJECTION,
            }:
                return (
                    FindingSeverity.HIGH,
                    f"Corroborated {category.value.replace('_', ' ')} finding supported by independent detection signals, awaiting final strict verification criteria.",
                )
            return (
                FindingSeverity.MEDIUM,
                "Corroborated finding supported by multiple independent evidence items.",
            )

        # Potential Indicators / Under Analysis / Verification Required
        if category in {
            VulnerabilityCategory.SQL_INJECTION,
            VulnerabilityCategory.NOSQL_INJECTION,
        }:
            if "error" in technique.lower() or "operator" in technique.lower():
                return (
                    FindingSeverity.MEDIUM,
                    "Potential database error or operator injection signal observed; pending formal corroboration and verification.",
                )
            return (
                FindingSeverity.LOW,
                "Potential response variance observed during differential testing; confidence remains preliminary.",
            )

        return (
            FindingSeverity.LOW,
            "Preliminary indicator observed during automated assessment; verification criteria have not yet been evaluated.",
        )

    @classmethod
    def get_cwe_mapping(cls, category: VulnerabilityCategory) -> tuple[str | None, str | None]:
        """Return (cwe_id, cwe_name) if reliably associated with this category, or (None, None)."""
        mapping = _CWE_CATALOG.get(category)
        if mapping:
            return mapping[0], mapping[1]
        return None, None

    @classmethod
    def get_remediation(cls, category: VulnerabilityCategory) -> str:
        """Return standardized, actionable remediation guidance for this category."""
        return _REMEDIATION_CATALOG.get(
            category, _REMEDIATION_CATALOG[VulnerabilityCategory.UNKNOWN]
        )
