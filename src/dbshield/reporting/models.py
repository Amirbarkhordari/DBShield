"""Structured finding and assessment report models (Phase 8).

Defines stable, normalized data models for security findings, severity ratings,
vulnerability categories, report metadata, and structured assessment reports.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from dbshield.sqli.models import ParameterLocation
from dbshield.verification.models import ConfidenceLevel, VerificationStatus


class FindingSeverity(StrEnum):
    """Qualitative severity rating for an assessment finding.

    Strictly decoupled from verification confidence:
    - Severity describes potential technical impact on confidentiality, integrity, or availability.
    - Confidence describes certainty that the finding exists and is reproducible.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(StrEnum):
    """Standardized classification of security vulnerability categories."""

    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    INFORMATION_DISCLOSURE = "information_disclosure"
    CONFIGURATION_WEAKNESS = "configuration_weakness"
    UNKNOWN = "unknown"


class NormalizedSecurityFinding(BaseModel):
    """Normalized, cross-engine security finding with provenance and remediation.

    Represents a unified, machine-readable finding produced by DBShield
    evaluation engines and Phase 7 verification analysis.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        description="Deterministic or UUID identifier for this finding.",
    )
    title: str = Field(
        description="Concise, technical summary title of the finding.",
    )
    category: VulnerabilityCategory = Field(
        description="Standardized vulnerability category.",
    )
    subtype: str = Field(
        default="generic",
        description="Specific injection technique or subtype (e.g., 'error_based', 'operator_injection').",
    )
    target_url: str = Field(
        description="Target endpoint URL tested.",
    )
    endpoint: str = Field(
        description="Parsed URL path (e.g., '/api/search').",
    )
    http_method: str = Field(
        default="GET",
        description="HTTP request method (GET, POST, etc.).",
    )
    parameter_name: str = Field(
        description="Affected parameter name (redacted if sensitive).",
    )
    parameter_location: ParameterLocation = Field(
        description="Transport location of the parameter (query, body_form, body_json, header).",
    )
    engine: str = Field(
        description="Detection engine producing this finding ('sqli', 'nosqli', etc.).",
    )
    technique: str = Field(
        description="Specific testing technique utilized.",
    )
    verification_status: VerificationStatus = Field(
        description="Current verified finding lifecycle state from Phase 7 engine.",
    )
    confidence_level: ConfidenceLevel = Field(
        description="Qualitative confidence classification.",
    )
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Composite verification confidence score (0.0 to 1.0).",
    )
    severity: FindingSeverity = Field(
        description="Qualitative severity rating based on impact and verification state.",
    )
    severity_rationale: str = Field(
        description="Transparent justification explaining why this severity was assigned.",
    )
    description: str = Field(
        description="Detailed technical description of observed behavior and risks.",
    )
    evidence_summary: str = Field(
        description="Safe, bounded, sanitized excerpt of evidence demonstrating the signal.",
    )
    evidence_count: int = Field(
        default=1,
        ge=0,
        description="Number of corroborated evidence records associated with this finding.",
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Identifiers of contributing normalized evidence records.",
    )
    remediation: str = Field(
        description="Actionable, prioritized remediation guidance.",
    )
    cwe_id: str | None = Field(
        default=None,
        description="Common Weakness Enumeration ID if reliably applicable (e.g., 'CWE-89').",
    )
    cwe_name: str | None = Field(
        default=None,
        description="Official Common Weakness Enumeration title.",
    )
    execution_references: dict[str, Any] = Field(
        default_factory=dict,
        description="Traceability references to executions, test IDs, and payload IDs.",
    )
    first_observed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the indicator was first recorded.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional operational or forensic metadata.",
    )

    @classmethod
    def compute_deterministic_id(
        cls,
        target_url: str,
        category: str,
        parameter_location: str,
        parameter_name: str,
        technique: str,
    ) -> str:
        """Generate a deterministic SHA-256 finding identifier based on canonical coordinates."""
        key = f"{target_url.strip().lower()}|{category.strip().lower()}|{parameter_location.strip().lower()}|{parameter_name.strip().lower()}|{technique.strip().lower()}"
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"DBS-{digest[:12].upper()}"


class ReportMetadata(BaseModel):
    """Metadata describing a generated assessment report."""

    model_config = ConfigDict(frozen=True)

    report_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique report instance UUID.",
    )
    title: str = Field(
        default="DBShield Security Assessment Report",
        description="Human-readable title for the report.",
    )
    target_url: str = Field(
        description="Primary target URL or scope assessed.",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of report generation.",
    )
    version: str = Field(
        default="1.0.0",
        description="DBShield report schema specification version.",
    )
    total_findings: int = Field(
        default=0,
        ge=0,
        description="Total number of findings in this report.",
    )
    findings_by_severity: dict[str, int] = Field(
        default_factory=dict,
        description="Finding count breakdown by severity rating.",
    )
    findings_by_status: dict[str, int] = Field(
        default_factory=dict,
        description="Finding count breakdown by verification lifecycle status.",
    )
    findings_by_category: dict[str, int] = Field(
        default_factory=dict,
        description="Finding count breakdown by vulnerability category.",
    )
    assessment_scope: list[str] = Field(
        default_factory=list,
        description="Authorized target scope and host boundaries.",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Assessment disclaimers, test boundaries, and analytical limitations.",
    )


class SecurityAssessmentReport(BaseModel):
    """Complete, self-contained structured security assessment report."""

    model_config = ConfigDict(frozen=True)

    metadata: ReportMetadata = Field(
        description="Report metadata, scope, and aggregate metrics.",
    )
    findings: list[NormalizedSecurityFinding] = Field(
        default_factory=list,
        description="Collection of normalized security findings.",
    )
