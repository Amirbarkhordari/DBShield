"""Data models for DBShield Evidence Analysis and Vulnerability Verification Engine (Phase 7).

Defines structured, immutable representations of normalized evidence,
evidence provenance, correlation groups, confidence assessments,
verification lifecycle states, state transitions, and aggregated verification results.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from dbshield.sqli.models import ParameterLocation


class EvidenceType(StrEnum):
    """Categorization of observed security test evidence."""

    ERROR_SIGNATURE = "error_signature"
    DIFFERENTIAL_PAIR = "differential_pair"
    STATUS_CODE_DIFFERENCE = "status_code_difference"
    BODY_SIMILARITY = "body_similarity"
    BASELINE_COMPARISON = "baseline_comparison"
    EXECUTION_TRACE = "execution_trace"


class VulnerabilityClass(StrEnum):
    """Vulnerability classification category."""

    SQLI = "sqli"
    NOSQLI = "nosqli"
    UNKNOWN = "unknown"


class VerificationStatus(StrEnum):
    """Lifecycle verification states for assessment findings.

    Semantics:
    - POTENTIAL_INDICATOR: Initial raw signal observed by detector.
    - UNDER_ANALYSIS: Currently undergoing verification and corroboration analysis.
    - VERIFICATION_REQUIRED: Potential signal requires additional independent evidence.
    - CORROBORATED: Supported by corroborating evidence from independent detectors/checks.
    - VERIFIED: Formally verified according to strict, documented criteria.
    - INCONCLUSIVE: Baseline unstable, chaotic divergence, or ambiguous evidence.
    - REJECTED: Proven false positive (baseline error, generic 500, or identical pair response).
    - UNVERIFIABLE: Source execution failed, skipped, cancelled, or missing required evidence.
    """

    POTENTIAL_INDICATOR = "potential_indicator"
    UNDER_ANALYSIS = "under_analysis"
    VERIFICATION_REQUIRED = "verification_required"
    CORROBORATED = "corroborated"
    VERIFIED = "verified"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"
    UNVERIFIABLE = "unverifiable"


class ConfidenceLevel(StrEnum):
    """Qualitative confidence classification for verified or evaluated findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"


class EvidenceProvenance(BaseModel):
    """Traceable provenance and execution origin metadata for an evidence record."""

    model_config = ConfigDict(frozen=True)

    engine: str = Field(
        description="Detection engine producing this evidence ('sqli', 'nosqli', etc.)."
    )
    vulnerability_class: VulnerabilityClass = Field(
        default=VulnerabilityClass.UNKNOWN, description="Class of vulnerability tested."
    )
    target_url: str = Field(description="Target endpoint URL tested.")
    parameter_name: str = Field(description="Parameter name tested (sensitive values redacted).")
    parameter_location: ParameterLocation = Field(
        description="Transport location of the parameter."
    )
    test_id: str | None = Field(default=None, description="Original test case identifier.")
    payload_id: str | None = Field(default=None, description="Payload identifier utilized.")
    execution_id: str | None = Field(
        default=None, description="Execution run identifier if available."
    )
    run_id: str | None = Field(
        default=None, description="Overall execution session UUID if available."
    )
    source_finding_id: str | None = Field(
        default=None, description="ID of source finding if derived from one."
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when evidence was observed or recorded.",
    )


class NormalizedEvidence(BaseModel):
    """Standardized, cross-engine evidence record with provenance and safety redaction."""

    model_config = ConfigDict(frozen=True)

    evidence_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique evidence record UUID."
    )
    evidence_type: EvidenceType = Field(description="Classification of the evidence observation.")
    provenance: EvidenceProvenance = Field(description="Traceable execution origin metadata.")
    rule_id: str = Field(description="Detection rule, signature key, or detector name.")
    matched_pattern: str = Field(description="Pattern description or signature that matched.")
    safe_snippet: str = Field(
        description="Safe, bounded, redacted excerpt of response content demonstrating the signal."
    )
    description: str = Field(
        description="Human-readable explanation of why this signal was flagged."
    )
    provider_or_family: str = Field(
        default="unknown", description="Database or driver family hint (e.g., 'mysql', 'mongodb')."
    )
    baseline_status: int | None = Field(default=None, description="HTTP status code of baseline.")
    test_status: int | None = Field(default=None, description="HTTP status code of test probe.")
    similarity_score: float | None = Field(
        default=None, description="Normalized response body similarity score (0.0 to 1.0)."
    )
    is_baseline_stable: bool = Field(
        default=True, description="Whether endpoint baseline was verified stable."
    )
    is_preexisting_in_baseline: bool = Field(
        default=False, description="Whether this indicator also occurred in the baseline probe."
    )
    is_contradictory: bool = Field(
        default=False, description="Whether this evidence contradicts other related observations."
    )
    details: dict[str, Any] = Field(
        default_factory=dict, description="Additional structured operational parameters."
    )


class StateTransitionRecord(BaseModel):
    """Audit log entry capturing a valid transition in a finding's verification lifecycle."""

    model_config = ConfigDict(frozen=True)

    from_status: VerificationStatus = Field(description="Pre-transition lifecycle state.")
    to_status: VerificationStatus = Field(description="Post-transition lifecycle state.")
    reason: str = Field(description="Documented rationale explaining why the state changed.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when transition occurred.",
    )


class ConfidenceAssessment(BaseModel):
    """Explainable confidence assessment detailing observation vs vulnerability certainty."""

    model_config = ConfigDict(frozen=True)

    level: ConfidenceLevel = Field(description="Overall qualitative confidence classification.")
    score: float = Field(
        ge=0.0,
        le=1.0,
        description="Transparent composite score between 0.0 and 1.0 representing verification confidence.",
    )
    observation_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence that the observed signal is genuine and reproducible (0.0 to 1.0).",
    )
    vulnerability_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence that the observed signal indicates an actual vulnerability (0.0 to 1.0).",
    )
    contributing_factors: list[str] = Field(
        default_factory=list, description="List of positive evidence factors increasing confidence."
    )
    degrading_factors: list[str] = Field(
        default_factory=list,
        description="List of negative or uncertainty factors decreasing confidence.",
    )
    explanation: str = Field(
        description="Documented explanation of how the confidence was determined."
    )


class CorrelationGroup(BaseModel):
    """Deterministic grouping of evidence related to the same candidate finding."""

    model_config = ConfigDict(frozen=True)

    group_id: str = Field(description="Deterministic fingerprint of this correlation group.")
    target_url: str = Field(description="Target endpoint URL.")
    vulnerability_class: VulnerabilityClass = Field(description="Vulnerability class under test.")
    parameter_name: str = Field(description="Parameter name under test.")
    parameter_location: ParameterLocation = Field(
        description="Transport location of the parameter."
    )
    evidence_items: list[NormalizedEvidence] = Field(
        default_factory=list, description="Consolidated normalized evidence records for this group."
    )
    source_finding_ids: list[str] = Field(
        default_factory=list, description="Original finding IDs associated with this group."
    )
    execution_ids: list[str] = Field(
        default_factory=list, description="Associated execution run IDs."
    )
    deduplication_notes: list[str] = Field(
        default_factory=list,
        description="Audit notes explaining any deduplicated or merged evidence.",
    )


class VerificationFinding(BaseModel):
    """Comprehensive, verified assessment result for a candidate vulnerability."""

    model_config = ConfigDict(frozen=True)

    verification_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique verification finding UUID."
    )
    finding_id: str | None = Field(
        default=None, description="Original source finding ID if directly linked."
    )
    vulnerability_class: VulnerabilityClass = Field(description="Vulnerability category.")
    engine: str = Field(description="Detection engine name ('sqli', 'nosqli', etc.).")
    target_url: str = Field(description="Target endpoint tested.")
    parameter_name: str = Field(description="Target parameter name (redacted if sensitive).")
    parameter_location: ParameterLocation = Field(description="Parameter transport location.")
    status: VerificationStatus = Field(description="Current verified finding lifecycle status.")
    confidence: ConfidenceAssessment = Field(description="Explainable confidence assessment.")
    corroborating_evidence: list[NormalizedEvidence] = Field(
        default_factory=list, description="Normalized evidence supporting this finding."
    )
    contradictory_evidence: list[NormalizedEvidence] = Field(
        default_factory=list,
        description="Normalized evidence that contradicts or weakens this finding.",
    )
    all_evidence: list[NormalizedEvidence] = Field(
        default_factory=list, description="All normalized evidence items evaluated."
    )
    state_history: list[StateTransitionRecord] = Field(
        default_factory=list, description="Traceable audit log of lifecycle state transitions."
    )
    verification_rationale: str = Field(
        description="Detailed technical reasoning justifying the final verification status."
    )
    rejection_or_downgrade_reason: str | None = Field(
        default=None,
        description="Explanation when finding is rejected (false positive) or downgraded to inconclusive.",
    )
    recommended_next_step: str | None = Field(
        default=None,
        description="Recommended safe next validation step (e.g. for inconclusive findings).",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Analytical limitations, disclaimers, and scope boundaries.",
    )
    execution_references: dict[str, Any] = Field(
        default_factory=dict,
        description="Traceability references to executions, test IDs, and payloads.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when verification completed.",
    )


class VerificationSummary(BaseModel):
    """Aggregated metrics across all evaluated findings in a verification session."""

    model_config = ConfigDict(frozen=True)

    total_evaluated: int = Field(default=0, description="Total candidate findings evaluated.")
    verified_count: int = Field(default=0, description="Findings verified against strict criteria.")
    corroborated_count: int = Field(
        default=0, description="Findings supported by corroborating evidence."
    )
    potential_indicator_count: int = Field(
        default=0, description="Findings remaining at raw potential indicator state."
    )
    inconclusive_count: int = Field(
        default=0, description="Findings marked inconclusive due to noise or ambiguity."
    )
    rejected_count: int = Field(
        default=0, description="Findings rejected as confirmed false positives."
    )
    unverifiable_count: int = Field(
        default=0, description="Findings that could not be verified due to execution errors."
    )


class VerificationResult(BaseModel):
    """Complete, immutable result of an evidence analysis and verification session."""

    model_config = ConfigDict(frozen=True)

    result_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique verification assessment session UUID.",
    )
    target_url: str = Field(description="Target URL or scope analyzed.")
    assessment_version: str = Field(
        default="1.0.0", description="Verification engine specification version."
    )
    summary: VerificationSummary = Field(description="Aggregated summary counts.")
    findings: list[VerificationFinding] = Field(
        default_factory=list, description="Detailed verified finding records."
    )
    correlation_groups: list[CorrelationGroup] = Field(
        default_factory=list, description="Correlated and deduplicated evidence groups."
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Global framework limitations and verification boundaries.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when assessment completed.",
    )
