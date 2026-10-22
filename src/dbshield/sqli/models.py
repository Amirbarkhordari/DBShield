"""Data models for SQL Injection Detection Engine (Phase 4).

Defines structured, immutable representations of candidate parameters,
detection techniques, evidence records, baseline profiles, finding states,
and scan results.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ParameterLocation(StrEnum):
    """Location where an input parameter is transmitted."""

    QUERY = "query"
    BODY_URLENCODED = "body_urlencoded"
    BODY_JSON = "body_json"
    HEADER = "header"
    COOKIE = "cookie"


class CandidateParameter(BaseModel):
    """Structured representation of a candidate input parameter for testing.

    Retains full origin and eligibility metadata. For safety and zero-credential
    guarantees, sensitive fields (e.g. passwords, authentication tokens) are
    flagged ineligible for injection testing.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Parameter name.")
    location: ParameterLocation = Field(description="Parameter transport location.")
    original_value: str | None = Field(
        default=None, description="Original value observed or provided."
    )
    endpoint: str = Field(description="Target endpoint URL containing this parameter.")
    method: str = Field(default="GET", description="HTTP method used to send this parameter.")
    content_type: str | None = Field(
        default=None, description="Content-Type header when parameter is in request body."
    )
    source: str = Field(
        default="explicit",
        description="Source of parameter discovery (e.g. 'query_string', 'discovered_form', 'explicit_config').",
    )
    is_eligible: bool = Field(
        default=True, description="Whether parameter is safe and eligible for testing."
    )
    skip_reason: str | None = Field(
        default=None, description="Explanation why parameter was skipped or ineligible."
    )


class TestTechnique(StrEnum):
    """SQL injection detection technique categories."""

    __test__ = False

    ERROR_BASED = "error_based"
    BOOLEAN_DIFFERENTIAL = "boolean_differential"
    TIME_BASED = "time_based"


class DetectionStatus(StrEnum):
    """Finding and execution status classifications.

    Semantics:
    - NOT_RUN: Test scheduled but not yet executed.
    - SKIPPED: Test intentionally skipped due to safety, eligibility, or unsupported context.
    - NO_INDICATOR: Test completed; no SQL injection signal was observed. (Does NOT prove endpoint is secure).
    - POTENTIAL_INDICATOR: Evidence suggests SQL injection but has not been independently verified.
    - INCONCLUSIVE: Response behavior was unstable, ambiguous, or failed comparison rules.
    - BLOCKED_BY_SCOPE: Target URL or redirect was blocked by ScopeManager.
    - ERROR: Test failed due to transport, protocol, or internal operational failure.
    """

    NOT_RUN = "not_run"
    SKIPPED = "skipped"
    NO_INDICATOR = "no_indicator"
    POTENTIAL_INDICATOR = "potential_indicator"
    INCONCLUSIVE = "inconclusive"
    BLOCKED_BY_SCOPE = "blocked_by_scope"
    ERROR = "error"


class ConfidenceRating(StrEnum):
    """Confidence classification for detected indicators."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DatabaseFamily(StrEnum):
    """Database management system family hints derived from error patterns."""

    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"
    MSSQL = "mssql"
    ORACLE = "oracle"
    GENERIC_SQL = "generic_sql"
    UNKNOWN = "unknown"


class EvidenceRecord(BaseModel):
    """Structured record of observed evidence supporting a candidate finding.

    Strictly redacts sensitive application data, passwords, and tokens.
    """

    model_config = ConfigDict(frozen=True)

    technique: TestTechnique = Field(description="Detection technique that yielded this evidence.")
    rule_id: str = Field(description="Identifier of the detection rule or signature matched.")
    matched_pattern: str = Field(description="Description or pattern key that matched.")
    snippet: str = Field(
        description="Safe, bounded, redacted excerpt of the response content displaying the signal."
    )
    description: str = Field(
        description="Human-readable explanation of why this signal was flagged."
    )
    db_family_hint: DatabaseFamily = Field(
        default=DatabaseFamily.UNKNOWN,
        description="Tentative database family hint (unconfirmed).",
    )
    confirmed: bool = Field(
        default=False,
        description="Always False in Phase 4. Independent verification belongs to Phase 7.",
    )


class BaselineProfile(BaseModel):
    """Characterization of an endpoint's normal, unperturbed response behavior."""

    model_config = ConfigDict(frozen=True)

    status_code: int = Field(description="Baseline HTTP status code.")
    content_type: str | None = Field(default=None, description="Baseline Content-Type header.")
    content_length: int = Field(default=0, description="Baseline body length in bytes.")
    elapsed_seconds: float = Field(
        default=0.0, description="Average baseline response elapsed time."
    )
    is_stable: bool = Field(
        default=True, description="Whether baseline responses exhibited reproducible consistency."
    )
    instability_reason: str | None = Field(
        default=None, description="Reason why baseline was deemed unstable."
    )
    sample_count: int = Field(default=1, description="Number of baseline probe requests executed.")
    body_hash: str | None = Field(
        default=None, description="Hash of normalized baseline body content."
    )


class SQLiFinding(BaseModel):
    """Structured assessment finding for a tested candidate parameter."""

    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique finding UUID."
    )
    test_id: str = Field(description="Identifier of the specific test definition.")
    technique: TestTechnique = Field(description="SQLi detection technique employed.")
    target_url: str = Field(description="Endpoint URL tested.")
    http_method: str = Field(description="HTTP method used for testing.")
    parameter: CandidateParameter = Field(description="Candidate parameter tested.")
    status: DetectionStatus = Field(description="Final detection classification status.")
    confidence: ConfidenceRating | None = Field(
        default=None, description="Confidence classification if potential indicator detected."
    )
    evidence_summary: str = Field(
        default="", description="Summary explanation of the finding outcome."
    )
    evidence_records: list[EvidenceRecord] = Field(
        default_factory=list, description="Detailed evidence records supporting finding."
    )
    baseline_metadata: dict[str, Any] = Field(
        default_factory=dict, description="Operational characteristics of baseline response."
    )
    test_response_metadata: dict[str, Any] = Field(
        default_factory=dict, description="Operational characteristics of test response(s)."
    )
    request_count: int = Field(
        default=0, description="Total HTTP requests dispatched for this specific test."
    )
    error_or_skip_reason: str | None = Field(
        default=None,
        description="Failure or skip explanation when status is not POTENTIAL_INDICATOR.",
    )
    limitations: list[str] = Field(
        default_factory=list, description="Applicable analytical limitations and disclaimers."
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when test completed.",
    )


class SQLiScanSummary(BaseModel):
    """Aggregated metrics across all tested parameters in a scan."""

    model_config = ConfigDict(frozen=True)

    total_parameters: int = Field(default=0, description="Total parameters evaluated.")
    tested_parameters: int = Field(default=0, description="Parameters actively tested.")
    skipped_parameters: int = Field(default=0, description="Parameters skipped due to safety.")
    potential_indicators: int = Field(default=0, description="Potential indicators identified.")
    clean_parameters: int = Field(default=0, description="Parameters with no indicator observed.")
    inconclusive_parameters: int = Field(
        default=0, description="Parameters with inconclusive results."
    )
    blocked_parameters: int = Field(default=0, description="Parameters blocked by scope.")
    error_parameters: int = Field(
        default=0, description="Parameters failing due to transport errors."
    )
    total_requests: int = Field(default=0, description="Total HTTP requests transmitted.")
    duration_seconds: float = Field(
        default=0.0, description="Total scan execution duration in seconds."
    )


class SQLiScanResult(BaseModel):
    """Complete, immutable result of an SQL injection detection session."""

    model_config = ConfigDict(frozen=True)

    scan_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique scan session UUID."
    )
    target_url: str = Field(description="Primary target URL.")
    execution_status: str = Field(default="completed", description="Scan execution status.")
    summary: SQLiScanSummary = Field(description="Aggregated scan summary metrics.")
    findings: list[SQLiFinding] = Field(
        default_factory=list, description="List of all finding records."
    )
    parameters: list[CandidateParameter] = Field(
        default_factory=list, description="List of all candidate parameters evaluated."
    )
    limitations: list[str] = Field(
        default_factory=list, description="General framework limitations and disclaimers."
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when scan session completed.",
    )
