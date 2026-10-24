"""Data models for reproducible lab validation, scenario execution, and reliability metrics (Phase 9).

Defines standardized schemas for synthetic test scenarios, expected detection outcomes,
confusion matrices, precision/recall metrics, and validation assessment reports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScenarioCategory(StrEnum):
    """Broad functional category of the lab validation scenario."""

    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    SAFETY_BUDGET = "safety_budget"
    VERIFICATION_CONSISTENCY = "verification_consistency"


class ExpectedClassification(StrEnum):
    """Truth label for evaluating detector precision, recall, and reliability."""

    TRUE_POSITIVE = "true_positive"
    TRUE_NEGATIVE = "true_negative"
    AMBIGUOUS_INCONCLUSIVE = "ambiguous_inconclusive"
    BLOCKED_OR_ERROR = "blocked_or_error"


class ScenarioOutcome(StrEnum):
    """Test execution verdict for a single scenario."""

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"


class MockHTTPResponse(BaseModel):
    """Deterministic simulated HTTP response matching a URL pattern."""

    model_config = ConfigDict(frozen=True)

    url_pattern: str = Field(
        description="URL substring or prefix to match against outbound request.",
    )
    method: str | None = Field(
        default=None,
        description="HTTP method to match (or None to match any method).",
    )
    status_code: int = Field(
        default=200,
        description="Simulated HTTP response status code.",
    )
    headers: dict[str, str] = Field(
        default_factory=lambda: {"content-type": "text/html; charset=utf-8"},
        description="Simulated HTTP response headers.",
    )
    body: str = Field(
        default="",
        description="Simulated HTTP response body payload.",
    )
    is_prefix: bool = Field(
        default=True,
        description="If True, matches when request URL starts with or contains url_pattern.",
    )


class ExpectedOutcome(BaseModel):
    """Target expectation for verifying detector and verification engine behavior."""

    model_config = ConfigDict(frozen=True)

    classification: ExpectedClassification = Field(
        description="Ground truth security classification for this scenario.",
    )
    status: str | None = Field(
        default=None,
        description="Expected detection status (e.g., 'potential_indicator', 'no_indicator').",
    )
    technique: str | None = Field(
        default=None,
        description="Expected testing technique (e.g., 'error_based', 'boolean_differential').",
    )
    family: str | None = Field(
        default=None,
        description="Expected database engine or provider family hint (e.g., 'mysql', 'mongodb').",
    )
    min_evidence_count: int = Field(
        default=0,
        ge=0,
        description="Minimum number of evidence records expected.",
    )
    verification_status: str | None = Field(
        default=None,
        description="Expected Phase 7 verification status if evaluated through verification engine.",
    )


class LabScenario(BaseModel):
    """Complete, self-contained synthetic lab validation scenario."""

    model_config = ConfigDict(frozen=True)

    scenario_id: str = Field(
        description="Unique identifier for the scenario (e.g., 'SQLI-ERR-MYSQL-01').",
    )
    name: str = Field(
        description="Human-readable title of the scenario.",
    )
    description: str = Field(
        description="Detailed explanation of what injection signal or safe behavior is being validated.",
    )
    category: ScenarioCategory = Field(
        description="Functional category for this scenario.",
    )

    @field_validator("category", mode="before")
    @classmethod
    def _normalize_category(cls, val: Any) -> Any:
        if isinstance(val, str):
            clean = val.lower().strip()
            aliases = {
                "sqli": ScenarioCategory.SQL_INJECTION,
                "nosqli": ScenarioCategory.NOSQL_INJECTION,
                "safety": ScenarioCategory.SAFETY_BUDGET,
                "verification": ScenarioCategory.VERIFICATION_CONSISTENCY,
            }
            if clean in aliases:
                return aliases[clean]
        return val

    target_url: str = Field(
        description="Target endpoint URL to be evaluated.",
    )
    http_method: str = Field(
        default="GET",
        description="HTTP request method.",
    )
    parameter_name: str = Field(
        default="id",
        description="Name of the parameter being evaluated.",
    )
    parameter_location: str = Field(
        default="query",
        description="Parameter location (query, body_form, body_json, header, cookie).",
    )
    data: str | None = Field(
        default=None,
        description="Raw form data for POST requests.",
    )
    json_data: dict[str, Any] | None = Field(
        default=None,
        description="JSON dictionary for JSON body requests.",
    )
    headers: dict[str, str] | None = Field(
        default=None,
        description="Custom request headers to send.",
    )
    cookies: dict[str, str] | None = Field(
        default=None,
        description="Custom cookies to send.",
    )
    mock_responses: list[MockHTTPResponse] = Field(
        default_factory=list,
        description="List of deterministic mock responses simulating target behavior.",
    )
    expected: ExpectedOutcome = Field(
        description="Target expectation for validating actual engine results.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Arbitrary tags for filtering scenarios (e.g., ['error', 'mysql', 'fast']).",
    )


class ScenarioExecutionResult(BaseModel):
    """Detailed result of running a single validation scenario."""

    model_config = ConfigDict(frozen=True)

    scenario_id: str = Field(description="Identifier of executed scenario.")
    scenario_name: str = Field(description="Name of executed scenario.")
    category: ScenarioCategory = Field(description="Category of scenario.")
    outcome: ScenarioOutcome = Field(description="Overall execution verdict.")
    expected_classification: ExpectedClassification = Field(description="Ground truth expectation.")
    actual_status: str | None = Field(default=None, description="Actual detection status observed.")
    actual_technique: str | None = Field(default=None, description="Actual technique identified.")
    actual_family: str | None = Field(
        default=None, description="Actual database family identified."
    )
    actual_evidence_count: int = Field(default=0, description="Actual evidence count collected.")
    actual_verification_status: str | None = Field(
        default=None, description="Actual verification status if evaluated."
    )
    discrepancies: list[str] = Field(
        default_factory=list,
        description="List of observed differences between expected and actual results.",
    )
    execution_time_ms: float = Field(
        default=0.0,
        description="Elapsed wall-clock execution time in milliseconds.",
    )


class ConfusionMatrix(BaseModel):
    """Statistical summary of detection precision, recall, and accuracy."""

    model_config = ConfigDict(frozen=True)

    true_positives: int = Field(
        default=0, ge=0, description="Correctly identified vulnerabilities."
    )
    false_positives: int = Field(
        default=0, ge=0, description="Clean behaviors incorrectly flagged."
    )
    true_negatives: int = Field(default=0, ge=0, description="Clean behaviors correctly rejected.")
    false_negatives: int = Field(default=0, ge=0, description="Actual vulnerabilities missed.")
    inconclusive: int = Field(default=0, ge=0, description="Ambiguous or unstable scenarios.")
    skipped: int = Field(default=0, ge=0, description="Skipped or out-of-scope scenarios.")
    precision: float | None = Field(default=None, description="TP / (TP + FP) if denominator > 0.")
    recall: float | None = Field(default=None, description="TP / (TP + FN) if denominator > 0.")
    f1_score: float | None = Field(
        default=None, description="Harmonic mean of precision and recall."
    )
    accuracy: float | None = Field(
        default=None, description="(TP + TN) / (TP + TN + FP + FN) if denominator > 0."
    )


class ValidationReport(BaseModel):
    """Comprehensive validation assessment report aggregating scenario outcomes."""

    model_config = ConfigDict(frozen=True)

    suite_name: str = Field(
        default="DBShield Lab Validation Suite",
        description="Name of the validation test suite.",
    )
    total_scenarios: int = Field(description="Total count of evaluated scenarios.")
    passed: int = Field(
        default=0, ge=0, description="Scenarios where expectations matched perfectly."
    )
    failed: int = Field(default=0, ge=0, description="Scenarios where expectations diverged.")
    inconclusive: int = Field(default=0, ge=0, description="Scenarios with ambiguous outcomes.")
    skipped: int = Field(default=0, ge=0, description="Scenarios skipped due to budget or policy.")
    confusion_matrix: ConfusionMatrix = Field(
        description="Structured accuracy and reliability metrics.",
    )
    dataset_limitations: list[str] = Field(
        default_factory=list,
        description="Explicit documentation of test dataset composition and limitations.",
    )
    results: list[ScenarioExecutionResult] = Field(
        default_factory=list,
        description="Per-scenario execution outcomes.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the validation suite was executed.",
    )
