"""Discovery result and form inventory models for DBShield Phase 2.

Provides structured, validated, and serializable representations of discovered
login pages, HTML forms, input controls, parameters, and classification evidence.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FieldClassification(StrEnum):
    """Rule-based security classification of discovered HTML form controls."""

    USERNAME = "username"
    EMAIL = "email"
    PASSWORD = "password"
    OTP = "otp"
    CSRF_TOKEN = "csrf_token"
    HIDDEN = "hidden"
    GENERIC_INPUT = "generic_input"
    SUBMIT = "submit"
    UNKNOWN = "unknown"


class PageClassification(StrEnum):
    """Overall classification of the analyzed target page."""

    LOGIN_FORM_DETECTED = "login_form_detected"
    MULTIPLE_LOGIN_FORMS = "multiple_login_forms"
    LOGIN_INPUTS_WITHOUT_FORM = "login_inputs_without_form"
    NO_LOGIN_FORM_DETECTED = "no_login_form_detected"
    PAGE_COULD_NOT_BE_ANALYZED = "page_could_not_be_analyzed"
    PAGE_INACCESSIBLE_OR_BLOCKED = "page_inaccessible_or_blocked"


class DiscoveryStatus(StrEnum):
    """Overall execution status of the discovery operation."""

    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"
    BLOCKED_BY_SCOPE = "blocked_by_scope"


class InputField(BaseModel):
    """Structured representation of a single discovered HTML form control or input point.

    Security Notice: For safety and zero-credential leak guarantees, actual values
    of sensitive fields (e.g. password, tokens) are never collected or stored.
    """

    model_config = ConfigDict(frozen=True)

    name: str | None = Field(default=None, description="Control 'name' attribute.")
    input_type: str = Field(
        default="text", description="HTML input type (e.g., text, password, hidden)."
    )
    element_type: str = Field(
        default="input", description="HTML element tag (input, textarea, select, button)."
    )
    form_id: str | None = Field(
        default=None, description="Identifier of the parent form, if associated."
    )
    id_attr: str | None = Field(default=None, description="Control 'id' attribute.")
    autocomplete: str | None = Field(default=None, description="HTML autocomplete attribute value.")
    placeholder: str | None = Field(default=None, description="Placeholder text.")
    required: bool = Field(default=False, description="Whether the field is marked as required.")
    is_hidden: bool = Field(
        default=False, description="Whether the field is hidden from user view."
    )
    is_auth_related: bool = Field(
        default=False, description="Whether field is heuristically related to authentication."
    )
    classification: FieldClassification = Field(
        default=FieldClassification.UNKNOWN, description="Rule-based classification."
    )
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Classification confidence score."
    )
    evidence: list[str] = Field(
        default_factory=list, description="Reasoning and attributes supporting classification."
    )


class DiscoveredForm(BaseModel):
    """Structured representation of an HTML form discovered on a target page."""

    model_config = ConfigDict(frozen=True)

    form_id: str = Field(description="Unique identifier for the form within the discovery session.")
    declared_action: str | None = Field(
        default=None, description="Form action exactly as declared in HTML."
    )
    resolved_action: str = Field(description="Normalized action URL resolved against page origin.")
    method: str = Field(
        default="GET", description="HTTP method declared by the form (GET or POST)."
    )
    enctype: str = Field(
        default="application/x-www-form-urlencoded", description="Form content encoding type."
    )
    attributes: dict[str, str] = Field(
        default_factory=dict, description="HTML attributes present on the form tag."
    )
    controls: list[InputField] = Field(
        default_factory=list, description="All discovered input controls within the form."
    )
    query_params: list[str] = Field(
        default_factory=list, description="Query parameter names present in resolved action URL."
    )
    duplicate_field_names: list[str] = Field(
        default_factory=list, description="Field names appearing more than once."
    )
    is_same_origin: bool = Field(
        default=True, description="Whether resolved action shares the target origin."
    )
    is_action_in_scope: bool = Field(
        default=True, description="Whether action URL is authorized by scope rules."
    )
    is_login_candidate: bool = Field(
        default=False, description="Whether the form appears to be a login/authentication form."
    )
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Confidence of login candidate classification."
    )
    evidence: list[str] = Field(
        default_factory=list, description="Evidence supporting login form classification."
    )

    @property
    def control_count(self) -> int:
        """Total number of form controls discovered."""
        return len(self.controls)


class DiscoverySummary(BaseModel):
    """Aggregated metrics and counts from the discovery process."""

    model_config = ConfigDict(frozen=True)

    total_forms: int = Field(default=0, description="Total HTML forms discovered.")
    login_forms: int = Field(default=0, description="Forms classified as login candidates.")
    candidate_fields: int = Field(
        default=0, description="Interactive candidate input fields discovered."
    )
    hidden_fields: int = Field(default=0, description="Hidden inputs identified across all forms.")
    password_fields: int = Field(default=0, description="Password fields identified.")
    username_fields: int = Field(default=0, description="Username/email fields identified.")
    csrf_fields: int = Field(
        default=0, description="CSRF-related or anti-automation tokens identified."
    )
    action_urls_in_scope: int = Field(
        default=0, description="Discovered action URLs within authorized scope."
    )
    action_urls_out_of_scope: int = Field(
        default=0, description="Discovered action URLs outside authorized scope."
    )


class DiscoveryResult(BaseModel):
    """Comprehensive discovery result model for DBShield Phase 2.

    Independent of CLI presentation layer; fully serializable to machine-readable JSON.
    """

    model_config = ConfigDict(frozen=True)

    discovery_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique discovery session identifier.",
    )
    target_url: str = Field(description="Initial user-supplied target URL.")
    final_url: str | None = Field(
        default=None, description="Final resolved URL following any in-scope redirects."
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of discovery execution.",
    )
    status: DiscoveryStatus = Field(description="Overall execution status.")
    http_status_code: int | None = Field(
        default=None, description="HTTP response status code, if retrieved."
    )
    content_type: str | None = Field(
        default=None, description="HTTP Content-Type header from response."
    )
    page_title: str | None = Field(
        default=None, description="HTML page title tag content, if present."
    )
    page_query_params: list[str] = Field(
        default_factory=list, description="Query parameter names present in target URL."
    )
    page_classification: PageClassification = Field(description="Overall page classification.")
    page_evidence: list[str] = Field(
        default_factory=list, description="Evidence supporting page classification."
    )
    forms: list[DiscoveredForm] = Field(
        default_factory=list, description="Forms discovered on the page."
    )
    orphan_inputs: list[InputField] = Field(
        default_factory=list,
        description="Input controls detected outside any formal HTML <form> element.",
    )
    summary: DiscoverySummary = Field(
        default_factory=DiscoverySummary, description="Summary counts and metrics."
    )
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings encountered.")
    errors: list[str] = Field(
        default_factory=list, description="Errors or limitations encountered."
    )

    def to_safe_dict(self) -> dict[str, Any]:
        """Return serialized dictionary representation guaranteed to be JSON-serializable and secret-free."""
        return self.model_dump(mode="json")
