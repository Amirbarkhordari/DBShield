"""Data models for DBShield Payload Management subsystem (Phase 6).

Defines structured, immutable representations of security payloads,
categories, risk classifications, compatibility constraints, and catalog entries.
"""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from dbshield.sqli.models import ParameterLocation


class PayloadCategory(StrEnum):
    """Categorization of security payload types."""

    SQLI = "sqli"
    NOSQLI = "nosqli"
    GENERIC = "generic"


class PayloadRiskLevel(StrEnum):
    """Risk rating for payload execution safety.

    All Phase 6 payloads are strictly bounded, defensive, and read-only.
    """

    SAFE_PROBE = "safe_probe"
    READ_ONLY = "read_only"


class SecurityPayload(BaseModel):
    """Structured, immutable definition of an individual test payload.

    Separates payload data definitions from execution and detection orchestration.
    """

    model_config = ConfigDict(frozen=True)

    payload_id: str = Field(description="Unique, stable payload identifier.")
    name: str = Field(description="Human-readable descriptive payload name.")
    description: str = Field(description="Detailed explanation of payload purpose and behavior.")
    category: PayloadCategory = Field(description="Payload security category (sqli, nosqli).")
    technique: str = Field(
        description="Testing technique (error_based, boolean_differential, operator_injection)."
    )
    applicable_locations: list[ParameterLocation] = Field(
        description="HTTP transport locations where this payload can be applied."
    )
    applicable_engines: list[str] = Field(
        default_factory=list,
        description="Target engine identifiers compatible with this payload ('sqli', 'nosqli').",
    )
    target_providers: list[str] = Field(
        default_factory=list,
        description="Target DBMS or NoSQL driver families ('mysql', 'postgres', 'mongodb', 'couchdb', 'generic').",
    )
    payload_value: Any = Field(
        description="Actual payload input data (string, integer, dictionary, or list)."
    )
    is_paired: bool = Field(
        default=False,
        description="Whether this payload participates in a paired differential test.",
    )
    pair_role: str | None = Field(
        default=None,
        description="Role within a paired differential test ('true', 'false', or None).",
    )
    paired_with_id: str | None = Field(
        default=None,
        description="Identifier of complementary paired payload for differential testing.",
    )
    risk_level: PayloadRiskLevel = Field(
        default=PayloadRiskLevel.SAFE_PROBE,
        description="Assessed risk level (always safe/defensive).",
    )
    safety_constraints: list[str] = Field(
        default_factory=list,
        description="Mandatory safety boundaries and operating requirements.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Searchable categorization tags.",
    )
    version: str = Field(
        default="1.0.0",
        description="Payload specification semantic version.",
    )
