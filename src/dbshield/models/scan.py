"""Scan metadata and lifecycle status models.

Represents scan records, selected test profiles, and execution counters.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScanStatus(StrEnum):
    """Execution status states for a security assessment session."""

    PENDING = "pending"
    INITIALIZED = "initialized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class ScanProfile(StrEnum):
    """Configured scanning profile determining depth of tests in future phases."""

    PASSIVE = "passive"
    DISCOVERY = "discovery"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


class Scan(BaseModel):
    """Foundational data model tracking scan session parameters and status."""

    model_config = ConfigDict(validate_assignment=True)

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Unique scan session identifier (UUIDv4).",
    )
    target_url: str = Field(description="Normalized target URL.")
    target_host: str = Field(description="Target hostname.")
    profile: ScanProfile = Field(
        default=ScanProfile.STANDARD,
        description="Selected scan profile.",
    )
    status: ScanStatus = Field(
        default=ScanStatus.PENDING,
        description="Current scan lifecycle status.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC creation timestamp.",
    )
    planned_test_count: int = Field(
        default=0,
        ge=0,
        description="Total planned security test checks.",
    )
    executed_test_count: int = Field(
        default=0,
        ge=0,
        description="Count of tests executed so far.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary session metadata and environment attributes.",
    )
