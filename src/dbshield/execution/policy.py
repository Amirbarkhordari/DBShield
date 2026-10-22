"""Execution policies and budget enforcement for DBShield test runs (Phase 6).

Centralizes budget ceilings, timeout management, sensitive parameter exclusion,
and early termination / cancellation controls.
"""

import logging

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("dbshield.execution.policy")

DEFAULT_INELIGIBLE_PATTERNS = {
    "password",
    "pass",
    "pwd",
    "secret",
    "token",
    "csrf",
    "csrf_token",
    "_token",
    "authenticity_token",
    "auth_token",
    "session",
    "sessionid",
    "otp",
}


class ExecutionPolicy(BaseModel):
    """Centralized policy configuration governing test execution."""

    model_config = ConfigDict(frozen=True)

    max_total_requests: int = Field(
        default=50,
        ge=5,
        le=500,
        description="Global ceiling on HTTP requests across the entire execution run.",
    )
    max_requests_per_parameter: int = Field(
        default=8,
        ge=2,
        le=30,
        description="Ceiling on HTTP requests dispatched for any single parameter.",
    )
    max_payloads_per_parameter: int = Field(
        default=6,
        ge=1,
        le=20,
        description="Maximum number of distinct payloads applied to any single parameter.",
    )
    timeout_seconds: float = Field(
        default=10.0,
        gt=0.5,
        le=60.0,
        description="Per-request timeout budget in seconds.",
    )
    enable_differential: bool = Field(
        default=True,
        description="Whether to execute paired boolean differential test cases.",
    )
    stop_on_first_indicator: bool = Field(
        default=False,
        description="Whether to terminate testing immediately upon detecting a candidate indicator.",
    )
    disallowed_parameter_patterns: set[str] = Field(
        default_factory=lambda: set(DEFAULT_INELIGIBLE_PATTERNS),
        description="Parameter name patterns strictly excluded from active payload delivery.",
    )

    def evaluate_parameter_eligibility(self, param_name: str) -> tuple[bool, str | None]:
        """Verify whether candidate parameter is safe for payload execution."""
        tokens = param_name.lower().replace("-", "_").split(".")
        for tok in tokens:
            for forbidden in self.disallowed_parameter_patterns:
                if forbidden == tok or tok.endswith(f"_{forbidden}"):
                    return (
                        False,
                        f"Parameter '{param_name}' matches sensitive security control pattern ({forbidden}).",
                    )
        return True, None


class ExecutionBudgetTracker:
    """Tracks and enforces request budgets and cancellation states during a test run."""

    def __init__(self, policy: ExecutionPolicy) -> None:
        """Initialize tracker with active execution policy."""
        self.policy = policy
        self._total_requests: int = 0
        self._per_param_requests: dict[str, int] = {}
        self._per_param_payloads: dict[str, int] = {}
        self._is_cancelled: bool = False
        self._cancel_reason: str | None = None

    @property
    def total_requests(self) -> int:
        """Total HTTP requests dispatched so far."""
        return self._total_requests

    @property
    def is_cancelled(self) -> bool:
        """Whether execution has been cancelled or aborted."""
        return self._is_cancelled

    @property
    def cancel_reason(self) -> str | None:
        """Explanation of why execution was cancelled."""
        return self._cancel_reason

    def cancel(self, reason: str = "Execution aborted by policy or user.") -> None:
        """Cancel remaining test dispatch."""
        self._is_cancelled = True
        self._cancel_reason = reason
        logger.warning("Test execution run cancelled: %s", reason)

    def can_dispatch_test(
        self, param_name: str, estimated_requests: int = 1
    ) -> tuple[bool, str | None]:
        """Check whether budget allows executing a test case on parameter.

        Args:
            param_name: Target parameter name.
            estimated_requests: Number of requests test case will require (1 for error, 2 for diff).

        Returns:
            Tuple of (can_dispatch: bool, rejection_reason: str | None).
        """
        if self._is_cancelled:
            return False, f"Run cancelled: {self._cancel_reason}"

        # 1. Global request budget check
        if self._total_requests + estimated_requests > self.policy.max_total_requests:
            return (
                False,
                f"Global request budget reached ({self._total_requests}/{self.policy.max_total_requests}).",
            )

        # 2. Per-parameter request budget check
        param_reqs = self._per_param_requests.get(param_name, 0)
        if param_reqs + estimated_requests > self.policy.max_requests_per_parameter:
            return (
                False,
                f"Parameter request budget reached for '{param_name}' ({param_reqs}/{self.policy.max_requests_per_parameter}).",
            )

        # 3. Per-parameter payload count check
        param_payloads = self._per_param_payloads.get(param_name, 0)
        if param_payloads >= self.policy.max_payloads_per_parameter:
            return (
                False,
                f"Maximum payload count reached for '{param_name}' ({param_payloads}/{self.policy.max_payloads_per_parameter}).",
            )

        return True, None

    def record_dispatch(self, param_name: str, count: int = 1) -> None:
        """Record completed HTTP request dispatch for a parameter."""
        self._total_requests += count
        self._per_param_requests[param_name] = self._per_param_requests.get(param_name, 0) + count
        self._per_param_payloads[param_name] = self._per_param_payloads.get(param_name, 0) + 1
        logger.debug(
            "Dispatched %d request(s) for '%s'. Total: %d/%d",
            count,
            param_name,
            self._total_requests,
            self.policy.max_total_requests,
        )

    def get_parameter_requests(self, param_name: str) -> int:
        """Get total requests dispatched for a specific parameter."""
        return self._per_param_requests.get(param_name, 0)
