"""DBShield Execution Subsystem (Phase 6).

Provides a centralized, reusable engine for safe payload transformation,
execution budgeting, scope enforcement, orchestrating security test cases,
and integrating with engine detectors.
"""

from dbshield.execution.adapters import (
    EngineAdapter,
    NoSQLiExecutionAdapter,
    SQLiExecutionAdapter,
)
from dbshield.execution.models import (
    ExecutionRecord,
    ExecutionRunResult,
    ExecutionStatus,
    ExecutionSummary,
)
from dbshield.execution.orchestrator import TestExecutionOrchestrator
from dbshield.execution.policy import ExecutionBudgetTracker, ExecutionPolicy
from dbshield.execution.transformer import PayloadTransformer

__all__ = [
    "EngineAdapter",
    "ExecutionBudgetTracker",
    "ExecutionPolicy",
    "ExecutionRecord",
    "ExecutionRunResult",
    "ExecutionStatus",
    "ExecutionSummary",
    "NoSQLiExecutionAdapter",
    "PayloadTransformer",
    "SQLiExecutionAdapter",
    "TestExecutionOrchestrator",
]
