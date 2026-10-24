"""DBShield Lab Validation, Detection Reliability & Stabilization subsystem (Phase 9).

Provides deterministic testing frameworks, synthetic HTTP response simulation,
detection reliability analysis, confusion matrix evaluation, and engine performance
profiling.
"""

from dbshield.validation.models import (
    ConfusionMatrix,
    ExpectedClassification,
    ExpectedOutcome,
    LabScenario,
    MockHTTPResponse,
    ScenarioCategory,
    ScenarioExecutionResult,
    ScenarioOutcome,
    ValidationReport,
)
from dbshield.validation.profiler import (
    BenchmarkResult,
    PerformanceProfiler,
    ProfilerReport,
)
from dbshield.validation.runner import (
    DEFAULT_DATASET_LIMITATIONS,
    LabValidationRunner,
)
from dbshield.validation.scenarios import (
    load_scenarios_from_file,
    load_standard_scenarios,
)

__all__ = [
    "BenchmarkResult",
    "ConfusionMatrix",
    "DEFAULT_DATASET_LIMITATIONS",
    "ExpectedClassification",
    "ExpectedOutcome",
    "LabScenario",
    "LabValidationRunner",
    "MockHTTPResponse",
    "PerformanceProfiler",
    "ProfilerReport",
    "ScenarioCategory",
    "ScenarioExecutionResult",
    "ScenarioOutcome",
    "ValidationReport",
    "load_scenarios_from_file",
    "load_standard_scenarios",
]
