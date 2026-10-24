"""Performance and resource profiling framework for DBShield core engines (Phase 9).

Measures execution duration, throughput, and memory consumption across critical paths:
1. Payload generation and filtering
2. Error signature regex matching across large bodies
3. Boolean differential comparison (SequenceMatcher)
4. Evidence correlation and verification state evaluation
5. Multi-format report export (JSON, Markdown, CSV, HTML)

Uses standard library time.perf_counter and tracemalloc. Avoids fragile timing
assertions while establishing reproducible benchmarks.
"""

from __future__ import annotations

import platform
import sys
import time
import tracemalloc
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from dbshield.nosqli.detectors.differential_detector import NoSQLDifferentialDetector
from dbshield.nosqli.models import NoSQLProviderFamily
from dbshield.payloads.catalog import PayloadCatalog
from dbshield.reporting.exporters.csv_exporter import CSVReportExporter
from dbshield.reporting.exporters.json_exporter import JSONReportExporter
from dbshield.reporting.exporters.markdown_exporter import MarkdownReportExporter
from dbshield.reporting.exporters.terminal_exporter import TerminalReportExporter
from dbshield.reporting.models import (
    FindingSeverity,
    NormalizedSecurityFinding,
    ReportMetadata,
    SecurityAssessmentReport,
    VulnerabilityCategory,
)
from dbshield.sqli.detectors.differential_detector import DifferentialDetector
from dbshield.sqli.models import (
    ParameterLocation,
)
from dbshield.sqli.signatures import SignatureCatalog
from dbshield.verification.correlator import EvidenceCorrelator
from dbshield.verification.models import (
    ConfidenceLevel,
    EvidenceProvenance,
    EvidenceType,
    NormalizedEvidence,
    VerificationStatus,
    VulnerabilityClass,
)


class BenchmarkResult(BaseModel):
    """Result of an individual component benchmark workload."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Benchmark name.")
    description: str = Field(description="Description of the workload under test.")
    iterations: int = Field(description="Number of iterations executed.")
    total_time_ms: float = Field(description="Total wall-clock duration in milliseconds.")
    avg_time_ms: float = Field(description="Average duration per iteration in milliseconds.")
    min_time_ms: float = Field(description="Minimum iteration duration in milliseconds.")
    max_time_ms: float = Field(description="Maximum iteration duration in milliseconds.")
    memory_peak_mb: float = Field(description="Peak memory allocated during workload in MB.")
    ops_per_sec: float = Field(description="Operations completed per second.")


class ProfilerReport(BaseModel):
    """Complete profiling report aggregating all benchmark workloads."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when benchmark suite was completed.",
    )
    environment: dict[str, str] = Field(
        description="Execution environment characteristics (OS, Python version, platform).",
    )
    benchmarks: list[BenchmarkResult] = Field(
        default_factory=list,
        description="Individual benchmark results.",
    )
    total_duration_ms: float = Field(
        description="Total duration of the entire benchmarking suite in milliseconds.",
    )


class PerformanceProfiler:
    """Orchestrates deterministic local microbenchmarks for DBShield components."""

    def __init__(self) -> None:
        self.env_info: dict[str, str] = {
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or "Unknown",
        }

    def _measure_workload(
        self,
        name: str,
        description: str,
        iterations: int,
        workload_fn: Any,
    ) -> BenchmarkResult:
        """Run a workload function across specified iterations with timing and tracemalloc."""
        durations: list[float] = []

        tracemalloc.reset_peak()
        if not tracemalloc.is_tracing():
            tracemalloc.start()

        start_total = time.perf_counter()
        for _ in range(iterations):
            iter_start = time.perf_counter()
            workload_fn()
            iter_end = time.perf_counter()
            durations.append((iter_end - iter_start) * 1000.0)

        end_total = time.perf_counter()
        _, peak_bytes = tracemalloc.get_traced_memory()

        total_ms = (end_total - start_total) * 1000.0
        avg_ms = total_ms / iterations if iterations > 0 else 0.0
        min_ms = min(durations) if durations else 0.0
        max_ms = max(durations) if durations else 0.0
        peak_mb = peak_bytes / (1024.0 * 1024.0)
        ops_sec = (iterations / (total_ms / 1000.0)) if total_ms > 0 else 0.0

        return BenchmarkResult(
            name=name,
            description=description,
            iterations=iterations,
            total_time_ms=round(total_ms, 3),
            avg_time_ms=round(avg_ms, 3),
            min_time_ms=round(min_ms, 3),
            max_time_ms=round(max_ms, 3),
            memory_peak_mb=round(peak_mb, 4),
            ops_per_sec=round(ops_sec, 1),
        )

    def benchmark_payload_generation(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark payload repository query and filter operations."""
        catalog = PayloadCatalog()

        def workload() -> None:
            _ = catalog.filter_payloads(tags=["sqli"])
            _ = catalog.filter_payloads(tags=["nosqli"])
            _ = catalog.filter_payloads(tags=["error_based"])
            _ = catalog.filter_payloads(tags=["differential"])

        return self._measure_workload(
            name="payload_generation_and_filtering",
            description="Querying and filtering SQLi and NoSQLi payloads by tags from catalog",
            iterations=iterations,
            workload_fn=workload,
        )

    def benchmark_signature_matching(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark error signature matching against medium-sized synthetic HTTP bodies."""
        # Synthetic 10KB HTML body containing HTML structure and mixed error strings
        sample_body = (
            "<html><head><title>System Status</title></head><body>"
            "<div>" + ("<p>Log line info normal data 12345</p>\n" * 100) + "</div>"
            "<div class='error'>You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version near ''' at line 1</div>"
            "<div>" + ("<p>Additional application content block</p>\n" * 50) + "</div>"
            "</body></html>"
        )

        def workload() -> None:
            _ = SignatureCatalog.match_signatures(sample_body)
            _ = SignatureCatalog.is_generic_server_error(sample_body)

        return self._measure_workload(
            name="signature_catalog_matching",
            description="Regex pattern matching and snippet extraction across a 10KB synthetic response",
            iterations=iterations,
            workload_fn=workload,
        )

    def benchmark_differential_comparison(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark SequenceMatcher boolean differential analysis."""
        base_body = (
            "<html><body><h1>User Account</h1><p>ID: 42</p><p>Name: Alice</p>"
            + ("<div>Data line</div>" * 40)
            + "</body></html>"
        )
        true_body = base_body  # Exact match
        false_body = (
            "<html><body><h1>User Account</h1><p>No user found for query</p>"
            + ("<div>Different block</div>" * 30)
            + "</body></html>"
        )

        def workload() -> None:
            _ = DifferentialDetector.analyze_pair(
                baseline_body=base_body,
                baseline_status=200,
                is_baseline_stable=True,
                true_body=true_body,
                true_status=200,
                false_body=false_body,
                false_status=200,
            )
            _ = NoSQLDifferentialDetector.analyze_pair(
                baseline_body=base_body,
                baseline_status=200,
                is_baseline_stable=True,
                true_body=true_body,
                true_status=200,
                false_body=false_body,
                false_status=200,
                provider_hint=NoSQLProviderFamily.MONGODB,
            )

        return self._measure_workload(
            name="boolean_differential_comparison",
            description="SequenceMatcher ratio computation and anomaly analysis for SQLi and NoSQLi pairs",
            iterations=iterations,
            workload_fn=workload,
        )

    def benchmark_evidence_correlation(self, iterations: int = 100) -> BenchmarkResult:
        """Benchmark Phase 7 verification correlation and deduplication across finding batches."""
        evidence_batch: list[NormalizedEvidence] = []
        for i in range(20):
            prov = EvidenceProvenance(
                engine="sqli",
                vulnerability_class=VulnerabilityClass.SQLI,
                target_url=f"http://lab.local/user?id={i % 5}",
                parameter_name="id",
                parameter_location=ParameterLocation.QUERY,
                execution_id=f"exec-{i}",
                source_finding_id=f"find-{i % 5}",
            )
            ev = NormalizedEvidence(
                provenance=prov,
                evidence_type=EvidenceType.ERROR_SIGNATURE,
                rule_id="ERR_MYSQL_SYNTAX",
                matched_pattern="syntax error",
                safe_snippet="syntax error near '1'",
                description="MySQL syntax error observed in response.",
                provider_or_family="mysql",
                test_status=500,
            )
            evidence_batch.append(ev)

        def workload() -> None:
            _ = EvidenceCorrelator.correlate(evidence_batch)

        return self._measure_workload(
            name="evidence_correlation_and_deduplication",
            description="Phase 7 EvidenceCorrelator grouping, deduplication, and fingerprint computation",
            iterations=iterations,
            workload_fn=workload,
        )

    def benchmark_report_generation(self, iterations: int = 30) -> BenchmarkResult:
        """Benchmark Phase 8 report generation across all 4 export formats."""
        findings: list[NormalizedSecurityFinding] = []
        for i in range(25):
            f = NormalizedSecurityFinding(
                id=f"DBS-BENCH-{i:03d}",
                title=f"SQL Injection in parameter param_{i}",
                category=VulnerabilityCategory.SQL_INJECTION,
                subtype="error_based",
                target_url=f"http://lab.local/catalog?item={i}",
                endpoint="/catalog",
                http_method="GET",
                parameter_name=f"param_{i}",
                parameter_location=ParameterLocation.QUERY,
                engine="sqli",
                technique="error_based",
                verification_status=VerificationStatus.VERIFIED,
                confidence_level=ConfidenceLevel.VERIFIED,
                confidence_score=0.95,
                severity=FindingSeverity.HIGH,
                severity_rationale="Database syntax error confirmed in test response.",
                description="Observed MySQL error indicating direct query injection.",
                evidence_summary="syntax error near '1'",
                evidence_count=2,
                remediation="Apply parameterized SQL queries.",
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
            )
            findings.append(f)

        meta = ReportMetadata(
            target_url="http://lab.local/catalog",
            total_findings=len(findings),
            findings_by_severity={"high": len(findings)},
            findings_by_status={"verified": len(findings)},
            findings_by_category={"sql_injection": len(findings)},
            assessment_scope=["http://lab.local/catalog"],
            limitations=["Controlled local benchmark report."],
        )
        report = SecurityAssessmentReport(metadata=meta, findings=findings)

        json_exp = JSONReportExporter()
        md_exp = MarkdownReportExporter()
        csv_exp = CSVReportExporter()
        term_exp = TerminalReportExporter()

        def workload() -> None:
            _ = json_exp.export(report)
            _ = md_exp.export(report)
            _ = csv_exp.export(report)
            _ = term_exp.export(report)

        return self._measure_workload(
            name="multi_format_report_export",
            description="Exporting 25 normalized findings to JSON, Markdown, CSV, and Terminal formats",
            iterations=iterations,
            workload_fn=workload,
        )

    def run_all(
        self,
        payload_iters: int = 50,
        sig_iters: int = 50,
        diff_iters: int = 50,
        corr_iters: int = 50,
        report_iters: int = 20,
    ) -> ProfilerReport:
        """Execute all microbenchmarks and return an aggregated report."""
        suite_start = time.perf_counter()
        benchmarks: list[BenchmarkResult] = [
            self.benchmark_payload_generation(payload_iters),
            self.benchmark_signature_matching(sig_iters),
            self.benchmark_differential_comparison(diff_iters),
            self.benchmark_evidence_correlation(corr_iters),
            self.benchmark_report_generation(report_iters),
        ]
        total_suite_ms = (time.perf_counter() - suite_start) * 1000.0

        return ProfilerReport(
            environment=self.env_info,
            benchmarks=benchmarks,
            total_duration_ms=round(total_suite_ms, 3),
        )
