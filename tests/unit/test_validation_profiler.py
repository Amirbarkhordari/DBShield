"""Unit tests for Phase 9 performance and resource profiler."""

from dbshield.validation.profiler import (
    PerformanceProfiler,
    ProfilerReport,
)


def test_profiler_initialization() -> None:
    profiler = PerformanceProfiler()
    assert "python_version" in profiler.env_info
    assert "platform" in profiler.env_info


def test_profiler_payload_generation() -> None:
    profiler = PerformanceProfiler()
    result = profiler.benchmark_payload_generation(iterations=5)

    assert result.name == "payload_generation_and_filtering"
    assert result.iterations == 5
    assert result.total_time_ms >= 0.0
    assert result.avg_time_ms >= 0.0
    assert result.ops_per_sec >= 0.0


def test_profiler_signature_matching() -> None:
    profiler = PerformanceProfiler()
    result = profiler.benchmark_signature_matching(iterations=5)

    assert result.name == "signature_catalog_matching"
    assert result.iterations == 5
    assert result.total_time_ms >= 0.0


def test_profiler_evidence_correlation() -> None:
    profiler = PerformanceProfiler()
    result = profiler.benchmark_evidence_correlation(iterations=5)

    assert result.name == "evidence_correlation_and_deduplication"
    assert result.iterations == 5
    assert result.total_time_ms >= 0.0


def test_profiler_report_generation() -> None:
    profiler = PerformanceProfiler()
    result = profiler.benchmark_report_generation(iterations=3)

    assert result.name == "multi_format_report_export"
    assert result.iterations == 3
    assert result.total_time_ms >= 0.0


def test_profiler_run_all_smoke() -> None:
    profiler = PerformanceProfiler()
    report = profiler.run_all(
        payload_iters=3,
        sig_iters=3,
        diff_iters=2,
        corr_iters=3,
        report_iters=2,
    )

    assert isinstance(report, ProfilerReport)
    assert len(report.benchmarks) == 5
    assert report.total_duration_ms > 0.0
    for b in report.benchmarks:
        assert b.iterations > 0
        assert b.memory_peak_mb >= 0.0
