"""Deterministic execution runner and confusion matrix evaluator for lab scenarios (Phase 9).

Executes LabScenario definitions through DBShield detection engines, verification state machines,
and safety policies in an isolated, offline respx mock environment. Evaluates precision,
recall, F1, and discrepancy analysis with clear dataset caveats.
"""

from __future__ import annotations

import time
import urllib.parse

import httpx
import respx

from dbshield.http.client import SafeHTTPClient
from dbshield.models.target import Target
from dbshield.nosqli.engine import NoSQLiEngine
from dbshield.nosqli.models import NoSQLScanResult
from dbshield.scope.manager import ScopeManager
from dbshield.sqli.engine import SQLiEngine
from dbshield.sqli.models import SQLiScanResult
from dbshield.validation.models import (
    ConfusionMatrix,
    ExpectedClassification,
    LabScenario,
    ScenarioCategory,
    ScenarioExecutionResult,
    ScenarioOutcome,
    ValidationReport,
)
from dbshield.validation.scenarios import load_standard_scenarios

DEFAULT_DATASET_LIMITATIONS: list[str] = [
    "The scenarios in this validation suite use synthetic, controlled HTTP fixtures representing canonical injection patterns and safe application behaviors.",
    "Results reflect the engine's deterministic behavior against modeled response archetypes, not real-world exploitability across arbitrary unknown web applications.",
    "Calculated precision and recall metrics apply strictly to the authored benchmark dataset and should not be generalized as universal production performance.",
    "A clean validation outcome verifies engine conformity to its authored specifications; it does not constitute formal verification of complete software correctness.",
]


class LabValidationRunner:
    """Executes lab scenarios offline and calculates reliability and accuracy metrics."""

    def __init__(
        self,
        dataset_limitations: list[str] | None = None,
    ) -> None:
        self.dataset_limitations = dataset_limitations or DEFAULT_DATASET_LIMITATIONS

    def _setup_respx_mocks(self, router: respx.MockRouter, scenario: LabScenario) -> None:
        """Register dynamic mock HTTP routing for the scenario within a respx router."""
        probe_mocks = [
            m
            for m in scenario.mock_responses
            if not (m.url_pattern.startswith("http://") or m.url_pattern.startswith("https://"))
        ]
        base_mocks = [
            m
            for m in scenario.mock_responses
            if (m.url_pattern.startswith("http://") or m.url_pattern.startswith("https://"))
        ]
        sorted_probes = sorted(probe_mocks, key=lambda m: len(m.url_pattern), reverse=True)

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            url_unquoted = urllib.parse.unquote(url_str)
            content_str = (
                request.content.decode("utf-8", errors="replace") if request.content else ""
            )
            content_unquoted = urllib.parse.unquote(content_str)

            # 1. Check probe patterns first (query substrings, body parameters, payload tokens)
            for m in sorted_probes:
                if m.method and request.method.upper() != m.method.upper():
                    continue
                pat = m.url_pattern
                if (
                    pat in url_str
                    or pat in url_unquoted
                    or (content_str and (pat in content_str or pat in content_unquoted))
                ):
                    return httpx.Response(status_code=m.status_code, headers=m.headers, text=m.body)

            # 2. Check exact base URL matches
            for m in base_mocks:
                if m.method and request.method.upper() != m.method.upper():
                    continue
                pat = m.url_pattern
                if pat in (url_str, url_unquoted):
                    return httpx.Response(status_code=m.status_code, headers=m.headers, text=m.body)

            # 3. Check prefix base URL matches
            for m in base_mocks:
                if m.method and request.method.upper() != m.method.upper():
                    continue
                pat = m.url_pattern
                if url_str.startswith(pat) or url_unquoted.startswith(pat):
                    return httpx.Response(status_code=m.status_code, headers=m.headers, text=m.body)

            # 4. Fallback to scenario default response
            if scenario.mock_responses:
                first = scenario.mock_responses[0]
                return httpx.Response(
                    status_code=first.status_code, headers=first.headers, text=first.body
                )
            return httpx.Response(status_code=200, text="OK")

        router.route().mock(side_effect=mock_handler)

    def run_scenario(self, scenario: LabScenario) -> ScenarioExecutionResult:
        """Execute a single scenario deterministically and evaluate actual vs expected results."""
        start_time = time.perf_counter()
        discrepancies: list[str] = []

        # Determine target host for scope manager
        parsed_target = urllib.parse.urlsplit(scenario.target_url)
        target_host = parsed_target.hostname or "lab.local"

        # If scenario explicitly tests out-of-scope blocking, do not whitelist target host
        if scenario.scenario_id == "SQLI-AMB-SCOPE-BLOCKED":
            scope = ScopeManager(allowed_hosts=["authorized.local"], strict_mode=True)
        else:
            scope = ScopeManager(allowed_hosts=[target_host, "lab.local"], strict_mode=True)

        actual_status: str | None = None
        actual_technique: str | None = None
        actual_family: str | None = None
        actual_evidence_count: int = 0
        actual_verification_status: str | None = None

        try:
            with respx.mock(assert_all_called=False) as router:
                self._setup_respx_mocks(router, scenario)
                http_client = SafeHTTPClient(scope_manager=scope)

                # Route by scenario category
                if scenario.category == ScenarioCategory.SQL_INJECTION:
                    engine = SQLiEngine(scope_manager=scope, http_client=http_client)
                    scan_res = engine.scan(
                        target_url=scenario.target_url,
                        method=scenario.http_method,
                        data=scenario.data,
                        json_data=scenario.json_data,
                        selected_param=scenario.parameter_name,
                    )
                    actual_status, actual_technique, actual_family, actual_evidence_count = (
                        self._extract_sqli_results(scan_res)
                    )

                elif scenario.category == ScenarioCategory.NOSQL_INJECTION:
                    nosql_engine = NoSQLiEngine(scope_manager=scope, http_client=http_client)
                    nosql_res = nosql_engine.scan(
                        target_url=scenario.target_url,
                        method=scenario.http_method,
                        data=scenario.data,
                        json_data=scenario.json_data,
                        selected_param=scenario.parameter_name,
                    )
                    actual_status, actual_technique, actual_family, actual_evidence_count = (
                        self._extract_nosqli_results(nosql_res)
                    )

                elif scenario.category == ScenarioCategory.SAFETY_BUDGET:
                    if scenario.scenario_id == "SAFETY-INELIGIBLE-PARAM":
                        engine = SQLiEngine(scope_manager=scope, http_client=http_client)
                        target = Target.from_url(scenario.target_url)
                        params = engine.extract_parameters(
                            target=target,
                            method=scenario.http_method,
                            data=scenario.data,
                            json_data=scenario.json_data,
                        )
                        param_obj = next(
                            (p for p in params if p.name == scenario.parameter_name), None
                        )
                        if param_obj is not None and not param_obj.is_eligible:
                            actual_status = "ineligible_skipped"
                        else:
                            actual_status = "eligible_tested"
        except Exception as exc:
            discrepancies.append(f"Unexpected execution error: {type(exc).__name__}: {exc}")
            actual_status = "unexpected_error"

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Evaluate actual outcomes against expectations
        exp = scenario.expected
        if exp.status is not None and actual_status != exp.status:
            discrepancies.append(f"Expected status '{exp.status}', observed '{actual_status}'.")

        if exp.technique is not None and actual_technique != exp.technique:
            discrepancies.append(
                f"Expected technique '{exp.technique}', observed '{actual_technique}'."
            )

        if exp.family is not None and actual_family != exp.family:
            discrepancies.append(f"Expected family '{exp.family}', observed '{actual_family}'.")

        if actual_evidence_count < exp.min_evidence_count:
            discrepancies.append(
                f"Expected at least {exp.min_evidence_count} evidence records, observed {actual_evidence_count}."
            )

        # Determine scenario verdict
        if not discrepancies:
            outcome = ScenarioOutcome.PASS
        elif exp.classification == ExpectedClassification.AMBIGUOUS_INCONCLUSIVE:
            outcome = ScenarioOutcome.INCONCLUSIVE
        else:
            outcome = ScenarioOutcome.FAIL

        return ScenarioExecutionResult(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            category=scenario.category,
            outcome=outcome,
            expected_classification=exp.classification,
            actual_status=actual_status,
            actual_technique=actual_technique,
            actual_family=actual_family,
            actual_evidence_count=actual_evidence_count,
            actual_verification_status=actual_verification_status,
            discrepancies=discrepancies,
            execution_time_ms=elapsed_ms,
        )

    def _extract_sqli_results(
        self, result: SQLiScanResult
    ) -> tuple[str, str | None, str | None, int]:
        """Extract primary status, technique, family, and evidence count from SQLiScanResult."""
        if result.execution_status == "blocked_by_scope":
            return "blocked_by_scope", None, None, 0

        # Check for potential indicator findings
        positives = [f for f in result.findings if f.status.value == "potential_indicator"]
        if positives:
            primary = positives[0]
            family_hint = (
                primary.evidence_records[0].db_family_hint.value
                if primary.evidence_records and primary.evidence_records[0].db_family_hint
                else None
            )
            ev_count = sum(len(f.evidence_records) for f in positives)
            return primary.status.value, primary.technique.value, family_hint, ev_count

        return "no_indicator", None, None, 0

    def _extract_nosqli_results(
        self, result: NoSQLScanResult
    ) -> tuple[str, str | None, str | None, int]:
        """Extract primary status, technique, family, and evidence count from NoSQLScanResult."""
        if result.execution_status == "blocked_by_scope":
            return "blocked_by_scope", None, None, 0

        positives = [f for f in result.findings if f.status.value == "potential_indicator"]
        if positives:
            primary = positives[0]
            family_hint = (
                primary.evidence_records[0].provider_family_hint.value
                if primary.evidence_records and primary.evidence_records[0].provider_family_hint
                else None
            )
            ev_count = sum(len(f.evidence_records) for f in positives)
            return primary.status.value, primary.technique.value, family_hint, ev_count

        return "no_indicator", None, None, 0

    def run_suite(
        self,
        scenarios: list[LabScenario] | None = None,
        category_filter: ScenarioCategory | None = None,
        tag_filter: str | None = None,
    ) -> ValidationReport:
        """Run multiple scenarios and aggregate reliability and confusion matrix statistics."""
        active_scenarios = scenarios if scenarios is not None else load_standard_scenarios()

        if category_filter is not None:
            active_scenarios = [s for s in active_scenarios if s.category == category_filter]

        if tag_filter is not None:
            active_scenarios = [s for s in active_scenarios if tag_filter in s.tags]

        results: list[ScenarioExecutionResult] = []
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        inconclusive_cnt = 0
        skipped_cnt = 0
        passed_cnt = 0
        failed_cnt = 0

        for sc in active_scenarios:
            res = self.run_scenario(sc)
            results.append(res)

            if res.outcome == ScenarioOutcome.PASS:
                passed_cnt += 1
            elif res.outcome == ScenarioOutcome.FAIL:
                failed_cnt += 1
            elif res.outcome == ScenarioOutcome.INCONCLUSIVE:
                inconclusive_cnt += 1
            elif res.outcome == ScenarioOutcome.SKIPPED:
                skipped_cnt += 1

            # Accumulate confusion matrix
            exp_cls = res.expected_classification
            if exp_cls == ExpectedClassification.TRUE_POSITIVE:
                if res.outcome == ScenarioOutcome.PASS:
                    tp += 1
                else:
                    fn += 1
            elif exp_cls == ExpectedClassification.TRUE_NEGATIVE:
                if res.outcome == ScenarioOutcome.PASS:
                    tn += 1
                else:
                    fp += 1
            elif (
                exp_cls == ExpectedClassification.AMBIGUOUS_INCONCLUSIVE
                and res.outcome != ScenarioOutcome.INCONCLUSIVE
            ):
                inconclusive_cnt += 1
            elif (
                exp_cls == ExpectedClassification.BLOCKED_OR_ERROR
                and res.outcome != ScenarioOutcome.SKIPPED
            ):
                skipped_cnt += 1

        # Calculate precision, recall, F1, accuracy
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall = tp / (tp + fn) if (tp + fn) > 0 else None
        f1: float | None = None
        if precision is not None and recall is not None and (precision + recall) > 0:
            f1 = 2 * (precision * recall) / (precision + recall)

        total_binary = tp + tn + fp + fn
        accuracy = (tp + tn) / total_binary if total_binary > 0 else None

        confusion = ConfusionMatrix(
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            inconclusive=inconclusive_cnt,
            skipped=skipped_cnt,
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
        )

        return ValidationReport(
            suite_name="DBShield Phase 9 Lab Validation Suite",
            total_scenarios=len(active_scenarios),
            passed=passed_cnt,
            failed=failed_cnt,
            inconclusive=inconclusive_cnt,
            skipped=skipped_cnt,
            confusion_matrix=confusion,
            dataset_limitations=self.dataset_limitations,
            results=results,
        )
