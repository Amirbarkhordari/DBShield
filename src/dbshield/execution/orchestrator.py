"""Centralized test execution orchestrator for DBShield (Phase 6).

Coordinates the lifecycle of security test cases across candidate parameters,
payload selection, request transformation, budget tracking, HTTP execution,
and engine detector evaluation.
"""

import logging
import time
import urllib.parse
from typing import Any, ClassVar

from dbshield.auth.manager import SessionManager
from dbshield.exceptions import ScopeViolationError
from dbshield.execution.adapters import EngineAdapter
from dbshield.execution.models import (
    ExecutionRecord,
    ExecutionRunResult,
    ExecutionStatus,
    ExecutionSummary,
)
from dbshield.execution.policy import ExecutionBudgetTracker, ExecutionPolicy
from dbshield.execution.transformer import PayloadTransformer
from dbshield.http.client import SafeHTTPClient
from dbshield.models.http import HTTPMethod, HTTPResponse
from dbshield.models.target import Target
from dbshield.payloads.catalog import PayloadCatalog
from dbshield.payloads.models import PayloadCategory, SecurityPayload
from dbshield.scope.manager import ScopeManager
from dbshield.sqli.models import ParameterLocation

logger = logging.getLogger("dbshield.execution.orchestrator")


class TestExecutionOrchestrator:
    """Orchestrates controlled execution of security test payloads."""

    __test__: ClassVar[bool] = False

    def __init__(
        self,
        scope_manager: ScopeManager,
        http_client: SafeHTTPClient | None = None,
        session_manager: SessionManager | None = None,
        policy: ExecutionPolicy | None = None,
        catalog: PayloadCatalog | None = None,
    ) -> None:
        """Initialize orchestrator with scope, client, policy, and catalog."""
        self.scope_manager = scope_manager
        self.session_manager = session_manager
        self.http_client = (
            http_client
            if http_client is not None
            else SafeHTTPClient(
                scope_manager=self.scope_manager,
                session_manager=self.session_manager,
            )
        )
        self.policy = policy or ExecutionPolicy()
        self.catalog = catalog or PayloadCatalog()

    def run(
        self,
        target_url: str | Target,
        adapter: EngineAdapter,
        method: str | HTTPMethod = HTTPMethod.GET,
        selected_param: str | None = None,
        data: Any | None = None,
        json_data: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> ExecutionRunResult:
        """Execute eligible test payloads against target endpoint.

        Args:
            target_url: Target URL string or Target instance.
            adapter: EngineAdapter connecting to engine detectors (SQLi or NoSQLi).
            method: HTTP method.
            selected_param: Optional specific parameter name to test.
            data: Raw or form body data.
            json_data: JSON payload.
            headers: Custom request headers.

        Returns:
            Structured ExecutionRunResult with per-test records, summary, and findings.
        """
        start_time = time.monotonic()
        req_method = method.value if isinstance(method, HTTPMethod) else str(method).upper()

        # Step 1: Pre-flight Scope Check
        try:
            target = self.scope_manager.assert_in_scope(target_url)
        except ScopeViolationError as exc:
            logger.warning("Target %s blocked by ScopeManager: %s", target_url, exc.message)
            record = ExecutionRecord(
                test_case_id="SCOPE_CHECK",
                payload_id="NONE",
                parameter_name=selected_param or "all",
                parameter_location=ParameterLocation.QUERY,
                status=ExecutionStatus.SKIPPED,
                error_or_skip_reason=f"Target host is out of authorized scope: {exc.message}",
            )
            summary = ExecutionSummary(
                total_test_cases=1,
                skipped_test_cases=1,
                duration_seconds=round(time.monotonic() - start_time, 3),
            )
            return ExecutionRunResult(
                target_url=str(target_url),
                engine_name=adapter.engine_name,
                execution_status="blocked_by_scope",
                summary=summary,
                records=[record],
                findings=[],
            )

        budget_tracker = ExecutionBudgetTracker(policy=self.policy)
        records: list[ExecutionRecord] = []
        all_findings: list[Any] = []

        # Step 2: Extract candidate parameters
        candidate_params = self._extract_parameters(
            target=target,
            _method=req_method,
            data=data,
            json_data=json_data,
            selected_param=selected_param,
        )

        if not candidate_params:
            summary = ExecutionSummary(
                total_test_cases=0,
                duration_seconds=round(time.monotonic() - start_time, 3),
            )
            return ExecutionRunResult(
                target_url=target.full_url,
                engine_name=adapter.engine_name,
                execution_status="completed",
                summary=summary,
                records=[],
                findings=[],
            )

        # Step 3: Establish baseline response
        try:
            can_baseline, reason = budget_tracker.can_dispatch_test("baseline", 1)
            if not can_baseline:
                raise RuntimeError(reason)

            baseline_resp = self.http_client.request(
                method=req_method,
                url=target.full_url,
                data=data,
                json=json_data,
                headers=headers,
            )
            budget_tracker.record_dispatch("baseline", 1)
            is_baseline_stable = not baseline_resp.is_server_error
        except Exception as exc:
            logger.error("Failed to establish baseline response for %s: %s", target.full_url, exc)
            record = ExecutionRecord(
                test_case_id="BASELINE_PROBE",
                payload_id="BASELINE",
                parameter_name="target",
                parameter_location=ParameterLocation.QUERY,
                status=ExecutionStatus.FAILED,
                error_or_skip_reason=f"Failed to establish baseline response: {exc}",
            )
            summary = ExecutionSummary(
                total_test_cases=1,
                failed_test_cases=1,
                total_requests=budget_tracker.total_requests,
                duration_seconds=round(time.monotonic() - start_time, 3),
            )
            return ExecutionRunResult(
                target_url=target.full_url,
                engine_name=adapter.engine_name,
                execution_status="failed",
                summary=summary,
                records=[record],
                findings=[],
            )

        # Step 4: Execute tests across parameters and payloads
        for param_name, param_location, key_path in candidate_params:
            if budget_tracker.is_cancelled:
                break

            # Check parameter eligibility
            is_eligible, skip_reason = self.policy.evaluate_parameter_eligibility(param_name)
            if not is_eligible:
                records.append(
                    ExecutionRecord(
                        test_case_id=f"ELIGIBILITY_{param_name}",
                        payload_id="NONE",
                        parameter_name=param_name,
                        parameter_location=param_location,
                        status=ExecutionStatus.SKIPPED,
                        error_or_skip_reason=skip_reason,
                    )
                )
                continue

            # Select compatible payloads for this engine and parameter location
            payloads = self.catalog.filter_payloads(
                engine=adapter.engine_name,
                location=param_location,
            )

            # Separate unpaired error payloads from paired differential payloads
            unpaired_payloads = [p for p in payloads if not p.is_paired]
            paired_true = [p for p in payloads if p.is_paired and p.pair_role == "true"]

            # Run unpaired probes
            for payload in unpaired_payloads:
                can_dispatch, budget_reason = budget_tracker.can_dispatch_test(param_name, 1)
                if not can_dispatch:
                    records.append(
                        ExecutionRecord(
                            test_case_id=f"TEST_{payload.payload_id}_{param_name}",
                            payload_id=payload.payload_id,
                            parameter_name=param_name,
                            parameter_location=param_location,
                            status=ExecutionStatus.CANCELLED
                            if budget_tracker.is_cancelled
                            else ExecutionStatus.SKIPPED,
                            error_or_skip_reason=budget_reason,
                        )
                    )
                    continue

                rec, finding = self._execute_single_test(
                    target=target,
                    param_name=param_name,
                    param_location=param_location,
                    key_path=key_path,
                    payload=payload,
                    method=req_method,
                    data=data,
                    json_data=json_data,
                    headers=headers,
                    baseline_resp=baseline_resp,
                    adapter=adapter,
                    budget_tracker=budget_tracker,
                )
                records.append(rec)
                if finding:
                    all_findings.append(finding)
                    if self.policy.stop_on_first_indicator and getattr(finding, "status", None) in (
                        "potential_indicator",
                        "confirmed",
                    ):
                        budget_tracker.cancel("Terminating early on first potential indicator.")
                        break

            # Run paired differential probes if enabled
            if self.policy.enable_differential:
                for true_p in paired_true:
                    false_p = (
                        self.catalog.get_payload(true_p.paired_with_id)
                        if true_p.paired_with_id
                        else None
                    )
                    if not false_p:
                        continue

                    can_dispatch, budget_reason = budget_tracker.can_dispatch_test(param_name, 2)
                    if not can_dispatch:
                        records.append(
                            ExecutionRecord(
                                test_case_id=f"DIFF_PAIR_{param_name}",
                                payload_id=f"{true_p.payload_id}/{false_p.payload_id}",
                                parameter_name=param_name,
                                parameter_location=param_location,
                                status=ExecutionStatus.SKIPPED,
                                error_or_skip_reason=budget_reason,
                            )
                        )
                        continue

                    rec, finding = self._execute_paired_test(
                        target=target,
                        param_name=param_name,
                        param_location=param_location,
                        key_path=key_path,
                        true_payload=true_p,
                        false_payload=false_p,
                        method=req_method,
                        data=data,
                        json_data=json_data,
                        headers=headers,
                        baseline_resp=baseline_resp,
                        is_baseline_stable=is_baseline_stable,
                        adapter=adapter,
                        budget_tracker=budget_tracker,
                    )
                    records.append(rec)
                    if finding:
                        all_findings.append(finding)
                        if self.policy.stop_on_first_indicator and getattr(
                            finding, "status", None
                        ) in ("potential_indicator", "confirmed"):
                            budget_tracker.cancel("Terminating early on first potential indicator.")
                            break

        # Step 5: Construct summary
        total_tests = len(records)
        executed_tests = sum(1 for r in records if r.status == ExecutionStatus.EXECUTED)
        skipped_tests = sum(1 for r in records if r.status == ExecutionStatus.SKIPPED)
        failed_tests = sum(1 for r in records if r.status == ExecutionStatus.FAILED)
        cancelled_tests = sum(1 for r in records if r.status == ExecutionStatus.CANCELLED)

        summary = ExecutionSummary(
            total_test_cases=total_tests,
            executed_test_cases=executed_tests,
            skipped_test_cases=skipped_tests,
            failed_test_cases=failed_tests,
            cancelled_test_cases=cancelled_tests,
            total_requests=budget_tracker.total_requests,
            duration_seconds=round(time.monotonic() - start_time, 3),
        )

        return ExecutionRunResult(
            target_url=target.full_url,
            engine_name=adapter.engine_name,
            execution_status="cancelled" if budget_tracker.is_cancelled else "completed",
            summary=summary,
            records=records,
            findings=all_findings,
        )

    def _execute_single_test(
        self,
        target: Target,
        param_name: str,
        param_location: ParameterLocation,
        key_path: list[str] | None,
        payload: SecurityPayload,
        method: str,
        data: Any | None,
        json_data: Any | None,
        headers: dict[str, str] | None,
        baseline_resp: HTTPResponse,
        adapter: EngineAdapter,
        budget_tracker: ExecutionBudgetTracker,
    ) -> tuple[ExecutionRecord, Any | None]:
        """Execute a single test payload mutation and evaluate findings."""
        t0 = time.monotonic()
        test_id = f"TEST_{payload.payload_id}_{param_name}"

        try:
            req_params, req_data, req_json = PayloadTransformer.transform(
                target=target,
                param_location=param_location,
                param_name=param_name,
                payload_value=payload.payload_value,
                key_path=key_path,
                data=data,
                json_data=json_data,
            )

            resp = self.http_client.request(
                method=method,
                url=target.full_url
                if param_location != ParameterLocation.QUERY
                else target.origin + target.path,
                params=req_params,
                data=req_data,
                json=req_json,
                headers=headers,
            )
            budget_tracker.record_dispatch(param_name, 1)

            finding = adapter.evaluate_single_probe(
                target_url=target.full_url,
                param_name=param_name,
                param_location=param_location,
                payload=payload,
                test_resp=resp,
                baseline_resp=baseline_resp,
            )

            rec = ExecutionRecord(
                test_case_id=test_id,
                payload_id=payload.payload_id,
                parameter_name=param_name,
                parameter_location=param_location,
                status=ExecutionStatus.EXECUTED,
                request_count=1,
                elapsed_seconds=round(time.monotonic() - t0, 3),
                status_code=resp.status_code,
                findings=[finding] if finding else [],
            )
            return rec, finding

        except Exception as exc:
            logger.warning("Test case %s failed with exception: %s", test_id, exc)
            rec = ExecutionRecord(
                test_case_id=test_id,
                payload_id=payload.payload_id,
                parameter_name=param_name,
                parameter_location=param_location,
                status=ExecutionStatus.FAILED,
                request_count=0,
                elapsed_seconds=round(time.monotonic() - t0, 3),
                error_or_skip_reason=str(exc),
            )
            return rec, None

    def _execute_paired_test(
        self,
        target: Target,
        param_name: str,
        param_location: ParameterLocation,
        key_path: list[str] | None,
        true_payload: SecurityPayload,
        false_payload: SecurityPayload,
        method: str,
        data: Any | None,
        json_data: Any | None,
        headers: dict[str, str] | None,
        baseline_resp: HTTPResponse,
        is_baseline_stable: bool,
        adapter: EngineAdapter,
        budget_tracker: ExecutionBudgetTracker,
    ) -> tuple[ExecutionRecord, Any | None]:
        """Execute paired differential test payloads (True vs False) and evaluate findings."""
        t0 = time.monotonic()
        test_id = f"DIFF_{true_payload.payload_id}_{false_payload.payload_id}_{param_name}"

        try:
            t_params, t_data, t_json = PayloadTransformer.transform(
                target=target,
                param_location=param_location,
                param_name=param_name,
                payload_value=true_payload.payload_value,
                key_path=key_path,
                data=data,
                json_data=json_data,
            )
            f_params, f_data, f_json = PayloadTransformer.transform(
                target=target,
                param_location=param_location,
                param_name=param_name,
                payload_value=false_payload.payload_value,
                key_path=key_path,
                data=data,
                json_data=json_data,
            )

            t_resp = self.http_client.request(
                method=method,
                url=target.full_url
                if param_location != ParameterLocation.QUERY
                else target.origin + target.path,
                params=t_params,
                data=t_data,
                json=t_json,
                headers=headers,
            )
            budget_tracker.record_dispatch(param_name, 1)

            f_resp = self.http_client.request(
                method=method,
                url=target.full_url
                if param_location != ParameterLocation.QUERY
                else target.origin + target.path,
                params=f_params,
                data=f_data,
                json=f_json,
                headers=headers,
            )
            budget_tracker.record_dispatch(param_name, 1)

            finding = adapter.evaluate_paired_probes(
                target_url=target.full_url,
                param_name=param_name,
                param_location=param_location,
                true_payload=true_payload,
                false_payload=false_payload,
                true_resp=t_resp,
                false_resp=f_resp,
                baseline_resp=baseline_resp,
                is_baseline_stable=is_baseline_stable,
            )

            rec = ExecutionRecord(
                test_case_id=test_id,
                payload_id=f"{true_payload.payload_id}/{false_payload.payload_id}",
                parameter_name=param_name,
                parameter_location=param_location,
                status=ExecutionStatus.EXECUTED,
                request_count=2,
                elapsed_seconds=round(time.monotonic() - t0, 3),
                status_code=t_resp.status_code,
                findings=[finding] if finding else [],
            )
            return rec, finding

        except Exception as exc:
            logger.warning("Paired test %s failed: %s", test_id, exc)
            rec = ExecutionRecord(
                test_case_id=test_id,
                payload_id=f"{true_payload.payload_id}/{false_payload.payload_id}",
                parameter_name=param_name,
                parameter_location=param_location,
                status=ExecutionStatus.FAILED,
                request_count=0,
                elapsed_seconds=round(time.monotonic() - t0, 3),
                error_or_skip_reason=str(exc),
            )
            return rec, None

    def _extract_parameters(
        self,
        target: Target,
        _method: str,
        data: Any | None,
        json_data: Any | None,
        selected_param: str | None,
    ) -> list[tuple[str, ParameterLocation, list[str] | None]]:
        """Extract candidate parameter names, locations, and optional nested key paths."""
        params: list[tuple[str, ParameterLocation, list[str] | None]] = []

        if target.query:
            parsed = urllib.parse.parse_qs(target.query, keep_blank_values=True)
            for k in parsed:
                params.append((k, ParameterLocation.QUERY, [k]))

        if data and isinstance(data, str) and "=" in data:
            try:
                parsed = urllib.parse.parse_qs(data, keep_blank_values=True)
                for k in parsed:
                    params.append((k, ParameterLocation.BODY_URLENCODED, [k]))
            except Exception:
                pass

        if json_data:
            dict_data = json_data
            if isinstance(json_data, str):
                import json

                try:
                    dict_data = json.loads(json_data)
                except Exception:
                    dict_data = None
            if isinstance(dict_data, dict):
                params.extend(self._extract_json_keypaths(dict_data))

        if selected_param:
            selected_lower = selected_param.lower()
            filtered = [
                p
                for p in params
                if p[0].lower() == selected_lower
                or (p[2] is not None and p[2][-1].lower() == selected_lower)
            ]
            if not filtered:
                params = [(selected_param, ParameterLocation.QUERY, [selected_param])]
            else:
                params = filtered

        return params

    def _extract_json_keypaths(
        self, data: Any, prefix: list[str] | None = None
    ) -> list[tuple[str, ParameterLocation, list[str]]]:
        """Recursively discover dot-delimited key paths in JSON structures."""
        prefix = prefix or []
        results: list[tuple[str, ParameterLocation, list[str]]] = []

        if isinstance(data, dict):
            for k, v in data.items():
                curr_path = prefix + [str(k)]
                if isinstance(v, dict):
                    results.extend(self._extract_json_keypaths(v, curr_path))
                elif isinstance(v, list):
                    for idx, elem in enumerate(v):
                        if isinstance(elem, (str, int, float, bool)):
                            results.append(
                                (
                                    ".".join(curr_path + [str(idx)]),
                                    ParameterLocation.BODY_JSON,
                                    curr_path + [str(idx)],
                                )
                            )
                        elif isinstance(elem, dict):
                            results.extend(
                                self._extract_json_keypaths(elem, curr_path + [str(idx)])
                            )
                else:
                    results.append((".".join(curr_path), ParameterLocation.BODY_JSON, curr_path))

        return results

    execute_suite = run

    @classmethod
    def execute_offline_fixture(
        cls,
        target_url: str,
        param_name: str,
        param_location: ParameterLocation,
        payload_id: str,
        baseline_response: HTTPResponse,
        test_response: HTTPResponse,
        adapter: EngineAdapter,
        true_response: HTTPResponse | None = None,
        false_response: HTTPResponse | None = None,
    ) -> ExecutionRunResult:
        """Perform offline assessment of response fixtures through the execution layer."""
        start_time = time.monotonic()
        records: list[ExecutionRecord] = []
        findings: list[Any] = []

        catalog = PayloadCatalog()
        payload = catalog.get_payload(payload_id) or SecurityPayload(
            payload_id=payload_id,
            name=f"Fixture Payload ({payload_id})",
            description="Offline test fixture payload",
            category=PayloadCategory.SQLI
            if adapter.engine_name == "sqli"
            else PayloadCategory.NOSQLI,
            technique="error_based",
            applicable_locations=[param_location],
            payload_value="fixture",
        )

        # Single error probe evaluation
        err_finding = adapter.evaluate_single_probe(
            target_url=target_url,
            param_name=param_name,
            param_location=param_location,
            payload=payload,
            test_resp=test_response,
            baseline_resp=baseline_response,
        )
        if err_finding:
            findings.append(err_finding)

        records.append(
            ExecutionRecord(
                test_case_id=f"FIXTURE_{payload_id}_{param_name}",
                payload_id=payload_id,
                parameter_name=param_name,
                parameter_location=param_location,
                status=ExecutionStatus.EXECUTED,
                request_count=0,
                elapsed_seconds=0.0,
                status_code=test_response.status_code,
                findings=[err_finding] if err_finding else [],
            )
        )

        # Paired differential evaluation if true/false fixtures provided
        if true_response and false_response:
            is_stable = not baseline_response.is_server_error
            diff_finding = adapter.evaluate_paired_probes(
                target_url=target_url,
                param_name=param_name,
                param_location=param_location,
                true_payload=payload,
                false_payload=payload,
                true_resp=true_response,
                false_resp=false_response,
                baseline_resp=baseline_response,
                is_baseline_stable=is_stable,
            )
            if diff_finding:
                findings.append(diff_finding)

            records.append(
                ExecutionRecord(
                    test_case_id=f"FIXTURE_DIFF_{param_name}",
                    payload_id=f"{payload_id}_PAIR",
                    parameter_name=param_name,
                    parameter_location=param_location,
                    status=ExecutionStatus.EXECUTED,
                    request_count=0,
                    elapsed_seconds=0.0,
                    status_code=true_response.status_code,
                    findings=[diff_finding] if diff_finding else [],
                )
            )

        summary = ExecutionSummary(
            total_test_cases=len(records),
            executed_test_cases=len(records),
            total_requests=0,
            duration_seconds=round(time.monotonic() - start_time, 3),
        )

        return ExecutionRunResult(
            target_url=target_url,
            engine_name=adapter.engine_name,
            execution_status="completed",
            summary=summary,
            records=records,
            findings=findings,
        )
