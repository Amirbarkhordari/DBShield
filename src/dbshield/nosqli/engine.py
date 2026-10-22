"""NoSQL Injection Testing and Detection Engine for DBShield Phase 5.

Coordinates parameter extraction (including nested JSON structures), baseline characterization,
error-based detection, and boolean/operator differential response analysis. Strictly enforces
target scope, request budgets, credential safety, and explainable finding classifications.
"""

import copy
import json
import logging
import time
import urllib.parse
from typing import Any

from dbshield.auth.manager import SessionManager
from dbshield.exceptions import (
    ScopeViolationError,
)
from dbshield.http.client import SafeHTTPClient
from dbshield.models.http import HTTPMethod, HTTPResponse
from dbshield.models.target import Target
from dbshield.nosqli.baseline import NoSQLBaselineCharacterizer
from dbshield.nosqli.detectors.differential_detector import NoSQLDifferentialDetector
from dbshield.nosqli.detectors.error_detector import NoSQLErrorDetector
from dbshield.nosqli.models import (
    NoSQLCandidateParameter,
    NoSQLDetectionStatus,
    NoSQLFinding,
    NoSQLProviderFamily,
    NoSQLScanResult,
    NoSQLScanSummary,
    NoSQLTestTechnique,
    ParameterLocation,
)
from dbshield.scope.manager import ScopeManager

logger = logging.getLogger("dbshield.nosqli.engine")

# Sensitive parameter names that must NEVER be tested actively
INELIGIBLE_PARAM_PATTERNS = {
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

DEFAULT_LIMITATIONS = [
    "Tests are strictly non-destructive and defensive; exploitation, authentication bypass, and data extraction are prohibited.",
    "A potential indicator is unconfirmed and requires independent verification (Phase 7).",
    "A 'no_indicator' result indicates that tested payloads did not trigger observable signals; it does NOT prove the endpoint is immune to NoSQL injection.",
    "Resource-intensive, long-delay time-based probes were omitted to prevent server degradation or denial of service.",
    "Nested JSON structures are traversed up to candidate key-paths; deeply recursive documents or unsupported schemas are handled gracefully.",
]


class NoSQLiEngine:
    """Orchestrates controlled NoSQL injection testing workflow."""

    def __init__(
        self,
        scope_manager: ScopeManager,
        http_client: SafeHTTPClient | None = None,
        session_manager: SessionManager | None = None,
        max_requests_per_parameter: int = 8,
        total_request_budget: int = 50,
        enable_differential: bool = True,
    ) -> None:
        """Initialize NoSQLiEngine.

        Args:
            scope_manager: Authoritative ScopeManager for outbound authorization.
            http_client: SafeHTTPClient instance (created automatically if omitted).
            session_manager: Optional SessionManager for authenticated requests.
            max_requests_per_parameter: Request budget ceiling per parameter.
            total_request_budget: Overall scan request budget ceiling.
            enable_differential: Whether to perform boolean/operator differential testing.
        """
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
        self.max_requests_per_parameter = max(3, min(max_requests_per_parameter, 20))
        self.total_request_budget = max(10, min(total_request_budget, 200))
        self.enable_differential = enable_differential

    def _extract_json_parameters(
        self,
        data: Any,
        prefix: list[str] | None = None,
    ) -> list[tuple[list[str], str, Any]]:
        """Recursively traverse a JSON object and discover candidate key paths.

        Returns:
            List of tuples: (key_path, dot_name, original_value).
        """
        prefix = prefix or []
        results: list[tuple[list[str], str, Any]] = []

        if isinstance(data, dict):
            for k, v in data.items():
                curr_path = prefix + [str(k)]
                if isinstance(v, dict):
                    results.extend(self._extract_json_parameters(v, curr_path))
                elif isinstance(v, list):
                    for idx, elem in enumerate(v):
                        if isinstance(elem, (str, int, float, bool)):
                            results.append(
                                (curr_path + [str(idx)], ".".join(curr_path + [str(idx)]), elem)
                            )
                        elif isinstance(elem, dict):
                            results.extend(
                                self._extract_json_parameters(elem, curr_path + [str(idx)])
                            )
                else:
                    results.append((curr_path, ".".join(curr_path), v))

        return results

    def extract_parameters(
        self,
        target: Target,
        method: str = "GET",
        data: Any | None = None,
        json_data: Any | None = None,
        selected_param: str | None = None,
    ) -> list[NoSQLCandidateParameter]:
        """Extract and classify candidate parameters from URL, form body, or JSON data.

        Supports nested JSON key paths and URL query/form structures.
        """
        params: list[NoSQLCandidateParameter] = []

        # 1. URL Query Parameters
        if target.query:
            parsed_query = urllib.parse.parse_qs(target.query, keep_blank_values=True)
            for name, values in parsed_query.items():
                orig_val = values[0] if values else ""
                is_eligible, skip_reason = self._evaluate_eligibility(name)
                params.append(
                    NoSQLCandidateParameter(
                        name=name,
                        location=ParameterLocation.QUERY,
                        key_path=[name],
                        original_value=orig_val,
                        endpoint=target.origin + target.path,
                        method="GET",
                        source="query_string",
                        is_eligible=is_eligible,
                        skip_reason=skip_reason,
                    )
                )

        # 2. Form Body Parameters
        if data and isinstance(data, str) and "=" in data:
            try:
                parsed_form = urllib.parse.parse_qs(data, keep_blank_values=True)
                for name, values in parsed_form.items():
                    orig_val = values[0] if values else ""
                    is_eligible, skip_reason = self._evaluate_eligibility(name)
                    params.append(
                        NoSQLCandidateParameter(
                            name=name,
                            location=ParameterLocation.BODY_URLENCODED,
                            key_path=[name],
                            original_value=orig_val,
                            endpoint=target.full_url,
                            method=method.upper(),
                            content_type="application/x-www-form-urlencoded",
                            source="form_body",
                            is_eligible=is_eligible,
                            skip_reason=skip_reason,
                        )
                    )
            except Exception as exc:
                logger.debug("Failed to parse form data as query string: %s", exc)

        # 3. JSON Parameters (top-level and nested)
        if json_data is not None:
            dict_data = json_data
            if isinstance(json_data, str):
                try:
                    dict_data = json.loads(json_data)
                except Exception:
                    dict_data = None
            if isinstance(dict_data, dict):
                extracted = self._extract_json_parameters(dict_data)
                for key_path, dot_name, orig_val in extracted:
                    is_eligible, skip_reason = self._evaluate_eligibility(dot_name)
                    params.append(
                        NoSQLCandidateParameter(
                            name=dot_name,
                            location=ParameterLocation.BODY_JSON,
                            key_path=key_path,
                            original_value=orig_val,
                            endpoint=target.full_url,
                            method=method.upper(),
                            content_type="application/json",
                            source="json_body",
                            is_eligible=is_eligible,
                            skip_reason=skip_reason,
                        )
                    )

        # Filter by selected parameter if specified
        if selected_param:
            selected_lower = selected_param.lower()
            filtered = [
                p
                for p in params
                if p.name.lower() == selected_lower
                or (p.key_path and p.key_path[-1].lower() == selected_lower)
            ]
            if not filtered:
                # Add as explicitly declared query param if not found
                params = [
                    NoSQLCandidateParameter(
                        name=selected_param,
                        location=ParameterLocation.QUERY,
                        key_path=[selected_param],
                        original_value="",
                        endpoint=target.origin + target.path,
                        method=method.upper(),
                        source="explicit_parameter",
                        is_eligible=True,
                    )
                ]
            else:
                params = filtered

        return params

    def _evaluate_eligibility(self, param_name: str) -> tuple[bool, str | None]:
        """Determine whether parameter is safe for testing."""
        # For nested names (e.g. filter.password), check the terminal field and dot-tokens
        tokens = param_name.lower().replace("-", "_").split(".")
        for tok in tokens:
            for forbidden in INELIGIBLE_PARAM_PATTERNS:
                if forbidden == tok or tok.endswith(f"_{forbidden}"):
                    return (
                        False,
                        f"Parameter '{param_name}' matches sensitive credential/security control pattern ({forbidden}).",
                    )
        return True, None

    def scan(
        self,
        target_url: str | Target,
        method: str | HTTPMethod = HTTPMethod.GET,
        selected_param: str | None = None,
        data: Any | None = None,
        json_data: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> NoSQLScanResult:
        """Execute NoSQL injection detection testing over target URL and candidate parameters.

        Args:
            target_url: Target URL string or Target instance.
            method: HTTP method.
            selected_param: Optional parameter name to limit testing to.
            data: Raw or form body data.
            json_data: JSON payload.
            headers: Custom request headers.

        Returns:
            Structured NoSQLScanResult with findings, parameter inventory, and summary.
        """
        start_time = time.monotonic()
        req_method = method.value if isinstance(method, HTTPMethod) else str(method).upper()

        # Step 1: Pre-flight Scope Check
        try:
            target = self.scope_manager.assert_in_scope(target_url)
        except ScopeViolationError as exc:
            logger.warning("Target %s blocked by ScopeManager: %s", target_url, exc.message)
            dummy_param = NoSQLCandidateParameter(
                name=selected_param or "all",
                location=ParameterLocation.QUERY,
                endpoint=str(target_url),
                method=req_method,
                is_eligible=False,
                skip_reason=exc.message,
            )
            blocked_finding = NoSQLFinding(
                test_id="SCOPE_CHECK",
                technique=NoSQLTestTechnique.ERROR_BASED,
                target_url=str(target_url),
                http_method=req_method,
                parameter=dummy_param,
                status=NoSQLDetectionStatus.BLOCKED_BY_SCOPE,
                error_or_skip_reason=f"Target host is out of authorized scope: {exc.message}",
                limitations=DEFAULT_LIMITATIONS,
            )
            summary = NoSQLScanSummary(
                total_parameters=1,
                blocked_parameters=1,
                duration_seconds=round(time.monotonic() - start_time, 3),
            )
            return NoSQLScanResult(
                target_url=str(target_url),
                execution_status="blocked_by_scope",
                summary=summary,
                findings=[blocked_finding],
                parameters=[dummy_param],
                limitations=DEFAULT_LIMITATIONS,
            )

        # Step 2: Extract candidate parameters
        candidate_params = self.extract_parameters(
            target=target,
            method=req_method,
            data=data,
            json_data=json_data,
            selected_param=selected_param,
        )

        findings: list[NoSQLFinding] = []
        total_requests = 0

        if not candidate_params:
            logger.info("No parameters found to test on target: %s", target.full_url)
            summary = NoSQLScanSummary(
                total_parameters=0,
                duration_seconds=round(time.monotonic() - start_time, 3),
            )
            return NoSQLScanResult(
                target_url=target.full_url,
                execution_status="completed",
                summary=summary,
                findings=[],
                parameters=[],
                limitations=DEFAULT_LIMITATIONS,
            )

        characterizer = NoSQLBaselineCharacterizer(
            http_client=self.http_client,
            stability_samples=2,
        )

        # Step 3: Test each candidate parameter
        for param in candidate_params:
            # Check global request budget
            if total_requests >= self.total_request_budget:
                logger.warning(
                    "Scan request budget (%d) reached; skipping remaining parameters.",
                    self.total_request_budget,
                )
                findings.append(
                    NoSQLFinding(
                        test_id="BUDGET_LIMIT",
                        technique=NoSQLTestTechnique.ERROR_BASED,
                        target_url=target.full_url,
                        http_method=req_method,
                        parameter=param,
                        status=NoSQLDetectionStatus.SKIPPED,
                        error_or_skip_reason=f"Scan request budget limit of {self.total_request_budget} requests reached.",
                        limitations=DEFAULT_LIMITATIONS,
                    )
                )
                continue

            # Check eligibility
            if not param.is_eligible:
                findings.append(
                    NoSQLFinding(
                        test_id="ELIGIBILITY_CHECK",
                        technique=NoSQLTestTechnique.ERROR_BASED,
                        target_url=target.full_url,
                        http_method=req_method,
                        parameter=param,
                        status=NoSQLDetectionStatus.SKIPPED,
                        error_or_skip_reason=param.skip_reason
                        or "Parameter is not eligible for active testing.",
                        limitations=DEFAULT_LIMITATIONS,
                    )
                )
                continue

            # Test this parameter
            param_findings, param_req_count = self._test_parameter(
                target=target,
                param=param,
                characterizer=characterizer,
                data=data,
                json_data=json_data,
                headers=headers,
                remaining_budget=self.total_request_budget - total_requests,
            )
            total_requests += param_req_count
            findings.extend(param_findings)

        # Step 4: Aggregate summary per candidate parameter
        param_findings_map: dict[str, list[NoSQLFinding]] = {}
        for f in findings:
            param_findings_map.setdefault(f.parameter.name, []).append(f)

        potential_cnt = 0
        inconclusive_cnt = 0
        error_cnt = 0
        clean_cnt = 0
        skipped_cnt = 0
        blocked_cnt = 0
        tested_cnt = 0

        for p in candidate_params:
            p_findings = param_findings_map.get(p.name, [])
            if not p_findings:
                continue
            statuses = {f.status for f in p_findings}
            if NoSQLDetectionStatus.POTENTIAL_INDICATOR in statuses:
                potential_cnt += 1
                tested_cnt += 1
            elif NoSQLDetectionStatus.INCONCLUSIVE in statuses:
                inconclusive_cnt += 1
                tested_cnt += 1
            elif NoSQLDetectionStatus.ERROR in statuses:
                error_cnt += 1
                tested_cnt += 1
            elif statuses == {NoSQLDetectionStatus.NO_INDICATOR}:
                clean_cnt += 1
                tested_cnt += 1
            elif NoSQLDetectionStatus.SKIPPED in statuses:
                skipped_cnt += 1
            elif NoSQLDetectionStatus.BLOCKED_BY_SCOPE in statuses:
                blocked_cnt += 1

        summary = NoSQLScanSummary(
            total_parameters=len(candidate_params),
            tested_parameters=tested_cnt,
            skipped_parameters=skipped_cnt,
            potential_indicators=potential_cnt,
            clean_parameters=clean_cnt,
            inconclusive_parameters=inconclusive_cnt,
            blocked_parameters=blocked_cnt,
            error_parameters=error_cnt,
            total_requests=total_requests,
            duration_seconds=round(time.monotonic() - start_time, 3),
        )

        return NoSQLScanResult(
            target_url=target.full_url,
            execution_status="completed",
            summary=summary,
            findings=findings,
            parameters=candidate_params,
            limitations=DEFAULT_LIMITATIONS,
        )

    def _test_parameter(
        self,
        target: Target,
        param: NoSQLCandidateParameter,
        characterizer: NoSQLBaselineCharacterizer,
        data: Any | None,
        json_data: Any | None,
        headers: dict[str, str] | None,
        remaining_budget: int,
    ) -> tuple[list[NoSQLFinding], int]:
        """Execute error-based and differential tests on a single candidate parameter."""
        findings: list[NoSQLFinding] = []
        req_count = 0

        # Step A: Baseline characterization
        baseline_params, baseline_data, baseline_json = self._prepare_payload(
            target, param, param.original_value, data, json_data
        )

        try:
            profile, baseline_resp = characterizer.characterize(
                endpoint=target.full_url
                if param.location != ParameterLocation.QUERY
                else target.origin + target.path,
                method=param.method,
                params=baseline_params,
                data=baseline_data,
                json_data=baseline_json,
                headers=headers,
            )
            req_count += profile.sample_count
        except Exception as exc:
            logger.warning("Baseline probe failed for parameter %s: %s", param.name, exc)
            findings.append(
                NoSQLFinding(
                    test_id=f"BASELINE_FAIL_{param.name}",
                    technique=NoSQLTestTechnique.ERROR_BASED,
                    target_url=target.full_url,
                    http_method=param.method,
                    parameter=param,
                    status=NoSQLDetectionStatus.ERROR,
                    error_or_skip_reason=f"Failed to establish baseline response: {exc}",
                    request_count=req_count,
                    limitations=DEFAULT_LIMITATIONS,
                )
            )
            return findings, req_count

        baseline_meta = {
            "status_code": profile.status_code,
            "content_length": profile.content_length,
            "elapsed_seconds": profile.elapsed_seconds,
            "is_stable": profile.is_stable,
            "sample_count": profile.sample_count,
        }

        # Step B: Error-based probe
        # Inject invalid operator syntax or malformed selector
        if req_count < self.max_requests_per_parameter and (req_count < remaining_budget):
            error_probe_value: Any
            if param.location == ParameterLocation.BODY_JSON:
                # MongoDB invalid operator probe
                error_probe_value = {"$invalid_nosql_op": 1}
            else:
                # Query/Form operator error syntax
                error_probe_value = "[$invalid_nosql_op]=1"

            err_params, err_data, err_json = self._prepare_payload(
                target, param, error_probe_value, data, json_data
            )

            try:
                test_resp = self.http_client.request(
                    method=param.method,
                    url=target.full_url
                    if param.location != ParameterLocation.QUERY
                    else target.origin + target.path,
                    params=err_params,
                    data=err_data,
                    json=err_json,
                    headers=headers,
                )
                req_count += 1

                err_status, err_conf, err_evidence, err_summary = (
                    NoSQLErrorDetector.analyze_response(
                        test_body=test_resp.body,
                        test_status=test_resp.status_code,
                        baseline_body=baseline_resp.body,
                        baseline_status=baseline_resp.status_code,
                    )
                )

                findings.append(
                    NoSQLFinding(
                        test_id=f"NOSQL_ERR_{param.name}",
                        technique=NoSQLTestTechnique.ERROR_BASED,
                        target_url=target.full_url,
                        http_method=param.method,
                        parameter=param,
                        status=err_status,
                        confidence=err_conf,
                        evidence_summary=err_summary,
                        evidence_records=err_evidence,
                        baseline_metadata=baseline_meta,
                        test_response_metadata={
                            "status_code": test_resp.status_code,
                            "content_length": len(test_resp.body),
                            "elapsed_seconds": test_resp.elapsed_seconds,
                        },
                        request_count=req_count,
                        limitations=DEFAULT_LIMITATIONS,
                    )
                )
            except Exception as exc:
                logger.warning("Error test probe failed for %s: %s", param.name, exc)
                findings.append(
                    NoSQLFinding(
                        test_id=f"NOSQL_ERR_{param.name}",
                        technique=NoSQLTestTechnique.ERROR_BASED,
                        target_url=target.full_url,
                        http_method=param.method,
                        parameter=param,
                        status=NoSQLDetectionStatus.ERROR,
                        error_or_skip_reason=f"Transport error during error probe: {exc}",
                        baseline_metadata=baseline_meta,
                        request_count=req_count,
                        limitations=DEFAULT_LIMITATIONS,
                    )
                )

        # Step C: Operator / Boolean Differential Probing
        if (
            self.enable_differential
            and (req_count + 2 <= self.max_requests_per_parameter)
            and (req_count + 2 <= remaining_budget)
        ):
            val_true: Any
            val_false: Any

            if param.location == ParameterLocation.BODY_JSON:
                # Truthy: MongoDB $ne with nonexistent sentinel matches existing documents
                val_true = {"$ne": "__dbshield_sentinel__"}
                # Falsy: MongoDB $in with empty array or $eq matches no documents
                val_false = {"$in": []}
            else:
                # Query/Form operator syntax (e.g. Express / qs array syntax)
                val_true = "[$ne]=__dbshield_sentinel__"
                val_false = "[$eq]=__dbshield_sentinel__"

            t_params, t_data, t_json = self._prepare_payload(
                target, param, val_true, data, json_data
            )
            f_params, f_data, f_json = self._prepare_payload(
                target, param, val_false, data, json_data
            )

            try:
                t_resp = self.http_client.request(
                    method=param.method,
                    url=target.full_url
                    if param.location != ParameterLocation.QUERY
                    else target.origin + target.path,
                    params=t_params,
                    data=t_data,
                    json=t_json,
                    headers=headers,
                )
                req_count += 1

                f_resp = self.http_client.request(
                    method=param.method,
                    url=target.full_url
                    if param.location != ParameterLocation.QUERY
                    else target.origin + target.path,
                    params=f_params,
                    data=f_data,
                    json=f_json,
                    headers=headers,
                )
                req_count += 1

                diff_res = NoSQLDifferentialDetector.analyze_pair(
                    baseline_body=baseline_resp.body,
                    baseline_status=baseline_resp.status_code,
                    is_baseline_stable=profile.is_stable,
                    true_body=t_resp.body,
                    true_status=t_resp.status_code,
                    false_body=f_resp.body,
                    false_status=f_resp.status_code,
                    provider_hint=NoSQLProviderFamily.MONGODB,
                )

                findings.append(
                    NoSQLFinding(
                        test_id=f"NOSQL_DIFF_{param.name}",
                        technique=NoSQLTestTechnique.BOOLEAN_DIFFERENTIAL,
                        target_url=target.full_url,
                        http_method=param.method,
                        parameter=param,
                        status=diff_res.status,
                        confidence=diff_res.confidence,
                        evidence_summary=diff_res.explanation,
                        evidence_records=diff_res.evidence,
                        baseline_metadata=baseline_meta,
                        test_response_metadata={
                            "true_status": t_resp.status_code,
                            "false_status": f_resp.status_code,
                            "sim_true_base": diff_res.similarity_true_baseline,
                            "sim_false_base": diff_res.similarity_false_baseline,
                            "sim_true_false": diff_res.similarity_true_false,
                        },
                        request_count=req_count,
                        limitations=DEFAULT_LIMITATIONS,
                    )
                )
            except Exception as exc:
                logger.warning("Differential test probe failed for %s: %s", param.name, exc)
                findings.append(
                    NoSQLFinding(
                        test_id=f"NOSQL_DIFF_{param.name}",
                        technique=NoSQLTestTechnique.BOOLEAN_DIFFERENTIAL,
                        target_url=target.full_url,
                        http_method=param.method,
                        parameter=param,
                        status=NoSQLDetectionStatus.ERROR,
                        error_or_skip_reason=f"Transport error during differential probe: {exc}",
                        baseline_metadata=baseline_meta,
                        request_count=req_count,
                        limitations=DEFAULT_LIMITATIONS,
                    )
                )

        return findings, req_count

    def _prepare_payload(
        self,
        target: Target,
        param: NoSQLCandidateParameter,
        new_value: Any,
        data: Any | None,
        json_data: Any | None,
    ) -> tuple[dict[str, Any] | None, Any | None, Any | None]:
        """Inject test value into the candidate parameter location while preserving rest of request."""
        req_params: dict[str, Any] | None = None
        req_data: Any | None = data
        req_json: Any | None = json_data

        if param.location == ParameterLocation.QUERY:
            existing = urllib.parse.parse_qs(target.query, keep_blank_values=True)
            if isinstance(new_value, str) and new_value.startswith("[") and "]=" in new_value:
                # Express/qs style object injection into query: param[$op]=val
                op_key, op_val = new_value.split("]=", 1)
                full_param = f"{param.name}{op_key}]"
                # Remove original flat param and inject operator subkey
                existing.pop(param.name, None)
                existing[full_param] = [op_val]
            else:
                existing[param.name] = [str(new_value) if new_value is not None else ""]
            req_params = {k: v[0] for k, v in existing.items()}

        elif param.location == ParameterLocation.BODY_URLENCODED:
            if isinstance(data, str):
                parsed = urllib.parse.parse_qs(data, keep_blank_values=True)
                if isinstance(new_value, str) and new_value.startswith("[") and "]=" in new_value:
                    op_key, op_val = new_value.split("]=", 1)
                    full_param = f"{param.name}{op_key}]"
                    parsed.pop(param.name, None)
                    parsed[full_param] = [op_val]
                else:
                    parsed[param.name] = [str(new_value) if new_value is not None else ""]
                req_data = urllib.parse.urlencode({k: v[0] for k, v in parsed.items()})

        elif param.location == ParameterLocation.BODY_JSON:
            dict_json = (
                json.loads(json_data)
                if isinstance(json_data, str)
                else copy.deepcopy(json_data or {})
            )
            # Mutate nested or top-level path
            req_json = self._mutate_json_path(dict_json, param.key_path or [param.name], new_value)

        return req_params, req_data, req_json

    @classmethod
    def _mutate_json_path(cls, data: Any, path: list[str], new_value: Any) -> Any:
        """Mutate a specific nested key path in a JSON structure while preserving all other keys."""
        cloned = copy.deepcopy(data)
        if not path:
            return new_value

        curr = cloned
        for step in path[:-1]:
            if isinstance(curr, dict):
                curr = curr[step]
            elif isinstance(curr, list) and step.isdigit():
                curr = curr[int(step)]

        last_key = path[-1]
        if isinstance(curr, dict):
            curr[last_key] = new_value
        elif isinstance(curr, list) and last_key.isdigit():
            curr[int(last_key)] = new_value

        return cloned

    @classmethod
    def analyze_fixture_records(
        cls,
        target_url: str,
        param_name: str,
        baseline_response: HTTPResponse,
        test_response: HTTPResponse,
        true_response: HTTPResponse | None = None,
        false_response: HTTPResponse | None = None,
    ) -> NoSQLScanResult:
        """Perform offline laboratory assessment from captured response fixtures.

        Enables reproducible, zero-network evaluation of NoSQL error and differential patterns.
        """
        start_time = time.monotonic()
        param = NoSQLCandidateParameter(
            name=param_name,
            location=ParameterLocation.QUERY,
            key_path=[param_name],
            endpoint=target_url,
            is_eligible=True,
        )

        profile, _ = NoSQLBaselineCharacterizer.from_captured_response(baseline_response)
        baseline_meta = {
            "status_code": profile.status_code,
            "content_length": profile.content_length,
            "elapsed_seconds": profile.elapsed_seconds,
            "is_stable": profile.is_stable,
        }

        findings: list[NoSQLFinding] = []

        # Error analysis
        err_status, err_conf, err_evidence, err_summary = NoSQLErrorDetector.analyze_response(
            test_body=test_response.body,
            test_status=test_response.status_code,
            baseline_body=baseline_response.body,
            baseline_status=baseline_response.status_code,
        )
        findings.append(
            NoSQLFinding(
                test_id=f"FIXTURE_ERR_{param_name}",
                technique=NoSQLTestTechnique.ERROR_BASED,
                target_url=target_url,
                http_method="GET",
                parameter=param,
                status=err_status,
                confidence=err_conf,
                evidence_summary=err_summary,
                evidence_records=err_evidence,
                baseline_metadata=baseline_meta,
                test_response_metadata={
                    "status_code": test_response.status_code,
                    "content_length": len(test_response.body),
                },
                request_count=0,
                limitations=DEFAULT_LIMITATIONS,
            )
        )

        # Differential analysis if true/false fixtures provided
        if true_response and false_response:
            diff_res = NoSQLDifferentialDetector.analyze_pair(
                baseline_body=baseline_response.body,
                baseline_status=baseline_response.status_code,
                is_baseline_stable=profile.is_stable,
                true_body=true_response.body,
                true_status=true_response.status_code,
                false_body=false_response.body,
                false_status=false_response.status_code,
                provider_hint=NoSQLProviderFamily.MONGODB,
            )
            findings.append(
                NoSQLFinding(
                    test_id=f"FIXTURE_DIFF_{param_name}",
                    technique=NoSQLTestTechnique.BOOLEAN_DIFFERENTIAL,
                    target_url=target_url,
                    http_method="GET",
                    parameter=param,
                    status=diff_res.status,
                    confidence=diff_res.confidence,
                    evidence_summary=diff_res.explanation,
                    evidence_records=diff_res.evidence,
                    baseline_metadata=baseline_meta,
                    test_response_metadata={
                        "true_status": true_response.status_code,
                        "false_status": false_response.status_code,
                        "sim_true_base": diff_res.similarity_true_baseline,
                        "sim_false_base": diff_res.similarity_false_baseline,
                        "sim_true_false": diff_res.similarity_true_false,
                    },
                    request_count=0,
                    limitations=DEFAULT_LIMITATIONS,
                )
            )

        total_p = 1
        tested_p = sum(
            1
            for f in findings
            if f.status
            in (
                NoSQLDetectionStatus.POTENTIAL_INDICATOR,
                NoSQLDetectionStatus.NO_INDICATOR,
                NoSQLDetectionStatus.INCONCLUSIVE,
            )
        )
        pot_ind = sum(1 for f in findings if f.status == NoSQLDetectionStatus.POTENTIAL_INDICATOR)
        clean_p = sum(1 for f in findings if f.status == NoSQLDetectionStatus.NO_INDICATOR)
        inconc_p = sum(1 for f in findings if f.status == NoSQLDetectionStatus.INCONCLUSIVE)

        summary = NoSQLScanSummary(
            total_parameters=total_p,
            tested_parameters=tested_p,
            potential_indicators=pot_ind,
            clean_parameters=clean_p,
            inconclusive_parameters=inconc_p,
            total_requests=0,
            duration_seconds=round(time.monotonic() - start_time, 3),
        )

        return NoSQLScanResult(
            target_url=target_url,
            execution_status="completed",
            summary=summary,
            findings=findings,
            parameters=[param],
            limitations=DEFAULT_LIMITATIONS,
        )
