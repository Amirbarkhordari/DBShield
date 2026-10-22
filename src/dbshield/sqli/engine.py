"""SQL Injection Testing and Detection Engine for DBShield Phase 4.

Coordinates parameter extraction, baseline characterization, error-based detection,
and boolean differential response analysis. Strictly enforces target scope, request
budgets, zero-credential safety, and explainable finding classifications.
"""

import json
import logging
import time
import urllib.parse
from typing import Any

from dbshield.auth.manager import SessionManager
from dbshield.exceptions import (
    NetworkError,
    ScopeViolationError,
)
from dbshield.http.client import SafeHTTPClient
from dbshield.models.http import HTTPMethod, HTTPResponse
from dbshield.models.target import Target
from dbshield.scope.manager import ScopeManager
from dbshield.sqli.baseline import BaselineCharacterizer
from dbshield.sqli.detectors.differential_detector import DifferentialDetector
from dbshield.sqli.detectors.error_detector import ErrorDetector
from dbshield.sqli.models import (
    CandidateParameter,
    DetectionStatus,
    ParameterLocation,
    SQLiFinding,
    SQLiScanResult,
    SQLiScanSummary,
    TestTechnique,
)

logger = logging.getLogger("dbshield.sqli.engine")

# Parameter names that must NEVER be tested actively (passwords, tokens, nonces)
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
    "Tests are strictly non-destructive and defensive; exploitation and data exfiltration are prohibited.",
    "A potential indicator is unconfirmed and requires independent verification (Phase 7).",
    "A 'no_indicator' result indicates that tested payloads did not trigger observable signals; it does NOT prove the endpoint is secure.",
    "Resource-intensive, long-delay time-based probes were omitted to prevent server degradation.",
    "JSON parameter extraction evaluates top-level properties; nested object structures and arrays are deferred to Phase 6.",
]


class SQLiEngine:
    """Orchestrates controlled SQL injection testing workflow."""

    def __init__(
        self,
        scope_manager: ScopeManager,
        http_client: SafeHTTPClient | None = None,
        session_manager: SessionManager | None = None,
        max_requests_per_parameter: int = 8,
        total_request_budget: int = 50,
        enable_differential: bool = True,
    ) -> None:
        """Initialize SQLiEngine.

        Args:
            scope_manager: Authoritative ScopeManager for outbound authorization.
            http_client: SafeHTTPClient instance (created automatically if omitted).
            session_manager: Optional SessionManager for authenticated requests.
            max_requests_per_parameter: Request budget ceiling per parameter.
            total_request_budget: Overall scan request budget ceiling.
            enable_differential: Whether to perform boolean differential testing.
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

    def extract_parameters(
        self,
        target: Target,
        method: str = "GET",
        data: Any | None = None,
        json_data: Any | None = None,
        selected_param: str | None = None,
    ) -> list[CandidateParameter]:
        """Extract and classify candidate parameters from URL, form body, or JSON data.

        Args:
            target: Validated Target object.
            method: HTTP method.
            data: Form-encoded or raw body data.
            json_data: JSON object body.
            selected_param: Optional specific parameter name to filter for.

        Returns:
            List of CandidateParameter instances.
        """
        params: list[CandidateParameter] = []

        # 1. URL Query Parameters
        if target.query:
            parsed_query = urllib.parse.parse_qs(target.query, keep_blank_values=True)
            for name, values in parsed_query.items():
                orig_val = values[0] if values else ""
                is_eligible, skip_reason = self._evaluate_eligibility(name)
                params.append(
                    CandidateParameter(
                        name=name,
                        location=ParameterLocation.QUERY,
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
                        CandidateParameter(
                            name=name,
                            location=ParameterLocation.BODY_URLENCODED,
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

        # 3. JSON Parameters
        if json_data:
            dict_data = json_data
            if isinstance(json_data, str):
                try:
                    dict_data = json.loads(json_data)
                except Exception:
                    dict_data = None
            if isinstance(dict_data, dict):
                for name, val in dict_data.items():
                    is_eligible, skip_reason = self._evaluate_eligibility(name)
                    params.append(
                        CandidateParameter(
                            name=name,
                            location=ParameterLocation.BODY_JSON,
                            original_value=str(val) if val is not None else "",
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
            filtered = [p for p in params if p.name.lower() == selected_lower]
            if not filtered:
                # Add as explicitly declared query param if not found in query
                params = [
                    CandidateParameter(
                        name=selected_param,
                        location=ParameterLocation.QUERY,
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
        clean_name = param_name.lower().replace("-", "_").strip()
        for forbidden in INELIGIBLE_PARAM_PATTERNS:
            if forbidden == clean_name or clean_name.endswith(f"_{forbidden}"):
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
    ) -> SQLiScanResult:
        """Execute SQL injection detection testing over target URL and candidate parameters.

        Args:
            target_url: Target URL string or Target instance.
            method: HTTP method.
            selected_param: Optional parameter name to limit testing to.
            data: Raw or form body data.
            json_data: JSON payload.
            headers: Custom request headers.

        Returns:
            Structured SQLiScanResult with findings, parameter inventory, and summary.
        """
        start_time = time.monotonic()
        req_method = method.value if isinstance(method, HTTPMethod) else str(method).upper()

        # Step 1: Pre-flight Scope Check
        try:
            target = self.scope_manager.assert_in_scope(target_url)
        except ScopeViolationError as exc:
            logger.warning("Target %s blocked by ScopeManager: %s", target_url, exc.message)
            dummy_param = CandidateParameter(
                name=selected_param or "all",
                location=ParameterLocation.QUERY,
                endpoint=str(target_url),
                method=req_method,
                is_eligible=False,
                skip_reason=exc.message,
            )
            blocked_finding = SQLiFinding(
                test_id="SCOPE_CHECK",
                technique=TestTechnique.ERROR_BASED,
                target_url=str(target_url),
                http_method=req_method,
                parameter=dummy_param,
                status=DetectionStatus.BLOCKED_BY_SCOPE,
                error_or_skip_reason=f"Target host is out of authorized scope: {exc.message}",
                limitations=DEFAULT_LIMITATIONS,
            )
            summary = SQLiScanSummary(
                total_parameters=1,
                blocked_parameters=1,
                duration_seconds=round(time.monotonic() - start_time, 3),
            )
            return SQLiScanResult(
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

        findings: list[SQLiFinding] = []
        total_requests = 0

        if not candidate_params:
            logger.info("No parameters found to test on target: %s", target.full_url)
            summary = SQLiScanSummary(
                total_parameters=0,
                duration_seconds=round(time.monotonic() - start_time, 3),
            )
            return SQLiScanResult(
                target_url=target.full_url,
                execution_status="completed",
                summary=summary,
                findings=[],
                parameters=[],
                limitations=DEFAULT_LIMITATIONS,
            )

        characterizer = BaselineCharacterizer(
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
                    SQLiFinding(
                        test_id="BUDGET_LIMIT",
                        technique=TestTechnique.ERROR_BASED,
                        target_url=target.full_url,
                        http_method=req_method,
                        parameter=param,
                        status=DetectionStatus.SKIPPED,
                        error_or_skip_reason=f"Scan request budget limit of {self.total_request_budget} requests reached.",
                        limitations=DEFAULT_LIMITATIONS,
                    )
                )
                continue

            # Check eligibility
            if not param.is_eligible:
                findings.append(
                    SQLiFinding(
                        test_id="ELIGIBILITY_CHECK",
                        technique=TestTechnique.ERROR_BASED,
                        target_url=target.full_url,
                        http_method=req_method,
                        parameter=param,
                        status=DetectionStatus.SKIPPED,
                        error_or_skip_reason=param.skip_reason
                        or "Parameter is not eligible for active testing.",
                        limitations=DEFAULT_LIMITATIONS,
                    )
                )
                continue

            # Execute tests on eligible parameter
            param_findings, param_reqs = self._test_parameter(
                target=target,
                param=param,
                characterizer=characterizer,
                headers=headers,
                data=data,
                json_data=json_data,
            )
            total_requests += param_reqs
            findings.extend(param_findings)

        # Compute parameter-level summary metrics
        param_findings_map: dict[str, list[SQLiFinding]] = {}
        for f in findings:
            param_findings_map.setdefault(f.parameter.name, []).append(f)

        potential_cnt = 0
        clean_cnt = 0
        inconclusive_cnt = 0
        error_cnt = 0
        skipped_cnt = 0
        blocked_cnt = 0
        tested_cnt = 0

        for p in candidate_params:
            p_findings = param_findings_map.get(p.name, [])
            if not p_findings:
                continue
            statuses = {f.status for f in p_findings}
            if DetectionStatus.POTENTIAL_INDICATOR in statuses:
                potential_cnt += 1
                tested_cnt += 1
            elif DetectionStatus.INCONCLUSIVE in statuses:
                inconclusive_cnt += 1
                tested_cnt += 1
            elif DetectionStatus.ERROR in statuses:
                error_cnt += 1
                tested_cnt += 1
            elif statuses == {DetectionStatus.NO_INDICATOR}:
                clean_cnt += 1
                tested_cnt += 1
            elif DetectionStatus.SKIPPED in statuses:
                skipped_cnt += 1
            elif DetectionStatus.BLOCKED_BY_SCOPE in statuses:
                blocked_cnt += 1

        summary = SQLiScanSummary(
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

        return SQLiScanResult(
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
        param: CandidateParameter,
        characterizer: BaselineCharacterizer,
        headers: dict[str, str] | None = None,
        data: Any | None = None,
        json_data: Any | None = None,
    ) -> tuple[list[SQLiFinding], int]:
        """Run error-based and boolean-differential tests on a single parameter."""
        findings: list[SQLiFinding] = []
        req_count = 0

        # 1. Establish baseline
        base_params, base_data, base_json = self._prepare_payload(
            target, param, param.original_value or "1", data, json_data
        )

        try:
            profile, baseline_resp = characterizer.characterize(
                endpoint=target.full_url
                if param.location != ParameterLocation.QUERY
                else target.origin + target.path,
                method=param.method,
                params=base_params,
                data=base_data,
                json_data=base_json,
                headers=headers,
            )
            req_count += profile.sample_count
        except (NetworkError, Exception) as exc:
            logger.warning("Baseline request failed for parameter %s: %s", param.name, exc)
            findings.append(
                SQLiFinding(
                    test_id=f"BASELINE_{param.name}",
                    technique=TestTechnique.ERROR_BASED,
                    target_url=target.full_url,
                    http_method=param.method,
                    parameter=param,
                    status=DetectionStatus.ERROR,
                    error_or_skip_reason=f"Transport error while establishing baseline: {exc}",
                    request_count=1,
                    limitations=DEFAULT_LIMITATIONS,
                )
            )
            return findings, 1

        baseline_meta = {
            "status_code": profile.status_code,
            "content_length": profile.content_length,
            "elapsed_seconds": profile.elapsed_seconds,
            "is_stable": profile.is_stable,
            "instability_reason": profile.instability_reason,
        }

        # Check baseline stability
        if not profile.is_stable:
            logger.info(
                "Baseline for parameter %s is unstable: %s; marking inconclusive.",
                param.name,
                profile.instability_reason,
            )
            findings.append(
                SQLiFinding(
                    test_id=f"SQLI_TEST_{param.name}",
                    technique=TestTechnique.ERROR_BASED,
                    target_url=target.full_url,
                    http_method=param.method,
                    parameter=param,
                    status=DetectionStatus.INCONCLUSIVE,
                    evidence_summary="Baseline response was unstable or returned server errors; reliable comparison aborted.",
                    baseline_metadata=baseline_meta,
                    request_count=req_count,
                    error_or_skip_reason=profile.instability_reason,
                    limitations=DEFAULT_LIMITATIONS,
                )
            )
            return findings, req_count

        # 2. Error-Based Test Probe
        # Use minimal non-destructive quote delimiter
        test_val = (param.original_value or "") + "'"
        err_params, err_data, err_json = self._prepare_payload(
            target, param, test_val, data, json_data
        )

        try:
            err_resp = self.http_client.request(
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
        except Exception as exc:
            logger.warning("Error test probe request failed for parameter %s: %s", param.name, exc)
            findings.append(
                SQLiFinding(
                    test_id=f"SQLI_ERR_{param.name}",
                    technique=TestTechnique.ERROR_BASED,
                    target_url=target.full_url,
                    http_method=param.method,
                    parameter=param,
                    status=DetectionStatus.ERROR,
                    error_or_skip_reason=f"Transport error during error-based probe: {exc}",
                    baseline_metadata=baseline_meta,
                    request_count=req_count,
                    limitations=DEFAULT_LIMITATIONS,
                )
            )
            return findings, req_count

        # Analyze error response
        err_status, err_conf, err_evidence, err_summary = ErrorDetector.analyze_response(
            test_body=err_resp.body,
            test_status=err_resp.status_code,
            baseline_body=baseline_resp.body,
            baseline_status=baseline_resp.status_code,
        )

        findings.append(
            SQLiFinding(
                test_id=f"SQLI_ERR_{param.name}",
                technique=TestTechnique.ERROR_BASED,
                target_url=target.full_url,
                http_method=param.method,
                parameter=param,
                status=err_status,
                confidence=err_conf,
                evidence_summary=err_summary,
                evidence_records=err_evidence,
                baseline_metadata=baseline_meta,
                test_response_metadata={
                    "status_code": err_resp.status_code,
                    "content_length": len(err_resp.body),
                    "elapsed_seconds": err_resp.elapsed_seconds,
                },
                request_count=req_count,
                limitations=DEFAULT_LIMITATIONS,
            )
        )

        # 3. Boolean Differential Test (if enabled and within budget)
        if self.enable_differential and req_count + 2 <= self.max_requests_per_parameter:
            orig = param.original_value or "1"
            # Paired logical conditions
            val_true = f"{orig} AND 1=1" if orig.isdigit() else f"{orig}' AND '1'='1"
            val_false = f"{orig} AND 1=2" if orig.isdigit() else f"{orig}' AND '1'='2"

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

                diff_res = DifferentialDetector.analyze_pair(
                    baseline_body=baseline_resp.body,
                    baseline_status=baseline_resp.status_code,
                    is_baseline_stable=profile.is_stable,
                    true_body=t_resp.body,
                    true_status=t_resp.status_code,
                    false_body=f_resp.body,
                    false_status=f_resp.status_code,
                )

                findings.append(
                    SQLiFinding(
                        test_id=f"SQLI_DIFF_{param.name}",
                        technique=TestTechnique.BOOLEAN_DIFFERENTIAL,
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
                    SQLiFinding(
                        test_id=f"SQLI_DIFF_{param.name}",
                        technique=TestTechnique.BOOLEAN_DIFFERENTIAL,
                        target_url=target.full_url,
                        http_method=param.method,
                        parameter=param,
                        status=DetectionStatus.ERROR,
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
        param: CandidateParameter,
        new_value: str,
        data: Any | None,
        json_data: Any | None,
    ) -> tuple[dict[str, Any] | None, Any | None, Any | None]:
        """Inject test value into the appropriate parameter transport location."""
        req_params: dict[str, Any] | None = None
        req_data: Any | None = data
        req_json: Any | None = json_data

        if param.location == ParameterLocation.QUERY:
            existing = urllib.parse.parse_qs(target.query, keep_blank_values=True)
            # Replace candidate parameter
            existing[param.name] = [new_value]
            req_params = {k: v[0] for k, v in existing.items()}
        elif param.location == ParameterLocation.BODY_URLENCODED:
            if isinstance(data, str):
                parsed = urllib.parse.parse_qs(data, keep_blank_values=True)
                parsed[param.name] = [new_value]
                req_data = urllib.parse.urlencode({k: v[0] for k, v in parsed.items()})
        elif param.location == ParameterLocation.BODY_JSON:
            dict_json = (
                json.loads(json_data) if isinstance(json_data, str) else dict(json_data or {})
            )
            dict_json[param.name] = new_value
            req_json = dict_json

        return req_params, req_data, req_json

    @classmethod
    def analyze_fixture_records(
        cls,
        target_url: str,
        param_name: str,
        baseline_response: HTTPResponse,
        test_response: HTTPResponse,
        true_response: HTTPResponse | None = None,
        false_response: HTTPResponse | None = None,
    ) -> SQLiScanResult:
        """Perform offline laboratory assessment from captured response fixtures.

        Enables reproducible, zero-network evaluation of error and differential patterns.
        """
        start_time = time.monotonic()
        param = CandidateParameter(
            name=param_name,
            location=ParameterLocation.QUERY,
            endpoint=target_url,
            is_eligible=True,
        )

        profile, _ = BaselineCharacterizer.from_captured_response(baseline_response)
        baseline_meta = {
            "status_code": profile.status_code,
            "content_length": profile.content_length,
            "elapsed_seconds": profile.elapsed_seconds,
            "is_stable": profile.is_stable,
        }

        findings: list[SQLiFinding] = []

        # Error analysis
        err_status, err_conf, err_evidence, err_summary = ErrorDetector.analyze_response(
            test_body=test_response.body,
            test_status=test_response.status_code,
            baseline_body=baseline_response.body,
            baseline_status=baseline_response.status_code,
        )
        findings.append(
            SQLiFinding(
                test_id=f"FIXTURE_ERR_{param_name}",
                technique=TestTechnique.ERROR_BASED,
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
            diff_res = DifferentialDetector.analyze_pair(
                baseline_body=baseline_response.body,
                baseline_status=baseline_response.status_code,
                is_baseline_stable=profile.is_stable,
                true_body=true_response.body,
                true_status=true_response.status_code,
                false_body=false_response.body,
                false_status=false_response.status_code,
            )
            findings.append(
                SQLiFinding(
                    test_id=f"FIXTURE_DIFF_{param_name}",
                    technique=TestTechnique.BOOLEAN_DIFFERENTIAL,
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

        statuses = {f.status for f in findings}
        potential_cnt = 1 if DetectionStatus.POTENTIAL_INDICATOR in statuses else 0
        inconclusive_cnt = (
            1 if DetectionStatus.INCONCLUSIVE in statuses and not potential_cnt else 0
        )
        clean_cnt = 1 if statuses == {DetectionStatus.NO_INDICATOR} else 0

        summary = SQLiScanSummary(
            total_parameters=1,
            tested_parameters=1,
            potential_indicators=potential_cnt,
            clean_parameters=clean_cnt,
            inconclusive_parameters=inconclusive_cnt,
            total_requests=0,
            duration_seconds=round(time.monotonic() - start_time, 3),
        )

        return SQLiScanResult(
            target_url=target_url,
            execution_status="completed",
            summary=summary,
            findings=findings,
            parameters=[param],
            limitations=DEFAULT_LIMITATIONS,
        )
