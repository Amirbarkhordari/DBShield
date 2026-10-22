"""Engine adapters connecting the shared test execution layer to SQLi and NoSQLi detectors (Phase 6).

Consumes existing detector interfaces without duplicating vulnerability classification
or detection logic.
"""

from abc import ABC, abstractmethod
from typing import Any

from dbshield.models.http import HTTPResponse
from dbshield.nosqli.detectors.differential_detector import NoSQLDifferentialDetector
from dbshield.nosqli.detectors.error_detector import NoSQLErrorDetector
from dbshield.nosqli.models import (
    NoSQLCandidateParameter,
    NoSQLFinding,
    NoSQLProviderFamily,
    NoSQLTestTechnique,
)
from dbshield.payloads.models import SecurityPayload
from dbshield.sqli.detectors.differential_detector import DifferentialDetector
from dbshield.sqli.detectors.error_detector import ErrorDetector
from dbshield.sqli.models import (
    CandidateParameter,
    ParameterLocation,
    SQLiFinding,
    TestTechnique,
)


class EngineAdapter(ABC):
    """Abstract interface adapting engine-specific detection logic to the execution orchestrator."""

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Name of the engine (e.g. 'sqli', 'nosqli')."""
        ...

    @abstractmethod
    def evaluate_single_probe(
        self,
        target_url: str,
        param_name: str,
        param_location: ParameterLocation,
        payload: SecurityPayload,
        test_resp: HTTPResponse,
        baseline_resp: HTTPResponse,
    ) -> Any:
        """Evaluate a single error or syntax probe response against baseline."""
        ...

    @abstractmethod
    def evaluate_paired_probes(
        self,
        target_url: str,
        param_name: str,
        param_location: ParameterLocation,
        true_payload: SecurityPayload,
        false_payload: SecurityPayload,
        true_resp: HTTPResponse,
        false_resp: HTTPResponse,
        baseline_resp: HTTPResponse,
        is_baseline_stable: bool,
    ) -> Any:
        """Evaluate paired differential probe responses against baseline."""
        ...


class SQLiExecutionAdapter(EngineAdapter):
    """Adapter invoking SQL injection error and differential detectors."""

    @property
    def engine_name(self) -> str:
        return "sqli"

    def evaluate_single_probe(
        self,
        target_url: str,
        param_name: str,
        param_location: ParameterLocation,
        payload: SecurityPayload,
        test_resp: HTTPResponse,
        baseline_resp: HTTPResponse,
    ) -> SQLiFinding:
        param = CandidateParameter(
            name=param_name,
            location=param_location,
            endpoint=target_url,
            is_eligible=True,
        )
        status, conf, evidence, summary = ErrorDetector.analyze_response(
            test_body=test_resp.body,
            test_status=test_resp.status_code,
            baseline_body=baseline_resp.body,
            baseline_status=baseline_resp.status_code,
        )
        return SQLiFinding(
            test_id=f"EXEC_{payload.payload_id}_{param_name}",
            technique=TestTechnique.ERROR_BASED,
            target_url=target_url,
            http_method="GET",
            parameter=param,
            status=status,
            confidence=conf,
            evidence_summary=summary,
            evidence_records=evidence,
            test_response_metadata={
                "status_code": test_resp.status_code,
                "content_length": len(test_resp.body),
            },
        )

    def evaluate_paired_probes(
        self,
        target_url: str,
        param_name: str,
        param_location: ParameterLocation,
        true_payload: SecurityPayload,
        false_payload: SecurityPayload,
        true_resp: HTTPResponse,
        false_resp: HTTPResponse,
        baseline_resp: HTTPResponse,
        is_baseline_stable: bool,
    ) -> SQLiFinding:
        param = CandidateParameter(
            name=param_name,
            location=param_location,
            endpoint=target_url,
            is_eligible=True,
        )
        diff_res = DifferentialDetector.analyze_pair(
            baseline_body=baseline_resp.body,
            baseline_status=baseline_resp.status_code,
            is_baseline_stable=is_baseline_stable,
            true_body=true_resp.body,
            true_status=true_resp.status_code,
            false_body=false_resp.body,
            false_status=false_resp.status_code,
        )
        return SQLiFinding(
            test_id=f"EXEC_DIFF_{true_payload.payload_id}_{false_payload.payload_id}_{param_name}",
            technique=TestTechnique.BOOLEAN_DIFFERENTIAL,
            target_url=target_url,
            http_method="GET",
            parameter=param,
            status=diff_res.status,
            confidence=diff_res.confidence,
            evidence_summary=diff_res.explanation,
            evidence_records=diff_res.evidence,
            test_response_metadata={
                "true_payload": true_payload.payload_id,
                "false_payload": false_payload.payload_id,
                "true_status": true_resp.status_code,
                "false_status": false_resp.status_code,
                "sim_true_base": diff_res.similarity_true_baseline,
                "sim_false_base": diff_res.similarity_false_baseline,
                "sim_true_false": diff_res.similarity_true_false,
            },
        )


class NoSQLiExecutionAdapter(EngineAdapter):
    """Adapter invoking NoSQL injection error and differential detectors."""

    @property
    def engine_name(self) -> str:
        return "nosqli"

    def evaluate_single_probe(
        self,
        target_url: str,
        param_name: str,
        param_location: ParameterLocation,
        payload: SecurityPayload,
        test_resp: HTTPResponse,
        baseline_resp: HTTPResponse,
    ) -> NoSQLFinding:
        param = NoSQLCandidateParameter(
            name=param_name,
            location=param_location,
            endpoint=target_url,
            key_path=param_name.split("."),
            is_eligible=True,
        )
        status, conf, evidence, summary = NoSQLErrorDetector.analyze_response(
            test_body=test_resp.body,
            test_status=test_resp.status_code,
            baseline_body=baseline_resp.body,
            baseline_status=baseline_resp.status_code,
        )
        return NoSQLFinding(
            test_id=f"EXEC_{payload.payload_id}_{param_name}",
            technique=NoSQLTestTechnique.ERROR_BASED,
            target_url=target_url,
            http_method="GET",
            parameter=param,
            status=status,
            confidence=conf,
            evidence_summary=summary,
            evidence_records=evidence,
            test_response_metadata={
                "status_code": test_resp.status_code,
                "content_length": len(test_resp.body),
            },
        )

    def evaluate_paired_probes(
        self,
        target_url: str,
        param_name: str,
        param_location: ParameterLocation,
        true_payload: SecurityPayload,
        false_payload: SecurityPayload,
        true_resp: HTTPResponse,
        false_resp: HTTPResponse,
        baseline_resp: HTTPResponse,
        is_baseline_stable: bool,
    ) -> NoSQLFinding:
        param = NoSQLCandidateParameter(
            name=param_name,
            location=param_location,
            endpoint=target_url,
            key_path=param_name.split("."),
            is_eligible=True,
        )
        diff_res = NoSQLDifferentialDetector.analyze_pair(
            baseline_body=baseline_resp.body,
            baseline_status=baseline_resp.status_code,
            is_baseline_stable=is_baseline_stable,
            true_body=true_resp.body,
            true_status=true_resp.status_code,
            false_body=false_resp.body,
            false_status=false_resp.status_code,
            provider_hint=NoSQLProviderFamily.MONGODB,
        )
        return NoSQLFinding(
            test_id=f"EXEC_DIFF_{true_payload.payload_id}_{false_payload.payload_id}_{param_name}",
            technique=NoSQLTestTechnique.BOOLEAN_DIFFERENTIAL,
            target_url=target_url,
            http_method="GET",
            parameter=param,
            status=diff_res.status,
            confidence=diff_res.confidence,
            evidence_summary=diff_res.explanation,
            evidence_records=diff_res.evidence,
            test_response_metadata={
                "true_payload": true_payload.payload_id,
                "false_payload": false_payload.payload_id,
                "true_status": true_resp.status_code,
                "false_status": false_resp.status_code,
                "sim_true_base": diff_res.similarity_true_baseline,
                "sim_false_base": diff_res.similarity_false_baseline,
                "sim_true_false": diff_res.similarity_true_false,
            },
        )
