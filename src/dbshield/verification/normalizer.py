"""Evidence Normalization and Validation subsystem for DBShield (Phase 7).

Normalizes, redacts, and validates candidate security evidence across SQLi,
NoSQLi, Phase 6 execution records, and offline fixtures into standardized
immutable NormalizedEvidence models with traceable provenance.
"""

import contextlib
import re
from typing import Any

from dbshield.execution.models import ExecutionRecord, ExecutionRunResult, ExecutionStatus
from dbshield.nosqli.models import NoSQLFinding, NoSQLTestTechnique
from dbshield.sqli.models import ParameterLocation, SQLiFinding, TestTechnique
from dbshield.verification.models import (
    EvidenceProvenance,
    EvidenceType,
    NormalizedEvidence,
    VulnerabilityClass,
)

# Common credential and token regexes for sanitizing evidence snippets and metadata
_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Authorization headers
    (
        re.compile(r"(?i)(authorization\s*:\s*)(bearer|basic|token)\s+[^\s,;]+"),
        r"\1\2 [REDACTED]",
    ),
    # Cookies
    (
        re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(set-cookie\s*:\s*)[^\r\n]+"),
        r"\1[REDACTED]",
    ),
    # Specific API Tokens & Keys
    (
        re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b"),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "[REDACTED_AWS_KEY]",
    ),
    # Common password / secret key-value pairs
    (
        re.compile(
            r'(?i)(["\']?(?:password|passwd|pwd|token|access_token|refresh_token|api_key|secret|client_secret)["\']?\s*[:=]\s*["\']?)(?!\[REDACTED)([^"\'\s&]+)(["\']?)'
        ),
        r"\1[REDACTED]\3",
    ),
]

_SENSITIVE_PARAM_NAMES: set[str] = {
    "password",
    "passwd",
    "pwd",
    "token",
    "access_token",
    "refresh_token",
    "auth_token",
    "api_key",
    "secret",
    "secret_key",
    "session",
    "csrf",
    "otp",
}


def sanitize_snippet(snippet: str) -> str:
    """Sanitize sensitive credentials, tokens, and authorization data from evidence snippets."""
    if not snippet:
        return ""
    result = snippet
    for pattern, replacement in _SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    # Bounded length to guarantee memory safety and clean formatting (max 500 chars)
    if len(result) > 500:
        result = result[:497] + "..."
    return result


def is_sensitive_parameter_name(name: str) -> bool:
    """Check if a parameter name corresponds to a sensitive authentication or secret credential."""
    name_clean = name.lower().replace("-", "_").replace(".", "_")
    return any(p in name_clean for p in _SENSITIVE_PARAM_NAMES)


class EvidenceNormalizer:
    """Deterministic normalizer and validator for security test evidence."""

    @classmethod
    def redact_parameter_name(cls, name: str) -> str:
        """Return safe parameter reference, preserving identity while masking secrets."""
        if is_sensitive_parameter_name(name):
            return f"[REDACTED_PARAM:{name[:3]}***]" if len(name) > 3 else "[REDACTED_PARAM]"
        return name

    @classmethod
    def normalize_sqli_finding(
        cls,
        finding: SQLiFinding,
        execution_id: str | None = None,
        run_id: str | None = None,
    ) -> list[NormalizedEvidence]:
        """Normalize an SQLiFinding into a list of NormalizedEvidence records."""
        results: list[NormalizedEvidence] = []
        target_url = finding.target_url
        param_name = finding.parameter.name
        param_loc = finding.parameter.location
        test_id = finding.test_id

        # Determine evidence type from technique
        if finding.technique == TestTechnique.ERROR_BASED:
            default_ev_type = EvidenceType.ERROR_SIGNATURE
        elif finding.technique == TestTechnique.BOOLEAN_DIFFERENTIAL:
            default_ev_type = EvidenceType.DIFFERENTIAL_PAIR
        else:
            default_ev_type = EvidenceType.BASELINE_COMPARISON

        baseline_status = finding.baseline_metadata.get("status_code")
        test_status = finding.test_response_metadata.get("status_code")
        similarity = finding.test_response_metadata.get("similarity")
        is_stable = finding.baseline_metadata.get("is_stable", True)

        # Baseline preexisting indicator check
        preexisting = finding.baseline_metadata.get("has_preexisting_error", False)

        provenance = EvidenceProvenance(
            engine="sqli",
            vulnerability_class=VulnerabilityClass.SQLI,
            target_url=target_url,
            parameter_name=param_name,
            parameter_location=param_loc,
            test_id=test_id,
            execution_id=execution_id,
            run_id=run_id,
            source_finding_id=finding.finding_id,
            timestamp=finding.timestamp,
        )

        if not finding.evidence_records:
            # Handle finding with no detailed records (e.g. inconclusive or clean)
            ev = NormalizedEvidence(
                evidence_type=default_ev_type,
                provenance=provenance,
                rule_id=finding.technique.value,
                matched_pattern="no_specific_pattern",
                safe_snippet=sanitize_snippet(finding.evidence_summary),
                description=finding.evidence_summary or "SQLi detector outcome summary.",
                provider_or_family="unknown",
                baseline_status=baseline_status,
                test_status=test_status,
                similarity_score=float(similarity) if similarity is not None else None,
                is_baseline_stable=is_stable,
                is_preexisting_in_baseline=preexisting,
                details={
                    "detection_status": finding.status.value,
                    "confidence": finding.confidence.value if finding.confidence else None,
                    "request_count": finding.request_count,
                    "limitations": finding.limitations,
                },
            )
            results.append(ev)
            return results

        for rec in finding.evidence_records:
            sanitized = sanitize_snippet(rec.snippet)
            transformed = sanitized != rec.snippet

            ev = NormalizedEvidence(
                evidence_type=default_ev_type,
                provenance=provenance,
                rule_id=rec.rule_id,
                matched_pattern=rec.matched_pattern,
                safe_snippet=sanitized,
                description=rec.description,
                provider_or_family=rec.db_family_hint.value,
                baseline_status=baseline_status,
                test_status=test_status,
                similarity_score=float(similarity) if similarity is not None else None,
                is_baseline_stable=is_stable,
                is_preexisting_in_baseline=preexisting,
                details={
                    "detection_status": finding.status.value,
                    "confidence": finding.confidence.value if finding.confidence else None,
                    "snippet_redacted": transformed,
                    "request_count": finding.request_count,
                    "limitations": finding.limitations,
                },
            )
            results.append(ev)

        return results

    @classmethod
    def normalize_nosqli_finding(
        cls,
        finding: NoSQLFinding,
        execution_id: str | None = None,
        run_id: str | None = None,
    ) -> list[NormalizedEvidence]:
        """Normalize a NoSQLFinding into a list of NormalizedEvidence records."""
        results: list[NormalizedEvidence] = []
        target_url = finding.target_url
        param_name = finding.parameter.name
        param_loc = finding.parameter.location
        test_id = finding.test_id

        if finding.technique == NoSQLTestTechnique.ERROR_BASED:
            default_ev_type = EvidenceType.ERROR_SIGNATURE
        else:
            default_ev_type = EvidenceType.DIFFERENTIAL_PAIR

        baseline_status = finding.baseline_metadata.get("status_code")
        test_status = finding.test_response_metadata.get("status_code")
        similarity = finding.test_response_metadata.get("similarity")
        is_stable = finding.baseline_metadata.get("is_stable", True)
        preexisting = finding.baseline_metadata.get("has_preexisting_error", False)

        provenance = EvidenceProvenance(
            engine="nosqli",
            vulnerability_class=VulnerabilityClass.NOSQLI,
            target_url=target_url,
            parameter_name=param_name,
            parameter_location=param_loc,
            test_id=test_id,
            execution_id=execution_id,
            run_id=run_id,
            source_finding_id=finding.finding_id,
            timestamp=finding.timestamp,
        )

        if not finding.evidence_records:
            ev = NormalizedEvidence(
                evidence_type=default_ev_type,
                provenance=provenance,
                rule_id=finding.technique.value,
                matched_pattern="no_specific_pattern",
                safe_snippet=sanitize_snippet(finding.evidence_summary),
                description=finding.evidence_summary or "NoSQLi detector outcome summary.",
                provider_or_family="unknown",
                baseline_status=baseline_status,
                test_status=test_status,
                similarity_score=float(similarity) if similarity is not None else None,
                is_baseline_stable=is_stable,
                is_preexisting_in_baseline=preexisting,
                details={
                    "detection_status": finding.status.value,
                    "confidence": finding.confidence.value if finding.confidence else None,
                    "request_count": finding.request_count,
                    "limitations": finding.limitations,
                },
            )
            results.append(ev)
            return results

        for rec in finding.evidence_records:
            sanitized = sanitize_snippet(rec.snippet)
            transformed = sanitized != rec.snippet

            ev = NormalizedEvidence(
                evidence_type=default_ev_type,
                provenance=provenance,
                rule_id=rec.rule_id,
                matched_pattern=rec.matched_pattern,
                safe_snippet=sanitized,
                description=rec.description,
                provider_or_family=rec.provider_family_hint.value,
                baseline_status=baseline_status,
                test_status=test_status,
                similarity_score=float(similarity) if similarity is not None else None,
                is_baseline_stable=is_stable,
                is_preexisting_in_baseline=preexisting,
                details={
                    "detection_status": finding.status.value,
                    "confidence": finding.confidence.value if finding.confidence else None,
                    "snippet_redacted": transformed,
                    "request_count": finding.request_count,
                    "limitations": finding.limitations,
                },
            )
            results.append(ev)

        return results

    @classmethod
    def normalize_execution_record(
        cls,
        record: ExecutionRecord,
        target_url: str,
        engine_name: str,
        run_id: str | None = None,
    ) -> list[NormalizedEvidence]:
        """Normalize an ExecutionRecord and any nested findings into NormalizedEvidence records."""
        results: list[NormalizedEvidence] = []

        v_class = (
            VulnerabilityClass.SQLI
            if "sqli" in engine_name.lower() and "nosqli" not in engine_name.lower()
            else (
                VulnerabilityClass.NOSQLI
                if "nosqli" in engine_name.lower()
                else VulnerabilityClass.UNKNOWN
            )
        )

        provenance = EvidenceProvenance(
            engine=engine_name,
            vulnerability_class=v_class,
            target_url=target_url,
            parameter_name=record.parameter_name,
            parameter_location=record.parameter_location,
            test_id=record.test_case_id,
            payload_id=record.payload_id,
            execution_id=record.execution_id,
            run_id=run_id,
            timestamp=record.timestamp,
        )

        # If execution was not successful (SKIPPED, FAILED, CANCELLED), record an execution trace evidence
        if record.status in (
            ExecutionStatus.FAILED,
            ExecutionStatus.SKIPPED,
            ExecutionStatus.CANCELLED,
        ):
            ev = NormalizedEvidence(
                evidence_type=EvidenceType.EXECUTION_TRACE,
                provenance=provenance,
                rule_id=f"execution_status_{record.status.value}",
                matched_pattern=record.status.value,
                safe_snippet=sanitize_snippet(record.error_or_skip_reason or ""),
                description=(
                    f"Execution {record.status.value}: {record.error_or_skip_reason or 'No details'}"
                ),
                provider_or_family="unknown",
                test_status=record.status_code,
                is_baseline_stable=True,
                is_preexisting_in_baseline=False,
                details={
                    "execution_status": record.status.value,
                    "request_count": record.request_count,
                    "elapsed_seconds": record.elapsed_seconds,
                },
            )
            results.append(ev)
            return results

        # If the execution record contains nested findings, normalize them
        if record.findings:
            for f in record.findings:
                if isinstance(f, SQLiFinding):
                    results.extend(
                        cls.normalize_sqli_finding(
                            f, execution_id=record.execution_id, run_id=run_id
                        )
                    )
                elif isinstance(f, NoSQLFinding):
                    results.extend(
                        cls.normalize_nosqli_finding(
                            f, execution_id=record.execution_id, run_id=run_id
                        )
                    )
                elif isinstance(f, dict):
                    # Dict finding
                    results.extend(
                        cls.normalize_dict_finding(
                            f,
                            target_url=target_url,
                            engine_name=engine_name,
                            execution_id=record.execution_id,
                            run_id=run_id,
                        )
                    )
        else:
            # Successfully executed test case with no findings generated
            ev = NormalizedEvidence(
                evidence_type=EvidenceType.EXECUTION_TRACE,
                provenance=provenance,
                rule_id="execution_clean",
                matched_pattern="no_signal",
                safe_snippet="",
                description="Test case completed execution with no signal observed.",
                provider_or_family="unknown",
                test_status=record.status_code,
                is_baseline_stable=True,
                is_preexisting_in_baseline=False,
                details={
                    "execution_status": record.status.value,
                    "request_count": record.request_count,
                    "elapsed_seconds": record.elapsed_seconds,
                },
            )
            results.append(ev)

        return results

    @classmethod
    def normalize_dict_finding(
        cls,
        data: dict[str, Any],
        target_url: str | None = None,
        engine_name: str | None = None,
        execution_id: str | None = None,
        run_id: str | None = None,
    ) -> list[NormalizedEvidence]:
        """Normalize an arbitrary dictionary finding or fixture record with robust fallbacks."""
        t_url = data.get("target_url") or target_url or "http://unknown.local"
        eng = data.get("engine") or engine_name or "sqli"

        v_class = VulnerabilityClass.NOSQLI if "nosqli" in eng.lower() else VulnerabilityClass.SQLI

        p_name = "unknown"
        p_loc = ParameterLocation.QUERY

        if "parameter" in data and isinstance(data["parameter"], dict):
            p_name = data["parameter"].get("name", "unknown")
            loc_val = data["parameter"].get("location", "query")
            try:
                p_loc = ParameterLocation(loc_val)
            except ValueError:
                p_loc = ParameterLocation.QUERY
        elif "parameter" in data and isinstance(data["parameter"], str):
            p_name = data["parameter"]
        elif "param_name" in data:
            p_name = data["param_name"]

        if "location" in data:
            with contextlib.suppress(ValueError):
                p_loc = ParameterLocation(data["location"])

        test_id = data.get("test_id") or data.get("test_case_id")
        payload_id = data.get("payload_id")

        provenance = EvidenceProvenance(
            engine=eng,
            vulnerability_class=v_class,
            target_url=t_url,
            parameter_name=p_name,
            parameter_location=p_loc,
            test_id=test_id,
            payload_id=payload_id,
            execution_id=execution_id or data.get("execution_id"),
            run_id=run_id or data.get("run_id"),
            source_finding_id=data.get("finding_id"),
        )

        base_info = data.get("baseline_metadata") or data.get("baseline", {})
        test_info = data.get("test_response_metadata") or data.get("test", {})

        base_status = base_info.get("status_code")
        test_status = test_info.get("status_code")
        similarity = test_info.get("similarity")
        is_stable = base_info.get("is_stable", True)
        preexisting = base_info.get("has_preexisting_error", False)

        evidence_records = data.get("evidence_records", [])
        if evidence_records and isinstance(evidence_records, list):
            results = []
            for rec in evidence_records:
                if isinstance(rec, dict):
                    snip = sanitize_snippet(rec.get("snippet", ""))
                    provider_hint = str(
                        rec.get("db_family_hint") or rec.get("provider_family_hint") or "unknown"
                    )
                    ev = NormalizedEvidence(
                        evidence_type=EvidenceType.ERROR_SIGNATURE,
                        provenance=provenance,
                        rule_id=rec.get("rule_id", "dict_rule"),
                        matched_pattern=rec.get("matched_pattern", "error_pattern"),
                        safe_snippet=snip,
                        description=rec.get("description", "Dictionary error evidence"),
                        provider_or_family=provider_hint,
                        baseline_status=base_status,
                        test_status=test_status,
                        similarity_score=float(similarity) if similarity is not None else None,
                        is_baseline_stable=is_stable,
                        is_preexisting_in_baseline=preexisting,
                        details={"status": data.get("status")},
                    )
                    results.append(ev)
            return results

        # Single evidence record from dict
        ev_summary = sanitize_snippet(data.get("evidence_summary", data.get("description", "")))
        ev = NormalizedEvidence(
            evidence_type=(
                EvidenceType.DIFFERENTIAL_PAIR
                if "differential" in str(data.get("technique", "")).lower()
                else EvidenceType.ERROR_SIGNATURE
            ),
            provenance=provenance,
            rule_id=str(data.get("rule_id", data.get("technique", "dict_evidence"))),
            matched_pattern=str(data.get("matched_pattern", "dict_signal")),
            safe_snippet=ev_summary,
            description=ev_summary or "Dictionary evidence representation.",
            provider_or_family=str(data.get("db_family", data.get("provider", "unknown"))),
            baseline_status=base_status,
            test_status=test_status,
            similarity_score=float(similarity) if similarity is not None else None,
            is_baseline_stable=is_stable,
            is_preexisting_in_baseline=preexisting,
            details={"status": data.get("status")},
        )
        return [ev]

    @classmethod
    def normalize_execution_run_result(
        cls, run_result: ExecutionRunResult
    ) -> list[NormalizedEvidence]:
        """Normalize an entire ExecutionRunResult and its records."""
        results: list[NormalizedEvidence] = []
        for rec in run_result.records:
            results.extend(
                cls.normalize_execution_record(
                    record=rec,
                    target_url=run_result.target_url,
                    engine_name=run_result.engine_name,
                    run_id=run_result.run_id,
                )
            )
        return results
