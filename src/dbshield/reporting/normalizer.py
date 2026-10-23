"""Finding normalization, correlation, and deduplication layer (Phase 8).

Translates findings and verification results from Phase 4 (SQLi), Phase 5 (NoSQLi),
Phase 6 (Execution Orchestrator), and Phase 7 (Verification Engine) into unified,
deterministic NormalizedSecurityFinding objects and structured SecurityAssessmentReports.
"""

from __future__ import annotations

import contextlib
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from dbshield.nosqli.models import NoSQLScanResult
from dbshield.reporting.models import (
    FindingSeverity,
    NormalizedSecurityFinding,
    ReportMetadata,
    SecurityAssessmentReport,
    VulnerabilityCategory,
)
from dbshield.reporting.redaction import redact_parameter, redact_text
from dbshield.reporting.severity import SeverityAssessor
from dbshield.sqli.models import SQLiScanResult
from dbshield.verification.models import (
    ConfidenceLevel,
    VerificationFinding,
    VerificationResult,
    VerificationStatus,
)


def _extract_endpoint(url: str) -> str:
    """Extract path component from target URL, defaulting to '/' if empty."""
    try:
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path
        return path if path else "/"
    except Exception:
        return "/"


def _canonicalize_category(raw_category: str) -> VulnerabilityCategory:
    """Normalize arbitrary string category into standard VulnerabilityCategory."""
    clean = raw_category.lower().strip().replace("-", "_").replace(" ", "_")
    if "nosql" in clean:
        return VulnerabilityCategory.NOSQL_INJECTION
    if "sql" in clean:
        return VulnerabilityCategory.SQL_INJECTION
    if "auth" in clean or "login" in clean:
        return VulnerabilityCategory.AUTHENTICATION_BYPASS
    if "info" in clean or "disclosure" in clean or "leak" in clean:
        return VulnerabilityCategory.INFORMATION_DISCLOSURE
    if "config" in clean:
        return VulnerabilityCategory.CONFIGURATION_WEAKNESS
    return VulnerabilityCategory.UNKNOWN


class FindingNormalizer:
    """Cross-engine normalization, correlation, and report synthesis."""

    @classmethod
    def from_verification_finding(cls, finding: VerificationFinding) -> NormalizedSecurityFinding:
        """Convert a Phase 7 VerificationFinding into a NormalizedSecurityFinding."""
        category = _canonicalize_category(finding.vulnerability_class.value)
        endpoint = _extract_endpoint(finding.target_url)
        param_name = redact_parameter(finding.parameter_name)
        technique = (
            finding.corroborating_evidence[0].rule_id
            if finding.corroborating_evidence
            else "generic"
        )
        finding_id = NormalizedSecurityFinding.compute_deterministic_id(
            target_url=finding.target_url,
            category=category.value,
            parameter_location=finding.parameter_location.value,
            parameter_name=param_name,
            technique=technique,
        )

        severity, rationale = SeverityAssessor.evaluate_severity(
            category=category,
            status=finding.status,
            technique=technique,
        )

        cwe_id, cwe_name = SeverityAssessor.get_cwe_mapping(category)
        remediation = SeverityAssessor.get_remediation(category)

        # Build clean evidence summary from corroborating or all evidence
        ev_items = finding.corroborating_evidence or finding.all_evidence
        ev_summary = (
            redact_text(ev_items[0].description)
            if ev_items
            else redact_text(finding.verification_rationale)
        )
        ev_ids = [ev.evidence_id for ev in ev_items]

        title = f"{status_prefix(finding.status)} {category.value.replace('_', ' ').title()} in {finding.parameter_location.value} parameter '{param_name}'"

        return NormalizedSecurityFinding(
            id=finding_id,
            title=title,
            category=category,
            subtype=technique,
            target_url=finding.target_url,
            endpoint=endpoint,
            http_method="GET",
            parameter_name=param_name,
            parameter_location=finding.parameter_location,
            engine=finding.engine,
            technique=technique,
            verification_status=finding.status,
            confidence_level=finding.confidence.level,
            confidence_score=finding.confidence.score,
            severity=severity,
            severity_rationale=rationale,
            description=redact_text(finding.verification_rationale),
            evidence_summary=ev_summary,
            evidence_count=len(ev_items),
            evidence_ids=ev_ids,
            remediation=remediation,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            execution_references=finding.execution_references,
            first_observed_at=finding.timestamp,
            metadata={"verification_id": finding.verification_id},
        )

    @classmethod
    def from_verification_result(
        cls, result: VerificationResult, scope: list[str] | None = None
    ) -> SecurityAssessmentReport:
        """Translate a Phase 7 VerificationResult into a complete SecurityAssessmentReport."""
        normalized_findings: list[NormalizedSecurityFinding] = []
        for f in result.findings:
            normalized_findings.append(cls.from_verification_finding(f))

        # Deduplicate and consolidate findings
        deduped = cls.deduplicate_findings(normalized_findings)

        # Build aggregate metadata
        metadata = cls.build_report_metadata(
            target_url=result.target_url,
            findings=deduped,
            scope=scope or [result.target_url],
            limitations=result.limitations,
        )

        return SecurityAssessmentReport(
            metadata=metadata,
            findings=deduped,
        )

    @classmethod
    def from_sqli_scan_result(
        cls, result: SQLiScanResult, scope: list[str] | None = None
    ) -> SecurityAssessmentReport:
        """Convert Phase 4 SQLiScanResult directly into a SecurityAssessmentReport."""
        findings: list[NormalizedSecurityFinding] = []
        category = VulnerabilityCategory.SQL_INJECTION
        cwe_id, cwe_name = SeverityAssessor.get_cwe_mapping(category)
        remediation = SeverityAssessor.get_remediation(category)

        for f in result.findings:
            param_name = redact_parameter(f.parameter.name)
            endpoint = _extract_endpoint(f.target_url)
            technique = f.technique.value
            finding_id = NormalizedSecurityFinding.compute_deterministic_id(
                target_url=f.target_url,
                category=category.value,
                parameter_location=f.parameter.location.value,
                parameter_name=param_name,
                technique=technique,
            )

            # Map detection status to preliminary verification status
            status = VerificationStatus.POTENTIAL_INDICATOR
            conf_level = ConfidenceLevel.MEDIUM
            conf_score = 0.50

            severity, rationale = SeverityAssessor.evaluate_severity(
                category=category,
                status=status,
                technique=technique,
            )

            ev_summary = (
                redact_text(f.evidence_records[0].description)
                if f.evidence_records
                else "SQL injection indicator observed."
            )

            findings.append(
                NormalizedSecurityFinding(
                    id=finding_id,
                    title=f"Potential SQL Injection in {f.parameter.location.value} parameter '{param_name}'",
                    category=category,
                    subtype=technique,
                    target_url=f.target_url,
                    endpoint=endpoint,
                    http_method=f.http_method,
                    parameter_name=param_name,
                    parameter_location=f.parameter.location,
                    engine="sqli",
                    technique=technique,
                    verification_status=status,
                    confidence_level=conf_level,
                    confidence_score=conf_score,
                    severity=severity,
                    severity_rationale=rationale,
                    description=f"Potential SQL injection detected via {technique} technique.",
                    evidence_summary=ev_summary,
                    evidence_count=len(f.evidence_records),
                    evidence_ids=[],
                    remediation=remediation,
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    execution_references={"test_id": f.test_id},
                    first_observed_at=datetime.now(UTC),
                )
            )

        deduped = cls.deduplicate_findings(findings)
        metadata = cls.build_report_metadata(
            target_url=result.target_url,
            findings=deduped,
            scope=scope or [result.target_url],
            limitations=["Unverified direct detector results; subject to Phase 7 verification."],
        )
        return SecurityAssessmentReport(metadata=metadata, findings=deduped)

    @classmethod
    def from_nosqli_scan_result(
        cls, result: NoSQLScanResult, scope: list[str] | None = None
    ) -> SecurityAssessmentReport:
        """Convert Phase 5 NoSQLScanResult directly into a SecurityAssessmentReport."""
        findings: list[NormalizedSecurityFinding] = []
        category = VulnerabilityCategory.NOSQL_INJECTION
        cwe_id, cwe_name = SeverityAssessor.get_cwe_mapping(category)
        remediation = SeverityAssessor.get_remediation(category)

        for f in result.findings:
            param_name = redact_parameter(f.parameter.name)
            endpoint = _extract_endpoint(f.target_url)
            technique = f.technique.value
            finding_id = NormalizedSecurityFinding.compute_deterministic_id(
                target_url=f.target_url,
                category=category.value,
                parameter_location=f.parameter.location.value,
                parameter_name=param_name,
                technique=technique,
            )

            status = VerificationStatus.POTENTIAL_INDICATOR
            conf_level = ConfidenceLevel.MEDIUM
            conf_score = 0.50

            severity, rationale = SeverityAssessor.evaluate_severity(
                category=category,
                status=status,
                technique=technique,
            )

            ev_summary = (
                redact_text(f.evidence_records[0].description)
                if f.evidence_records
                else "NoSQL injection indicator observed."
            )

            findings.append(
                NormalizedSecurityFinding(
                    id=finding_id,
                    title=f"Potential NoSQL Injection in {f.parameter.location.value} parameter '{param_name}'",
                    category=category,
                    subtype=technique,
                    target_url=f.target_url,
                    endpoint=endpoint,
                    http_method=f.http_method,
                    parameter_name=param_name,
                    parameter_location=f.parameter.location,
                    engine="nosqli",
                    technique=technique,
                    verification_status=status,
                    confidence_level=conf_level,
                    confidence_score=conf_score,
                    severity=severity,
                    severity_rationale=rationale,
                    description=f"Potential NoSQL injection detected via {technique} technique.",
                    evidence_summary=ev_summary,
                    evidence_count=len(f.evidence_records),
                    evidence_ids=[],
                    remediation=remediation,
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    execution_references={"test_id": f.test_id},
                    first_observed_at=datetime.now(UTC),
                )
            )

        deduped = cls.deduplicate_findings(findings)
        metadata = cls.build_report_metadata(
            target_url=result.target_url,
            findings=deduped,
            scope=scope or [result.target_url],
            limitations=["Unverified direct detector results; subject to Phase 7 verification."],
        )
        return SecurityAssessmentReport(metadata=metadata, findings=deduped)

    @classmethod
    def from_dict_payload(
        cls, data: dict[str, Any], default_target_url: str = "http://unknown"
    ) -> SecurityAssessmentReport:
        """Parse raw dictionary data (e.g. from JSON file) into a SecurityAssessmentReport."""
        # 1. Direct SecurityAssessmentReport structure
        if "findings" in data and "metadata" in data:
            return SecurityAssessmentReport.model_validate(data)

        # 2. Phase 7 VerificationResult structure
        if "summary" in data and "findings" in data:
            vr = VerificationResult.model_validate(data)
            return cls.from_verification_result(vr)

        # 3. Phase 4 SQLiScanResult structure
        if "findings" in data and "candidate_parameters" in data:
            sqli_res = SQLiScanResult.model_validate(data)
            return cls.from_sqli_scan_result(sqli_res)

        # 4. Phase 5 NoSQLScanResult structure
        if "findings" in data and "tested_providers" in data:
            nosqli_res = NoSQLScanResult.model_validate(data)
            return cls.from_nosqli_scan_result(nosqli_res)

        # 5. Generic dictionary with findings list
        findings_raw = data.get("findings", [])
        if isinstance(findings_raw, list):
            findings: list[NormalizedSecurityFinding] = []
            for item in findings_raw:
                if isinstance(item, dict):
                    with contextlib.suppress(Exception):
                        findings.append(NormalizedSecurityFinding.model_validate(item))
            target_url = data.get("target_url", default_target_url)
            deduped = cls.deduplicate_findings(findings)
            meta = cls.build_report_metadata(
                target_url=target_url,
                findings=deduped,
                scope=[target_url],
                limitations=data.get("limitations", []),
            )
            return SecurityAssessmentReport(metadata=meta, findings=deduped)

        target_url = data.get("target_url", default_target_url)
        meta = cls.build_report_metadata(
            target_url=target_url,
            findings=[],
            scope=[target_url],
            limitations=[],
        )
        return SecurityAssessmentReport(metadata=meta, findings=[])

    @classmethod
    def deduplicate_findings(
        cls, findings: list[NormalizedSecurityFinding]
    ) -> list[NormalizedSecurityFinding]:
        """Deduplicate findings based on unique finding ID.

        If duplicate IDs exist:
        - Prioritize higher verification status (VERIFIED > CORROBORATED > POTENTIAL_INDICATOR > INCONCLUSIVE > REJECTED).
        - Accumulate evidence count and consolidate evidence IDs.
        - Preserve distinct parameters and transport locations.
        """
        status_rank: dict[VerificationStatus, int] = {
            VerificationStatus.VERIFIED: 10,
            VerificationStatus.CORROBORATED: 8,
            VerificationStatus.POTENTIAL_INDICATOR: 5,
            VerificationStatus.UNDER_ANALYSIS: 4,
            VerificationStatus.VERIFICATION_REQUIRED: 4,
            VerificationStatus.INCONCLUSIVE: 2,
            VerificationStatus.UNVERIFIABLE: 1,
            VerificationStatus.REJECTED: 0,
        }

        severity_rank: dict[FindingSeverity, int] = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 3,
            FindingSeverity.LOW: 2,
            FindingSeverity.INFO: 1,
        }

        grouped: dict[str, list[NormalizedSecurityFinding]] = {}
        for f in findings:
            grouped.setdefault(f.id, []).append(f)

        deduped: list[NormalizedSecurityFinding] = []
        for group in grouped.values():
            if len(group) == 1:
                deduped.append(group[0])
                continue

            # Select primary finding with highest verification status rank
            group.sort(
                key=lambda x: (
                    status_rank.get(x.verification_status, 0),
                    severity_rank.get(x.severity, 0),
                    x.confidence_score,
                ),
                reverse=True,
            )
            primary = group[0]

            # Merge evidence IDs and counts
            all_ev_ids = list(dict.fromkeys([ev for item in group for ev in item.evidence_ids]))
            total_ev_count = sum(item.evidence_count for item in group)

            merged = primary.model_copy(
                update={
                    "evidence_ids": all_ev_ids,
                    "evidence_count": max(len(all_ev_ids), total_ev_count),
                }
            )
            deduped.append(merged)

        # Sort output findings deterministically by severity (descending), then endpoint, then parameter
        deduped.sort(
            key=lambda x: (
                -severity_rank.get(x.severity, 0),
                -status_rank.get(x.verification_status, 0),
                x.endpoint,
                x.parameter_name,
            )
        )
        return deduped

    @classmethod
    def build_report_metadata(
        cls,
        target_url: str,
        findings: list[NormalizedSecurityFinding],
        scope: list[str],
        limitations: list[str],
    ) -> ReportMetadata:
        """Compute aggregate totals and summary counts for report metadata."""
        sev_counts: dict[str, int] = {s.value: 0 for s in FindingSeverity}
        status_counts: dict[str, int] = {st.value: 0 for st in VerificationStatus}
        cat_counts: dict[str, int] = {c.value: 0 for c in VulnerabilityCategory}

        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
            status_counts[f.verification_status.value] = (
                status_counts.get(f.verification_status.value, 0) + 1
            )
            cat_counts[f.category.value] = cat_counts.get(f.category.value, 0) + 1

        return ReportMetadata(
            target_url=target_url,
            total_findings=len(findings),
            findings_by_severity=sev_counts,
            findings_by_status=status_counts,
            findings_by_category=cat_counts,
            assessment_scope=scope,
            limitations=limitations,
        )


def status_prefix(status: VerificationStatus) -> str:
    """Return user-friendly descriptive prefix based on verification status."""
    if status == VerificationStatus.VERIFIED:
        return "Verified"
    if status == VerificationStatus.CORROBORATED:
        return "Corroborated"
    if status == VerificationStatus.INCONCLUSIVE:
        return "Inconclusive"
    if status == VerificationStatus.REJECTED:
        return "Rejected"
    if status == VerificationStatus.UNVERIFIABLE:
        return "Unverifiable"
    return "Potential"
