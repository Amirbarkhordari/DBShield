"""Evidence Analysis and Vulnerability Verification Engine for DBShield (Phase 7).

Coordinates evidence normalization, correlation, deduplication, confidence assessment,
state machine transitions, and false-positive reduction into reproducible assessment results.
"""

from typing import Any

from dbshield.execution.models import ExecutionRunResult
from dbshield.nosqli.models import NoSQLFinding
from dbshield.sqli.models import SQLiFinding
from dbshield.verification.confidence import ConfidenceAssessor
from dbshield.verification.correlator import EvidenceCorrelator
from dbshield.verification.models import (
    EvidenceType,
    NormalizedEvidence,
    StateTransitionRecord,
    VerificationFinding,
    VerificationResult,
    VerificationStatus,
    VerificationSummary,
)
from dbshield.verification.normalizer import EvidenceNormalizer
from dbshield.verification.state_machine import VerificationStateMachine

_DEFAULT_LIMITATIONS = [
    "Verification is strictly non-destructive and defensive; it does not perform automated exploitation or schema dumping.",
    "A clean, inconclusive, or rejected assessment does not guarantee the complete absence of secondary injection vulnerabilities.",
    "Confidence scores represent deterministic analytical certainty, not empirical or statistical exploitability probabilities.",
    "Baseline characterization reflects observed HTTP conditions at test time; dynamic environment changes may influence reproducibility.",
]


class VerificationEngine:
    """Core engine for evidence analysis and vulnerability verification."""

    def __init__(self, limitations: list[str] | None = None) -> None:
        self.limitations = limitations or _DEFAULT_LIMITATIONS

    def verify_evidence(
        self,
        evidence_items: list[NormalizedEvidence],
        target_url: str = "http://unknown.local",
        execution_status: str = "executed",
    ) -> VerificationResult:
        """Analyze normalized evidence items, correlating and verifying candidate findings."""
        if not evidence_items:
            summary = VerificationSummary()
            return VerificationResult(
                target_url=target_url,
                summary=summary,
                findings=[],
                correlation_groups=[],
                limitations=self.limitations,
            )

        # 1. Correlate and deduplicate evidence into groups
        groups = EvidenceCorrelator.correlate(evidence_items)

        findings: list[VerificationFinding] = []
        verified_cnt = 0
        corroborated_cnt = 0
        potential_cnt = 0
        inconclusive_cnt = 0
        rejected_cnt = 0
        unverifiable_cnt = 0

        # 2. Evaluate each correlation group
        for group in groups:
            items = group.evidence_items
            is_stable = all(ev.is_baseline_stable for ev in items)
            has_preexisting = any(ev.is_preexisting_in_baseline for ev in items)

            # Separate corroborating and contradictory items
            corroborating = [
                ev
                for ev in items
                if not ev.is_contradictory and ev.evidence_type != EvidenceType.EXECUTION_TRACE
            ]
            contradictory = [ev for ev in items if ev.is_contradictory]

            # Audit trail
            history: list[StateTransitionRecord] = []

            # Initial state
            init_status = VerificationStatus.POTENTIAL_INDICATOR
            _, r_init = VerificationStateMachine.transition(
                from_status=init_status,
                to_status=VerificationStatus.UNDER_ANALYSIS,
                reason="Initiating multi-factor evidence analysis and false-positive filtering.",
                evidence_items=items,
                is_baseline_stable=is_stable,
                execution_status=execution_status,
                has_preexisting_baseline_error=has_preexisting,
                history=history,
            )

            # Determine final state & rationale
            target_status, rationale = VerificationStateMachine.evaluate_target_status(
                evidence_items=items,
                is_baseline_stable=is_stable,
                execution_status=execution_status,
                has_preexisting_baseline_error=has_preexisting,
            )

            # Check if execution failed or was cancelled
            has_failed = execution_status.lower() in {"failed", "cancelled", "skipped"} or any(
                ev.evidence_type == EvidenceType.EXECUTION_TRACE
                and ev.details.get("execution_status") in {"failed", "cancelled", "skipped"}
                for ev in items
            )

            # Transition to target state
            final_status, _ = VerificationStateMachine.transition(
                from_status=VerificationStatus.UNDER_ANALYSIS,
                to_status=target_status,
                reason=rationale,
                evidence_items=items,
                is_baseline_stable=is_stable,
                execution_status=execution_status,
                has_preexisting_baseline_error=has_preexisting,
                history=history,
            )

            # Calculate explainable confidence
            confidence = ConfidenceAssessor.evaluate(
                evidence_items=items,
                is_baseline_stable=is_stable,
                has_failed_execution=has_failed,
            )

            # Determine rejection/downgrade reason
            rejection_reason = None
            if final_status in (VerificationStatus.REJECTED, VerificationStatus.INCONCLUSIVE):
                rejection_reason = rationale

            # Determine recommended next step
            recommended_next = None
            if final_status == VerificationStatus.INCONCLUSIVE:
                recommended_next = (
                    "Baseline stability or differential response was ambiguous. "
                    "Recommend repeating the test with increased baseline sample count, "
                    "or safely reviewing database error logs under laboratory conditions."
                )
            elif final_status == VerificationStatus.UNVERIFIABLE:
                recommended_next = (
                    "Execution did not complete successfully. Verify target scope authorization, "
                    "network connectivity, and request budget parameters."
                )

            # Redact parameter name if sensitive
            safe_param_name = EvidenceNormalizer.redact_parameter_name(group.parameter_name)

            # Count totals
            if final_status == VerificationStatus.VERIFIED:
                verified_cnt += 1
            elif final_status == VerificationStatus.CORROBORATED:
                corroborated_cnt += 1
            elif final_status == VerificationStatus.POTENTIAL_INDICATOR:
                potential_cnt += 1
            elif final_status == VerificationStatus.INCONCLUSIVE:
                inconclusive_cnt += 1
            elif final_status == VerificationStatus.REJECTED:
                rejected_cnt += 1
            elif final_status == VerificationStatus.UNVERIFIABLE:
                unverifiable_cnt += 1

            finding = VerificationFinding(
                finding_id=group.source_finding_ids[0] if group.source_finding_ids else None,
                vulnerability_class=group.vulnerability_class,
                engine=items[0].provenance.engine if items else "unknown",
                target_url=group.target_url,
                parameter_name=safe_param_name,
                parameter_location=group.parameter_location,
                status=final_status,
                confidence=confidence,
                corroborating_evidence=corroborating,
                contradictory_evidence=contradictory,
                all_evidence=items,
                state_history=history,
                verification_rationale=rationale,
                rejection_or_downgrade_reason=rejection_reason,
                recommended_next_step=recommended_next,
                limitations=self.limitations,
                execution_references={
                    "correlation_group_id": group.group_id,
                    "execution_ids": group.execution_ids,
                    "source_finding_ids": group.source_finding_ids,
                    "deduplication_notes": group.deduplication_notes,
                },
            )
            findings.append(finding)

        summary = VerificationSummary(
            total_evaluated=len(findings),
            verified_count=verified_cnt,
            corroborated_count=corroborated_cnt,
            potential_indicator_count=potential_cnt,
            inconclusive_count=inconclusive_cnt,
            rejected_count=rejected_cnt,
            unverifiable_count=unverifiable_cnt,
        )

        return VerificationResult(
            target_url=target_url,
            summary=summary,
            findings=findings,
            correlation_groups=groups,
            limitations=self.limitations,
        )

    def verify_findings(
        self,
        sqli_findings: list[SQLiFinding] | None = None,
        nosqli_findings: list[NoSQLFinding] | None = None,
        target_url: str = "http://unknown.local",
    ) -> VerificationResult:
        """Normalize and verify existing SQLi and NoSQLi findings."""
        evidence_items: list[NormalizedEvidence] = []
        if sqli_findings:
            for f in sqli_findings:
                evidence_items.extend(EvidenceNormalizer.normalize_sqli_finding(f))
                if target_url == "http://unknown.local" and f.target_url:
                    target_url = f.target_url

        if nosqli_findings:
            for nf in nosqli_findings:
                evidence_items.extend(EvidenceNormalizer.normalize_nosqli_finding(nf))
                if target_url == "http://unknown.local" and nf.target_url:
                    target_url = nf.target_url

        return self.verify_evidence(evidence_items=evidence_items, target_url=target_url)

    def verify_execution_run(self, run_result: ExecutionRunResult) -> VerificationResult:
        """Normalize and verify an ExecutionRunResult from Phase 6."""
        evidence_items = EvidenceNormalizer.normalize_execution_run_result(run_result)
        return self.verify_evidence(
            evidence_items=evidence_items,
            target_url=run_result.target_url,
            execution_status=run_result.execution_status,
        )

    def verify_dict_records(
        self, records: list[dict[str, Any]], target_url: str = "http://unknown.local"
    ) -> VerificationResult:
        """Normalize and verify raw dictionary findings or offline fixture records."""
        evidence_items: list[NormalizedEvidence] = []
        for r in records:
            evidence_items.extend(
                EvidenceNormalizer.normalize_dict_finding(r, target_url=target_url)
            )
            if target_url == "http://unknown.local" and "target_url" in r:
                target_url = r["target_url"]

        return self.verify_evidence(evidence_items=evidence_items, target_url=target_url)
