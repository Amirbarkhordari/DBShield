"""Verification Lifecycle State Machine for DBShield (Phase 7).

Manages formal state transitions, validates prerequisites, blocks illegal transitions,
and maintains an immutable, traceable audit history for every candidate finding.
"""

from dbshield.exceptions import InvalidStateTransitionError
from dbshield.verification.models import (
    EvidenceType,
    NormalizedEvidence,
    StateTransitionRecord,
    VerificationStatus,
)

# Valid state transition graph
_VALID_TRANSITIONS: dict[VerificationStatus, set[VerificationStatus]] = {
    VerificationStatus.POTENTIAL_INDICATOR: {
        VerificationStatus.UNDER_ANALYSIS,
        VerificationStatus.UNVERIFIABLE,
    },
    VerificationStatus.UNDER_ANALYSIS: {
        VerificationStatus.VERIFICATION_REQUIRED,
        VerificationStatus.CORROBORATED,
        VerificationStatus.VERIFIED,
        VerificationStatus.INCONCLUSIVE,
        VerificationStatus.REJECTED,
        VerificationStatus.UNVERIFIABLE,
    },
    VerificationStatus.VERIFICATION_REQUIRED: {
        VerificationStatus.CORROBORATED,
        VerificationStatus.VERIFIED,
        VerificationStatus.INCONCLUSIVE,
        VerificationStatus.REJECTED,
        VerificationStatus.UNVERIFIABLE,
    },
    VerificationStatus.CORROBORATED: {
        VerificationStatus.VERIFIED,
        VerificationStatus.INCONCLUSIVE,
        VerificationStatus.REJECTED,
        VerificationStatus.UNVERIFIABLE,
    },
    VerificationStatus.INCONCLUSIVE: {
        VerificationStatus.UNDER_ANALYSIS,
        VerificationStatus.REJECTED,
        VerificationStatus.UNVERIFIABLE,
    },
    VerificationStatus.VERIFIED: {
        VerificationStatus.INCONCLUSIVE,
        VerificationStatus.REJECTED,
    },
    VerificationStatus.REJECTED: set(),  # Terminal state
    VerificationStatus.UNVERIFIABLE: set(),  # Terminal state
}


class VerificationStateMachine:
    """Enforces state transition rules, prerequisites, and audit logging."""

    @classmethod
    def can_transition(
        cls,
        from_status: VerificationStatus,
        to_status: VerificationStatus,
    ) -> bool:
        """Check if a transition between two states is structurally permitted in the lifecycle graph."""
        if from_status == to_status:
            return True
        allowed = _VALID_TRANSITIONS.get(from_status, set())
        return to_status in allowed

    @classmethod
    def validate_prerequisites(
        cls,
        from_status: VerificationStatus,
        to_status: VerificationStatus,
        evidence_items: list[NormalizedEvidence],
        is_baseline_stable: bool = True,
        execution_status: str = "executed",
        has_preexisting_baseline_error: bool = False,
    ) -> tuple[bool, str | None]:
        """Validate whether domain prerequisites for transitioning to `to_status` are satisfied."""
        if from_status == to_status:
            return True, None

        exec_status_clean = execution_status.lower()

        # Rule 1: A failed, cancelled, or skipped execution CANNOT produce VERIFIED or CORROBORATED
        if exec_status_clean in {"failed", "cancelled", "skipped"} and to_status in {
            VerificationStatus.VERIFIED,
            VerificationStatus.CORROBORATED,
        }:
            return (
                False,
                f"Execution status is '{exec_status_clean}'; failed or cancelled executions cannot produce verified findings.",
            )

        # Rule 2: A database error pre-existing in baseline cannot be attributed to test input
        if has_preexisting_baseline_error and to_status in {
            VerificationStatus.VERIFIED,
            VerificationStatus.CORROBORATED,
        }:
            return (
                False,
                "Pre-existing database error in baseline precludes verification as an injection finding.",
            )

        # Rule 3: Unstable baseline precludes differential verification
        if not is_baseline_stable:
            has_diff = any(
                ev.evidence_type == EvidenceType.DIFFERENTIAL_PAIR for ev in evidence_items
            )
            if has_diff and to_status == VerificationStatus.VERIFIED:
                return (
                    False,
                    "Baseline is unstable; differential response comparisons cannot confirm vulnerability.",
                )

        # Rule 4: Generic HTTP error alone cannot confirm a vulnerability
        if to_status == VerificationStatus.VERIFIED:
            has_specific_signal = any(
                ev.evidence_type in {EvidenceType.ERROR_SIGNATURE, EvidenceType.DIFFERENTIAL_PAIR}
                and ev.provider_or_family not in {"unknown", "generic_server_error"}
                for ev in evidence_items
            )
            if not has_specific_signal and not any(
                ev.evidence_type == EvidenceType.DIFFERENTIAL_PAIR
                and ev.similarity_score is not None
                for ev in evidence_items
            ):
                return (
                    False,
                    "Verification requires specific database error signature or differential evidence; generic HTTP status is insufficient.",
                )

        return True, None

    @classmethod
    def transition(
        cls,
        from_status: VerificationStatus,
        to_status: VerificationStatus,
        reason: str,
        evidence_items: list[NormalizedEvidence] | None = None,
        is_baseline_stable: bool = True,
        execution_status: str = "executed",
        has_preexisting_baseline_error: bool = False,
        history: list[StateTransitionRecord] | None = None,
    ) -> tuple[VerificationStatus, StateTransitionRecord]:
        """Execute a state transition, verifying graph legality and domain prerequisites.

        Raises:
            InvalidStateTransitionError: If the transition is illegal or prerequisites are violated.
        """
        # Graph legality check
        if not cls.can_transition(from_status, to_status):
            msg = f"Illegal verification state transition from '{from_status.value}' to '{to_status.value}'."
            cause = "The state transition is not allowed by the verification lifecycle graph."
            remedy = f"Valid transitions from '{from_status.value}' are: {[s.value for s in _VALID_TRANSITIONS.get(from_status, set())]}."
            raise InvalidStateTransitionError(
                message=msg,
                cause=cause,
                remedy=remedy,
                context={"from_status": from_status.value, "to_status": to_status.value},
            )

        # Domain prerequisites check
        items = evidence_items or []
        ok, prerequisite_failure = cls.validate_prerequisites(
            from_status=from_status,
            to_status=to_status,
            evidence_items=items,
            is_baseline_stable=is_baseline_stable,
            execution_status=execution_status,
            has_preexisting_baseline_error=has_preexisting_baseline_error,
        )
        if not ok:
            msg = f"Cannot transition to '{to_status.value}': prerequisite condition failed."
            cause = prerequisite_failure or "Domain prerequisites were not satisfied."
            remedy = "Review evidence quality, execution status, and baseline stability."
            raise InvalidStateTransitionError(
                message=msg,
                cause=cause,
                remedy=remedy,
                context={
                    "from_status": from_status.value,
                    "to_status": to_status.value,
                    "reason": prerequisite_failure,
                },
            )

        record = StateTransitionRecord(
            from_status=from_status,
            to_status=to_status,
            reason=reason,
        )

        if history is not None:
            history.append(record)

        return to_status, record

    @classmethod
    def evaluate_target_status(
        cls,
        evidence_items: list[NormalizedEvidence],
        is_baseline_stable: bool = True,
        execution_status: str = "executed",
        has_preexisting_baseline_error: bool = False,
    ) -> tuple[VerificationStatus, str]:
        """Deterministically determine the appropriate lifecycle status and rationale based on evidence."""
        exec_status_clean = execution_status.lower()

        # 1. Transport or execution operational failures
        if exec_status_clean in {"failed", "cancelled", "skipped"}:
            return (
                VerificationStatus.UNVERIFIABLE,
                f"Execution did not complete successfully (status: '{exec_status_clean}').",
            )

        if not evidence_items:
            return (
                VerificationStatus.UNVERIFIABLE,
                "No evidence records available to evaluate.",
            )

        # 2. Check for pre-existing baseline errors -> REJECTED (False positive)
        if has_preexisting_baseline_error or any(
            ev.is_preexisting_in_baseline for ev in evidence_items
        ):
            return (
                VerificationStatus.REJECTED,
                "Database error indicator was present in normal baseline response prior to testing.",
            )

        # 3. Check for generic server errors without DB signatures -> REJECTED (False positive)
        is_all_generic = all(
            ev.provider_or_family in {"generic_server_error", "unknown"}
            and ev.evidence_type != EvidenceType.DIFFERENTIAL_PAIR
            and (ev.test_status in {400, 500} or "generic" in ev.rule_id.lower())
            for ev in evidence_items
        )
        if is_all_generic:
            return (
                VerificationStatus.REJECTED,
                "Response returned generic HTTP error code without database-specific error signatures.",
            )

        # 4. Check for contradictory evidence
        has_contradictions = any(ev.is_contradictory for ev in evidence_items)
        if has_contradictions:
            return (
                VerificationStatus.INCONCLUSIVE,
                "Contradictory or chaotic responses observed across comparative probes.",
            )

        # 5. Check baseline stability
        if not is_baseline_stable or any(not ev.is_baseline_stable for ev in evidence_items):
            return (
                VerificationStatus.INCONCLUSIVE,
                "Baseline response behavior was unstable; differential analysis cannot be confirmed.",
            )

        # 6. Look for high-specificity database signatures
        specific_db_families = {
            "mysql",
            "postgresql",
            "sqlite",
            "mssql",
            "oracle",
            "mongodb",
            "couchdb",
        }
        specific_error_evidence = [
            ev
            for ev in evidence_items
            if ev.evidence_type == EvidenceType.ERROR_SIGNATURE
            and ev.provider_or_family.lower() in specific_db_families
        ]

        differential_evidence = [
            ev for ev in evidence_items if ev.evidence_type == EvidenceType.DIFFERENTIAL_PAIR
        ]

        # 7. Corroborated: Agreement between independent detectors or multiple specific indicators
        if specific_error_evidence and differential_evidence:
            return (
                VerificationStatus.VERIFIED,
                "Corroborated by independent database error signature and boolean differential detector.",
            )

        # 8. Verified by specific error signature
        if specific_error_evidence:
            return (
                VerificationStatus.VERIFIED,
                f"Verified by provider-specific error signature ({specific_error_evidence[0].provider_or_family}).",
            )

        # 9. Verified by clean differential pair with stable baseline
        if differential_evidence:
            first_diff = differential_evidence[0]
            sim = first_diff.similarity_score
            # If status codes differed or similarity diverged significantly
            if (
                first_diff.baseline_status
                and first_diff.test_status
                and first_diff.baseline_status != first_diff.test_status
            ):
                return (
                    VerificationStatus.VERIFIED,
                    f"Verified by boolean differential status code divergence ({first_diff.baseline_status} vs {first_diff.test_status}).",
                )
            if sim is not None and sim < 0.70:
                return (
                    VerificationStatus.VERIFIED,
                    f"Verified by boolean differential body divergence (similarity: {sim:.2f}).",
                )
            return (
                VerificationStatus.CORROBORATED,
                "Differential indicator observed, supported by stable baseline.",
            )

        # Default fallback: inconclusive
        return (
            VerificationStatus.INCONCLUSIVE,
            "Evidence signal insufficient to confirm or reject finding.",
        )
