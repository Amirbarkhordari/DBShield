"""Unit tests for DBShield Verification State Machine and Lifecycle Transitions (Phase 7)."""

import pytest

from dbshield.exceptions import InvalidStateTransitionError
from dbshield.sqli.models import ParameterLocation
from dbshield.verification.models import (
    EvidenceProvenance,
    EvidenceType,
    NormalizedEvidence,
    StateTransitionRecord,
    VerificationStatus,
    VulnerabilityClass,
)
from dbshield.verification.state_machine import VerificationStateMachine


def _make_evidence(
    ev_type: EvidenceType = EvidenceType.ERROR_SIGNATURE,
    provider: str = "mysql",
    is_stable: bool = True,
    is_preexisting: bool = False,
    is_contradictory: bool = False,
    base_status: int = 200,
    test_status: int = 500,
    sim_score: float | None = None,
) -> NormalizedEvidence:
    prov = EvidenceProvenance(
        engine="sqli",
        vulnerability_class=VulnerabilityClass.SQLI,
        target_url="http://target.local/api",
        parameter_name="id",
        parameter_location=ParameterLocation.QUERY,
    )
    return NormalizedEvidence(
        evidence_type=ev_type,
        provenance=prov,
        rule_id="RULE_TEST",
        matched_pattern="pattern",
        safe_snippet="sample snippet",
        description="test description",
        provider_or_family=provider,
        baseline_status=base_status,
        test_status=test_status,
        similarity_score=sim_score,
        is_baseline_stable=is_stable,
        is_preexisting_in_baseline=is_preexisting,
        is_contradictory=is_contradictory,
    )


def test_state_machine_valid_transitions() -> None:
    """Verify permitted transitions in the lifecycle graph."""
    assert VerificationStateMachine.can_transition(
        VerificationStatus.POTENTIAL_INDICATOR, VerificationStatus.UNDER_ANALYSIS
    )
    assert VerificationStateMachine.can_transition(
        VerificationStatus.UNDER_ANALYSIS, VerificationStatus.VERIFIED
    )
    assert VerificationStateMachine.can_transition(
        VerificationStatus.UNDER_ANALYSIS, VerificationStatus.REJECTED
    )
    assert VerificationStateMachine.can_transition(
        VerificationStatus.UNDER_ANALYSIS, VerificationStatus.INCONCLUSIVE
    )
    assert VerificationStateMachine.can_transition(
        VerificationStatus.INCONCLUSIVE, VerificationStatus.UNDER_ANALYSIS
    )


def test_state_machine_invalid_transitions_rejected() -> None:
    """Verify illegal transitions are rejected by graph structure."""
    # From POTENTIAL_INDICATOR directly to VERIFIED is illegal without analysis
    assert not VerificationStateMachine.can_transition(
        VerificationStatus.POTENTIAL_INDICATOR, VerificationStatus.VERIFIED
    )
    # Terminal state REJECTED cannot transition to VERIFIED
    assert not VerificationStateMachine.can_transition(
        VerificationStatus.REJECTED, VerificationStatus.VERIFIED
    )
    # Terminal state UNVERIFIABLE cannot transition to VERIFIED
    assert not VerificationStateMachine.can_transition(
        VerificationStatus.UNVERIFIABLE, VerificationStatus.VERIFIED
    )


def test_transition_raises_on_illegal_graph_move() -> None:
    """Verify transition method raises InvalidStateTransitionError on forbidden transition."""
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        VerificationStateMachine.transition(
            from_status=VerificationStatus.REJECTED,
            to_status=VerificationStatus.VERIFIED,
            reason="Illegal attempt to un-reject",
        )
    assert "Illegal verification state transition" in exc_info.value.message


def test_prerequisite_blocks_verified_on_failed_execution() -> None:
    """Verify prerequisite check blocks VERIFIED if execution failed."""
    ev = _make_evidence()
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        VerificationStateMachine.transition(
            from_status=VerificationStatus.UNDER_ANALYSIS,
            to_status=VerificationStatus.VERIFIED,
            reason="Attempt verify on failed run",
            evidence_items=[ev],
            execution_status="failed",
        )
    assert "prerequisite condition failed" in exc_info.value.message.lower()


def test_prerequisite_blocks_verified_on_preexisting_baseline_error() -> None:
    """Verify prerequisite check blocks VERIFIED if error pre-existed in baseline."""
    ev = _make_evidence(is_preexisting=True)
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        VerificationStateMachine.transition(
            from_status=VerificationStatus.UNDER_ANALYSIS,
            to_status=VerificationStatus.VERIFIED,
            reason="Attempt verify on baseline error",
            evidence_items=[ev],
            has_preexisting_baseline_error=True,
        )
    assert "prerequisite condition failed" in exc_info.value.message.lower()


def test_prerequisite_blocks_differential_on_unstable_baseline() -> None:
    """Verify prerequisite check blocks VERIFIED for differential evidence if baseline is unstable."""
    ev = _make_evidence(ev_type=EvidenceType.DIFFERENTIAL_PAIR, is_stable=False)
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        VerificationStateMachine.transition(
            from_status=VerificationStatus.UNDER_ANALYSIS,
            to_status=VerificationStatus.VERIFIED,
            reason="Attempt verify on unstable baseline",
            evidence_items=[ev],
            is_baseline_stable=False,
        )
    assert "prerequisite condition failed" in exc_info.value.message.lower()


def test_evaluate_target_status_preexisting_error_yields_rejected() -> None:
    """Verify evaluate_target_status marks pre-existing baseline errors as REJECTED."""
    ev = _make_evidence(is_preexisting=True)
    status, rationale = VerificationStateMachine.evaluate_target_status(
        [ev], is_baseline_stable=True, has_preexisting_baseline_error=True
    )
    assert status == VerificationStatus.REJECTED
    assert "pre-existing" in rationale.lower() or "baseline" in rationale.lower()


def test_evaluate_target_status_generic_error_yields_rejected() -> None:
    """Verify evaluate_target_status marks generic HTTP errors without DB pattern as REJECTED."""
    ev = _make_evidence(provider="generic_server_error", test_status=500)
    status, rationale = VerificationStateMachine.evaluate_target_status(
        [ev], is_baseline_stable=True
    )
    assert status == VerificationStatus.REJECTED
    assert "generic http error" in rationale.lower()


def test_evaluate_target_status_unstable_baseline_yields_inconclusive() -> None:
    """Verify evaluate_target_status marks unstable baselines as INCONCLUSIVE."""
    ev = _make_evidence(ev_type=EvidenceType.DIFFERENTIAL_PAIR, is_stable=False)
    status, rationale = VerificationStateMachine.evaluate_target_status(
        [ev], is_baseline_stable=False
    )
    assert status == VerificationStatus.INCONCLUSIVE
    assert "unstable" in rationale.lower()


def test_evaluate_target_status_specific_db_error_yields_verified() -> None:
    """Verify evaluate_target_status marks specific DB error on stable baseline as VERIFIED."""
    ev = _make_evidence(provider="mysql", is_stable=True)
    status, rationale = VerificationStateMachine.evaluate_target_status(
        [ev], is_baseline_stable=True
    )
    assert status == VerificationStatus.VERIFIED
    assert "mysql" in rationale.lower()


def test_transition_records_audit_history() -> None:
    """Verify transition appends an immutable StateTransitionRecord to the provided history list."""
    history: list[StateTransitionRecord] = []
    ev = _make_evidence(provider="postgresql", is_stable=True)

    VerificationStateMachine.transition(
        from_status=VerificationStatus.POTENTIAL_INDICATOR,
        to_status=VerificationStatus.UNDER_ANALYSIS,
        reason="Start analysis",
        evidence_items=[ev],
        history=history,
    )
    VerificationStateMachine.transition(
        from_status=VerificationStatus.UNDER_ANALYSIS,
        to_status=VerificationStatus.VERIFIED,
        reason="Specific PostgreSQL pattern verified",
        evidence_items=[ev],
        history=history,
    )

    assert len(history) == 2
    assert history[0].from_status == VerificationStatus.POTENTIAL_INDICATOR
    assert history[0].to_status == VerificationStatus.UNDER_ANALYSIS
    assert history[1].from_status == VerificationStatus.UNDER_ANALYSIS
    assert history[1].to_status == VerificationStatus.VERIFIED
