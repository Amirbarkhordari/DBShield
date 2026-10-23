"""Explainable Confidence Assessment subsystem for DBShield (Phase 7).

Evaluates normalized evidence to produce transparent, explainable confidence assessments
distinguishing certainty in the observation from certainty of vulnerability exploitability.
"""

from dbshield.verification.models import (
    ConfidenceAssessment,
    ConfidenceLevel,
    EvidenceType,
    NormalizedEvidence,
)


class ConfidenceAssessor:
    """Calculates explainable, calibrated confidence ratings for correlated security evidence."""

    @classmethod
    def evaluate(
        cls,
        evidence_items: list[NormalizedEvidence],
        is_baseline_stable: bool = True,
        has_failed_execution: bool = False,
    ) -> ConfidenceAssessment:
        """Evaluate a set of normalized evidence items for a correlated finding.

        Rubric and Scale:
        - Score range: 0.0 to 1.0.
        - Categories:
            * LOW (< 0.40): Ambiguous, weak, or uncorroborated single signal.
            * MEDIUM (0.40 - 0.69): Generic syntax error, partial differential, or baseline instability.
            * HIGH (0.70 - 0.89): Strong provider-specific error signature absent from baseline, or verified differential.
            * VERIFIED (>= 0.90): Strict criteria met: stable baseline, corroborating or specific evidence, zero contradictions.
        """
        contributing: list[str] = []
        degrading: list[str] = []

        if not evidence_items:
            return ConfidenceAssessment(
                level=ConfidenceLevel.LOW,
                score=0.0,
                observation_confidence=0.0,
                vulnerability_confidence=0.0,
                contributing_factors=[],
                degrading_factors=["No evidence records available."],
                explanation="No evidence was provided to assess confidence.",
            )

        # Baseline execution check
        if has_failed_execution:
            degrading.append("Associated execution run failed, was skipped, or was cancelled.")
            return ConfidenceAssessment(
                level=ConfidenceLevel.LOW,
                score=0.0,
                observation_confidence=0.0,
                vulnerability_confidence=0.0,
                contributing_factors=[],
                degrading_factors=degrading,
                explanation="Execution failure or cancellation prevents any reliable confidence evaluation.",
            )

        # Check for pre-existing baseline errors
        has_preexisting_error = any(ev.is_preexisting_in_baseline for ev in evidence_items)
        if has_preexisting_error:
            degrading.append(
                "Observed database error signature was pre-existing in normal baseline response."
            )
            return ConfidenceAssessment(
                level=ConfidenceLevel.LOW,
                score=0.05,
                observation_confidence=0.80,  # The observation itself is real, but NOT a test finding!
                vulnerability_confidence=0.0,  # 0% confidence that test caused it!
                contributing_factors=["Consistent response observation."],
                degrading_factors=degrading,
                explanation="Indicator existed in baseline prior to payload injection; proven false positive.",
            )

        # Separate evidence types
        error_items = [
            ev for ev in evidence_items if ev.evidence_type == EvidenceType.ERROR_SIGNATURE
        ]
        diff_items = [
            ev for ev in evidence_items if ev.evidence_type == EvidenceType.DIFFERENTIAL_PAIR
        ]
        trace_items = [
            ev for ev in evidence_items if ev.evidence_type == EvidenceType.EXECUTION_TRACE
        ]

        # Check for contradictions
        has_contradictions = any(ev.is_contradictory for ev in evidence_items)
        if has_contradictions:
            degrading.append("Contradictory evidence observed across test probes.")

        # Baseline stability evaluation
        if not is_baseline_stable or any(not ev.is_baseline_stable for ev in evidence_items):
            degrading.append("Endpoint baseline was unstable across multi-probe samples.")
            baseline_penalty = 0.35
        else:
            contributing.append("Target baseline was verified stable and reproducible.")
            baseline_penalty = 0.0

        # Assess observation confidence
        obs_score = 0.50
        if error_items:
            obs_score += 0.25
            contributing.append(f"Captured {len(error_items)} distinct error signature(s).")
        if diff_items:
            obs_score += 0.25
            contributing.append(f"Captured {len(diff_items)} boolean differential signal(s).")
        if trace_items:
            obs_score += 0.10
        obs_score = max(0.0, min(1.0, obs_score - (0.30 if not is_baseline_stable else 0.0)))

        # Assess vulnerability confidence based on specificity and corroboration
        vuln_score = 0.0

        # Specificity of database errors
        specific_db_families = {
            "mysql",
            "postgresql",
            "sqlite",
            "mssql",
            "oracle",
            "mongodb",
            "couchdb",
        }
        has_specific_error = any(
            ev.provider_or_family.lower() in specific_db_families for ev in error_items
        )
        has_generic_error = any(
            ev.provider_or_family.lower() in {"generic_sql", "generic_nosql", "unknown"}
            for ev in error_items
        )

        if has_specific_error:
            vuln_score += 0.70
            contributing.append(
                "Specific database engine error signature matched (high specificity)."
            )
        elif has_generic_error:
            vuln_score += 0.35
            contributing.append("Generic SQL/NoSQL syntax error matched (moderate specificity).")

        # Differential evidence
        for d in diff_items:
            sim = d.similarity_score
            # If status codes differed significantly
            if d.baseline_status and d.test_status and d.baseline_status != d.test_status:
                vuln_score += 0.25
                contributing.append(
                    f"Differential status divergence (Baseline {d.baseline_status} vs Test {d.test_status})."
                )
            elif sim is not None and sim < 0.70:
                vuln_score += 0.20
                contributing.append(
                    f"Significant normalized body divergence (similarity: {sim:.2f})."
                )
            else:
                vuln_score += 0.10

        # Agreement between independent evidence types (corroboration boost)
        if error_items and diff_items:
            vuln_score += 0.20
            contributing.append(
                "Agreement between independent error signature and differential detectors."
            )

        # Deduct penalties
        vuln_score -= baseline_penalty
        if has_contradictions:
            vuln_score -= 0.40

        vuln_score = max(0.0, min(1.0, vuln_score))

        # Composite score
        composite_score = round(0.3 * obs_score + 0.7 * vuln_score, 2)
        composite_score = max(0.0, min(1.0, composite_score))

        # Assign confidence level
        if (
            composite_score >= 0.85
            and vuln_score >= 0.80
            and is_baseline_stable
            and not has_contradictions
        ):
            level = ConfidenceLevel.VERIFIED
        elif composite_score >= 0.70:
            level = ConfidenceLevel.HIGH
        elif composite_score >= 0.40:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        # Generate human-readable explanation
        explanation_parts = []
        if level in (ConfidenceLevel.VERIFIED, ConfidenceLevel.HIGH):
            explanation_parts.append(
                f"High confidence ({composite_score:.2f}) supported by "
                f"{', '.join(contributing[:2])}."
            )
        elif level == ConfidenceLevel.MEDIUM:
            explanation_parts.append(
                f"Moderate confidence ({composite_score:.2f}). Evidence suggests potential injection "
                "but requires independent corroboration or exhibits partial noise."
            )
        else:
            reasons = degrading if degrading else ["Weak or uncorroborated indicator"]
            explanation_parts.append(
                f"Low confidence ({composite_score:.2f}) due to {reasons[0].lower()}."
            )

        explanation = " ".join(explanation_parts)

        return ConfidenceAssessment(
            level=level,
            score=composite_score,
            observation_confidence=round(obs_score, 2),
            vulnerability_confidence=round(vuln_score, 2),
            contributing_factors=contributing,
            degrading_factors=degrading,
            explanation=explanation,
        )
