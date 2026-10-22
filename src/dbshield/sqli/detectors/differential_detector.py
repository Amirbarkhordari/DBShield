"""Boolean-based differential response detector.

Performs controlled differential comparisons between paired condition responses
(e.g., Condition True vs Condition False vs Baseline). Strictly requires a stable
baseline and reproducible differential behavior before flagging a candidate indicator.
"""

import logging
from dataclasses import dataclass

from dbshield.sqli.models import (
    ConfidenceRating,
    DetectionStatus,
    EvidenceRecord,
    TestTechnique,
)
from dbshield.sqli.normalization import ResponseNormalizer

logger = logging.getLogger("dbshield.sqli.detector.differential")


@dataclass(frozen=True)
class DifferentialComparisonResult:
    """Outcome of differential analysis over paired responses."""

    status: DetectionStatus
    confidence: ConfidenceRating | None
    evidence: list[EvidenceRecord]
    similarity_true_baseline: float
    similarity_false_baseline: float
    similarity_true_false: float
    explanation: str


class DifferentialDetector:
    """Analyzes paired test responses against baseline for logical differential behavior."""

    # Default similarity thresholds
    TRUE_MATCH_MIN_SIMILARITY: float = 0.85
    FALSE_DIVERGE_MAX_SIMILARITY: float = 0.75
    PAIR_DIVERGE_MAX_SIMILARITY: float = 0.80

    @classmethod
    def analyze_pair(
        cls,
        baseline_body: str,
        baseline_status: int,
        is_baseline_stable: bool,
        true_body: str,
        true_status: int,
        false_body: str,
        false_status: int,
    ) -> DifferentialComparisonResult:
        """Compare true-condition response, false-condition response, and baseline.

        Args:
            baseline_body: Normalized or raw baseline body.
            baseline_status: Baseline HTTP status code.
            is_baseline_stable: Whether baseline was established as stable.
            true_body: Body of truthy/positive probe response.
            true_status: Status code of truthy/positive probe response.
            false_body: Body of falsy/negative probe response.
            false_status: Status code of falsy/negative probe response.

        Returns:
            DifferentialComparisonResult with status, metrics, and evidence.
        """
        # Rule 1: A stable baseline is mandatory for differential testing
        if not is_baseline_stable:
            return DifferentialComparisonResult(
                status=DetectionStatus.INCONCLUSIVE,
                confidence=None,
                evidence=[],
                similarity_true_baseline=0.0,
                similarity_false_baseline=0.0,
                similarity_true_false=0.0,
                explanation="Differential testing marked inconclusive because baseline response behavior is unstable.",
            )

        # Normalize bodies
        norm_base = ResponseNormalizer.normalize(baseline_body)
        norm_true = ResponseNormalizer.normalize(true_body)
        norm_false = ResponseNormalizer.normalize(false_body)

        # Compute structural similarities
        sim_true_base = ResponseNormalizer.compute_similarity(norm_true, norm_base)
        sim_false_base = ResponseNormalizer.compute_similarity(norm_false, norm_base)
        sim_true_false = ResponseNormalizer.compute_similarity(norm_true, norm_false)

        logger.debug(
            "Differential metrics: sim(True, Base)=%.3f, sim(False, Base)=%.3f, sim(True, False)=%.3f, "
            "statuses: Base=%d, True=%d, False=%d",
            sim_true_base,
            sim_false_base,
            sim_true_false,
            baseline_status,
            true_status,
            false_status,
        )

        # Rule 2: Both conditions failed or returned identical client/server errors
        if true_status >= 400 and false_status >= 400 and true_status == false_status:
            return DifferentialComparisonResult(
                status=DetectionStatus.NO_INDICATOR,
                confidence=None,
                evidence=[],
                similarity_true_baseline=sim_true_base,
                similarity_false_baseline=sim_false_base,
                similarity_true_false=sim_true_false,
                explanation=f"Both paired probes returned HTTP {true_status}; no differential logic observed.",
            )

        # Rule 3: Both conditions returned virtually identical bodies and status codes
        if true_status == false_status and sim_true_false >= 0.95:
            return DifferentialComparisonResult(
                status=DetectionStatus.NO_INDICATOR,
                confidence=None,
                evidence=[],
                similarity_true_baseline=sim_true_base,
                similarity_false_baseline=sim_false_base,
                similarity_true_false=sim_true_false,
                explanation="Paired test probes produced indistinguishable responses (similarity >= 0.95).",
            )

        # Rule 4: Check for differential behavior
        # Case A: True condition matches baseline status and content, while False condition diverges
        true_matches_baseline = (
            true_status == baseline_status and sim_true_base >= cls.TRUE_MATCH_MIN_SIMILARITY
        )
        false_diverges_from_baseline = (
            false_status != baseline_status or sim_false_base <= cls.FALSE_DIVERGE_MAX_SIMILARITY
        )
        conditions_diverge_from_each_other = (
            true_status != false_status or sim_true_false <= cls.PAIR_DIVERGE_MAX_SIMILARITY
        )

        if (
            true_matches_baseline
            and false_diverges_from_baseline
            and conditions_diverge_from_each_other
        ):
            confidence = (
                ConfidenceRating.HIGH
                if (true_status != false_status or sim_true_false <= 0.60)
                else ConfidenceRating.MEDIUM
            )
            evidence = [
                EvidenceRecord(
                    technique=TestTechnique.BOOLEAN_DIFFERENTIAL,
                    rule_id="DIFF_LOGICAL_SPLIT",
                    matched_pattern=f"True(sim={sim_true_base:.2f}, status={true_status}) vs False(sim={sim_false_base:.2f}, status={false_status})",
                    snippet=f"True/Base similarity: {sim_true_base:.2f}; False/Base similarity: {sim_false_base:.2f}; True/False similarity: {sim_true_false:.2f}",
                    description=(
                        "Response behaved differentially on paired logical conditions: True condition matched "
                        "baseline while False condition exhibited reproducible divergence."
                    ),
                    confirmed=False,
                )
            ]
            return DifferentialComparisonResult(
                status=DetectionStatus.POTENTIAL_INDICATOR,
                confidence=confidence,
                evidence=evidence,
                similarity_true_baseline=sim_true_base,
                similarity_false_baseline=sim_false_base,
                similarity_true_false=sim_true_false,
                explanation=(
                    f"Differential signal detected: True-probe matched baseline ({sim_true_base:.2f}), "
                    f"while False-probe diverged ({sim_false_base:.2f}). Unconfirmed potential indicator."
                ),
            )

        # Case B: True condition does NOT match baseline (both diverged randomly from baseline)
        if not true_matches_baseline and false_diverges_from_baseline:
            # Neither condition matched baseline — irregular response handling or arbitrary input rejection
            return DifferentialComparisonResult(
                status=DetectionStatus.INCONCLUSIVE,
                confidence=None,
                evidence=[],
                similarity_true_baseline=sim_true_base,
                similarity_false_baseline=sim_false_base,
                similarity_true_false=sim_true_false,
                explanation=(
                    f"Differential behavior is inconclusive: Neither probe matched the baseline "
                    f"(True sim={sim_true_base:.2f}, False sim={sim_false_base:.2f})."
                ),
            )

        # Default clean result
        return DifferentialComparisonResult(
            status=DetectionStatus.NO_INDICATOR,
            confidence=None,
            evidence=[],
            similarity_true_baseline=sim_true_base,
            similarity_false_baseline=sim_false_base,
            similarity_true_false=sim_true_false,
            explanation="Response did not demonstrate reproducible differential behavior across paired probes.",
        )
