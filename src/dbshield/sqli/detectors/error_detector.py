"""Error-based SQL injection detector.

Analyzes test responses for database-specific syntax and driver error patterns
that were absent in the baseline response. Strictly rejects generic HTTP 500
errors or application exceptions that do not contain verified database error signatures.
"""

import logging

from dbshield.sqli.models import (
    ConfidenceRating,
    DetectionStatus,
    EvidenceRecord,
    TestTechnique,
)
from dbshield.sqli.signatures import SignatureCatalog

logger = logging.getLogger("dbshield.sqli.detector.error")


class ErrorDetector:
    """Detects database-related error signatures in responses compared to baseline."""

    @classmethod
    def analyze_response(
        cls,
        test_body: str,
        test_status: int,
        baseline_body: str,
        baseline_status: int,
    ) -> tuple[DetectionStatus, ConfidenceRating | None, list[EvidenceRecord], str]:
        """Analyze test response compared to baseline response.

        Args:
            test_body: Body of the test probe response.
            test_status: Status code of the test probe response.
            baseline_body: Body of the baseline response.
            baseline_status: Status code of the baseline response.

        Returns:
            Tuple of (DetectionStatus, ConfidenceRating, list of EvidenceRecord, summary explanation).
        """
        # Step 1: Check if test response matches generic server errors without DB error signatures
        if SignatureCatalog.is_generic_server_error(test_body):
            logger.debug(
                "Response (HTTP %d) contains generic HTTP error; rejecting as SQLi indicator.",
                test_status,
            )
            return (
                DetectionStatus.NO_INDICATOR,
                None,
                [],
                "Response returned a generic server error without database-specific syntax or driver signatures.",
            )

        # Step 2: Check database signatures in test response
        test_matches = SignatureCatalog.match_signatures(test_body)
        if not test_matches:
            if test_status >= 500:
                logger.debug(
                    "Test returned HTTP %d but no database error signature was matched.",
                    test_status,
                )
                return (
                    DetectionStatus.NO_INDICATOR,
                    None,
                    [],
                    f"Test probe returned HTTP {test_status} but response body contains no recognized database error signatures.",
                )
            # No database signatures found in test response
            return (
                DetectionStatus.NO_INDICATOR,
                None,
                [],
                "No recognizable database error signatures observed in test response.",
            )

        # Step 3: Check database signatures in baseline response
        if baseline_status >= 500:
            logger.debug(
                "Baseline response already exhibited server error status HTTP %d", baseline_status
            )
        # If baseline already contains the exact same signature, the signature is not caused by the probe!
        baseline_matches = SignatureCatalog.match_signatures(baseline_body)
        baseline_rule_ids = {sig.rule_id for sig, _ in baseline_matches}

        new_evidence: list[EvidenceRecord] = []
        for sig, snippet in test_matches:
            if sig.rule_id in baseline_rule_ids:
                logger.debug(
                    "Database signature %s was already present in baseline response; ignoring as pre-existing.",
                    sig.rule_id,
                )
                continue

            evidence = EvidenceRecord(
                technique=TestTechnique.ERROR_BASED,
                rule_id=sig.rule_id,
                matched_pattern=sig.pattern.pattern,
                snippet=snippet,
                description=f"Observed {sig.description} ({sig.family.value.upper()}) absent in baseline.",
                db_family_hint=sig.family,
                confirmed=False,  # Unconfirmed candidate indicator
            )
            new_evidence.append(evidence)

        if not new_evidence:
            return (
                DetectionStatus.NO_INDICATOR,
                None,
                [],
                "Database error signatures matched were already present in the baseline response (pre-existing condition).",
            )

        # Step 4: Classify confidence
        # High confidence if explicit database-specific syntax error with DB family hint; medium if generic SQLSTATE
        primary_family = new_evidence[0].db_family_hint
        confidence = (
            ConfidenceRating.HIGH
            if primary_family != primary_family.GENERIC_SQL
            else ConfidenceRating.MEDIUM
        )

        families_str = ", ".join(sorted({ev.db_family_hint.value.upper() for ev in new_evidence}))
        summary = (
            f"Detected {len(new_evidence)} new database error signature(s) absent in baseline "
            f"(Family hint: {families_str}). Potential SQL injection indicator (unconfirmed)."
        )

        return (
            DetectionStatus.POTENTIAL_INDICATOR,
            confidence,
            new_evidence,
            summary,
        )
