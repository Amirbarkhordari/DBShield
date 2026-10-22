"""Error-based NoSQL injection detector.

Analyzes test responses for NoSQL database-specific syntax, driver, and operator errors
that were absent in the baseline response. Strictly rejects generic HTTP 500
errors or application exceptions that do not contain verified NoSQL error signatures.
"""

import logging

from dbshield.nosqli.models import (
    NoSQLConfidenceRating,
    NoSQLDetectionStatus,
    NoSQLEvidenceRecord,
    NoSQLProviderFamily,
    NoSQLTestTechnique,
)
from dbshield.nosqli.signatures import NoSQLSignatureCatalog

logger = logging.getLogger("dbshield.nosqli.detector.error")


class NoSQLErrorDetector:
    """Detects NoSQL database-related error signatures in responses compared to baseline."""

    @classmethod
    def analyze_response(
        cls,
        test_body: str,
        test_status: int,
        baseline_body: str,
        baseline_status: int,
    ) -> tuple[NoSQLDetectionStatus, NoSQLConfidenceRating | None, list[NoSQLEvidenceRecord], str]:
        """Analyze test response compared to baseline response.

        Args:
            test_body: Body of the test probe response.
            test_status: Status code of the test probe response.
            baseline_body: Body of the baseline response.
            baseline_status: Status code of the baseline response.

        Returns:
            Tuple of (NoSQLDetectionStatus, NoSQLConfidenceRating, list of NoSQLEvidenceRecord, summary explanation).
        """
        # Step 1: Check if test response matches generic server errors without NoSQL signatures
        if NoSQLSignatureCatalog.is_generic_server_error(test_body):
            logger.debug(
                "Response (HTTP %d) contains generic HTTP error; rejecting as NoSQL indicator.",
                test_status,
            )
            return (
                NoSQLDetectionStatus.NO_INDICATOR,
                None,
                [],
                "Response returned a generic server error without NoSQL-specific syntax or driver signatures.",
            )

        # Step 2: Check NoSQL signatures in test response
        test_matches = NoSQLSignatureCatalog.match_signatures(test_body)
        if not test_matches:
            if test_status >= 500:
                logger.debug(
                    "Test returned HTTP %d but no NoSQL database error signature was matched.",
                    test_status,
                )
                return (
                    NoSQLDetectionStatus.NO_INDICATOR,
                    None,
                    [],
                    f"Test probe returned HTTP {test_status} but response body contains no recognized NoSQL error signatures.",
                )
            # No NoSQL signatures found in test response
            return (
                NoSQLDetectionStatus.NO_INDICATOR,
                None,
                [],
                "No recognizable NoSQL database error signatures observed in test response.",
            )

        # Step 3: Check NoSQL signatures in baseline response
        if baseline_status >= 500:
            logger.debug(
                "Baseline response already exhibited server error status HTTP %d", baseline_status
            )
        # If baseline already contains the exact same signature, the signature is not caused by the probe!
        baseline_matches = NoSQLSignatureCatalog.match_signatures(baseline_body)
        baseline_rule_ids = {sig.rule_id for sig, _ in baseline_matches}

        new_evidence: list[NoSQLEvidenceRecord] = []
        for sig, snippet in test_matches:
            if sig.rule_id in baseline_rule_ids:
                logger.debug(
                    "NoSQL signature %s was already present in baseline response; ignoring as pre-existing.",
                    sig.rule_id,
                )
                continue

            evidence = NoSQLEvidenceRecord(
                technique=NoSQLTestTechnique.ERROR_BASED,
                rule_id=sig.rule_id,
                matched_pattern=sig.pattern.pattern,
                snippet=snippet,
                description=f"Observed {sig.description} ({sig.family.value.upper()}) absent in baseline.",
                provider_family_hint=sig.family,
                confirmed=False,  # Unconfirmed candidate indicator
            )
            new_evidence.append(evidence)

        if not new_evidence:
            return (
                NoSQLDetectionStatus.NO_INDICATOR,
                None,
                [],
                "NoSQL error signatures matched were already present in the baseline response (pre-existing condition).",
            )

        # Step 4: Classify confidence
        # High confidence if explicit MongoDB/CouchDB specific error; medium if generic NoSQL
        primary_family = new_evidence[0].provider_family_hint
        confidence = (
            NoSQLConfidenceRating.HIGH
            if primary_family != NoSQLProviderFamily.GENERIC_NOSQL
            else NoSQLConfidenceRating.MEDIUM
        )

        families_str = ", ".join(
            sorted({ev.provider_family_hint.value.upper() for ev in new_evidence})
        )
        summary = (
            f"Detected {len(new_evidence)} new NoSQL database error signature(s) absent in baseline "
            f"(Provider hint: {families_str}). Potential NoSQL injection indicator (unconfirmed)."
        )

        return (
            NoSQLDetectionStatus.POTENTIAL_INDICATOR,
            confidence,
            new_evidence,
            summary,
        )
