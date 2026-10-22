"""NoSQL Injection Detection Engine for DBShield (Phase 5).

Provides controlled, defensive NoSQL injection assessment, document-oriented
database error pattern matching, baseline characterization, nested JSON mutation,
and differential response analysis.
"""

from dbshield.nosqli.baseline import NoSQLBaselineCharacterizer
from dbshield.nosqli.detectors.differential_detector import (
    NoSQLDifferentialComparisonResult,
    NoSQLDifferentialDetector,
)
from dbshield.nosqli.detectors.error_detector import NoSQLErrorDetector
from dbshield.nosqli.engine import NoSQLiEngine
from dbshield.nosqli.models import (
    NoSQLBaselineProfile,
    NoSQLCandidateParameter,
    NoSQLConfidenceRating,
    NoSQLDetectionStatus,
    NoSQLEvidenceRecord,
    NoSQLFinding,
    NoSQLProviderFamily,
    NoSQLScanResult,
    NoSQLScanSummary,
    NoSQLTestTechnique,
    ParameterLocation,
)
from dbshield.nosqli.normalization import NoSQLResponseNormalizer
from dbshield.nosqli.signatures import NoSQLErrorSignature, NoSQLSignatureCatalog

__all__ = [
    "NoSQLBaselineCharacterizer",
    "NoSQLBaselineProfile",
    "NoSQLCandidateParameter",
    "NoSQLConfidenceRating",
    "NoSQLDetectionStatus",
    "NoSQLDifferentialComparisonResult",
    "NoSQLDifferentialDetector",
    "NoSQLErrorDetector",
    "NoSQLErrorSignature",
    "NoSQLEvidenceRecord",
    "NoSQLFinding",
    "NoSQLProviderFamily",
    "NoSQLResponseNormalizer",
    "NoSQLScanResult",
    "NoSQLScanSummary",
    "NoSQLSignatureCatalog",
    "NoSQLTestTechnique",
    "NoSQLiEngine",
    "ParameterLocation",
]
