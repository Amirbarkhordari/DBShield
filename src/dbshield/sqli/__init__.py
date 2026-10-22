"""SQL Injection Detection Engine for DBShield (Phase 4).

Provides controlled, defensive SQL injection assessment, database error pattern
matching, baseline characterization, and differential response analysis.
"""

from dbshield.sqli.baseline import BaselineCharacterizer
from dbshield.sqli.detectors.differential_detector import DifferentialDetector
from dbshield.sqli.detectors.error_detector import ErrorDetector
from dbshield.sqli.engine import SQLiEngine
from dbshield.sqli.models import (
    CandidateParameter,
    ConfidenceRating,
    DatabaseFamily,
    DetectionStatus,
    EvidenceRecord,
    ParameterLocation,
    SQLiFinding,
    SQLiScanResult,
    SQLiScanSummary,
    TestTechnique,
)
from dbshield.sqli.normalization import ResponseNormalizer
from dbshield.sqli.signatures import DBErrorSignature, SignatureCatalog

__all__ = [
    "BaselineCharacterizer",
    "CandidateParameter",
    "ConfidenceRating",
    "DBErrorSignature",
    "DatabaseFamily",
    "DetectionStatus",
    "DifferentialDetector",
    "ErrorDetector",
    "EvidenceRecord",
    "ParameterLocation",
    "ResponseNormalizer",
    "SQLiEngine",
    "SQLiFinding",
    "SQLiScanResult",
    "SQLiScanSummary",
    "SignatureCatalog",
    "TestTechnique",
]
