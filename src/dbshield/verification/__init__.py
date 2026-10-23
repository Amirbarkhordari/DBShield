"""DBShield Evidence Analysis and Vulnerability Verification Subsystem (Phase 7).

Public exports for normalized evidence, correlation, confidence assessment,
state machine transitions, and verification engine.
"""

from dbshield.verification.confidence import ConfidenceAssessor
from dbshield.verification.correlator import EvidenceCorrelator
from dbshield.verification.engine import VerificationEngine
from dbshield.verification.models import (
    ConfidenceAssessment,
    ConfidenceLevel,
    CorrelationGroup,
    EvidenceProvenance,
    EvidenceType,
    NormalizedEvidence,
    StateTransitionRecord,
    VerificationFinding,
    VerificationResult,
    VerificationStatus,
    VerificationSummary,
    VulnerabilityClass,
)
from dbshield.verification.normalizer import EvidenceNormalizer
from dbshield.verification.state_machine import VerificationStateMachine

__all__ = [
    "ConfidenceAssessment",
    "ConfidenceAssessor",
    "ConfidenceLevel",
    "CorrelationGroup",
    "EvidenceCorrelator",
    "EvidenceNormalizer",
    "EvidenceProvenance",
    "EvidenceType",
    "NormalizedEvidence",
    "StateTransitionRecord",
    "VerificationEngine",
    "VerificationFinding",
    "VerificationResult",
    "VerificationStateMachine",
    "VerificationStatus",
    "VerificationSummary",
    "VulnerabilityClass",
]
