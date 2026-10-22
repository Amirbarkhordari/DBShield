"""Focused SQL injection detection modules."""

from dbshield.sqli.detectors.differential_detector import DifferentialDetector
from dbshield.sqli.detectors.error_detector import ErrorDetector

__all__ = ["DifferentialDetector", "ErrorDetector"]
