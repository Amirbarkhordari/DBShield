"""Base exporter interface for DBShield security reports (Phase 8)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from dbshield.reporting.models import SecurityAssessmentReport


class BaseReportExporter(ABC):
    """Abstract base class defining report exporter contract."""

    @abstractmethod
    def export(self, report: SecurityAssessmentReport) -> str:
        """Render a SecurityAssessmentReport into target output string format."""
        raise NotImplementedError
