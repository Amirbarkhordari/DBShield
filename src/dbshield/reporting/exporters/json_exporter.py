"""JSON report exporter for DBShield security reports (Phase 8).

Generates deterministic, schema-compliant JSON representations of assessment results.
"""

from __future__ import annotations

import json
from typing import Any

from dbshield.reporting.exporters.base import BaseReportExporter
from dbshield.reporting.models import SecurityAssessmentReport


class JSONReportExporter(BaseReportExporter):
    """Serializes a SecurityAssessmentReport into clean, deterministic JSON format."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def export(self, report: SecurityAssessmentReport) -> str:
        """Export report as formatted JSON string with deterministic key ordering."""
        raw_dict = report.model_dump(mode="json")
        # Ensure top-level envelope includes explicit schema metadata
        envelope: dict[str, Any] = {
            "schema_version": report.metadata.version,
            "metadata": raw_dict["metadata"],
            "summary": {
                "total_findings": report.metadata.total_findings,
                "by_severity": report.metadata.findings_by_severity,
                "by_status": report.metadata.findings_by_status,
                "by_category": report.metadata.findings_by_category,
            },
            "findings": raw_dict["findings"],
        }
        return json.dumps(envelope, indent=self.indent, sort_keys=True)
