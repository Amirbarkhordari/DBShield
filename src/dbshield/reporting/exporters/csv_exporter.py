"""CSV report exporter for DBShield security reports (Phase 8).

Generates tabular CSV reports with protection against spreadsheet formula injection (CSV Injection/DDE).
"""

from __future__ import annotations

import csv
import io

from dbshield.reporting.exporters.base import BaseReportExporter
from dbshield.reporting.models import SecurityAssessmentReport
from dbshield.reporting.redaction import escape_csv_formula

# Documented, stable column set for DBShield CSV reports
CSV_COLUMNS: list[str] = [
    "finding_id",
    "title",
    "category",
    "subtype",
    "severity",
    "verification_status",
    "confidence_level",
    "confidence_score",
    "target_url",
    "endpoint",
    "http_method",
    "parameter_name",
    "parameter_location",
    "cwe_id",
    "cwe_name",
    "evidence_count",
    "evidence_summary",
    "remediation",
    "first_observed_at",
]


class CSVReportExporter(BaseReportExporter):
    """Exports findings as RFC-4180 compliant CSV with formula-injection neutralization."""

    def export(self, report: SecurityAssessmentReport) -> str:
        """Render findings to a CSV formatted string with spreadsheet injection safeguards."""
        output = io.StringIO()
        writer = csv.writer(
            output,
            dialect="excel",
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\r\n",
        )

        # Write header row
        writer.writerow(CSV_COLUMNS)

        # Write data rows
        for finding in report.findings:
            row = [
                escape_csv_formula(finding.id),
                escape_csv_formula(finding.title),
                escape_csv_formula(finding.category.value),
                escape_csv_formula(finding.subtype),
                escape_csv_formula(finding.severity.value),
                escape_csv_formula(finding.verification_status.value),
                escape_csv_formula(finding.confidence_level.value),
                f"{finding.confidence_score:.2f}",
                escape_csv_formula(finding.target_url),
                escape_csv_formula(finding.endpoint),
                escape_csv_formula(finding.http_method),
                escape_csv_formula(finding.parameter_name),
                escape_csv_formula(finding.parameter_location.value),
                escape_csv_formula(finding.cwe_id or ""),
                escape_csv_formula(finding.cwe_name or ""),
                str(finding.evidence_count),
                escape_csv_formula(finding.evidence_summary),
                escape_csv_formula(finding.remediation),
                finding.first_observed_at.isoformat(),
            ]
            writer.writerow(row)

        return output.getvalue()
