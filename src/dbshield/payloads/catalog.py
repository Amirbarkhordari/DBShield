"""Centralized Payload Catalog for DBShield (Phase 6).

Maintains a curated, data-driven registry of defensive security payloads
for SQL and NoSQL testing. Provides deterministic filtering, lookup,
and validation without coupling payload data to execution logic.
"""

import logging
from typing import ClassVar

from dbshield.payloads.models import (
    PayloadCategory,
    PayloadRiskLevel,
    SecurityPayload,
)
from dbshield.sqli.models import ParameterLocation

logger = logging.getLogger("dbshield.payloads.catalog")


class PayloadCatalog:
    """Registry and query interface for security test payloads."""

    _DEFAULT_PAYLOADS: ClassVar[list[SecurityPayload]] = [
        # --- SQL Injection Payloads ---
        SecurityPayload(
            payload_id="SQLI_ERR_QUOTE",
            name="SQL Single Quote Syntax Probe",
            description="Injects a single quote to elicit SQL syntax parsing errors.",
            category=PayloadCategory.SQLI,
            technique="error_based",
            applicable_locations=[
                ParameterLocation.QUERY,
                ParameterLocation.BODY_URLENCODED,
                ParameterLocation.BODY_JSON,
            ],
            applicable_engines=["sqli"],
            target_providers=["mysql", "postgresql", "sqlite", "mssql", "oracle", "generic"],
            payload_value="'",
            is_paired=False,
            risk_level=PayloadRiskLevel.SAFE_PROBE,
            safety_constraints=[
                "Read-only probe; does not execute data modification statements.",
                "Rejected if parameter name indicates sensitive credential.",
            ],
            tags=["sqli", "syntax", "error_based", "quote"],
        ),
        SecurityPayload(
            payload_id="SQLI_ERR_DQUOTE",
            name="SQL Double Quote Syntax Probe",
            description="Injects a double quote to elicit SQL identifier parsing errors.",
            category=PayloadCategory.SQLI,
            technique="error_based",
            applicable_locations=[
                ParameterLocation.QUERY,
                ParameterLocation.BODY_URLENCODED,
                ParameterLocation.BODY_JSON,
            ],
            applicable_engines=["sqli"],
            target_providers=["mysql", "sqlite", "generic"],
            payload_value='"',
            is_paired=False,
            risk_level=PayloadRiskLevel.SAFE_PROBE,
            safety_constraints=[
                "Read-only probe; does not execute data modification statements.",
            ],
            tags=["sqli", "syntax", "error_based", "double_quote"],
        ),
        SecurityPayload(
            payload_id="SQLI_DIFF_BOOL_TRUE",
            name="SQL Boolean True Condition",
            description="Injects a tautological true condition (+AND+1=1) matching baseline records.",
            category=PayloadCategory.SQLI,
            technique="boolean_differential",
            applicable_locations=[
                ParameterLocation.QUERY,
                ParameterLocation.BODY_URLENCODED,
                ParameterLocation.BODY_JSON,
            ],
            applicable_engines=["sqli"],
            target_providers=["mysql", "postgresql", "sqlite", "mssql", "oracle", "generic"],
            payload_value=" AND 1=1",
            is_paired=True,
            pair_role="true",
            paired_with_id="SQLI_DIFF_BOOL_FALSE",
            risk_level=PayloadRiskLevel.SAFE_PROBE,
            safety_constraints=[
                "Strictly read-only; requires stable baseline before evaluation.",
            ],
            tags=["sqli", "boolean", "differential", "tautology"],
        ),
        SecurityPayload(
            payload_id="SQLI_DIFF_BOOL_FALSE",
            name="SQL Boolean False Condition",
            description="Injects an unsatisfiable false condition (+AND+1=2) diverging from baseline.",
            category=PayloadCategory.SQLI,
            technique="boolean_differential",
            applicable_locations=[
                ParameterLocation.QUERY,
                ParameterLocation.BODY_URLENCODED,
                ParameterLocation.BODY_JSON,
            ],
            applicable_engines=["sqli"],
            target_providers=["mysql", "postgresql", "sqlite", "mssql", "oracle", "generic"],
            payload_value=" AND 1=2",
            is_paired=True,
            pair_role="false",
            paired_with_id="SQLI_DIFF_BOOL_TRUE",
            risk_level=PayloadRiskLevel.SAFE_PROBE,
            safety_constraints=[
                "Strictly read-only; paired with SQLI_DIFF_BOOL_TRUE.",
            ],
            tags=["sqli", "boolean", "differential", "contradiction"],
        ),
        # --- NoSQL Injection Payloads ---
        SecurityPayload(
            payload_id="NOSQLI_ERR_OP_JSON",
            name="NoSQL Invalid Operator Probe (JSON)",
            description="Injects an unrecognized query operator object into a JSON body to elicit driver/server BadValue errors.",
            category=PayloadCategory.NOSQLI,
            technique="error_based",
            applicable_locations=[ParameterLocation.BODY_JSON],
            applicable_engines=["nosqli"],
            target_providers=["mongodb", "couchdb", "generic_nosql"],
            payload_value={"$invalid_nosql_op": 1},
            is_paired=False,
            risk_level=PayloadRiskLevel.SAFE_PROBE,
            safety_constraints=[
                "Banned from authentication workflows; read-only query probe.",
            ],
            tags=["nosqli", "mongodb", "operator", "error_based", "json"],
        ),
        SecurityPayload(
            payload_id="NOSQLI_ERR_OP_PARAM",
            name="NoSQL Invalid Operator Probe (Query/Form)",
            description="Injects Express/qs bracket operator syntax into URL parameters to elicit operator errors.",
            category=PayloadCategory.NOSQLI,
            technique="error_based",
            applicable_locations=[
                ParameterLocation.QUERY,
                ParameterLocation.BODY_URLENCODED,
            ],
            applicable_engines=["nosqli"],
            target_providers=["mongodb", "couchdb", "generic_nosql"],
            payload_value="[$invalid_nosql_op]=1",
            is_paired=False,
            risk_level=PayloadRiskLevel.SAFE_PROBE,
            safety_constraints=[
                "Read-only query probe; does not modify records.",
            ],
            tags=["nosqli", "mongodb", "operator", "error_based", "query"],
        ),
        SecurityPayload(
            payload_id="NOSQLI_DIFF_TRUE_JSON",
            name="NoSQL Truthy Operator Probe (JSON)",
            description="Injects a $ne sentinel operator into a JSON document to match existing records.",
            category=PayloadCategory.NOSQLI,
            technique="boolean_differential",
            applicable_locations=[ParameterLocation.BODY_JSON],
            applicable_engines=["nosqli"],
            target_providers=["mongodb", "generic_nosql"],
            payload_value={"$ne": "__dbshield_sentinel__"},
            is_paired=True,
            pair_role="true",
            paired_with_id="NOSQLI_DIFF_FALSE_JSON",
            risk_level=PayloadRiskLevel.SAFE_PROBE,
            safety_constraints=[
                "Requires stable baseline; strictly non-destructive.",
            ],
            tags=["nosqli", "mongodb", "differential", "json", "truthy"],
        ),
        SecurityPayload(
            payload_id="NOSQLI_DIFF_FALSE_JSON",
            name="NoSQL Falsy Operator Probe (JSON)",
            description="Injects an empty $in array operator into a JSON document to match zero records.",
            category=PayloadCategory.NOSQLI,
            technique="boolean_differential",
            applicable_locations=[ParameterLocation.BODY_JSON],
            applicable_engines=["nosqli"],
            target_providers=["mongodb", "generic_nosql"],
            payload_value={"$in": []},
            is_paired=True,
            pair_role="false",
            paired_with_id="NOSQLI_DIFF_TRUE_JSON",
            risk_level=PayloadRiskLevel.SAFE_PROBE,
            safety_constraints=[
                "Paired with NOSQLI_DIFF_TRUE_JSON; non-destructive.",
            ],
            tags=["nosqli", "mongodb", "differential", "json", "falsy"],
        ),
        SecurityPayload(
            payload_id="NOSQLI_DIFF_TRUE_PARAM",
            name="NoSQL Truthy Operator Probe (Query/Form)",
            description="Injects an Express/qs $ne operator into query or form parameters to match records.",
            category=PayloadCategory.NOSQLI,
            technique="boolean_differential",
            applicable_locations=[
                ParameterLocation.QUERY,
                ParameterLocation.BODY_URLENCODED,
            ],
            applicable_engines=["nosqli"],
            target_providers=["mongodb", "generic_nosql"],
            payload_value="[$ne]=__dbshield_sentinel__",
            is_paired=True,
            pair_role="true",
            paired_with_id="NOSQLI_DIFF_FALSE_PARAM",
            risk_level=PayloadRiskLevel.SAFE_PROBE,
            safety_constraints=[
                "Requires stable baseline; strictly non-destructive.",
            ],
            tags=["nosqli", "mongodb", "differential", "query", "truthy"],
        ),
        SecurityPayload(
            payload_id="NOSQLI_DIFF_FALSE_PARAM",
            name="NoSQL Falsy Operator Probe (Query/Form)",
            description="Injects an Express/qs $eq sentinel operator into query or form parameters to match zero records.",
            category=PayloadCategory.NOSQLI,
            technique="boolean_differential",
            applicable_locations=[
                ParameterLocation.QUERY,
                ParameterLocation.BODY_URLENCODED,
            ],
            applicable_engines=["nosqli"],
            target_providers=["mongodb", "generic_nosql"],
            payload_value="[$eq]=__dbshield_sentinel__",
            is_paired=True,
            pair_role="false",
            paired_with_id="NOSQLI_DIFF_TRUE_PARAM",
            risk_level=PayloadRiskLevel.SAFE_PROBE,
            safety_constraints=[
                "Paired with NOSQLI_DIFF_TRUE_PARAM; non-destructive.",
            ],
            tags=["nosqli", "mongodb", "differential", "query", "falsy"],
        ),
    ]

    def __init__(self, payloads: list[SecurityPayload] | None = None) -> None:
        """Initialize catalog with custom or default payloads.

        Args:
            payloads: Optional list of SecurityPayload definitions. Defaults to _DEFAULT_PAYLOADS.
        """
        self._payloads: dict[str, SecurityPayload] = {}
        for p in payloads or self._DEFAULT_PAYLOADS:
            self.register(p)
        self.validate_catalog()

    def register(self, payload: SecurityPayload) -> None:
        """Register a new payload definition.

        Raises:
            ValueError: If a payload with the same ID is already registered.
        """
        if payload.payload_id in self._payloads:
            raise ValueError(f"Payload ID '{payload.payload_id}' is already registered in catalog.")
        self._payloads[payload.payload_id] = payload

    def get_payload(self, payload_id: str) -> SecurityPayload | None:
        """Retrieve payload by unique identifier."""
        return self._payloads.get(payload_id)

    def get_all(self) -> list[SecurityPayload]:
        """Return all registered payloads in deterministic order."""
        return sorted(self._payloads.values(), key=lambda p: p.payload_id)

    def filter_payloads(
        self,
        engine: str | None = None,
        category: PayloadCategory | None = None,
        location: ParameterLocation | None = None,
        technique: str | None = None,
        provider: str | None = None,
        risk_level: PayloadRiskLevel | None = None,
        tags: list[str] | None = None,
    ) -> list[SecurityPayload]:
        """Filter registered payloads by execution criteria."""
        results: list[SecurityPayload] = []

        for p in self.get_all():
            if engine and p.applicable_engines and engine.lower() not in p.applicable_engines:
                continue
            if category and p.category != category:
                continue
            if location and location not in p.applicable_locations:
                continue
            if technique and p.technique.lower() != technique.lower():
                continue
            if (
                provider
                and p.target_providers
                and provider.lower() not in p.target_providers
                and "generic" not in p.target_providers
                and "generic_nosql" not in p.target_providers
            ):
                continue
            if risk_level and p.risk_level != risk_level:
                continue
            if tags and not all(t.lower() in [tag.lower() for tag in p.tags] for t in tags):
                continue
            results.append(p)

        return results

    filter = filter_payloads

    def validate_catalog(self) -> None:
        """Verify internal consistency of catalog definitions."""
        for p in self._payloads.values():
            if p.is_paired:
                if not p.paired_with_id:
                    raise ValueError(
                        f"Paired payload '{p.payload_id}' must specify 'paired_with_id'."
                    )
                if p.pair_role not in {"true", "false"}:
                    raise ValueError(
                        f"Paired payload '{p.payload_id}' role must be 'true' or 'false'."
                    )
                if p.paired_with_id in self._payloads:
                    other = self._payloads[p.paired_with_id]
                    if other.paired_with_id != p.payload_id:
                        raise ValueError(
                            f"Pairing mismatch: '{p.payload_id}' points to '{p.paired_with_id}', "
                            f"but '{other.payload_id}' points to '{other.paired_with_id}'."
                        )
