"""Unit tests for DBShield Payload Models and Catalog (Phase 6)."""

import pytest
from pydantic import ValidationError

from dbshield.payloads.catalog import PayloadCatalog
from dbshield.payloads.models import (
    PayloadCategory,
    PayloadRiskLevel,
    SecurityPayload,
)
from dbshield.sqli.models import ParameterLocation


def test_payload_model_frozen_immutability() -> None:
    """Verify that SecurityPayload instances cannot be mutated in place."""
    payload = SecurityPayload(
        payload_id="TEST_01",
        name="Test Payload",
        description="Test description",
        category=PayloadCategory.SQLI,
        technique="error_based",
        applicable_locations=[ParameterLocation.QUERY],
        payload_value="'",
    )
    with pytest.raises(ValidationError):
        payload.payload_id = "CHANGED"  # type: ignore[misc]


def test_payload_model_field_validation() -> None:
    """Verify validation of required fields and default values."""
    payload = SecurityPayload(
        payload_id="TEST_02",
        name="Test Probe",
        description="Desc",
        category=PayloadCategory.NOSQLI,
        technique="operator_injection",
        applicable_locations=[ParameterLocation.BODY_JSON],
        payload_value={"$ne": None},
    )
    assert payload.category == PayloadCategory.NOSQLI
    assert payload.risk_level == PayloadRiskLevel.SAFE_PROBE
    assert payload.is_paired is False
    assert payload.pair_role is None
    assert payload.paired_with_id is None
    assert payload.version == "1.0.0"


def test_payload_catalog_initialization_and_count() -> None:
    """Verify default catalog loads curated payloads with valid count."""
    catalog = PayloadCatalog()
    all_payloads = catalog.get_all()
    assert len(all_payloads) >= 10
    # Deterministic sorting check
    ids = [p.payload_id for p in all_payloads]
    assert ids == sorted(ids)


def test_payload_catalog_lookup() -> None:
    """Verify get_payload finds existing ID and returns None for unknown ID."""
    catalog = PayloadCatalog()
    p = catalog.get_payload("SQLI_ERR_QUOTE")
    assert p is not None
    assert p.payload_id == "SQLI_ERR_QUOTE"
    assert p.category == PayloadCategory.SQLI

    assert catalog.get_payload("NON_EXISTENT_ID") is None


def test_payload_catalog_duplicate_registration_rejected() -> None:
    """Verify ValueError is raised if duplicate payload_id is registered."""
    catalog = PayloadCatalog()
    duplicate = SecurityPayload(
        payload_id="SQLI_ERR_QUOTE",
        name="Dup",
        description="Dup",
        category=PayloadCategory.SQLI,
        technique="error_based",
        applicable_locations=[ParameterLocation.QUERY],
        payload_value="'",
    )
    with pytest.raises(ValueError, match="already registered"):
        catalog.register(duplicate)


def test_payload_catalog_filtering_by_engine() -> None:
    """Verify filtering by applicable engine."""
    catalog = PayloadCatalog()
    sqli_list = catalog.filter_payloads(engine="sqli")
    for p in sqli_list:
        assert "sqli" in p.applicable_engines

    nosqli_list = catalog.filter_payloads(engine="nosqli")
    for p in nosqli_list:
        assert "nosqli" in p.applicable_engines


def test_payload_catalog_filtering_by_category() -> None:
    """Verify filtering by PayloadCategory enum."""
    catalog = PayloadCatalog()
    res = catalog.filter_payloads(category=PayloadCategory.NOSQLI)
    assert len(res) > 0
    for p in res:
        assert p.category == PayloadCategory.NOSQLI


def test_payload_catalog_filtering_by_location() -> None:
    """Verify filtering by ParameterLocation."""
    catalog = PayloadCatalog()
    json_only = catalog.filter_payloads(location=ParameterLocation.BODY_JSON)
    assert len(json_only) > 0
    for p in json_only:
        assert ParameterLocation.BODY_JSON in p.applicable_locations


def test_payload_catalog_filtering_by_technique() -> None:
    """Verify filtering by technique name."""
    catalog = PayloadCatalog()
    diffs = catalog.filter_payloads(technique="boolean_differential")
    assert len(diffs) > 0
    for p in diffs:
        assert p.technique == "boolean_differential"


def test_payload_catalog_filtering_by_risk_level() -> None:
    """Verify filtering by risk rating."""
    catalog = PayloadCatalog()
    safe = catalog.filter_payloads(risk_level=PayloadRiskLevel.SAFE_PROBE)
    assert len(safe) == len(catalog.get_all())


def test_payload_catalog_filtering_by_tags() -> None:
    """Verify filtering by search tags."""
    catalog = PayloadCatalog()
    tagged_syntax = catalog.filter_payloads(tags=["syntax"])
    assert len(tagged_syntax) >= 2
    tagged_quote = catalog.filter_payloads(tags=["quote"])
    assert len(tagged_quote) >= 1
    for p in tagged_quote:
        assert "quote" in p.tags


def test_payload_catalog_validation_paired_mismatch() -> None:
    """Verify catalog validation detects mismatched paired definitions."""
    p_true = SecurityPayload(
        payload_id="TEST_DIFF_TRUE",
        name="True Probe",
        description="True",
        category=PayloadCategory.SQLI,
        technique="differential",
        applicable_locations=[ParameterLocation.QUERY],
        payload_value="1",
        is_paired=True,
        pair_role="true",
        paired_with_id="TEST_DIFF_FALSE",
    )
    p_false_broken = SecurityPayload(
        payload_id="TEST_DIFF_FALSE",
        name="False Probe",
        description="False",
        category=PayloadCategory.SQLI,
        technique="differential",
        applicable_locations=[ParameterLocation.QUERY],
        payload_value="0",
        is_paired=True,
        pair_role="false",
        paired_with_id="WRONG_ID",
    )
    with pytest.raises(ValueError, match="Pairing mismatch"):
        PayloadCatalog(payloads=[p_true, p_false_broken])


def test_payload_catalog_validation_missing_paired_with_id() -> None:
    """Verify catalog validation fails if paired payload lacks paired_with_id."""
    broken = SecurityPayload(
        payload_id="TEST_BROKEN_PAIR",
        name="Broken",
        description="Broken",
        category=PayloadCategory.SQLI,
        technique="differential",
        applicable_locations=[ParameterLocation.QUERY],
        payload_value="1",
        is_paired=True,
        pair_role="true",
        paired_with_id=None,
    )
    with pytest.raises(ValueError, match="must specify 'paired_with_id'"):
        PayloadCatalog(payloads=[broken])


def test_payload_catalog_validation_invalid_role() -> None:
    """Verify catalog validation fails if pair_role is neither true nor false."""
    broken = SecurityPayload(
        payload_id="TEST_ROLE",
        name="Role",
        description="Role",
        category=PayloadCategory.SQLI,
        technique="differential",
        applicable_locations=[ParameterLocation.QUERY],
        payload_value="1",
        is_paired=True,
        pair_role="invalid_role",
        paired_with_id="SOME_ID",
    )
    with pytest.raises(ValueError, match="role must be 'true' or 'false'"):
        PayloadCatalog(payloads=[broken])
