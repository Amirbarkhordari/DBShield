"""Unit tests for DBShield Evidence Correlator and Deduplication (Phase 7)."""

from dbshield.sqli.models import ParameterLocation
from dbshield.verification.correlator import (
    EvidenceCorrelator,
    compute_group_id,
)
from dbshield.verification.models import (
    EvidenceProvenance,
    EvidenceType,
    NormalizedEvidence,
    VulnerabilityClass,
)


def _make_evidence(
    target_url: str = "http://target.local/api",
    vuln_class: VulnerabilityClass = VulnerabilityClass.SQLI,
    param_name: str = "id",
    param_loc: ParameterLocation = ParameterLocation.QUERY,
    rule_id: str = "RULE_SQL_ERR",
    matched_pattern: str = "error in syntax",
    snippet: str = "error in syntax",
    execution_id: str = "exec-1",
    finding_id: str = "find-1",
) -> NormalizedEvidence:
    prov = EvidenceProvenance(
        engine="sqli",
        vulnerability_class=vuln_class,
        target_url=target_url,
        parameter_name=param_name,
        parameter_location=param_loc,
        execution_id=execution_id,
        source_finding_id=finding_id,
    )
    return NormalizedEvidence(
        evidence_type=EvidenceType.ERROR_SIGNATURE,
        provenance=prov,
        rule_id=rule_id,
        matched_pattern=matched_pattern,
        safe_snippet=snippet,
        description="Observed error",
        provider_or_family="mysql",
        test_status=500,
    )


def test_correlator_groups_identical_candidates() -> None:
    """Verify evidence sharing URL, vuln_class, location, and param_name are grouped together."""
    ev1 = _make_evidence(rule_id="RULE_1", execution_id="exec-1")
    ev2 = _make_evidence(rule_id="RULE_2", execution_id="exec-2")  # Different rule on same param

    groups = EvidenceCorrelator.correlate([ev1, ev2])
    assert len(groups) == 1
    assert groups[0].parameter_name == "id"
    assert len(groups[0].evidence_items) == 2
    assert "exec-1" in groups[0].execution_ids
    assert "exec-2" in groups[0].execution_ids


def test_correlator_preserves_distinct_parameters() -> None:
    """Verify distinct parameters on the same target URL remain separate groups."""
    ev_id = _make_evidence(param_name="id")
    ev_search = _make_evidence(param_name="search")

    groups = EvidenceCorrelator.correlate([ev_id, ev_search])
    assert len(groups) == 2
    param_names = {g.parameter_name for g in groups}
    assert param_names == {"id", "search"}


def test_correlator_preserves_distinct_parameter_locations() -> None:
    """Verify same parameter name across different transport locations is not merged."""
    ev_query = _make_evidence(param_name="data", param_loc=ParameterLocation.QUERY)
    ev_json = _make_evidence(param_name="data", param_loc=ParameterLocation.BODY_JSON)

    groups = EvidenceCorrelator.correlate([ev_query, ev_json])
    assert len(groups) == 2
    locations = {g.parameter_location for g in groups}
    assert locations == {ParameterLocation.QUERY, ParameterLocation.BODY_JSON}


def test_correlator_preserves_distinct_vulnerability_classes() -> None:
    """Verify same parameter tested under SQLi and NoSQLi remain distinct groups."""
    ev_sqli = _make_evidence(param_name="id", vuln_class=VulnerabilityClass.SQLI)
    ev_nosqli = _make_evidence(param_name="id", vuln_class=VulnerabilityClass.NOSQLI)

    groups = EvidenceCorrelator.correlate([ev_sqli, ev_nosqli])
    assert len(groups) == 2
    v_classes = {g.vulnerability_class for g in groups}
    assert v_classes == {VulnerabilityClass.SQLI, VulnerabilityClass.NOSQLI}


def test_correlator_deduplicates_repeated_identical_evidence() -> None:
    """Verify repeated executions producing identical signals are deduplicated with audit notes."""
    ev1 = _make_evidence(rule_id="RULE_SYNTAX", snippet="syntax error", execution_id="exec-1")
    ev2 = _make_evidence(rule_id="RULE_SYNTAX", snippet="syntax error", execution_id="exec-2")

    groups = EvidenceCorrelator.correlate([ev1, ev2])
    assert len(groups) == 1
    # Only 1 unique item preserved
    assert len(groups[0].evidence_items) == 1
    # Both execution IDs preserved
    assert set(groups[0].execution_ids) == {"exec-1", "exec-2"}
    # Deduplication audit note generated
    assert len(groups[0].deduplication_notes) == 1
    assert "Deduplicated" in groups[0].deduplication_notes[0]


def test_compute_group_id_deterministic() -> None:
    """Verify correlation group ID computation is deterministic and case-insensitive on parameter name."""
    gid1 = compute_group_id(
        "http://target.local/api/", VulnerabilityClass.SQLI, ParameterLocation.QUERY, "ID"
    )
    gid2 = compute_group_id(
        "http://target.local/api", VulnerabilityClass.SQLI, ParameterLocation.QUERY, "id"
    )
    assert gid1 == gid2
