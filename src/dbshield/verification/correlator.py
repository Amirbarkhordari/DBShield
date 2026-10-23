"""Evidence Correlation and Deduplication subsystem for DBShield (Phase 7).

Provides deterministic grouping and deduplication of normalized security evidence
sharing candidate target, vulnerability class, parameter location, and parameter name,
while strictly preserving distinct findings and full execution provenance audit trails.
"""

import hashlib
from urllib.parse import urlparse

from dbshield.verification.models import (
    CorrelationGroup,
    NormalizedEvidence,
    ParameterLocation,
    VulnerabilityClass,
)


def _canonicalize_target_url(url: str) -> str:
    """Normalize target URL for deterministic correlation grouping."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or "/"
    # Clean trailing slashes except for root
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


def compute_group_id(
    target_url: str,
    vuln_class: VulnerabilityClass,
    param_location: ParameterLocation,
    param_name: str,
) -> str:
    """Compute a deterministic SHA-256 fingerprint identifying a candidate finding group."""
    canon_url = _canonicalize_target_url(target_url)
    key_str = f"{canon_url}|{vuln_class.value}|{param_location.value}|{param_name.strip().lower()}"
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()[:16]


def compute_evidence_fingerprint(ev: NormalizedEvidence) -> str:
    """Compute an identity hash to identify identical repeated evidence observations."""
    key = (
        f"{ev.evidence_type.value}|"
        f"{ev.rule_id}|"
        f"{ev.matched_pattern}|"
        f"{ev.provider_or_family}|"
        f"{ev.safe_snippet.strip()}|"
        f"{ev.test_status}|"
        f"{ev.similarity_score}"
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class EvidenceCorrelator:
    """Deterministic correlation and deduplication engine for normalized evidence."""

    @classmethod
    def correlate(cls, evidence_items: list[NormalizedEvidence]) -> list[CorrelationGroup]:
        """Correlate a list of NormalizedEvidence items into deduplicated CorrelationGroups."""
        if not evidence_items:
            return []

        # Bucket evidence by candidate target fingerprint
        buckets: dict[str, list[NormalizedEvidence]] = {}
        for ev in evidence_items:
            gid = compute_group_id(
                target_url=ev.provenance.target_url,
                vuln_class=ev.provenance.vulnerability_class,
                param_location=ev.provenance.parameter_location,
                param_name=ev.provenance.parameter_name,
            )
            buckets.setdefault(gid, []).append(ev)

        groups: list[CorrelationGroup] = []

        # Process each bucket deterministically
        for gid in sorted(buckets.keys()):
            items = buckets[gid]
            first = items[0]
            target_url = _canonicalize_target_url(first.provenance.target_url)
            vuln_class = first.provenance.vulnerability_class
            param_loc = first.provenance.parameter_location
            param_name = first.provenance.parameter_name

            seen_fingerprints: set[str] = set()
            deduped_items: list[NormalizedEvidence] = []
            dedup_notes: list[str] = []
            finding_ids: set[str] = set()
            exec_ids: set[str] = set()

            for itm in items:
                if itm.provenance.source_finding_id:
                    finding_ids.add(itm.provenance.source_finding_id)
                if itm.provenance.execution_id:
                    exec_ids.add(itm.provenance.execution_id)

                fp = compute_evidence_fingerprint(itm)
                if fp in seen_fingerprints:
                    dedup_notes.append(
                        f"Deduplicated identical {itm.evidence_type.value} signal: "
                        f"rule='{itm.rule_id}', pattern='{itm.matched_pattern}' "
                        f"(origin execution: {itm.provenance.execution_id or 'unknown'})"
                    )
                else:
                    seen_fingerprints.add(fp)
                    deduped_items.append(itm)

            # Deterministic sorting of evidence items within group
            sorted_items = sorted(
                deduped_items,
                key=lambda x: (
                    x.evidence_type.value,
                    x.rule_id,
                    x.matched_pattern,
                    x.safe_snippet,
                ),
            )

            group = CorrelationGroup(
                group_id=gid,
                target_url=target_url,
                vulnerability_class=vuln_class,
                parameter_name=param_name,
                parameter_location=param_loc,
                evidence_items=sorted_items,
                source_finding_ids=sorted(finding_ids),
                execution_ids=sorted(exec_ids),
                deduplication_notes=dedup_notes,
            )
            groups.append(group)

        return groups
