"""Route normalized evidence to injected providers without changing the evidence.

This module does not construct clients, retrieve secrets, or persist results.
The input is the dictionary returned by threat_evidence's normalizer (or a
model's model_dump(mode="json")). CVEs and candidate techniques must be supplied
explicitly by the caller; the coordinator never infers them from prose.
"""

from copy import deepcopy
from collections.abc import Mapping
import re

from providers import Indicator, MitreAttackProvider, ProviderResult


def _identifiers(values, pattern, label):
    """Validate the whole request before making any provider calls."""
    if not isinstance(values, (list, tuple)):
        raise ValueError(f"{label} must be a list or tuple of identifiers.")
    normalized = []
    for value in values:
        if not isinstance(value, str) or not re.fullmatch(pattern, value.strip().upper()):
            raise ValueError(f"Invalid {label} identifier.")
        normalized.append(value.strip().upper())
    return list(dict.fromkeys(normalized))


def enrich_threat_evidence(
    evidence: Mapping,
    *,
    abuseipdb,
    cisa_kev,
    mitre_attack,
    cve_ids=(),
    candidate_technique_ids=(),
) -> dict:
    """Return an evidence snapshot, per-provider result lists, and skip reasons.

    Providers are injected so tests need no network or AWS credentials. Missing
    identifiers are skipped; provider failures remain ERROR results. Neither a
    lookup failure nor NOT_FOUND means that the original evidence is safe.
    """
    if not isinstance(evidence, Mapping):
        raise ValueError("evidence must be a normalized mapping.")
    fields = evidence.get("indicator")
    if not isinstance(fields, Mapping):
        raise ValueError("evidence.indicator must be a mapping.")
    kind, value = fields.get("indicator_type"), fields.get("indicator_value")
    if not isinstance(kind, str) or not kind.strip() or not isinstance(value, str) or not value.strip():
        raise ValueError("indicator_type and indicator_value must be nonempty strings.")
    primary = Indicator.create(value, kind)
    cves = _identifiers(cve_ids, r"CVE-\d{4}-\d{4,}", "CVE")
    techniques = _identifiers(candidate_technique_ids, r"T\d{4}(?:\.\d{3})?", "ATT&CK")
    if primary.indicator_type == "CVE":
        cves = _identifiers([primary.value, *cves], r"CVE-\d{4}-\d{4,}", "CVE")
        primary = Indicator.create(primary.value.upper(), "CVE")

    record = {"evidence": deepcopy(dict(evidence)), "results": {}, "skipped": {}}

    def lookup(name, provider, indicator, context):
        try:
            # Each provider gets its own context so it cannot mutate another's.
            result = provider.enrich(indicator, deepcopy(context))
            if not isinstance(result, ProviderResult):
                raise TypeError("Provider must return ProviderResult")
        except Exception as exc:
            # Isolate unexpected failures, without copying exception text that
            # might contain credentials. Normal provider errors are handled
            # by BaseThreatIntelProvider.enrich before reaching this boundary.
            result = ProviderResult.failure(
                provider=name,
                indicator=indicator,
                ttl_seconds=900,
                error=f"Unexpected provider failure: {type(exc).__name__}",
            )
        record["results"].setdefault(name, []).append(result.to_dict())

    if primary.indicator_type in {"IPV4", "IPV6"}:
        lookup("abuseipdb", abuseipdb, primary, {})
    else:
        record["skipped"]["abuseipdb"] = "Primary indicator is not an IP address."

    if cves:
        for cve in cves:
            lookup("cisa_kev", cisa_kev, Indicator.create(cve, "CVE"), {})
    else:
        record["skipped"]["cisa_kev"] = "No CVE identifiers supplied."

    if not techniques:
        record["skipped"]["mitre_attack"] = "No candidate ATT&CK technique IDs supplied."
    elif primary.indicator_type not in MitreAttackProvider.supported_indicator_types:
        record["skipped"]["mitre_attack"] = "Primary indicator type is unsupported."
    else:
        lookup("mitre_attack", mitre_attack, primary, {"candidate_technique_ids": techniques})

    return record
