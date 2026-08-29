"""Convert an Asgard WAF correlation finding into normalized evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from ipaddress import ip_address
from typing import Any


VALID_SEVERITIES = {
    "INFORMATIONAL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


def _parse_timestamp(value: Any, field_name: str) -> datetime:
    """Return a timezone-aware datetime for a required ISO-8601 value."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty ISO-8601 string.")

    normalized = value.strip().replace("Z", "+00:00")

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"{field_name} must be a valid ISO-8601 timestamp.") from error

    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone.")

    return parsed.astimezone(timezone.utc)


def _to_json_safe(value: Any) -> Any:
    """Recursively convert DynamoDB Decimal values to JSON-safe numbers."""

    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)

    if isinstance(value, list):
        return [_to_json_safe(item) for item in value]

    if isinstance(value, dict):
        return {key: _to_json_safe(item) for key, item in value.items()}

    return value


def normalize_finding_to_threat_evidence(
    finding_id: str,
    evidence_package: dict[str, Any],
    bedrock_report: str = "",
    *,
    aws_account_id: str | None = None,
    aws_region: str | None = None,
    waf_web_acl_arn: str | None = None,
) -> dict[str, Any]:
    """Build one normalized record for the highest-risk correlated source IP."""

    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ValueError("finding_id cannot be empty.")

    source_findings = evidence_package.get("top_source_ips", [])

    if not source_findings:
        raise ValueError("evidence_package must contain at least one source finding.")

    primary_source = source_findings[0]
    source_ip = primary_source.get("source_ip")

    if not isinstance(source_ip, str) or not source_ip.strip():
        raise ValueError("primary source IP cannot be empty.")

    try:
        parsed_ip = ip_address(source_ip.strip())
    except ValueError as error:
        raise ValueError("primary source IP must be a valid IPv4 or IPv6 address.") from error

    severity = primary_source.get("severity")

    if severity not in VALID_SEVERITIES:
        raise ValueError(f"unsupported threat severity: {severity!r}.")

    analysis_window = evidence_package.get("analysis_window", {})
    observed_at = _parse_timestamp(primary_source.get("first_seen"), "first_seen")
    collected_at = _parse_timestamp(analysis_window.get("end"), "analysis_window.end")

    deterministic_findings = evidence_package.get("deterministic_findings", [])
    notes = " ".join(str(item).strip() for item in deterministic_findings if str(item).strip())

    if bedrock_report.strip():
        notes = f"{notes}\n\nBedrock interpretation:\n{bedrock_report.strip()}".strip()

    metadata = {
        "analysis_window": analysis_window,
        "summary": evidence_package.get("summary", {}),
        "risk_score": primary_source.get("risk_score"),
        "event_count": primary_source.get("event_count"),
        "blocked_count": primary_source.get("blocked_count"),
        "allowed_count": primary_source.get("allowed_count"),
        "uris": primary_source.get("uris", []),
        "rules": primary_source.get("rules", []),
        "countries": primary_source.get("countries", []),
        "last_seen": primary_source.get("last_seen"),
    }

    return {
        "identity": {
            "evidence_id": finding_id.strip(),
            "provider_name": "AWS WAF Correlation Agent",
            "provider_type": "CLOUD_NATIVE",
            "provider_platform": "AWS",
            "provider_version": "1.0.0",
            "observed_at": observed_at.isoformat(),
            "collected_at": collected_at.isoformat(),
        },
        "indicator": {
            "indicator_type": "IPV4" if parsed_ip.version == 4 else "IPV6",
            "indicator_value": str(parsed_ip),
            "indicator_source": "AWS_WAF",
            "condition": "OTHER",
        },
        "source": {
            "account_id": aws_account_id,
            "region": aws_region,
            "resource_id": waf_web_acl_arn,
            "repository": None,
            "hostname": None,
            "ip_address": str(parsed_ip),
            "metadata": _to_json_safe(metadata),
        },
        "context": {
            "severity": severity,
            "confidence": "CORRELATED",
            "provider_trust": "HIGH",
            "expires_at": None,
            "tags": ["asgard", "aws", "correlation", "waf"],
            "notes": notes,
        },
    }


def normalize_finding_item_to_threat_evidence(
    finding: dict[str, Any],
    *,
    aws_account_id: str | None = None,
    aws_region: str | None = None,
    waf_web_acl_arn: str | None = None,
) -> dict[str, Any]:
    """Normalize the dictionary produced by build_finding_item."""

    if not isinstance(finding, dict):
        raise ValueError("finding must be a dictionary.")

    evidence_package = finding.get("evidence")

    if not isinstance(evidence_package, dict):
        raise ValueError("finding.evidence must be a dictionary.")

    return normalize_finding_to_threat_evidence(
        finding_id=finding.get("finding_id", ""),
        evidence_package=evidence_package,
        bedrock_report=finding.get("bedrock_report", ""),
        aws_account_id=aws_account_id,
        aws_region=aws_region,
        waf_web_acl_arn=waf_web_acl_arn,
    )
