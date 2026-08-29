"""Tests for mapping WAF correlations into normalized threat evidence."""

from __future__ import annotations

import json
import sys
import unittest
from decimal import Decimal
from pathlib import Path


LAMBDA_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "Lambda_Src"
    / "response_agent_package"
)

sys.path.insert(0, str(LAMBDA_SOURCE))

from threat_evidence import (
    normalize_finding_item_to_threat_evidence,
    normalize_finding_to_threat_evidence,
)


def build_evidence_package(source_ip: str = "203.0.113.42") -> dict:
    """Return a representative deterministic Response Agent package."""

    return {
        "analysis_window": {
            "start": "2026-08-28T01:00:00+00:00",
            "end": "2026-08-28T02:00:00+00:00",
            "minutes": 60,
        },
        "summary": {
            "total_events": Decimal("5"),
            "blocked_events": 5,
            "allowed_events": 0,
            "unique_source_ips": 1,
            "unique_uris": 2,
        },
        "top_source_ips": [
            {
                "source_ip": source_ip,
                "event_count": Decimal("5"),
                "blocked_count": 5,
                "allowed_count": 0,
                "uris": ["/admin", "/login"],
                "rules": ["AWSManagedRulesCommonRuleSet"],
                "countries": ["US"],
                "first_seen": "2026-08-28T01:05:00Z",
                "last_seen": "2026-08-28T01:10:00Z",
                "risk_score": 70,
                "severity": "HIGH",
            }
        ],
        "deterministic_findings": ["Source generated five blocked WAF events."],
    }


class ThreatEvidenceNormalizerTests(unittest.TestCase):
    def test_maps_complete_ipv4_correlation(self) -> None:
        evidence = normalize_finding_to_threat_evidence(
            "finding-123",
            build_evidence_package(),
            "Analyst interpretation.",
            aws_account_id="123456789012",
            aws_region="us-west-1",
            waf_web_acl_arn="arn:aws:wafv2:us-west-1:123456789012:regional/webacl/asgard/example",
        )

        self.assertEqual(evidence["identity"]["evidence_id"], "finding-123")
        self.assertEqual(evidence["indicator"]["indicator_type"], "IPV4")
        self.assertEqual(evidence["indicator"]["indicator_value"], "203.0.113.42")
        self.assertEqual(evidence["indicator"]["indicator_source"], "AWS_WAF")
        self.assertEqual(evidence["context"]["severity"], "HIGH")
        self.assertEqual(evidence["context"]["confidence"], "CORRELATED")
        self.assertEqual(evidence["source"]["region"], "us-west-1")

    def test_classifies_ipv6_indicator(self) -> None:
        evidence = normalize_finding_to_threat_evidence(
            "finding-ipv6",
            build_evidence_package("2001:db8::1"),
        )

        self.assertEqual(evidence["indicator"]["indicator_type"], "IPV6")
        self.assertEqual(evidence["indicator"]["indicator_value"], "2001:db8::1")

    def test_normalizes_timestamps_to_utc(self) -> None:
        package = build_evidence_package()
        package["top_source_ips"][0]["first_seen"] = "2026-08-27T20:05:00-05:00"

        evidence = normalize_finding_to_threat_evidence("finding-time", package)

        self.assertEqual(evidence["identity"]["observed_at"], "2026-08-28T01:05:00+00:00")
        self.assertEqual(evidence["identity"]["collected_at"], "2026-08-28T02:00:00+00:00")

    def test_converts_decimal_metadata_for_json(self) -> None:
        evidence = normalize_finding_to_threat_evidence(
            "finding-json",
            build_evidence_package(),
        )

        serialized = json.dumps(evidence)

        self.assertIn('"total_events": 5', serialized)
        self.assertIn('"event_count": 5', serialized)

    def test_rejects_missing_source_findings(self) -> None:
        package = build_evidence_package()
        package["top_source_ips"] = []

        with self.assertRaisesRegex(ValueError, "at least one source finding"):
            normalize_finding_to_threat_evidence("finding-empty", package)

    def test_rejects_invalid_source_ip(self) -> None:
        with self.assertRaisesRegex(ValueError, "valid IPv4 or IPv6"):
            normalize_finding_to_threat_evidence(
                "finding-invalid-ip",
                build_evidence_package("UNKNOWN"),
            )

    def test_rejects_invalid_severity(self) -> None:
        package = build_evidence_package()
        package["top_source_ips"][0]["severity"] = "SEVERE"

        with self.assertRaisesRegex(ValueError, "unsupported threat severity"):
            normalize_finding_to_threat_evidence("finding-severity", package)

    def test_finding_adapter_rejects_missing_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "finding.evidence"):
            normalize_finding_item_to_threat_evidence(
                {"finding_id": "finding-no-evidence"}
            )


if __name__ == "__main__":
    unittest.main()
