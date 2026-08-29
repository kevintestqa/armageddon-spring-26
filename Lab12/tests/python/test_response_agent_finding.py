"""Tests for deterministic Response Agent finding construction."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("SECURITY_INCIDENTS_TABLE", "test-security-incidents")
os.environ.setdefault("CORRELATION_FINDINGS_TABLE", "test-correlation-findings")
os.environ.setdefault("WAF_EVENTS_TABLE", "test-waf-events")
os.environ.setdefault("THREAT_EVIDENCE_BUCKET", "test-evidence-archive")

LAMBDA_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "Lambda_Src"
    / "response_agent_package"
)

sys.path.insert(0, str(LAMBDA_SOURCE))

import response_agent
from response_agent import build_finding_item
from threat_evidence import normalize_finding_item_to_threat_evidence


def build_evidence_package() -> dict:
    """Return representative deterministic correlation evidence."""

    return {
        "analysis_window": {
            "start": "2026-08-28T01:00:00+00:00",
            "end": "2026-08-28T02:00:00+00:00",
            "minutes": 60,
        },
        "summary": {
            "total_events": 5,
            "blocked_events": 5,
            "allowed_events": 0,
            "unique_source_ips": 1,
            "unique_uris": 2,
        },
        "top_source_ips": [
            {
                "source_ip": "203.0.113.42",
                "event_count": 5,
                "blocked_count": 5,
                "allowed_count": 0,
                "uris": ["/admin", "/login"],
                "rules": ["AWSManagedRulesCommonRuleSet"],
                "countries": ["US"],
                "first_seen": "2026-08-28T01:05:00+00:00",
                "last_seen": "2026-08-28T01:10:00+00:00",
                "risk_score": 70,
                "severity": "HIGH",
            }
        ],
        "top_targeted_uris": [
            {
                "uri": "/admin",
                "event_count": 3,
            }
        ],
        "top_waf_rules": [],
        "deterministic_findings": [],
    }


class BuildFindingItemTests(unittest.TestCase):
    def test_archives_normalized_finding_and_returns_object_key(self) -> None:
        finding = build_finding_item(
            finding_id="finding-archive",
            created_at="2026-08-28T02:01:00+00:00",
            evidence_package=build_evidence_package(),
            bedrock_report="Correlation report.",
        )

        with patch.object(
            response_agent,
            "archive_threat_evidence",
            return_value="threat-evidence/year=2026/finding-archive.json",
        ) as archive:
            object_key = (
                response_agent.archive_finding_as_threat_evidence(finding)
            )

        self.assertEqual(
            object_key,
            "threat-evidence/year=2026/finding-archive.json",
        )
        archived_evidence = archive.call_args.kwargs["evidence"]
        self.assertEqual(
            archived_evidence["identity"]["evidence_id"],
            finding["finding_id"],
        )
        self.assertEqual(
            archive.call_args.kwargs["bucket_name"],
            "test-evidence-archive",
        )

    def test_archive_failure_does_not_escape_response_agent(self) -> None:
        finding = build_finding_item(
            finding_id="finding-archive-error",
            created_at="2026-08-28T02:01:00+00:00",
            evidence_package=build_evidence_package(),
            bedrock_report="Correlation report.",
        )

        with patch.object(
            response_agent,
            "archive_threat_evidence",
            side_effect=RuntimeError("S3 unavailable"),
        ):
            object_key = (
                response_agent.archive_finding_as_threat_evidence(finding)
            )

        self.assertIsNone(object_key)

    def test_save_finding_writes_and_returns_same_item(self) -> None:
        evidence_package = build_evidence_package()

        with patch.object(
            response_agent.findings_table,
            "put_item",
        ) as put_item:
            finding = response_agent.save_finding(
                evidence_package=evidence_package,
                bedrock_report="Correlation report.",
            )

        put_item.assert_called_once_with(Item=finding)
        self.assertEqual(finding["evidence"], evidence_package)
        self.assertEqual(finding["bedrock_report"], "Correlation report.")

    def test_builds_existing_dynamodb_item_shape(self) -> None:
        evidence_package = build_evidence_package()

        finding = build_finding_item(
            finding_id="finding-123",
            created_at="2026-08-28T02:01:00+00:00",
            evidence_package=evidence_package,
            bedrock_report="Correlation report.",
        )

        self.assertEqual(
            finding,
            {
                "finding_id": "finding-123",
                "created_at": "2026-08-28T02:01:00+00:00",
                "window_start": "2026-08-28T01:00:00+00:00",
                "window_end": "2026-08-28T02:00:00+00:00",
                "severity": "HIGH",
                "risk_score": 70,
                "event_count": 5,
                "primary_source_ip": "203.0.113.42",
                "primary_target": "/admin",
                "status": "OPEN",
                "bedrock_report": "Correlation report.",
                "evidence": evidence_package,
            },
        )

    def test_uses_safe_defaults_when_correlations_are_empty(self) -> None:
        evidence_package = build_evidence_package()
        evidence_package["top_source_ips"] = []
        evidence_package["top_targeted_uris"] = []

        finding = build_finding_item(
            finding_id="finding-empty",
            created_at="2026-08-28T02:01:00+00:00",
            evidence_package=evidence_package,
            bedrock_report="No correlation report.",
        )

        self.assertEqual(finding["risk_score"], 0)
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["primary_source_ip"], "NONE")
        self.assertEqual(finding["primary_target"], "NONE")

    def test_keeps_evidence_package_for_later_normalization(self) -> None:
        evidence_package = build_evidence_package()

        finding = build_finding_item(
            finding_id="finding-evidence",
            created_at="2026-08-28T02:01:00+00:00",
            evidence_package=evidence_package,
            bedrock_report="Correlation report.",
        )

        self.assertIs(finding["evidence"], evidence_package)

    def test_finding_item_feeds_threat_evidence_normalizer(self) -> None:
        finding = build_finding_item(
            finding_id="finding-normalized",
            created_at="2026-08-28T02:01:00+00:00",
            evidence_package=build_evidence_package(),
            bedrock_report="Correlation report.",
        )

        threat_evidence = normalize_finding_item_to_threat_evidence(
            finding,
            aws_account_id="123456789012",
            aws_region="us-west-1",
        )

        self.assertEqual(
            threat_evidence["identity"]["evidence_id"],
            finding["finding_id"],
        )
        self.assertEqual(
            threat_evidence["indicator"]["indicator_value"],
            finding["primary_source_ip"],
        )
        self.assertEqual(
            threat_evidence["context"]["severity"],
            finding["severity"],
        )
        self.assertIn(
            finding["bedrock_report"],
            threat_evidence["context"]["notes"],
        )


if __name__ == "__main__":
    unittest.main()
