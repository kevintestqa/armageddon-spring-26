"""Tests for archiving normalized threat evidence in Amazon S3."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock


LAMBDA_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "Lambda_Src"
    / "response_agent_package"
)
sys.path.insert(0, str(LAMBDA_SOURCE))

from threat_evidence import (
    archive_threat_evidence,
    build_evidence_object_key,
)


def build_threat_evidence() -> dict:
    """Return a representative normalized threat-evidence record."""

    return {
        "identity": {
            "evidence_id": "finding-123",
            "provider_name": "AWS WAF Correlation Agent",
            "provider_type": "CLOUD_NATIVE",
            "provider_platform": "AWS",
            "provider_version": "1.0.0",
            "observed_at": "2026-08-28T01:05:00+00:00",
            "collected_at": "2026-08-28T02:00:00+00:00",
        },
        "indicator": {
            "indicator_type": "IPV4",
            "indicator_value": "203.0.113.42",
            "indicator_source": "AWS_WAF",
            "condition": "OTHER",
        },
        "source": {
            "account_id": "123456789012",
            "region": "us-west-1",
            "resource_id": None,
            "repository": None,
            "hostname": None,
            "ip_address": "203.0.113.42",
            "metadata": {"risk_score": 70},
        },
        "context": {
            "severity": "HIGH",
            "confidence": "CORRELATED",
            "provider_trust": "HIGH",
            "expires_at": None,
            "tags": ["asgard", "aws", "correlation", "waf"],
            "notes": "Source generated five blocked WAF events.",
        },
    }


class ThreatEvidenceArchiveTests(unittest.TestCase):
    def test_builds_date_partitioned_object_key(self) -> None:
        object_key = build_evidence_object_key(
            build_threat_evidence()
        )

        self.assertEqual(
            object_key,
            "threat-evidence/year=2026/month=08/day=28/finding-123.json",
        )

    def test_normalizes_prefix_and_unsafe_evidence_id(self) -> None:
        evidence = build_threat_evidence()
        evidence["identity"]["evidence_id"] = "finding/../../../123"

        object_key = build_evidence_object_key(
            evidence,
            prefix="/audit/evidence/",
        )

        self.assertEqual(
            object_key,
            "audit/evidence/year=2026/month=08/day=28/"
            "finding_.._.._.._123.json",
        )

    def test_uploads_json_with_expected_s3_settings(self) -> None:
        s3_client = Mock()
        evidence = build_threat_evidence()

        object_key = archive_threat_evidence(
            s3_client=s3_client,
            bucket_name="asgard-threat-evidence",
            evidence=evidence,
        )

        s3_client.put_object.assert_called_once()
        request = s3_client.put_object.call_args.kwargs

        self.assertEqual(request["Bucket"], "asgard-threat-evidence")
        self.assertEqual(request["Key"], object_key)
        self.assertEqual(request["ContentType"], "application/json")
        self.assertEqual(request["ServerSideEncryption"], "AES256")
        self.assertEqual(json.loads(request["Body"]), evidence)

    def test_rejects_empty_bucket_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "bucket name cannot be empty"):
            archive_threat_evidence(
                s3_client=Mock(),
                bucket_name=" ",
                evidence=build_threat_evidence(),
            )

    def test_rejects_collection_timestamp_without_timezone(self) -> None:
        evidence = build_threat_evidence()
        evidence["identity"]["collected_at"] = "2026-08-28T02:00:00"

        with self.assertRaisesRegex(ValueError, "must include a timezone"):
            build_evidence_object_key(evidence)


if __name__ == "__main__":
    unittest.main()
