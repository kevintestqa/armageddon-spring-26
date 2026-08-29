"""Unit tests for the packaged threat-intelligence providers.

The tests inject an in-memory HTTP client so local development and CI never
contact AbuseIPDB, CISA, or MITRE over the network.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any


LAMBDA_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "Lambda_Src"
    / "response_agent_package"
)
sys.path.insert(0, str(LAMBDA_SOURCE))

from providers import (
    AbuseIpDbProvider,
    CisaKevProvider,
    Indicator,
    MitreAttackProvider,
)
from providers.base_provider import UnsupportedIndicatorError


class FakeHttpClient:
    """Return a fixed payload while recording each attempted HTTP request."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.calls: list[dict[str, Any]] = []

    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        query_parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "url": url,
                "headers": headers,
                "query_parameters": query_parameters,
            }
        )
        return self.payload


class AbuseIpDbProviderTests(unittest.TestCase):
    def test_normalizes_successful_ip_reputation_response(self) -> None:
        client = FakeHttpClient(
            {
                "data": {
                    "ipAddress": "203.0.113.42",
                    "ipVersion": 4,
                    "isPublic": True,
                    "isWhitelisted": False,
                    "abuseConfidenceScore": "82",
                    "countryCode": "US",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example ISP",
                    "domain": "example.test",
                    "hostnames": ["host.example.test"],
                    "isTor": False,
                    "totalReports": "12",
                    "numDistinctUsers": "7",
                    "lastReportedAt": "2026-08-28T01:00:00Z",
                }
            }
        )
        provider = AbuseIpDbProvider(api_key="test-key", http_client=client)

        result = provider.enrich(Indicator.create("203.0.113.42", "ipv4"))

        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.data["abuse_confidence_score"], 82)
        self.assertEqual(result.data["total_reports"], 12)
        self.assertEqual(result.data["risk"], "HIGH")
        self.assertEqual(client.calls[0]["headers"]["Key"], "test-key")
        self.assertEqual(
            client.calls[0]["query_parameters"]["ipAddress"],
            "203.0.113.42",
        )

    def test_missing_api_key_becomes_normalized_failure(self) -> None:
        provider = AbuseIpDbProvider(api_key="", http_client=FakeHttpClient({}))
        provider.api_key = None

        result = provider.enrich(Indicator.create("203.0.113.42", "IPV4"))

        self.assertEqual(result.status, "ERROR")
        self.assertIn("ABUSEIPDB_API_KEY", result.error)

    def test_invalid_ip_becomes_normalized_failure_without_http_call(self) -> None:
        client = FakeHttpClient({})
        provider = AbuseIpDbProvider(api_key="test-key", http_client=client)

        result = provider.enrich(Indicator.create("not-an-ip", "IPV4"))

        self.assertEqual(result.status, "ERROR")
        self.assertIn("Invalid IP address", result.error)
        self.assertEqual(client.calls, [])


class CisaKevProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FakeHttpClient(
            {
                "catalogVersion": "2026.08.28",
                "dateReleased": "2026-08-28T00:00:00Z",
                "count": 1,
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-44228",
                        "vendorProject": "Apache",
                        "product": "Log4j",
                        "vulnerabilityName": "Log4Shell",
                        "dateAdded": "2021-12-10",
                        "shortDescription": "Remote code execution.",
                        "requiredAction": "Apply vendor updates.",
                        "dueDate": "2021-12-24",
                        "knownRansomwareCampaignUse": "Known",
                        "notes": "",
                        "cwes": ["CWE-502"],
                    }
                ],
            }
        )
        self.provider = CisaKevProvider(http_client=self.client)

    def test_returns_known_exploited_cve(self) -> None:
        result = self.provider.enrich(
            Indicator.create("CVE-2021-44228", "CVE")
        )

        self.assertEqual(result.status, "SUCCESS")
        self.assertTrue(result.data["known_exploited"])
        self.assertEqual(result.data["product"], "Log4j")
        self.assertEqual(result.data["catalog_version"], "2026.08.28")

    def test_returns_not_found_without_claiming_cve_is_safe(self) -> None:
        result = self.provider.enrich(
            Indicator.create("CVE-2099-0001", "CVE")
        )

        self.assertEqual(result.status, "NOT_FOUND")
        self.assertFalse(result.data["known_exploited"])
        self.assertIn("does not establish", result.data["interpretation"])

    def test_reuses_catalog_from_memory(self) -> None:
        self.provider.enrich(Indicator.create("CVE-2021-44228", "CVE"))
        self.provider.enrich(Indicator.create("CVE-2099-0001", "CVE"))

        self.assertEqual(len(self.client.calls), 1)


class MitreAttackProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FakeHttpClient(
            {
                "objects": [
                    {
                        "type": "attack-pattern",
                        "name": "Brute Force",
                        "description": "Attempt to gain access by guessing.",
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": "T1110",
                            }
                        ],
                        "kill_chain_phases": [
                            {"phase_name": "credential-access"},
                            {"phase_name": "credential-access"},
                        ],
                        "x_mitre_platforms": ["Linux", "Windows"],
                        "x_mitre_is_subtechnique": False,
                        "created": "2017-05-31T21:31:22Z",
                        "modified": "2025-10-24T14:48:49Z",
                    },
                    {
                        "type": "attack-pattern",
                        "revoked": True,
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": "T9999",
                            }
                        ],
                    },
                ]
            }
        )
        self.provider = MitreAttackProvider(http_client=self.client)
        self.indicator = Indicator.create("203.0.113.42", "IPV4")

    def test_returns_not_found_without_candidate_techniques_or_http_call(self) -> None:
        result = self.provider.enrich(self.indicator)

        self.assertEqual(result.status, "NOT_FOUND")
        self.assertEqual(result.data["techniques"], [])
        self.assertEqual(self.client.calls, [])

    def test_normalizes_matched_and_unmatched_techniques(self) -> None:
        result = self.provider.enrich(
            self.indicator,
            {"candidate_technique_ids": [" t1110 ", "T9999", "T1110"]},
        )

        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.data["matched_technique_ids"], ["T1110"])
        self.assertEqual(result.data["unmatched_technique_ids"], ["T9999"])
        self.assertEqual(
            result.data["techniques"][0]["tactics"],
            ["credential-access"],
        )

    def test_reuses_stix_bundle_from_memory(self) -> None:
        context = {"candidate_technique_ids": ["T1110"]}

        self.provider.enrich(self.indicator, context)
        self.provider.enrich(self.indicator, context)

        self.assertEqual(len(self.client.calls), 1)

    def test_rejects_unsupported_indicator_before_http_call(self) -> None:
        with self.assertRaises(UnsupportedIndicatorError):
            self.provider.enrich(Indicator.create("user@example.test", "EMAIL"))

        self.assertEqual(self.client.calls, [])


if __name__ == "__main__":
    unittest.main()
