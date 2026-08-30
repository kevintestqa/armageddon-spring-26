"""Given/When/Then scenarios for enrichment routing without network calls."""

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Lambda_Src" / "response_agent_package"))

from providers.base_provider import ProviderResult
from enrichment_coordinator import enrich_threat_evidence


def evidence(kind="IPV4", value="203.0.113.42"):
    return {
        "identity": {"evidence_id": "finding-1"},
        "indicator": {"indicator_type": kind, "indicator_value": value},
        "context": {"severity": "HIGH"},
    }


def fake_provider(name):
    provider = Mock()
    provider.enrich.side_effect = lambda indicator, context: ProviderResult.success(
        provider=name, indicator=indicator, ttl_seconds=60, data={"fixture": True}
    )
    return provider


class EnrichmentCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.providers = {name: fake_provider(name) for name in ("abuseipdb", "cisa_kev", "mitre_attack")}

    def run_enrichment(self, item=None, **kwargs):
        return enrich_threat_evidence(
            evidence() if item is None else item,
            **self.providers,
            **kwargs,
        )

    def test_ip_only_skips_cisa_and_mitre(self):
        """Given an IP only, when enriched, then only AbuseIPDB is called."""
        result = self.run_enrichment()
        self.providers["abuseipdb"].enrich.assert_called_once()
        self.providers["cisa_kev"].enrich.assert_not_called()
        self.providers["mitre_attack"].enrich.assert_not_called()
        self.assertEqual(set(result["skipped"]), {"cisa_kev", "mitre_attack"})
        self.assertEqual(result["results"]["abuseipdb"][0]["status"], "SUCCESS")

    def test_all_providers_with_explicit_identifiers(self):
        """Given CVEs and techniques, when enriched, then deduplicated IDs are routed."""
        result = self.run_enrichment(
            cve_ids=[" cve-2021-44228 ", "CVE-2021-44228", "CVE-2020-1234"],
            candidate_technique_ids=[" t1110 ", "T1110", "T1059.001"],
        )
        self.assertEqual(len(result["results"]["cisa_kev"]), 2)
        self.assertEqual(
            [call.args[0].value for call in self.providers["cisa_kev"].enrich.call_args_list],
            ["CVE-2021-44228", "CVE-2020-1234"],
        )
        self.assertEqual(self.providers["mitre_attack"].enrich.call_args.args[1],
                         {"candidate_technique_ids": ["T1110", "T1059.001"]})
        self.assertEqual(result["skipped"], {})

    def test_ipv6_and_primary_cve_routing(self):
        """Given IPv6 or a primary CVE, when enriched, then the correct provider receives it."""
        self.run_enrichment(evidence("IPV6", "2001:db8::1"))
        self.assertEqual(self.providers["abuseipdb"].enrich.call_args.args[0].indicator_type, "IPV6")
        self.providers["abuseipdb"].reset_mock()
        result = self.run_enrichment(evidence("CVE", "cve-2021-44228"))
        self.providers["abuseipdb"].enrich.assert_not_called()
        self.assertEqual(result["results"]["cisa_kev"][0]["indicator"], "CVE-2021-44228")

    def test_unexpected_failure_does_not_stop_other_providers(self):
        """Given a provider exception, when enriched, then others run and secret text is omitted."""
        self.providers["abuseipdb"].enrich.side_effect = RuntimeError("secret-value")
        result = self.run_enrichment(cve_ids=["CVE-2021-44228"], candidate_technique_ids=["T1110"])
        self.assertEqual(result["results"]["abuseipdb"][0]["status"], "ERROR")
        self.assertNotIn("secret-value", json.dumps(result))
        self.providers["cisa_kev"].enrich.assert_called_once()
        self.providers["mitre_attack"].enrich.assert_called_once()

    def test_not_found_is_preserved(self):
        """Given a catalog miss, when enriched, then NOT_FOUND is not rewritten as success."""
        self.providers["cisa_kev"].enrich.side_effect = lambda indicator, context: ProviderResult.not_found(
            provider="cisa_kev", indicator=indicator, ttl_seconds=60
        )
        result = self.run_enrichment(cve_ids=["CVE-2021-44228"])
        self.assertEqual(result["results"]["cisa_kev"][0]["status"], "NOT_FOUND")

    def test_original_evidence_is_not_mutated(self):
        """Given evidence, when enriched, then original severity and nested data remain unchanged."""
        item = evidence()
        original = copy.deepcopy(item)
        result = self.run_enrichment(item)
        result["evidence"]["context"]["severity"] = "LOW"
        self.assertEqual(item, original)
        json.dumps(result)

    def test_invalid_identifiers_rejected_before_provider_calls(self):
        """Given malformed identifiers, when enriched, then validation fails before any lookup."""
        for kwargs in ({"cve_ids": "CVE-2021-44228"}, {"cve_ids": ["oops"]},
                       {"candidate_technique_ids": ["Tbad"]}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.run_enrichment(**kwargs)
        for provider in self.providers.values():
            provider.enrich.assert_not_called()

    def test_unsupported_primary_indicator_skips_ip_and_mitre(self):
        """Given an email indicator, when enriched, then unsupported lookups are skipped."""
        result = self.run_enrichment(evidence("EMAIL", "test@example.test"), candidate_technique_ids=["T1110"])
        self.assertEqual(set(result["skipped"]), set(self.providers))
        for provider in self.providers.values():
            provider.enrich.assert_not_called()


if __name__ == "__main__":
    unittest.main()
