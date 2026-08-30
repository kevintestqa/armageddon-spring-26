"""Given/When/Then tests for secret handling and Lambda enrichment."""

import json
import os
import unittest
from unittest.mock import Mock, patch

from test_response_agent_finding import (
    response_agent, build_evidence_package, build_finding_item,
)
import enrichment_runtime as runtime
from providers.base_provider import ProviderResponseError


class EnrichmentRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "ENABLE_THREAT_ENRICHMENT": "true", "ABUSEIPDB_SECRET_ARN": "test-secret-arn"
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.finding = build_finding_item(
            finding_id="test", created_at="2026-08-28T02:01:00Z",
            evidence_package=build_evidence_package(), bedrock_report="report",
        )
        self.evidence = response_agent.normalize_finding_item_to_threat_evidence(self.finding)

    def test_disabled_and_low_budget_make_no_calls(self):
        # Given Asgard threat enrichment is disabled or the Lambda has only ten seconds remaining,
        # when enrich_for_archive checks whether enrichment can proceed,
        # then it should return SKIPPED without creating an AWS client.

        with patch.object(runtime.boto3, "client") as client:
            with patch.dict(os.environ, {"ENABLE_THREAT_ENRICHMENT": "false"}):
                self.assertEqual(runtime.enrich_for_archive(self.evidence, self.finding)["status"], "SKIPPED")
            context = Mock()
            context.get_remaining_time_in_millis.return_value = 10000
            self.assertEqual(runtime.enrich_for_archive(self.evidence, self.finding, context)["status"], "SKIPPED")
            client.assert_not_called()

    def test_secret_used_only_for_provider_and_results_archived(self):
        # Given Asgard Secrets Manager returns an AbuseIPDB API key and the provider returns reputation data,
        # when the response agent enriches and archives the finding,
        # then it should use the key in the provider request but archive only the enrichment result while preserving HIGH finding severity.

        with (
            patch.object(runtime.boto3, "client") as client,
            patch.object(runtime.BudgetedHttpClient, "get_json", return_value={"data": {"abuseConfidenceScore": 80}}) as http,
            patch.object(response_agent, "archive_threat_evidence", return_value="test-key") as archive,
        ):
            client.return_value.get_secret_value.return_value = {"SecretString": "fixture-secret"}
            key = response_agent.archive_finding_as_threat_evidence(self.finding)
        self.assertEqual(key, "test-key")
        client.return_value.get_secret_value.assert_called_once_with(SecretId="test-secret-arn")
        self.assertEqual(http.call_args.kwargs["headers"]["Key"], "fixture-secret")
        saved = archive.call_args.kwargs["evidence"]
        self.assertNotIn("fixture-secret", json.dumps(saved))
        self.assertEqual(saved["enrichment"]["results"]["abuseipdb"][0]["status"], "SUCCESS")
        self.assertEqual(saved["context"]["severity"], "HIGH")

    def test_secret_failure_does_not_stop_other_providers(self):
        # Given Asgard secret retrieval fails and the finding contains a CVE identifier,
        # when enrich_for_archive runs the available providers,
        # then it should record the AbuseIPDB error, still query CISA, and omit the secret error text from the results.

        self.finding["evidence"]["cve_ids"] = ["CVE-2021-44228"]
        with (
            patch.object(runtime.boto3, "client") as client,
            patch.object(runtime.BudgetedHttpClient, "get_json", return_value={"vulnerabilities": []}) as http,
        ):
            client.return_value.get_secret_value.side_effect = RuntimeError("secret-value")
            result = runtime.enrich_for_archive(self.evidence, self.finding)
        self.assertEqual(result["results"]["abuseipdb"][0]["status"], "ERROR")
        self.assertEqual(result["results"]["cisa_kev"][0]["status"], "NOT_FOUND")
        self.assertNotIn("secret-value", json.dumps(result))
        http.assert_called_once()

    def test_request_checks_remaining_time(self):
        # Given the Asgard Lambda context reports only one second of execution time remaining,
        # when the budget-aware HTTP client attempts another provider lookup,
        # then it should raise ProviderResponseError without making an HTTP request.

        context = Mock()
        context.get_remaining_time_in_millis.return_value = 1000
        with patch.object(runtime.JsonHttpClient, "get_json") as http:
            with self.assertRaises(ProviderResponseError):
                runtime.BudgetedHttpClient(context).get_json("https://example.test")
            http.assert_not_called()

    def test_handler_survives_provider_failure(self):
        # Given Asgard AbuseIPDB requests fail while finding persistence and archival are available,
        # when the response agent Lambda handler processes the finding,
        # then it should return statusCode 200 and an archive key with the provider ERROR recorded in the archived evidence.

        with (
            patch.object(runtime.boto3, "client") as client,
            patch.object(runtime.BudgetedHttpClient, "get_json", side_effect=RuntimeError("offline")),
            patch.object(response_agent, "archive_threat_evidence", return_value="archived") as archive,
        ):
            client.return_value.get_secret_value.return_value = {"SecretString": "fixture-secret"}
            # Exercise real normalization, enrichment and archival orchestration.
            from datetime import datetime, timezone
            with (
                patch.object(response_agent, "get_recent_events", return_value=([{}, {}, {}], datetime.now(timezone.utc), datetime.now(timezone.utc))),
                patch.object(response_agent, "build_evidence_package", return_value=build_evidence_package()),
                patch.object(response_agent, "call_bedrock", return_value="report"),
                patch.object(response_agent, "save_finding", return_value=self.finding),
                patch.object(response_agent, "save_security_incident", return_value="incident"),
                patch.object(response_agent, "publish_finding_event"),
            ):
                result = response_agent.lambda_handler({}, None)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(json.loads(result["body"])["evidence_archive_key"], "archived")
        self.assertEqual(archive.call_args.kwargs["evidence"]["enrichment"]["results"]["abuseipdb"][0]["status"], "ERROR")
