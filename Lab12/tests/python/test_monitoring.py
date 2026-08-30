"""Gherkin-style acceptance tests for metric publishing; no AWS calls."""
import json
import unittest
from unittest.mock import patch
from test_response_agent_finding import response_agent, build_evidence_package
import monitoring


class MonitoringTests(unittest.TestCase):
    def capture(self, function, *args):
        with patch("builtins.print") as output:
            function(*args)
        return [json.loads(call.args[0]) for call in output.call_args_list]

    def test_finding_emf_contract(self):
        # Given the Asgard metric publisher receives a finding with HIGH severity,
        # when record_finding publishes the finding metrics,
        # then it should emit total and HIGH-severity counters with the expected EMF namespace, dimensions, timestamp, and Count unit.

        events = self.capture(monitoring.record_finding, "HIGH")
        self.assertEqual(events[0]["FindingsCreated"], 1)
        self.assertEqual(events[1]["Severity"], "HIGH")
        for event in events:
            definition = event["_aws"]["CloudWatchMetrics"][0]
            self.assertEqual(definition["Namespace"], "Asgard/ThreatMonitoring")
            self.assertEqual(definition["Metrics"][0]["Unit"], "Count")
            self.assertIsInstance(event["_aws"]["Timestamp"], int)
        self.assertEqual(events[0]["_aws"]["CloudWatchMetrics"][0]["Dimensions"], [[]])
        self.assertEqual(events[1]["_aws"]["CloudWatchMetrics"][0]["Dimensions"], [["Severity"]])

    def test_unknown_severity_is_bounded(self):
        # Given the Asgard metric publisher receives an unrecognized severity value,
        # when record_finding selects the severity dimension,
        # then it should use UNKNOWN instead of creating a dimension from the supplied value.

        self.assertEqual(self.capture(monitoring.record_finding, "private-data")[1]["Severity"], "UNKNOWN")

    def test_provider_outcomes(self):
        # Given the Asgard enrichment record contains successful, not-found, failed, and skipped provider lookups,
        # when record_enrichment publishes the outcome metrics,
        # then it should preserve each status and the provider dimensions without logging the supplied secret field.

        events = self.capture(monitoring.record_enrichment, {
            "results": {"abuseipdb": [{"status": "SUCCESS", "secret": "not-logged"}],
                        "cisa_kev": [{"status": "NOT_FOUND"}, {"status": "ERROR"}]},
            "skipped": {"mitre_attack": "No identifiers"},
        })
        self.assertEqual(len(events), 5)
        self.assertEqual([event["Status"] for event in events], ["COMPLETED", "SUCCESS", "NOT_FOUND", "ERROR", "SKIPPED"])
        self.assertNotIn("not-logged", json.dumps(events))
        self.assertEqual(events[1]["_aws"]["CloudWatchMetrics"][0]["Dimensions"], [["Provider", "Status"]])

    def test_disabled_enrichment_is_stage_skip(self):
        # Given the Asgard enrichment record has a SKIPPED stage status,
        # when record_enrichment publishes the stage outcome,
        # then it should emit one stage event without a Provider dimension.

        events = self.capture(monitoring.record_enrichment, {"status": "SKIPPED"})
        self.assertEqual(len(events), 1)
        self.assertNotIn("Provider", events[0])

    def test_archive_statuses(self):
        # Given the Asgard archive reports SUCCESS, ERROR, or SKIPPED,
        # when record_archive publishes each archive outcome,
        # then it should emit the corresponding Status dimension.

        for status in ("SUCCESS", "ERROR", "SKIPPED"):
            self.assertEqual(self.capture(monitoring.record_archive, status)[0]["Status"], status)

    def test_logging_failure_is_nonfatal(self):
        # Given the Asgard metric publisher cannot write to stdout because print raises an OSError,
        # when record_finding attempts to publish a LOW-severity finding,
        # then it should suppress the logging exception rather than raise it to the caller.

        with patch("builtins.print", side_effect=OSError("closed")):
            monitoring.record_finding("LOW")

    def test_failed_write_does_not_count_finding(self):
        # Given the Asgard findings table raises an error while persisting a finding,
        # when the response agent calls save_finding,
        # then it should propagate the write error without calling record_finding.

        with patch.object(response_agent.findings_table, "put_item", side_effect=RuntimeError), patch.object(response_agent, "record_finding") as record:
            with self.assertRaises(RuntimeError):
                response_agent.save_finding(build_evidence_package(), "report")
        record.assert_not_called()

    def test_archive_hooks(self):
        # Given the Asgard archive operation is configured to either return an object key or raise an error,
        # when the response agent normalizes, enriches, and attempts to archive a finding,
        # then it should record SUCCESS for the returned key and ERROR for the failed archive.

        for failure in (False, True):
            with patch.object(response_agent, "THREAT_EVIDENCE_BUCKET", "test"), patch.object(response_agent, "normalize_finding_item_to_threat_evidence", return_value={}), patch.object(response_agent, "enrich_for_archive", return_value={"status": "SKIPPED"}), patch.object(response_agent, "archive_threat_evidence", side_effect=RuntimeError if failure else None, return_value="key"), patch.object(response_agent, "record_archive") as record, patch("builtins.print"):
                response_agent.archive_finding_as_threat_evidence({})
            record.assert_called_once_with("ERROR" if failure else "SUCCESS")
