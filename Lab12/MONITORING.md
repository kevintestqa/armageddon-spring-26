# Asgard monitoring

Terraform owns the Asgard-Threat-Monitoring dashboard in cloudwatch.tf.
The response agent publishes JSON Embedded Metric Format (EMF) log events
through monitoring.py. CloudWatch extracts counters from those logs; no
PutMetricData call or additional IAM permission is needed. Keep Lambda's
application log format as Text so these JSON lines remain raw EMF events.

## Counter contract

- FindingsCreated: emitted after a successful finding write to DynamoDB.
- FindingsBySeverity: same event, with a bounded Severity dimension.
- ArchiveOutcomes: SUCCESS after upload; ERROR for normalization/upload failure;
  SKIPPED when the archive bucket is not configured.
- EnrichmentStageOutcomes: COMPLETED, ERROR, or SKIPPED.
  COMPLETED does not mean every provider succeeded.
- ProviderOutcomes: Provider and Status dimensions. Each lookup result is counted;
  absent identifiers produce SKIPPED, not ERROR. Disabled enrichment produces a
  stage skip, not fabricated provider outcomes.

Counters are processing events, not distinct findings. Reprocessing can increase
counts. No IP addresses, evidence IDs, API keys or error messages are dimensions.
Provider reputation never overrides the finding severity in these counters.

Native Lambda widgets cover invocations, errors, throttles and average duration
in milliseconds for the response, WAF analyzer, executive and compliance agents.
Handled exceptions/HTTP-style statusCode errors do not necessarily increment
the native Lambda Errors metric.

## Deploy and verify

1. Run Python tests and Terraform checks, then review terraform plan.
2. Deploy through the normal Lambda packaging/Terraform process. These edits do
   not rebuild the ZIP or deploy anything themselves.
3. Invoke the existing flow and inspect response-agent logs for a JSON event
   with an _aws key and namespace Asgard/ThreatMonitoring.
4. Open the dashboard and select a time range containing the invocation.
   Custom metrics have no historical backfill; allow time for extraction.
5. Compare FindingsCreated with successful writes and ArchiveOutcomes with
   the archived evidence. Missing data is not a confirmed zero.

The previous sample dashboard name changes from my-dashboard. Review that
change in your plan. Custom metrics and dashboard usage can incur AWS charges;
bounded dimensions limit the number of time series.

Local assertions: cloudwatch-check.tf.
CI assertions: tests/cloudwatch_dashboard.tftest.hcl.
Python unit tests: tests/python/test_monitoring.py.
