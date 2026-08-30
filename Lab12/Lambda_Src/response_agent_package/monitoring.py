"""Low-cardinality operational counters, published as CloudWatch EMF logs.

Lambda's existing CloudWatch Logs permissions are sufficient. Never include
IPs, finding IDs, exception text, or credentials in dimensions. These counters
describe processing outcomes, not a deduplicated inventory of threats.
"""

import json
import time

NAMESPACE = "Asgard/ThreatMonitoring"


def _emit(name, dimensions=None, value=1):
    dimensions = dimensions or {}
    try:
        print(json.dumps({
            "_aws": {
                "Timestamp": int(time.time() * 1000),
                "CloudWatchMetrics": [{
                    "Namespace": NAMESPACE,
                    "Dimensions": [list(dimensions)],
                    "Metrics": [{"Name": name, "Unit": "Count"}],
                }],
            },
            **dimensions,
            name: value,
        }))
    except Exception:
        # Telemetry must not turn a successful investigation into a failure.
        pass


def record_finding(severity):
    severity = severity if severity in {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"} else "UNKNOWN"
    _emit("FindingsCreated")
    _emit("FindingsBySeverity", {"Severity": severity})


def record_archive(status):
    if status in {"SUCCESS", "ERROR", "SKIPPED"}:
        _emit("ArchiveOutcomes", {"Status": status})


def record_enrichment(record):
    # Whole-stage skips/errors are not provider calls; count them separately.
    stage = record.get("status")
    if stage in {"SKIPPED", "ERROR"}:
        _emit("EnrichmentStageOutcomes", {"Status": stage})
        return
    _emit("EnrichmentStageOutcomes", {"Status": "COMPLETED"})
    for provider in ("abuseipdb", "cisa_kev", "mitre_attack"):
        for result in record.get("results", {}).get(provider, []):
            status = result.get("status")
            if status in {"SUCCESS", "NOT_FOUND", "ERROR"}:
                _emit("ProviderOutcomes", {"Provider": provider, "Status": status})
        if provider in record.get("skipped", {}):
            _emit("ProviderOutcomes", {"Provider": provider, "Status": "SKIPPED"})
