"""Lambda-only configuration for optional, best-effort enrichment."""

import os

import boto3
from botocore.config import Config

from enrichment_coordinator import enrich_threat_evidence
from providers import AbuseIpDbProvider, CisaKevProvider, MitreAttackProvider
from providers.base_provider import JsonHttpClient, ProviderResponseError


class BudgetedHttpClient(JsonHttpClient):
    """Check Lambda time before each request; avoid provider retry backoff.

    Socket timeouts are not an overall execution deadline. Keep a reserve for
    archival, and keep this feature optional for latency-sensitive workloads.
    """

    def __init__(self, context):
        super().__init__(timeout_seconds=3, max_attempts=1)
        self.context = context

    def get_json(self, *args, **kwargs):
        if self.context and self.context.get_remaining_time_in_millis() < 15000:
            raise ProviderResponseError("Insufficient Lambda time for enrichment.")
        return super().get_json(*args, **kwargs)


def enrich_for_archive(evidence, finding, context=None):
    """Return enrichment or an explicit skip; never expose secret error text."""
    if os.environ.get("ENABLE_THREAT_ENRICHMENT", "false").lower() != "true":
        return {"status": "SKIPPED", "reason": "Enrichment disabled."}
    if context and context.get_remaining_time_in_millis() < 20000:
        return {"status": "SKIPPED", "reason": "Insufficient Lambda time."}

    api_key = None
    try:
        secret_arn = os.environ.get("ABUSEIPDB_SECRET_ARN")
        if secret_arn:
            client = boto3.client("secretsmanager", config=Config(
                connect_timeout=2, read_timeout=2, retries={"total_max_attempts": 1}
            ))
            # Contract: a plaintext SecretString, not JSON. Never log the value
            # or store it in the evidence. Read each invocation for rotation.
            api_key = client.get_secret_value(SecretId=secret_arn)["SecretString"].strip()
    except Exception:
        # Missing credentials must not disable CISA/MITRE enrichment.
        api_key = None

    try:
        http = BudgetedHttpClient(context)
        abuse = AbuseIpDbProvider(api_key=api_key, http_client=http)
        # Do not silently fall back to a legacy plaintext environment secret.
        abuse.api_key = api_key
        record = enrich_threat_evidence(
            evidence,
            abuseipdb=abuse,
            cisa_kev=CisaKevProvider(http_client=http),
            mitre_attack=MitreAttackProvider(http_client=http),
            # Only structured deterministic fields are accepted, never IDs
            # extracted from the Bedrock report or untrusted invocation input.
            cve_ids=finding.get("evidence", {}).get("cve_ids", []),
            candidate_technique_ids=finding.get("evidence", {}).get("candidate_technique_ids", []),
        )
        return {"results": record["results"], "skipped": record["skipped"]}
    except Exception as error:
        return {"status": "ERROR", "reason": type(error).__name__}
