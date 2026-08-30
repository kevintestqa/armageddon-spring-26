# Optional Response Agent enrichment

The handler now saves the correlation finding, creates the incident, and emits
its event **before** performing best-effort enrichment and archival. Enrichment
does not change the original severity or decision. The existing S3 evidence
object gains an `enrichment` field containing provider results and skip reasons.
No second object, DynamoDB schema change, or new event payload is introduced.

## Activation (not performed by the implementation)

1. Review the Terraform plan before applying the secret container, scoped
   inline policy, and Lambda environment changes. Do not apply an unexpected
   full-stack create/destroy plan.
2. In Secrets Manager, populate the generated `asgard-abuseipdb-*` secret with
   the API key as **plaintext SecretString**, not a JSON object. Never put the
   value in Terraform variables, state, source code, logs, or this document.
3. Confirm the Lambda can reach the provider endpoints over HTTPS.
4. Set `enable_threat_enrichment = true`, review the plan, and deploy. The
   default is false so existing deployments do not unexpectedly call providers.
5. Exercise a controlled finding and inspect the S3 JSON object's `enrichment`
   field. A successful Lambda invocation does not prove all providers succeeded.
   Inspect each result's SUCCESS, NOT_FOUND, or ERROR status separately.

Set the flag back to false to stop enrichment. Archival continues and records
that enrichment was skipped. The secret has a 30-day deletion recovery window.
The Lambda can only GetSecretValue on that secret; it cannot update/delete it.

## Routing and failure behavior

- AbuseIPDB: primary IPv4/IPv6 indicator. Missing/failed secret retrieval yields
  an ERROR result; it does not block the other providers.
- CISA KEV: explicit `finding.evidence.cve_ids`, or a primary CVE indicator.
- MITRE: explicit `finding.evidence.candidate_technique_ids` and a supported
  primary indicator type. These IDs are never extracted from generated prose.

The current WAF correlation builder does not populate the CVE or technique
lists. Consequently IP reputation is initially the only active lookup. Future
deterministic mapping can supply these fields without altering the coordinator.

Providers are created per invocation. Their in-memory catalog caches are not
retained across invocations. Secret values are also reread each invocation to
support rotation. No durable threat-intelligence cache is introduced here.

## Execution-time limitations

Enrichment skips when fewer than 20 seconds remain. Each provider HTTP request
uses one attempt with a three-second socket timeout and checks for at least
15 seconds remaining before starting. Secrets Manager uses short connect/read
timeouts and one attempt. The existing 60-second Lambda timeout is unchanged.

Socket timeouts are **not** a hard total deadline: slow streaming responses or
large MITRE catalogs can still take longer. Core incident/event processing is
already complete, but the final archive/handler response can still be affected
by a Lambda timeout. Monitor duration before enabling this broadly; a separate
asynchronous enrichment worker is the next step if strict latency isolation is
required. This implementation is not an exactly-once processing guarantee.

## Verification

From `Lab12`: `python -m unittest discover -s tests/python -p 'test_*.py' -v`.
Provider HTTP and secret calls are mocked in integration tests.

`threat-enrichment-check.tf` supplies local Given/When/Then checks.
`tests/threat_enrichment.tftest.hcl` supplies mocked CI scenarios, automatically
discovered by the existing pre-flight workflow alongside the other suites.
