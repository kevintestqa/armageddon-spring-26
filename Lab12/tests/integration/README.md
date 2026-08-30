# Threat evidence archive acceptance check

This opt-in check invokes the deployed Response Agent and verifies that its
normalized evidence is stored in the protected S3 archive.

It is intentionally excluded from ordinary CI because invocation creates a
real correlation finding and requires recent WAF events in the deployed table.

Run it after `terraform apply` with AWS credentials for the target account:

```bash
export AWS_REGION="us-east-1"
export RESPONSE_AGENT_FUNCTION_NAME="$(terraform output -raw response_agent_lambda)"
export THREAT_EVIDENCE_BUCKET="$(terraform output -raw threat_evidence_bucket_name)"

python3 tests/integration/verify_threat_evidence_archive.py
```

The caller needs permission to invoke the Lambda and read the archived object.
The check verifies the handler result, evidence identity, AES256 encryption,
S3 version ID, Governance Object Lock mode, and future retention date.
