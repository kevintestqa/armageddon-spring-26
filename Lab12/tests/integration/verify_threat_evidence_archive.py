"""Opt-in post-deployment acceptance check for the Response Agent archive."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import boto3


def required_environment(name: str) -> str:
    """Read a required nonempty environment variable."""

    value = os.environ.get(name, "").strip()

    if not value:
        raise RuntimeError(f"{name} must be configured.")

    return value


def main() -> int:
    """Invoke the deployed agent and verify the resulting protected object."""

    region = os.environ.get("AWS_REGION", "us-west-1")
    function_name = required_environment("RESPONSE_AGENT_FUNCTION_NAME")
    bucket_name = required_environment("THREAT_EVIDENCE_BUCKET")

    lambda_client = boto3.client("lambda", region_name=region)
    s3_client = boto3.client("s3", region_name=region)

    # This invocation uses the normal Response Agent path. The deployed WAF
    # events table must already contain enough recent events for correlation.
    invocation = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps({}).encode("utf-8"),
    )

    payload = json.loads(invocation["Payload"].read())

    if invocation.get("FunctionError"):
        raise RuntimeError(f"Lambda invocation failed: {payload}")

    if payload.get("statusCode") != 200:
        raise RuntimeError(f"Response Agent returned an error: {payload}")

    body = json.loads(payload["body"])
    object_key = body.get("evidence_archive_key")

    if not object_key:
        raise RuntimeError(
            "No evidence_archive_key was returned. Ensure enough recent WAF "
            "events exist and inspect the Response Agent logs."
        )

    object_metadata = s3_client.head_object(
        Bucket=bucket_name,
        Key=object_key,
    )
    archived_object = s3_client.get_object(
        Bucket=bucket_name,
        Key=object_key,
    )
    evidence = json.loads(archived_object["Body"].read())

    if object_metadata.get("ServerSideEncryption") != "AES256":
        raise AssertionError("Archived evidence must use AES256 encryption.")

    if not object_metadata.get("VersionId"):
        raise AssertionError("Archived evidence must have an S3 version ID.")

    if object_metadata.get("ObjectLockMode") != "GOVERNANCE":
        raise AssertionError("Archived evidence must use GOVERNANCE retention.")

    retain_until = object_metadata.get("ObjectLockRetainUntilDate")

    if not retain_until or retain_until <= datetime.now(timezone.utc):
        raise AssertionError("Archived evidence retention must be in the future.")

    if evidence.get("identity", {}).get("evidence_id") != body["finding_id"]:
        raise AssertionError(
            "Archived evidence ID must match the returned finding ID."
        )

    print(f"Verified s3://{bucket_name}/{object_key}")
    print(f"Version: {object_metadata['VersionId']}")
    print(f"Retained until: {retain_until.isoformat()}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, ValueError) as error:
        print(f"Acceptance check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
