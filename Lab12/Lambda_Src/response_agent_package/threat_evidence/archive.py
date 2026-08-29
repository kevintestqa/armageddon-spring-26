"""Archive normalized Asgard threat evidence in Amazon S3."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any


DEFAULT_EVIDENCE_PREFIX = "threat-evidence"


def _required_identity_value(
    evidence: dict[str, Any],
    field_name: str,
) -> str:
    """Return a required nonempty string from the evidence identity."""

    identity = evidence.get("identity")

    if not isinstance(identity, dict):
        raise ValueError("evidence.identity must be a dictionary.")

    value = identity.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"evidence.identity.{field_name} cannot be empty.")

    return value.strip()


def _parse_collected_at(value: str) -> datetime:
    """Parse a timezone-aware ISO-8601 collection timestamp."""

    try:
        collected_at = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            "evidence.identity.collected_at must be a valid ISO-8601 timestamp."
        ) from error

    if collected_at.tzinfo is None:
        raise ValueError(
            "evidence.identity.collected_at must include a timezone."
        )

    return collected_at


def _safe_key_component(value: str) -> str:
    """Replace characters that could create unintended S3 key paths."""

    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def build_evidence_object_key(
    evidence: dict[str, Any],
    prefix: str = DEFAULT_EVIDENCE_PREFIX,
) -> str:
    """Build a date-partitioned S3 key for one evidence record."""

    normalized_prefix = prefix.strip().strip("/")

    if not normalized_prefix:
        raise ValueError("evidence prefix cannot be empty.")

    evidence_id = _required_identity_value(evidence, "evidence_id")
    collected_at_value = _required_identity_value(evidence, "collected_at")
    collected_at = _parse_collected_at(collected_at_value)

    # Hive-style date partitions keep the archive navigable and make future
    # Athena queries able to prune unrelated days efficiently.
    return (
        f"{normalized_prefix}/"
        f"year={collected_at:%Y}/"
        f"month={collected_at:%m}/"
        f"day={collected_at:%d}/"
        f"{_safe_key_component(evidence_id)}.json"
    )


def archive_threat_evidence(
    s3_client: Any,
    bucket_name: str,
    evidence: dict[str, Any],
    prefix: str = DEFAULT_EVIDENCE_PREFIX,
) -> str:
    """Serialize and upload normalized evidence, returning its S3 key."""

    if not isinstance(bucket_name, str) or not bucket_name.strip():
        raise ValueError("evidence bucket name cannot be empty.")

    object_key = build_evidence_object_key(
        evidence=evidence,
        prefix=prefix,
    )

    # Stable ordering makes archived records easier to compare during an
    # investigation, while UTF-8 bytes are accepted directly by put_object.
    body = json.dumps(
        evidence,
        indent=2,
        sort_keys=True,
    )

    # Retention is inherited from the bucket's default Object Lock rule. The
    # Lambda therefore needs PutObject only—not retention or bypass privileges.
    s3_client.put_object(
        Bucket=bucket_name.strip(),
        Key=object_key,
        Body=body.encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )

    return object_key
