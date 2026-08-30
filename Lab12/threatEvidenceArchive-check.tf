# ============================================================
# Feature: Immutable Threat Evidence Archive
# ============================================================
#
# Scenario: Protect the evidence bucket with S3 Object Lock
#   Given the threat evidence archive stores security audit records,
#   When the bucket configuration is evaluated,
#   Then Object Lock must be enabled and force destroy must be disabled.
#
check "threat_evidence_archive_is_immutable" {
  assert {
    condition = (
      aws_s3_bucket.asgard_threat_evidence.object_lock_enabled &&
      !aws_s3_bucket.asgard_threat_evidence.force_destroy
    )
    error_message = "Threat evidence must enable Object Lock and disable force_destroy."
  }
}

# ============================================================
# Scenario: Retain every evidence version for one year
#   Given Object Lock requires S3 Versioning,
#   When retention controls are evaluated,
#   Then versioning must be enabled with 365-day Governance retention.
#
check "threat_evidence_archive_retention_is_governed" {
  assert {
    condition = (
      one(aws_s3_bucket_versioning.asgard_threat_evidence.versioning_configuration).status == "Enabled" &&
      one(one(aws_s3_bucket_object_lock_configuration.asgard_threat_evidence.rule).default_retention).mode == "GOVERNANCE" &&
      one(one(aws_s3_bucket_object_lock_configuration.asgard_threat_evidence.rule).default_retention).days == 365
    )
    error_message = "Threat evidence must use versioning and 365-day Governance retention."
  }
}

# ============================================================
# Scenario: Encrypt archived threat evidence
#   Given evidence contains security-sensitive information,
#   When the bucket encryption configuration is evaluated,
#   Then SSE-S3 encryption must be enabled with AES256.
#
check "threat_evidence_archive_is_encrypted" {
  assert {
    condition = (
      one(one(aws_s3_bucket_server_side_encryption_configuration.asgard_threat_evidence.rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    )
    error_message = "Threat evidence must use AES256 server-side encryption."
  }
}

# ============================================================
# Scenario: Block every form of public access
#   Given threat evidence must remain private,
#   When S3 public-access controls are evaluated,
#   Then all four public-access protections must be enabled.
#
check "threat_evidence_archive_blocks_public_access" {
  assert {
    condition = (
      aws_s3_bucket_public_access_block.asgard_threat_evidence.block_public_acls &&
      aws_s3_bucket_public_access_block.asgard_threat_evidence.block_public_policy &&
      aws_s3_bucket_public_access_block.asgard_threat_evidence.ignore_public_acls &&
      aws_s3_bucket_public_access_block.asgard_threat_evidence.restrict_public_buckets
    )
    error_message = "Threat evidence must block all forms of public access."
  }
}

# ============================================================
# Scenario: Allocate archive costs to Asgard
#   Given the project uses cost-allocation tags,
#   When the evidence bucket tags are evaluated,
#   Then Project must equal Asgard.
#
check "threat_evidence_archive_has_asgard_tag" {
  assert {
    condition     = aws_s3_bucket.asgard_threat_evidence.tags["Project"] == "Asgard"
    error_message = "Threat evidence archive must use the Project=Asgard tag."
  }
}
