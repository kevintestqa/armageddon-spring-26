mock_provider "aws" {}

# ============================================================
# Feature: Immutable Threat Evidence Archive
# ============================================================
#
# Scenario: Plan a protected WORM evidence bucket
#   Given Asgard requires permanent security audit evidence,
#   When Terraform plans the evidence archive,
#   Then Object Lock must be enabled and force destroy must be disabled.
#
run "threat_evidence_bucket_is_protected" {
  command = plan

  assert {
    condition     = aws_s3_bucket.asgard_threat_evidence.object_lock_enabled == true
    error_message = "Threat evidence bucket must enable Object Lock."
  }

  assert {
    condition     = aws_s3_bucket.asgard_threat_evidence.force_destroy == false
    error_message = "Threat evidence bucket must disable force_destroy."
  }
}

# ============================================================
# Scenario: Apply Governance retention for one year
#   Given the archive uses S3 Object Lock,
#   When its retention rule is planned,
#   Then the mode must be Governance and the duration must be 365 days.
#
run "threat_evidence_retention_is_365_day_governance" {
  command = plan

  assert {
    condition = (
      one(one(aws_s3_bucket_object_lock_configuration.asgard_threat_evidence.rule).default_retention).mode == "GOVERNANCE"
    )
    error_message = "Threat evidence retention mode must be GOVERNANCE."
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_object_lock_configuration.asgard_threat_evidence.rule).default_retention).days == 365
    )
    error_message = "Threat evidence retention must be 365 days."
  }
}

# ============================================================
# Scenario: Require versioning and encryption
#   Given Object Lock protects individual object versions,
#   When storage controls are planned,
#   Then versioning and AES256 server-side encryption must be enabled.
#
run "threat_evidence_storage_controls_are_enabled" {
  command = plan

  assert {
    condition = (
      one(aws_s3_bucket_versioning.asgard_threat_evidence.versioning_configuration).status == "Enabled"
    )
    error_message = "Threat evidence bucket versioning must be enabled."
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_server_side_encryption_configuration.asgard_threat_evidence.rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    )
    error_message = "Threat evidence bucket must use AES256 encryption."
  }
}

# ============================================================
# Scenario: Prevent public access to security evidence
#   Given archived findings contain sensitive security data,
#   When public-access controls are planned,
#   Then every S3 public-access protection must be enabled.
#
run "threat_evidence_archive_is_private" {
  command = plan

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.asgard_threat_evidence.block_public_acls,
      aws_s3_bucket_public_access_block.asgard_threat_evidence.block_public_policy,
      aws_s3_bucket_public_access_block.asgard_threat_evidence.ignore_public_acls,
      aws_s3_bucket_public_access_block.asgard_threat_evidence.restrict_public_buckets
    ])
    error_message = "Threat evidence bucket must block all public access."
  }
}

# ============================================================
# Scenario: Reject unsafe retention values
#   Given archive retention must remain within the approved range,
#   When zero retention days are supplied,
#   Then Terraform must reject the variable value.
#
run "invalid_threat_evidence_retention_is_rejected" {
  command = plan

  variables {
    threat_evidence_retention_days = 0
  }

  expect_failures = [
    var.threat_evidence_retention_days
  ]
}

# ============================================================
# Scenario: Connect the Response Agent to the archive
#   Given the immutable evidence bucket has been planned,
#   When the Response Agent runtime configuration is evaluated,
#   Then it must receive the bucket name and prefix-scoped PutObject access.
#
run "response_agent_can_archive_threat_evidence" {
  command = plan

  assert {
    condition = (
      aws_lambda_function.asgard_response_agent_function.environment[0].variables["THREAT_EVIDENCE_BUCKET"] ==
      aws_s3_bucket.asgard_threat_evidence.bucket
    )
    error_message = "Response Agent must receive the threat evidence bucket name."
  }

  assert {
    condition = length([
      for statement in jsondecode(aws_iam_policy.asgard_lambda_app_policy.policy).Statement : statement
      if(
        try(statement.Sid, "") == "ArchiveThreatEvidence"
        && statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset(["s3:PutObject"])
        && try(statement.Resource, "") == "${aws_s3_bucket.asgard_threat_evidence.arn}/threat-evidence/*"
      )
    ]) == 1
    error_message = "Response Agent must have prefix-scoped s3:PutObject access to the archive."
  }
}
