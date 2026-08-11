# ============================================================
# Feature: Executive Report S3 Bucket
# ============================================================
#
# Scenario: Verify the executive report S3 bucket exists
#   Given the executive report S3 bucket is configured,
#   When the bucket is checked,
#   Then the executive report S3 bucket should exist.
#
check "executive_report_bucket_exists" {
  assert {
    condition     = aws_s3_bucket.asgard_executive_report.id != ""
    error_message = "Executive report S3 bucket was not created."
  }
}

# ============================================================
# Scenario: Verify force destroy is enabled
# ============================================================
#
#   Given the executive report S3 bucket is configured with force destroy,
#   When the force destroy setting is checked,
#   Then force_destroy should be enabled.
#
check "executive_report_force_destroy_enabled" {
  assert {
    condition     = aws_s3_bucket.asgard_executive_report.force_destroy
    error_message = "Executive report bucket should have force_destroy enabled."
  }
}

# ============================================================
# Scenario: Verify the bucket has a Name tag
# ============================================================
#
#   Given the executive report S3 bucket is configured with tags,
#   When the bucket tags are checked,
#   Then the bucket should contain a Name tag.
#
check "executive_report_bucket_name_tag" {
  assert {
    condition = contains(
      keys(aws_s3_bucket.asgard_executive_report.tags),
      "Name"
    )

    error_message = "Executive report bucket must have a Name tag."
  }
}

# ============================================================
# Scenario: Verify the expected bucket name
# ============================================================
#
#   Given the executive report S3 bucket is configured with a bucket name,
#   When the bucket name is checked,
#   Then the bucket name should equal "asgard-executive-report".
#
check "executive_report_bucket_expected_name" {
  assert {
    condition = aws_s3_bucket.asgard_executive_report.bucket == "asgard-executive-report"

    error_message = "Unexpected executive report bucket name."
  }
}

# ============================================================
# Feature: Compliance Report S3 Bucket
# ============================================================
#
# Scenario: Verify the compliance report S3 bucket exists
#   Given the compliance report S3 bucket is configured,
#   When the bucket is checked,
#   Then the compliance report S3 bucket should exist.
#
check "compliance_report_bucket_exists" {
  assert {
    condition     = aws_s3_bucket.asgard_compliance_report.id != ""
    error_message = "Compliance report S3 bucket was not created."
  }
}

# ============================================================
# Scenario: Verify force destroy is enabled
# ============================================================
#
#   Given the compliance report S3 bucket is configured with force destroy,
#   When the force destroy setting is checked,
#   Then force_destroy should be enabled.
#
check "compliance_report_force_destroy_enabled" {
  assert {
    condition     = aws_s3_bucket.asgard_compliance_report.force_destroy
    error_message = "Compliance report bucket should have force_destroy enabled."
  }
}

# ============================================================
# Scenario: Verify the bucket has a Name tag
# ============================================================
#
#   Given the compliance report S3 bucket is configured with tags,
#   When the bucket tags are checked,
#   Then the bucket should contain a Name tag.
#
check "compliance_report_bucket_name_tag" {
  assert {
    condition = contains(
      keys(aws_s3_bucket.asgard_compliance_report.tags),
      "Name"
    )

    error_message = "Compliance report bucket must have a Name tag."
  }
}

# ============================================================
# Scenario: Verify the expected bucket name
# ============================================================
#
#   Given the compliance report S3 bucket is configured with a bucket name,
#   When the bucket name is checked,
#   Then the bucket name should equal "asgard-compliance-report".
#
check "compliance_report_bucket_expected_name" {
  assert {
    condition = aws_s3_bucket.asgard_compliance_report.bucket == "asgard-compliance-report"

    error_message = "Unexpected compliance report bucket name."
  }
}