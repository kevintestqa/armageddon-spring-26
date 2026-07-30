# ============================================================
# Feature: Executive Report S3 Bucket
# ============================================================
#
# Scenario: Verify the executive report S3 bucket is created
#   Given the Terraform configuration defines the executive report S3 bucket
#   When Terraform creates the infrastructure
#   Then the executive report S3 bucket should exist
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
#   Given the executive report S3 bucket exists
#   When Terraform evaluates the bucket configuration
#   Then force_destroy should be enabled
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
#   Given the executive report S3 bucket exists
#   When Terraform evaluates the bucket tags
#   Then the bucket should contain a Name tag
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
# Scenario: Verify the bucket name is configured
# ============================================================
#
#   Given the executive report S3 bucket exists
#   When Terraform evaluates the bucket name
#   Then the bucket name should not be empty
#
check "executive_report_bucket_name_not_empty" {
  assert {
    condition     = aws_s3_bucket.asgard_executive_report.bucket != ""
    error_message = "Executive report bucket name cannot be empty."
  }
}

# ============================================================
# Scenario: Verify the expected bucket name
# ============================================================
#
#   Given the executive report S3 bucket exists
#   When Terraform evaluates the bucket name
#   Then the bucket name should equal "asgard-executive-report"
#
check "executive_report_bucket_expected_name" {
  assert {
    condition = aws_s3_bucket.asgard_executive_report.bucket == "asgard-executive-report"

    error_message = "Unexpected executive report bucket name."
  }
}