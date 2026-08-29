# ============================================================
# Immutable Threat Evidence Archive
# ============================================================
#
# This bucket is intentionally separate from the executive and compliance
# report buckets. Reports are replaceable presentation artifacts; normalized
# threat evidence is an audit record and requires write-once-read-many controls.
#
resource "aws_s3_bucket" "asgard_threat_evidence" {
  # S3 bucket names are global. bucket_prefix preserves the Asgard naming
  # convention while allowing AWS to append a unique suffix.
  bucket_prefix = var.threat_evidence_bucket_prefix

  # Object Lock must be enabled when this bucket is created. Once enabled, it
  # cannot be disabled. force_destroy remains false so Terraform cannot bypass
  # the archive's retention purpose during a destroy operation.
  object_lock_enabled = true
  force_destroy       = false

  tags = merge(local.common_tags, {
    Name               = "Asgard Threat Evidence Archive"
    Purpose            = "SecurityAuditEvidence"
    DataClassification = "SecuritySensitive"
  })
}

# Object Lock protects individual object versions, so versioning is a required
# part of the WORM design rather than an optional recovery feature.
resource "aws_s3_bucket_versioning" "asgard_threat_evidence" {
  bucket = aws_s3_bucket.asgard_threat_evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Governance mode prevents ordinary deletion or retention reduction while
# still permitting a separately authorized emergency bypass. The Response
# Agent will not receive s3:BypassGovernanceRetention permission.
resource "aws_s3_bucket_object_lock_configuration" "asgard_threat_evidence" {
  bucket              = aws_s3_bucket.asgard_threat_evidence.id
  object_lock_enabled = "Enabled"

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.threat_evidence_retention_days
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.asgard_threat_evidence
  ]
}

# SSE-S3 encrypts every archived evidence object at rest. The Python uploader
# also requests AES256 so the application and infrastructure agree explicitly.
resource "aws_s3_bucket_server_side_encryption_configuration" "asgard_threat_evidence" {
  bucket = aws_s3_bucket.asgard_threat_evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Enable all account-independent S3 public-access protections. This guards
# against both public ACLs and a future public bucket policy.
resource "aws_s3_bucket_public_access_block" "asgard_threat_evidence" {
  bucket = aws_s3_bucket.asgard_threat_evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Explicitly deny unencrypted network transport. A Deny applies even if a
# future IAM policy accidentally grants broader S3 permissions.
data "aws_iam_policy_document" "asgard_threat_evidence_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.asgard_threat_evidence.arn,
      "${aws_s3_bucket.asgard_threat_evidence.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# Apply the TLS-only policy after public-access protections are established.
resource "aws_s3_bucket_policy" "asgard_threat_evidence" {
  bucket = aws_s3_bucket.asgard_threat_evidence.id
  policy = data.aws_iam_policy_document.asgard_threat_evidence_bucket.json

  depends_on = [
    aws_s3_bucket_public_access_block.asgard_threat_evidence
  ]
}
