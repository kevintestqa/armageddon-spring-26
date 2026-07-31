resource "aws_s3_bucket" "asgard_executive_report" {
  bucket        = "asgard-executive-report"
  force_destroy = true

  tags = {
    Name = "Asgard Cloud Security Executive Report Bucket"
  }
}

resource "aws_s3_bucket_versioning" "asgard_executive_report_versioning" {
  bucket = aws_s3_bucket.asgard_executive_report.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "asgard_compliance_report" {
  bucket        = "asgard-compliance-report"
  force_destroy = true

  tags = {
    Name = "Asgard Cloud Security Compliance Report Bucket"
  }
}

resource "aws_s3_bucket_versioning" "asgard_compliance_report_versioning" {
  bucket = aws_s3_bucket.asgard_compliance_report.id
  versioning_configuration {
    status = "Enabled"
  }
}