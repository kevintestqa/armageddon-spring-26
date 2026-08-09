resource "aws_s3_bucket" "asgard_executive_report" {
  bucket        = var.executive_report_bucket_name
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
  bucket        = var.compliance_report_bucket_name
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