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