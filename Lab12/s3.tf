resource "aws_s3_bucket" "asgard_executive_report" {
  bucket        = "asgard-executive-report"
  force_destroy = true

  versioning {
    enabled = true
  }

  tags = {
    Name = "Asgard Cloud Security Executive Report Bucket"
  }
}