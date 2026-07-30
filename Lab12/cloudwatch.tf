resource "aws_cloudwatch_log_group" "asgard_logs" {
  name              = "asgard_logs"
  retention_in_days = 7

  tags = {
    Name = "${local.name_prefix}-log"
  }
}

resource "aws_cloudwatch_log_resource_policy" "asgard_logs_resource_policy" {
  policy_document = data.aws_iam_policy_document.asgard_waf_log_policy.json
  policy_name     = "WAF-logging-policy"
}