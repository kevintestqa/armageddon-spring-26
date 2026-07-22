resource "aws_cloudwatch_log_group" "odin_logs" {
  name = "odin_logs"
  retention_in_days = 7

  tags = {
    Name = "${local.name_prefix}-log"
  }
}

//Maybe I need this.  There is no policy document defined in the console
# resource "aws_cloudwatch_log_resource_policy" "odin_logs_resource_policy" {
#   policy_document = data.aws_iam_policy_document.waf_log_policy.json
#   policy_name     = "WAF-logging-policy"
# }