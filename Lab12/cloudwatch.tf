locals {
  name_prefix    = var.project_name
  ports_http     = 80
  ports_ssh      = 22
  ports_https    = 443
  ports_dns      = 53
  db_port        = 3306
  tcp_protocol   = "tcp"
  udp_protocol   = "udp"
  all_ip_address = "0.0.0.0/0"
  all_ports      = "-1"
  all_protocol   = "All"
  http           = "http"
  https          = "https"
}


resource "aws_cloudwatch_log_group" "asgard_logs" {
  name              = "asgard_logs"
  retention_in_days = 7

  tags = {
    Name = "${local.name_prefix}-log"
  }
}

//Maybe I need this.  There is no policy document defined in the console
resource "aws_cloudwatch_log_resource_policy" "asgard_logs_resource_policy" {
  policy_document = data.aws_iam_policy_document.waf_log_policy.json
  policy_name     = "WAF-logging-policy"
}