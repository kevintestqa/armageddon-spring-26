resource "aws_ce_anomaly_subscription" "asgard_anomaly_subscription" {
  name      = "${var.project_name}-anomaly-subscription"
  frequency = "DAILY"

  monitor_arn_list = [
    local.service_monitor_arn
  ]

  subscriber {
    type    = "EMAIL"
    address = var.sns_email_endpoint
  }

  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      match_options = ["GREATER_THAN_OR_EQUAL"]
      values        = [tostring(var.anomaly_threshold_absolute)]
    }
  }

  tags = local.common_tags
}
