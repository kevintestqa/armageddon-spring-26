resource "aws_sns_topic" "asgard_critical_alerts_topic" {
  name = "${local.name_prefix}-critical-incidents"
}

resource "aws_sns_topic_subscription" "asgard_critical_alerts_sub" {
  topic_arn = aws_sns_topic.asgard_critical_alerts_topic.arn
  protocol  = "email"
  endpoint  = var.sns_email_endpoint
}

resource "aws_sns_topic" "asgard_medium_high_alerts_topic" {
  name = "${local.name_prefix}-medium-high-incidents"
}

resource "aws_sns_topic_subscription" "asgard_medium_high_alerts_sub" {
  topic_arn = aws_sns_topic.asgard_medium_high_alerts_topic.arn
  protocol  = "email"
  endpoint  = var.sns_email_endpoint
}