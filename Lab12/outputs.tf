output "api_gateway_invoke_url" {
  description = "Invoke URL for the API Gateway REST API"
  value       = "https://${aws_api_gateway_rest_api.asgard_api_rest.id}.execute-api.${data.aws_region.current.region}.amazonaws.com/${aws_api_gateway_stage.qa_environment.stage_name}"
}

output "response_agent_lambda" {
  description = "Response Agent Lambda function."
  value       = aws_lambda_function.asgard_response_agent_function.function_name
}

output "threat_evidence_bucket_name" {
  description = "Immutable S3 archive used by the Response Agent."
  value       = aws_s3_bucket.asgard_threat_evidence.bucket
}

output "executive_dashboard_lambda" {
  description = "Executive Dashboard Lambda function."
  value       = aws_lambda_function.executive_dashboard_agent.function_name
}

output "correlation_findings_table" {
  value = aws_dynamodb_table.asgard_waf_correlation_findings.name
}

output "security_incidents_table" {
  value = aws_dynamodb_table.asgard_security_incidents.name
}

output "executive_reports_bucket" {
  value = aws_s3_bucket.asgard_executive_report.bucket
}

output "security_notifications_topic" {
  value = aws_sns_topic.asgard_medium_high_alerts_topic.arn
}

output "event_bus_name" {
  value = data.aws_cloudwatch_event_bus.default.name
}

output "web_acl_name" {
  value = aws_wafv2_web_acl.asgard_waf_v2.name
}

output "critical_alerts_topic_endpoint" {
  value = aws_sns_topic_subscription.asgard_critical_alerts_sub.endpoint
}

output "medium_high_alerts_topic_endpoint" {
  value = aws_sns_topic_subscription.asgard_medium_high_alerts_sub.endpoint
}
