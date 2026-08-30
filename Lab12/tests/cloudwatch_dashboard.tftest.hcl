mock_provider "aws" {}
mock_provider "archive" {}

# Given the pipeline is deployed, 
#when planning monitoring,
# then the dashboard uses actual Lambda names and bounded custom dimensions.
run "asgard_monitoring_contract" {
  command = plan
  assert {
    condition     = aws_cloudwatch_dashboard.main.dashboard_name == "Asgard-Threat-Monitoring" && length(jsondecode(aws_cloudwatch_dashboard.main.dashboard_body).widgets) == 12
    error_message = "The named dashboard must include all twelve widgets."
  }
  assert {
    condition     = alltrue([for widget in local.monitoring_widgets : widget.properties.region == "us-east-1" if widget.type == "metric"])
    error_message = "Every metric must target us-east-1."
  }
  assert {
    condition     = local.operational_charts[0].metrics[0][3] == aws_lambda_function.asgard_response_agent_function.function_name && local.operational_charts[3].stat == "Average"
    error_message = "Native widgets must use real function names and the documented duration statistic."
  }
  assert {
    condition     = alltrue([for chart in local.evidence_charts : chart.stat == "Sum" && alltrue([for metric in chart.metrics : metric[0] == "Asgard/ThreatMonitoring"])])
    error_message = "Custom count metrics must use Sum and the publisher namespace."
  }
  assert {
    condition     = tolist(local.evidence_charts[4].metrics[0]) == tolist(["Asgard/ThreatMonitoring", "ProviderOutcomes", "Provider", "abuseipdb", "Status", "SUCCESS"]) && local.monitoring_widgets[5].properties.setPeriodToTimeRange
    error_message = "Provider dimensions and the total's time-range aggregation must match the publisher."
  }
}
