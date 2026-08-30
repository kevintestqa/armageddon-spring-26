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

# Dashboard definitions consume metrics; they do not publish them.
locals {
  threat_metric_namespace = "Asgard/ThreatMonitoring"
  monitored_functions = [
    aws_lambda_function.asgard_response_agent_function.function_name,
    aws_lambda_function.waf_bedrock_analyzer.function_name,
    aws_lambda_function.executive_dashboard_agent.function_name,
    aws_lambda_function.compliance_agent.function_name,
  ]
  operational_charts = [
    for metric in ["Invocations", "Errors", "Throttles", "Duration"] : {
      title   = metric == "Duration" ? "Lambda duration (average milliseconds)" : "Lambda ${metric}"
      metrics = [for name in local.monitored_functions : ["AWS/Lambda", metric, "FunctionName", name]]
      stat    = metric == "Duration" ? "Average" : "Sum"
      view    = "timeSeries"
    }
  ]
  evidence_charts = concat([
    {
      title   = "Findings created (selected time range)"
      metrics = [[local.threat_metric_namespace, "FindingsCreated"]]
      stat    = "Sum"
      view    = "singleValue"
    },
    {
      title = "Findings by severity"
      metrics = [for severity in ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] :
      [local.threat_metric_namespace, "FindingsBySeverity", "Severity", severity]]
      stat = "Sum"
      view = "timeSeries"
    },
    {
      title = "Archive outcomes"
      metrics = [for status in ["SUCCESS", "ERROR", "SKIPPED"] :
      [local.threat_metric_namespace, "ArchiveOutcomes", "Status", status]]
      stat = "Sum"
      view = "timeSeries"
    },
    {
      title = "Enrichment stage outcomes"
      metrics = [for status in ["COMPLETED", "ERROR", "SKIPPED"] :
      [local.threat_metric_namespace, "EnrichmentStageOutcomes", "Status", status]]
      stat = "Sum"
      view = "timeSeries"
    }
    ], [
    for provider in ["abuseipdb", "cisa_kev", "mitre_attack"] : {
      title = "${provider} lookup outcomes"
      metrics = [for status in ["SUCCESS", "NOT_FOUND", "ERROR", "SKIPPED"] :
      [local.threat_metric_namespace, "ProviderOutcomes", "Provider", provider, "Status", status]]
      stat = "Sum"
      view = "timeSeries"
    }
  ])
  monitoring_widgets = concat([
    {
      type   = "text"
      x      = 0
      y      = 0
      width  = 24
      height = 3
      properties = {
        markdown = "# Asgard threat monitoring\nCustom counters begin after deployment and new invocations. Missing data is not zero. Counts describe processing, not unique threats. COMPLETED enrichment can include failed/skipped providers; provider outcomes are not finding severity. Lambda Errors excludes exceptions handled by application code."
      }
    }
    ], [
    for index, chart in concat(local.operational_charts, local.evidence_charts) : {
      type   = "metric"
      x      = (index % 2) * 12
      y      = 3 + floor(index / 2) * 6
      width  = 12
      height = 6
      properties = merge(chart, {
        region = "us-east-1"
        period = 300
        }, chart.view == "singleValue" ? {
        setPeriodToTimeRange = true
      } : {})
    }
  ])
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "Asgard-Threat-Monitoring"
  dashboard_body = jsonencode({
    start          = "-PT3H"
    periodOverride = "inherit"
    widgets        = local.monitoring_widgets
  })
}
