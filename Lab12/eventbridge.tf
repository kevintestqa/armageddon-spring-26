resource "aws_cloudwatch_event_rule" "asgard_medium_high_findings" {
  name = "soar-medium-high-findings"

  event_pattern = jsonencode({
    source      = ["seir.waf.correlation"]
    detail-type = ["WAF Threat Finding Created"]
    detail = {
      severity = ["MEDIUM", "HIGH"]
    }
  })
}

resource "aws_cloudwatch_event_target" "asgard_medium_high_findings_lambda" {
  rule = aws_cloudwatch_event_rule.asgard_medium_high_findings.name
  arn  = aws_lambda_function.asgard_lambda_function.arn
}

resource "aws_lambda_permission" "allow_eventbridge_asgard_medium_high_findings" {
  statement_id  = "AllowEventBridgeMediumHigh"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.asgard_lambda_function.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.asgard_medium_high_findings.arn
}

resource "aws_cloudwatch_event_rule" "asgard_critical_findings" {
  name = "asgard-critical-findings"

  event_pattern = jsonencode({
    source      = ["seir.waf.correlation"]
    detail-type = ["WAF Threat Finding Created"]
    detail = {
      severity = ["CRITICAL"]
    }
  })
}

resource "aws_lambda_permission" "allow_eventbridge_asgard_critical_findings" {
  statement_id  = "AllowEventBridgeCritical"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.asgard_lambda_function.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.asgard_critical_findings.arn
}

resource "aws_cloudwatch_event_target" "critical_asgard_lambda" {
  rule = aws_cloudwatch_event_rule.asgard_critical_findings.name
  arn  = aws_lambda_function.asgard_lambda_function.arn
}

resource "aws_cloudwatch_event_target" "critical_sns" {
  rule = aws_cloudwatch_event_rule.asgard_critical_findings.name
  arn  = aws_sns_topic.critical_alerts.arn
}

check "critical_rule_filters_critical_findings" {
  # Given the critical EventBridge rule,
  # when its event pattern is evaluated,
  # then its severity list must contain only CRITICAL
  assert {
    condition = toset(
      jsondecode(
        aws_cloudwatch_event_rule.asgard_critical_findings.event_pattern
      ).detail.severity
    ) == toset(["CRITICAL"])

    error_message = "The critical EventBridge rule must contain only the CRITICAL severity."
  }
}

check "medium_high_rule_filters_expected_severities" {
  # Given the medium/high EventBridge rule,
  # when its event pattern is evaluated,
  # then its severity list must contain only MEDIUM and HIGH
  assert {
    condition = toset(
      jsondecode(
        aws_cloudwatch_event_rule.asgard_medium_high_findings.event_pattern
      ).detail.severity
    ) == toset(["MEDIUM", "HIGH"])

    error_message = "The medium/high EventBridge rule must contain only MEDIUM and HIGH severities."
  }
}