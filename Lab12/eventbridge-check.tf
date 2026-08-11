check "critical_rule_filters_critical_findings" {
  # Given the critical EventBridge rule is configured with an event pattern,
  # when the severity filter is checked,
  # then the rule should contain only CRITICAL severity.

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
  # Given the medium/high EventBridge rule is configured with an event pattern,
  # when the severity filter is checked,
  # then the rule should contain only MEDIUM and HIGH severities.

  assert {
    condition = toset(
      jsondecode(
        aws_cloudwatch_event_rule.asgard_medium_high_findings.event_pattern
      ).detail.severity
    ) == toset(["MEDIUM", "HIGH"])

    error_message = "The medium/high EventBridge rule must contain only MEDIUM and HIGH severities."
  }
}