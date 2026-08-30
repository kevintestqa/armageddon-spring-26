mock_provider "aws" {}
mock_provider "archive" {}

run "finops_tags_and_budget_types" {
  command = plan
  # Given the canonical Project=Asgard cost tag is defined,
  # When the budget and tag activation are planned,
  # Then their key/value and numeric comparisons must agree.
  assert {
    condition = (
      local.common_tags.Project == "Asgard" &&
      aws_ce_cost_allocation_tag.asgard_cost_allocation_tag.tag_key == "Project" &&
      aws_ce_cost_allocation_tag.asgard_cost_allocation_tag.status == "Active" &&
      tonumber(aws_budgets_budget.asgard_budget.limit_amount) == var.budget_limit &&
      one(aws_budgets_budget.asgard_budget.cost_filter).values == tolist(["Project$Asgard"])
    )
    error_message = "Cost allocation and budget must consistently use Project=Asgard."
  }
}

run "reuse_existing_service_monitor" {
  command = plan
  variables {
    existing_service_monitor_arn = "arn:aws:ce::123456789012:anomalymonitor/example"
  }
  # Given an account-wide SERVICE monitor already exists,
  # When Asgard subscribes,
  # Then no new monitor is created or managed and its ARN is reused.
  assert {
    condition = (
      length(aws_ce_anomaly_monitor.asgard_service_anomaly_monitor) == 0 &&
      one(aws_ce_anomaly_subscription.asgard_anomaly_subscription.monitor_arn_list) == var.existing_service_monitor_arn
    )
    error_message = "Existing monitors must be reused without duplication."
  }
}

run "lambda_allowlist_includes_enrichment" {
  command = plan
  # Given optional threat enrichment is wired into the handler,
  # When the environment is planned,
  # Then its approved enable flag and secret reference must be present.
  assert {
    condition = toset(keys(aws_lambda_function.asgard_response_agent_function.environment[0].variables)) == toset([
      "CORRELATION_FINDINGS_TABLE", "SECURITY_INCIDENTS_TABLE", "WAF_EVENTS_TABLE",
      "THREAT_EVIDENCE_BUCKET", "BEDROCK_MODEL_ID", "ENABLE_BEDROCK",
      "ENABLE_THREAT_ENRICHMENT", "ABUSEIPDB_SECRET_ARN"
    ])
    error_message = "Only the eight approved Response Agent environment variables are allowed."
  }
}
