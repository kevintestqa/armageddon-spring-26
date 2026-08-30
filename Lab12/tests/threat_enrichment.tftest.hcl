mock_provider "aws" {}
mock_provider "archive" {}

override_resource {
  target          = aws_secretsmanager_secret.asgard_abuseipdb
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:asgard-abuseipdb-test" }
}

run "enrichment_defaults_off_and_uses_secret_reference" {
  command = plan
  # Given credentials are not populated by Terraform,
  # When planning defaults,
  # Then enrichment stays off and only a secret ARN is configured.
  assert {
    condition = (
      aws_lambda_function.asgard_response_agent_function.environment[0].variables.ENABLE_THREAT_ENRICHMENT == "false" &&
      aws_lambda_function.asgard_response_agent_function.environment[0].variables.ABUSEIPDB_SECRET_ARN == aws_secretsmanager_secret.asgard_abuseipdb.arn
    )
    error_message = "Enrichment must default off and use a secret reference."
  }
  assert {
    condition = (
      jsondecode(aws_iam_role_policy.asgard_response_agent_secret.policy).Statement[0].Resource == aws_secretsmanager_secret.asgard_abuseipdb.arn &&
      jsondecode(aws_iam_role_policy.asgard_response_agent_secret.policy).Statement[0].Action == ["secretsmanager:GetSecretValue"] &&
      aws_secretsmanager_secret.asgard_abuseipdb.recovery_window_in_days == 30 &&
      aws_secretsmanager_secret.asgard_abuseipdb.tags.Project == "Asgard"
    )
    error_message = "Secret policy, recovery period, and project tag must remain scoped."
  }
}

run "enrichment_can_be_enabled" {
  command = plan
  variables { enable_threat_enrichment = true }
  # Given credentials have been populated out of band,
  # When explicitly enabled,
  # Then the handler receives the enabled flag.
  assert {
    condition     = aws_lambda_function.asgard_response_agent_function.environment[0].variables.ENABLE_THREAT_ENRICHMENT == "true"
    error_message = "Enrichment must respect the explicit enable flag."
  }
}
