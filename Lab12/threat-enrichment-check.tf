# Feature: Isolated threat-intelligence credentials
check "threat_enrichment_secret_scope" {
  # Given the dedicated Response Agent role,
  # When its credential policy is evaluated,
  # Then only the one AbuseIPDB secret is readable.
  assert {
    condition = (
      aws_iam_role_policy.asgard_response_agent_secret.role == aws_iam_role.asgard_response_agent.id &&
      jsondecode(aws_iam_role_policy.asgard_response_agent_secret.policy).Statement[0].Resource == aws_secretsmanager_secret.asgard_abuseipdb.arn &&
      jsondecode(aws_iam_role_policy.asgard_response_agent_secret.policy).Statement[0].Action == ["secretsmanager:GetSecretValue"]
    )
    error_message = "Only the Response Agent may receive this scoped secret-read policy."
  }
}
