# Terraform owns the container only. Populate its plaintext value out of band
# so the AbuseIPDB key never enters Terraform configuration or state.
resource "aws_secretsmanager_secret" "asgard_abuseipdb" {
  name_prefix             = "asgard-abuseipdb-"
  recovery_window_in_days = 30
  tags = merge(local.common_tags, {
    Project = "Asgard"
    Purpose = "ThreatIntelligence"
  })
}

variable "enable_threat_enrichment" {
  description = "Enable only after the AbuseIPDB secret has a plaintext value and outbound connectivity is verified."
  type        = bool
  default     = false
}

# Kept separate from the core runtime policy: enabling an integration must not
# grant these credentials to the shared authentication/reporting Lambda role.
resource "aws_iam_role_policy" "asgard_response_agent_secret" {
  name = "asgard-abuseipdb-read"
  role = aws_iam_role.asgard_response_agent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = aws_secretsmanager_secret.asgard_abuseipdb.arn
    }]
  })
}
