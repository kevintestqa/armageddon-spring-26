# ============================================================
# Response Agent IAM
# ============================================================
#
# The Response Agent has a dedicated execution role so authentication,
# reporting, and compliance Lambdas do not inherit correlation or immutable
# archive permissions. Each statement maps to an AWS API call in
# response_agent.py.

locals {
  asgard_response_agent_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowLambdaAssumeRole"
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  # Keeping the statements in local JSON makes the policy deterministic under
  # the mocked AWS provider used by Terraform CI.
  asgard_response_agent_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadWafEvents"
        Effect   = "Allow"
        Action   = ["dynamodb:Scan"]
        Resource = aws_dynamodb_table.asgard_waf_events.arn
      },
      {
        Sid    = "WriteCorrelationRecords"
        Effect = "Allow"
        Action = ["dynamodb:PutItem"]
        Resource = [
          aws_dynamodb_table.asgard_waf_correlation_findings.arn,
          aws_dynamodb_table.asgard_security_incidents.arn
        ]
      },
      {
        Sid    = "InvokeBedrockModel"
        Effect = "Allow"
        Action = ["bedrock:InvokeModel"]

        # The cross-Region inference profile can route to foundation models in
        # multiple Regions. Restrict the action now; resource scoping can follow
        # after the model destination Region set is fixed.
        Resource = "*"
      },
      {
        Sid      = "PublishSecurityEvents"
        Effect   = "Allow"
        Action   = ["events:PutEvents"]
        Resource = data.aws_cloudwatch_event_bus.default.arn
      },
      {
        Sid      = "ArchiveThreatEvidence"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.asgard_threat_evidence.arn}/threat-evidence/*"
      }
    ]
  })
}

resource "aws_iam_role" "asgard_response_agent" {
  name               = "asgard_response_agent_role"
  assume_role_policy = local.asgard_response_agent_trust_policy
}

resource "aws_iam_role_policy_attachment" "asgard_response_agent_basic_execution" {
  role       = aws_iam_role.asgard_response_agent.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "asgard_response_agent" {
  name        = "asgard_response_agent_policy"
  description = "Least-privilege application permissions for the Asgard Response Agent."
  policy      = local.asgard_response_agent_policy
}

resource "aws_iam_role_policy_attachment" "asgard_response_agent" {
  role       = aws_iam_role.asgard_response_agent.name
  policy_arn = aws_iam_policy.asgard_response_agent.arn
}
