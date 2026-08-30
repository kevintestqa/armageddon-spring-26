locals {
  response_agent_trust_policy = jsondecode(
    aws_iam_role.asgard_response_agent.assume_role_policy
  )
  response_agent_policy = jsondecode(
    aws_iam_policy.asgard_response_agent.policy
  )
}

# ============================================================
# Feature: Least-privilege Response Agent identity
# ============================================================

check "response_agent_role_trusts_only_lambda" {
  # Given the Response Agent has a dedicated execution role,
  # when its trust policy is evaluated,
  # then only the Lambda service may assume it.

  assert {
    condition = (
      length(local.response_agent_trust_policy.Statement) == 1
      && local.response_agent_trust_policy.Statement[0].Effect == "Allow"
      && local.response_agent_trust_policy.Statement[0].Action == "sts:AssumeRole"
      && local.response_agent_trust_policy.Statement[0].Principal.Service == "lambda.amazonaws.com"
    )
    error_message = "The Response Agent role must trust only lambda.amazonaws.com."
  }
}

check "response_agent_policy_matches_runtime_calls" {
  # Given the Response Agent reads telemetry and persists correlations,
  # when its DynamoDB statements are evaluated,
  # then it may scan only WAF events and write only findings and incidents.

  assert {
    condition = (
      length([
        for statement in local.response_agent_policy.Statement : statement
        if(
          statement.Sid == "ReadWafEvents"
          && toset(try(tolist(statement.Action), [statement.Action])) == toset(["dynamodb:Scan"])
          && try(statement.Resource, "") == aws_dynamodb_table.asgard_waf_events.arn
        )
      ]) == 1
      && length([
        for statement in local.response_agent_policy.Statement : statement
        if(
          statement.Sid == "WriteCorrelationRecords"
          && toset(try(tolist(statement.Action), [statement.Action])) == toset(["dynamodb:PutItem"])
          && toset(try(tolist(statement.Resource), [statement.Resource])) == toset([
            aws_dynamodb_table.asgard_waf_correlation_findings.arn,
            aws_dynamodb_table.asgard_security_incidents.arn
          ])
        )
      ]) == 1
    )
    error_message = "The Response Agent must have only its required DynamoDB scan and write permissions."
  }
}

check "response_agent_policy_limits_integrations" {
  # Given the Response Agent invokes Bedrock, emits events, and archives evidence,
  # when its integration statements are evaluated,
  # then each integration must expose only its required action and resource.

  assert {
    condition = (
      length([
        for statement in local.response_agent_policy.Statement : statement
        if(
          statement.Sid == "InvokeBedrockModel"
          && toset(try(tolist(statement.Action), [statement.Action])) == toset(["bedrock:InvokeModel"])
          && try(statement.Resource, "") == "*"
        )
      ]) == 1
      && length([
        for statement in local.response_agent_policy.Statement : statement
        if(
          statement.Sid == "PublishSecurityEvents"
          && toset(try(tolist(statement.Action), [statement.Action])) == toset(["events:PutEvents"])
          && try(statement.Resource, "") == data.aws_cloudwatch_event_bus.default.arn
        )
      ]) == 1
      && length([
        for statement in local.response_agent_policy.Statement : statement
        if(
          statement.Sid == "ArchiveThreatEvidence"
          && toset(try(tolist(statement.Action), [statement.Action])) == toset(["s3:PutObject"])
          && try(statement.Resource, "") == "${aws_s3_bucket.asgard_threat_evidence.arn}/threat-evidence/*"
        )
      ]) == 1
    )
    error_message = "The Response Agent integration permissions must remain least privilege."
  }
}

check "response_agent_policy_has_no_unexpected_statements" {
  # Given the policy is derived from observed runtime calls,
  # when all statement IDs are evaluated,
  # then no unrelated application capability may be present.

  assert {
    condition = toset([
      for statement in local.response_agent_policy.Statement : statement.Sid
      ]) == toset([
      "ReadWafEvents",
      "WriteCorrelationRecords",
      "InvokeBedrockModel",
      "PublishSecurityEvents",
      "ArchiveThreatEvidence"
    ])
    error_message = "The Response Agent policy contains an unexpected permission statement."
  }
}
