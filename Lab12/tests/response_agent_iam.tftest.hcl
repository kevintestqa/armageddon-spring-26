mock_provider "aws" {}

# Generated ARNs are normally unknown during plan. These deterministic values
# let CI evaluate only the Response Agent relationships without mock-applying
# the repository's unrelated AWS resources.
override_resource {
  target          = aws_iam_role.asgard_response_agent
  override_during = plan
  values = {
    arn = "arn:aws:iam::123456789012:role/asgard_response_agent_role"
  }
}

override_resource {
  target          = aws_dynamodb_table.asgard_waf_events
  override_during = plan
  values = {
    arn = "arn:aws:dynamodb:us-west-1:123456789012:table/asgard-waf-events"
  }
}

override_resource {
  target          = aws_dynamodb_table.asgard_waf_correlation_findings
  override_during = plan
  values = {
    arn = "arn:aws:dynamodb:us-west-1:123456789012:table/waf-correlation-findings"
  }
}

override_resource {
  target          = aws_dynamodb_table.asgard_security_incidents
  override_during = plan
  values = {
    arn = "arn:aws:dynamodb:us-west-1:123456789012:table/security-incidents"
  }
}

override_resource {
  target          = aws_s3_bucket.asgard_threat_evidence
  override_during = plan
  values = {
    arn = "arn:aws:s3:::asgard-threat-evidence-test"
  }
}

override_data {
  target          = data.aws_cloudwatch_event_bus.default
  override_during = plan
  values = {
    arn = "arn:aws:events:us-west-1:123456789012:event-bus/default"
  }
}

# ============================================================
# Feature: Dedicated Response Agent IAM role
# ============================================================

run "response_agent_uses_dedicated_role" {
  command = plan

  # Given the Response Agent has distinct security responsibilities,
  # when its Lambda configuration is planned,
  # then it must use its dedicated role instead of the shared Lambda role.
  assert {
    condition = (
      aws_lambda_function.asgard_response_agent_function.role ==
      aws_iam_role.asgard_response_agent.arn
    )
    error_message = "Response Agent must use its dedicated execution role."
  }
}

run "response_agent_policy_excludes_unrelated_services" {
  command = plan

  # Given least privilege is required,
  # when the dedicated policy statements are planned,
  # then SNS, report buckets, compliance tables, and retention bypass must be absent.
  assert {
    condition = (
      length(jsondecode(aws_iam_policy.asgard_response_agent.policy).Statement) == 5
      && alltrue([
        for statement in jsondecode(aws_iam_policy.asgard_response_agent.policy).Statement :
        length(setintersection(
          toset(try(tolist(statement.Action), [statement.Action])),
          toset([
            "sns:Publish",
            "s3:ListBucket",
            "s3:BypassGovernanceRetention",
            "dynamodb:BatchWriteItem"
          ])
        )) == 0
      ])
    )
    error_message = "Response Agent policy must exclude unrelated or retention-bypass permissions."
  }
}
