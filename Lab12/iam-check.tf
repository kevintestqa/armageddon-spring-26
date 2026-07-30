locals {
  asgard_lambda_trust_policy = jsondecode(
    aws_iam_role.asgard_lambda_role.assume_role_policy
  )

  asgard_lambda_app_policy = jsondecode(
    aws_iam_policy.asgard_lambda_app_policy.policy
  )
}

check "lambda_role_trusts_only_lambda_service" {
  # Given the Lambda execution role trust policy,
  # when Terraform evaluates the trusted principal and allowed action,
  # then only the Lambda service may assume the role through sts:AssumeRole.
  assert {
    condition = (
      length(local.asgard_lambda_trust_policy.Statement) == 1
      &&
      alltrue([
        for statement in local.asgard_lambda_trust_policy.Statement :
        statement.Effect == "Allow"
        && statement.Action == "sts:AssumeRole"
        && statement.Principal.Service == "lambda.amazonaws.com"
      ])
    )

    error_message = "The Asgard Lambda role must trust only the Lambda service through sts:AssumeRole."
  }
}

check "lambda_policy_uses_expected_dynamodb_permissions" {
  # Given the Lambda application IAM policy,
  # when Terraform evaluates the DynamoDB permission statements,
  # then the correlation findings table must allow GetItem, UpdateItem, and PutItem,
  # and the security incidents table must allow PutItem and Scan,
  # and the WAF events table must allow PutItem and Scan.
  assert {
    condition = (
      length([
        for statement in local.asgard_lambda_app_policy.Statement : statement
        if(
          statement.Effect == "Allow"
          && toset(try(tolist(statement.Action), [statement.Action])) == toset([
            "dynamodb:GetItem",
            "dynamodb:UpdateItem",
            "dynamodb:PutItem"
          ])
          && contains(
            try(tolist(statement.Resource), [statement.Resource]),
            aws_dynamodb_table.asgard_waf_correlation_findings.arn
          )
          && length(
            try(tolist(statement.Resource), [statement.Resource])
          ) == 1
        )
      ]) == 1
      &&
      length([
        for statement in local.asgard_lambda_app_policy.Statement : statement
        if(
          statement.Effect == "Allow"
          && toset(try(tolist(statement.Action), [statement.Action])) == toset([
            "dynamodb:PutItem",
            "dynamodb:Scan"
          ])
          && contains(
            try(tolist(statement.Resource), [statement.Resource]),
            aws_dynamodb_table.asgard_security_incidents.arn
          )
          && length(
            try(tolist(statement.Resource), [statement.Resource])
          ) == 1
        )
      ]) == 1
      &&
      length([
        for statement in local.asgard_lambda_app_policy.Statement : statement
        if(
          statement.Effect == "Allow"
          && toset(try(tolist(statement.Action), [statement.Action])) == toset([
            "dynamodb:PutItem",
            "dynamodb:Scan"
          ])
          && contains(
            try(tolist(statement.Resource), [statement.Resource]),
            aws_dynamodb_table.asgard_waf_events.arn
          )
          && length(
            try(tolist(statement.Resource), [statement.Resource])
          ) == 1
        )
      ]) == 1
    )

    error_message = "The Lambda IAM policy must allow GetItem, UpdateItem, and PutItem on the correlation findings table, PutItem and Scan on the security incidents table, and PutItem and Scan on the WAF events table."
  }
}

check "lambda_policy_limits_sns_publish_to_critical_alerts" {
  # Given the Lambda application IAM policy,
  # when Terraform evaluates the SNS permission statement,
  # then Lambda may publish only to the critical alerts topic.
  assert {
    condition = length([
      for statement in local.asgard_lambda_app_policy.Statement : statement
      if(
        statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset([
          "sns:Publish"
        ])
        && contains(
          try(tolist(statement.Resource), [statement.Resource]),
          aws_sns_topic.asgard_critical_alerts_topic.arn
        )
        && length(
          try(tolist(statement.Resource), [statement.Resource])
        ) == 1
      )
    ]) == 1

    error_message = "The Lambda IAM policy must allow only sns:Publish to the critical alerts topic."
  }
}

check "lambda_policy_allows_only_bedrock_model_invocation" {
  # Given the Lambda application IAM policy,
  # when Terraform evaluates the Bedrock permission statement,
  # then the statement must allow only bedrock:InvokeModel.
  assert {
    condition = length([
      for statement in local.asgard_lambda_app_policy.Statement : statement
      if(
        statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset([
          "bedrock:InvokeModel"
        ])
        && contains(
          try(tolist(statement.Resource), [statement.Resource]),
          "*"
        )
        && length(
          try(tolist(statement.Resource), [statement.Resource])
        ) == 1
      )
    ]) == 1

    error_message = "The Lambda IAM policy must allow only bedrock:InvokeModel in the Bedrock statement."
  }
}

check "lambda_app_policy_allows_filter_log_events" {
  # Given the Asgard Lambda application policy,
  # when Terraform evaluates the CloudWatch Logs permissions,
  # then the Lambda role must be allowed to filter log events.

  assert {
    condition = (
      length([
        for statement in jsondecode(
          aws_iam_policy.asgard_lambda_app_policy.policy
        ).Statement : statement
        if statement.Effect == "Allow"
        && toset(statement.Action) == toset(["logs:FilterLogEvents"])
        && statement.Resource == "*"
      ]) == 1
    )

    error_message = "The Asgard Lambda application policy must allow logs:FilterLogEvents on all CloudWatch Logs resources."
  }
}