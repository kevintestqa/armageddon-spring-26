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
  # then correlation findings must allow GetItem, UpdateItem, PutItem, and Scan,
  # while security incidents and WAF events must share PutItem and Scan permissions.

  assert {
    condition = (
      length([
        for statement in local.asgard_lambda_app_policy.Statement : statement
        if(
          try(statement.Sid, "") == "ManageCorrelationFindings"
          && statement.Effect == "Allow"
          && toset(try(tolist(statement.Action), [statement.Action])) == toset([
            "dynamodb:GetItem",
            "dynamodb:UpdateItem",
            "dynamodb:PutItem",
            "dynamodb:Scan"
          ])
          && try(statement.Resource, "") ==
          aws_dynamodb_table.asgard_waf_correlation_findings.arn
        )
      ]) == 1
      &&
      length([
        for statement in local.asgard_lambda_app_policy.Statement : statement
        if(
          try(statement.Sid, "") == "WriteAndScanSecurityData"
          && statement.Effect == "Allow"
          && toset(try(tolist(statement.Action), [statement.Action])) == toset([
            "dynamodb:PutItem",
            "dynamodb:Scan"
          ])
          && toset(try(tolist(statement.Resource), [statement.Resource])) == toset([
            aws_dynamodb_table.asgard_security_incidents.arn,
            aws_dynamodb_table.asgard_waf_events.arn
          ])
        )
      ]) == 1
    )

    error_message = "The Lambda IAM policy must grant the expected least-privilege DynamoDB permissions to the Asgard tables."
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
        try(statement.Sid, "") == "PublishCriticalAlerts"
        && statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset([
          "sns:Publish"
        ])
        && try(statement.Resource, "") ==
        aws_sns_topic.asgard_critical_alerts_topic.arn
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
        try(statement.Sid, "") == "InvokeBedrockModel"
        && statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset([
          "bedrock:InvokeModel"
        ])
        && try(statement.Resource, "") == "*"
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
    condition = length([
      for statement in local.asgard_lambda_app_policy.Statement : statement
      if(
        try(statement.Sid, "") == "FilterCloudWatchLogs"
        && statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset([
          "logs:FilterLogEvents"
        ])
        && try(statement.Resource, "") == "*"
      )
    ]) == 1

    error_message = "The Asgard Lambda application policy must allow logs:FilterLogEvents on all CloudWatch Logs resources."
  }
}

check "lambda_policy_allows_eventbridge_put_events" {
  # Given the Lambda application IAM policy,
  # when Terraform evaluates the EventBridge permission statement,
  # then the Lambda role must be allowed to submit events to the default event bus.

  assert {
    condition = length([
      for statement in local.asgard_lambda_app_policy.Statement : statement
      if(
        try(statement.Sid, "") == "PublishSecurityEvents"
        && statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset([
          "events:PutEvents"
        ])
        && try(statement.Resource, "") ==
        data.aws_cloudwatch_event_bus.default.arn
      )
    ]) == 1

    error_message = "The Lambda IAM policy must allow events:PutEvents only on the default EventBridge bus."
  }
}

check "lambda_policy_limits_report_uploads_to_expected_prefix" {
  # Given the executive report S3 bucket exists,
  # when Terraform evaluates the S3 permission statement,
  # then Lambda may upload objects only under the executive-reports prefix.

  assert {
    condition = length([
      for statement in local.asgard_lambda_app_policy.Statement : statement
      if(
        try(statement.Sid, "") == "UploadExecutiveReports"
        && statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset([
          "s3:PutObject"
        ])
        && try(statement.Resource, "") ==
        "${aws_s3_bucket.asgard_executive_report.arn}/executive-reports/*"
      )
    ]) == 1

    error_message = "The Lambda IAM policy must allow only s3:PutObject under the executive-reports prefix."
  }
}

check "lambda_policy_uses_expected_compliance_dynamodb_permissions" {
  # Given the Lambda application IAM policy,
  # when Terraform evaluates the compliance DynamoDB permission statement,
  # then Lambda may write compliance records only to the evidence and findings tables.

  assert {
    condition = length([
      for statement in local.asgard_lambda_app_policy.Statement : statement
      if(
        try(statement.Sid, "") == "WriteComplianceRecords"
        && statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset([
          "dynamodb:PutItem",
          "dynamodb:BatchWriteItem"
        ])
        && toset(try(tolist(statement.Resource), [statement.Resource])) == toset([
          aws_dynamodb_table.asgard_compliance_evidence.arn,
          aws_dynamodb_table.asgard_compliance_findings.arn
        ])
      )
    ]) == 1

    error_message = "The Lambda IAM policy must allow only PutItem and BatchWriteItem on the compliance evidence and findings tables."
  }
}

check "lambda_policy_limits_compliance_report_uploads_to_expected_prefix" {
  # Given the compliance report S3 bucket exists,
  # when Terraform evaluates the compliance report upload statement,
  # then Lambda may upload objects only under the compliance-reports prefix.

  assert {
    condition = length([
      for statement in local.asgard_lambda_app_policy.Statement : statement
      if(
        try(statement.Sid, "") == "UploadComplianceReports"
        && statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset([
          "s3:PutObject"
        ])
        && try(statement.Resource, "") ==
        "${aws_s3_bucket.asgard_compliance_report.arn}/compliance-reports/*"
      )
    ]) == 1

    error_message = "The Lambda IAM policy must allow only s3:PutObject under the compliance-reports prefix."
  }
}

check "lambda_policy_allows_listing_report_buckets" {
  # Given the compliance agent evaluates report artifacts,
  # when Terraform evaluates the S3 bucket-listing permission,
  # then Lambda may list only the compliance and executive report buckets.

  assert {
    condition = length([
      for statement in local.asgard_lambda_app_policy.Statement : statement
      if(
        try(statement.Sid, "") == "ListReportBuckets"
        && statement.Effect == "Allow"
        && toset(try(tolist(statement.Action), [statement.Action])) == toset([
          "s3:ListBucket"
        ])
        && toset(try(tolist(statement.Resource), [statement.Resource])) == toset([
          aws_s3_bucket.asgard_compliance_report.arn,
          aws_s3_bucket.asgard_executive_report.arn
        ])
      )
    ]) == 1

    error_message = "The Lambda IAM policy must allow s3:ListBucket only on the compliance and executive report buckets."
  }
}

check "lambda_policy_allows_describing_compliance_data_sources" {
  # Given the compliance agent evaluates DynamoDB-backed controls,
  # when Terraform evaluates the table-description permission,
  # then Lambda may describe only the three security data source tables.

  assert {
    condition = length([
      for statement in local.asgard_lambda_app_policy.Statement : statement
      if(
        try(statement.Sid, "") == "DescribeComplianceDataSources"
        && statement.Effect == "Allow"
        && toset(
          try(
            tolist(statement.Action),
            [statement.Action]
          )
        ) == toset([
          "dynamodb:DescribeTable"
        ])
        && toset(
          try(
            tolist(statement.Resource),
            [statement.Resource]
          )
        ) == toset([
          aws_dynamodb_table.asgard_waf_events.arn,
          aws_dynamodb_table.asgard_waf_correlation_findings.arn,
          aws_dynamodb_table.asgard_security_incidents.arn
        ])
      )
    ]) == 1

    error_message = "The Lambda IAM policy must allow dynamodb:DescribeTable only on the WAF events, correlation findings, and security incidents tables."
  }
}