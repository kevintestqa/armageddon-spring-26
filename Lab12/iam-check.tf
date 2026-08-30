locals {
  asgard_lambda_trust_policy = jsondecode(
    aws_iam_role.asgard_lambda_role.assume_role_policy
  )

  asgard_lambda_app_policy = jsondecode(
    aws_iam_policy.asgard_lambda_app_policy.policy
  )
}

check "lambda_role_trusts_only_lambda_service" {
  # Given the Lambda execution role is configured with a trust policy,
  # when the trusted principal and allowed action are checked,
  # then only the Lambda service should be allowed to assume the role through sts:AssumeRole.

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
  # Given the Lambda application IAM policy is configured with DynamoDB permissions,
  # when the DynamoDB statements are checked,
  # then each Asgard table should have only the required actions and resources.

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
  # Given the Lambda application IAM policy is configured with SNS permissions,
  # when the SNS publish statement is checked,
  # then Lambda should be allowed to publish only to the critical alerts topic.

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
  # Given the Lambda application IAM policy is configured with Bedrock permissions,
  # when the Bedrock statement is checked,
  # then only bedrock:InvokeModel should be allowed.

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
  # Given the Lambda application IAM policy is configured with CloudWatch Logs permissions,
  # when the log permissions are checked,
  # then logs:FilterLogEvents should be allowed.

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

check "lambda_policy_limits_report_uploads_to_expected_prefix" {
  # Given the Lambda application IAM policy is configured with executive-report S3 permissions,
  # when the upload statement is checked,
  # then objects should be writable only under the executive-reports prefix.

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
  # Given the Lambda application IAM policy is configured with compliance DynamoDB permissions,
  # when the compliance table statements are checked,
  # then only PutItem and BatchWriteItem should be allowed on the compliance evidence and findings tables.

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
  # Given the Lambda application IAM policy is configured with compliance-report S3 permissions,
  # when the upload statement is checked,
  # then objects should be writable only under the compliance-reports prefix.

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
  # Given the Lambda application IAM policy is configured with S3 bucket-listing permissions,
  # when the ListBucket statement is checked,
  # then only the compliance and executive report buckets should be listable.

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
  # Given the Lambda application IAM policy is configured with DynamoDB DescribeTable permissions,
  # when the table-description statement is checked,
  # then only the WAF events, correlation findings, and security incidents tables should be describable.

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
