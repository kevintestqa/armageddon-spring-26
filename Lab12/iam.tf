resource "aws_iam_role" "asgard_lambda_role" {
  name = "asgard_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AllowLambdaAssumeRole"
        Effect = "Allow"
        Action = "sts:AssumeRole"

        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.asgard_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

  lifecycle {
    postcondition {
      condition     = self.role == aws_iam_role.asgard_lambda_role.name
      error_message = "The AWSLambdaBasicExecutionRole policy must be attached to the Asgard Lambda role."
    }
  }
}

resource "aws_iam_policy" "asgard_lambda_app_policy" {
  name        = "asgard_lambda_app_policy"
  description = "Allows Asgard Lambda functions to process security data, invoke Bedrock, publish alerts, emit events, and upload executive reports."

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "ManageCorrelationFindings"
        Effect = "Allow"

        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:PutItem",
          "dynamodb:Scan"
        ]

        Resource = aws_dynamodb_table.asgard_waf_correlation_findings.arn
      },
      {
        Sid    = "WriteAndScanSecurityData"
        Effect = "Allow"

        Action = [
          "dynamodb:PutItem",
          "dynamodb:Scan"
        ]

        Resource = [
          aws_dynamodb_table.asgard_security_incidents.arn,
          aws_dynamodb_table.asgard_waf_events.arn
        ]
      },
      {
        Sid    = "PublishCriticalAlerts"
        Effect = "Allow"

        Action = [
          "sns:Publish"
        ]

        Resource = aws_sns_topic.asgard_critical_alerts_topic.arn
      },
      {
        Sid    = "InvokeBedrockModel"
        Effect = "Allow"

        Action = [
          "bedrock:InvokeModel"
        ]

        Resource = "*"
      },
      {
        Sid    = "FilterCloudWatchLogs"
        Effect = "Allow"

        Action = [
          "logs:FilterLogEvents"
        ]

        Resource = "*"
      },
      {
        Sid    = "PublishSecurityEvents"
        Effect = "Allow"

        Action = [
          "events:PutEvents"
        ]

        Resource = data.aws_cloudwatch_event_bus.default.arn
      },
      {
        Sid    = "UploadExecutiveReports"
        Effect = "Allow"

        Action = [
          "s3:PutObject"
        ]

        Resource = "${aws_s3_bucket.asgard_executive_report.arn}/executive-reports/*"
      },
      {
        Sid    = "WriteComplianceRecords"
        Effect = "Allow"

        Action = [
          "dynamodb:PutItem",
          "dynamodb:BatchWriteItem" //The compliance.py uses batch_writer() to write multiple items to the compliance evidence and findings tables in a single request.
        ]

        Resource = [
          aws_dynamodb_table.asgard_compliance_evidence.arn,
          aws_dynamodb_table.asgard_compliance_findings.arn
        ]
      },
      {
        Sid    = "UploadComplianceReports"
        Effect = "Allow"

        Action = [
          "s3:PutObject"
        ]

        Resource = "${aws_s3_bucket.asgard_compliance_report.arn}/compliance-reports/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "asgard_lambda_app_policy_attach" {
  role       = aws_iam_role.asgard_lambda_role.name
  policy_arn = aws_iam_policy.asgard_lambda_app_policy.arn
}

data "aws_iam_policy_document" "asgard_waf_log_policy" {
  version = "2012-10-17"

  statement {
    sid    = "AllowWAFLogDelivery"
    effect = "Allow"

    principals {
      identifiers = ["delivery.logs.amazonaws.com"]
      type        = "Service"
    }

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = [
      "${aws_cloudwatch_log_group.asgard_waf_logs.arn}:*"
    ]

    condition {
      test     = "ArnLike"
      values   = ["${aws_wafv2_web_acl.asgard_waf_v2.arn}:*"]
      variable = "aws:SourceArn"
    }
  }
}