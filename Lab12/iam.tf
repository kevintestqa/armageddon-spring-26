resource "aws_iam_role" "asgard_lambda_role" {
  name = "asgard_lambda_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.asgard_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

  lifecycle {
    postcondition {
      condition     = aws_iam_role.asgard_lambda_role.name != null
      error_message = "API Gateway stage must be created before associating the WAF."
    }
  }
}

resource "aws_iam_policy" "asgard_lambda_app_policy" {
  name        = "asgard_lambda_app_policy"
  description = "Allows Lambda to filter logs, invoke Bedrock, and write WAF events to DynamoDB."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.waf_correlation_findings.arn
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = aws_dynamodb_table.security_incidents.arn
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.critical_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel"
        ]
        Resource = "*"
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
    effect = "Allow"
    principals {
      identifiers = ["delivery.logs.amazonaws.com"]
      type        = "Service"
    }

    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.asgard_logs.arn}:*"]
    condition {
      test     = "ArnLike"
      values   = ["${aws_wafv2_web_acl.asgard_waf_v2.arn}:*"]
      variable = "aws:SourceArn"
    }
  }
}