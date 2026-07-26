data "archive_file" "asgard_lambda_function" {
  type        = "zip"
  source_file = "${path.module}/Lambda_Src/response_agent.py"
  output_path = "${path.module}/Lambda_Src/response_agent.zip"
}
# Lambda function
resource "aws_lambda_function" "asgard_lambda_function" {
  filename      = data.archive_file.asgard_lambda_function.output_path
  function_name = "asgard_response_agent"
  role          = aws_iam_role.asgard_lambda_role.arn
  handler       = "response_agent.lambda_handler"
  code_sha256   = data.archive_file.asgard_lambda_function.output_base64sha256

  runtime = "python3.14"

  environment {
    variables = {
      CORRELATION_FINDINGS_TABLE = aws_dynamodb_table.waf_correlation_findings.name
      SECURITY_INCIDENTS_TABLE   = aws_dynamodb_table.security_incidents.name
      SNS_TOPIC_ARN              = aws_sns_topic.asgard_critical_alerts_topic.arn

      //May need to add these as environment variables in the response_agent.py file:
      # SNS_TOPIC_ARN_MEDIUM       = aws_sns_topic.asgard_medium_high_alerts_topic.arn
      # LOG_GROUP_NAME             = aws_cloudwatch_log_group.asgard_lambda_logs.name

      BEDROCK_MODEL_ID           = "us.anthropic.claude-sonnet-4-6"
      ENABLE_BEDROCK             = "true"
    }
  }
}

resource "aws_lambda_function" "waf_bedrock_analyzer" {
  filename      = data.archive_file.waf_bedrock_analyzer.output_path
  function_name = "waf_bedrock_analyzer"
  role          = aws_iam_role.asgard_lambda_role.arn
  handler       = "waf_bedrock_analyzer.lambda_handler"
  code_sha256   = data.archive_file.waf_bedrock_analyzer.output_base64sha256
  timeout       = 60

  runtime = "python3.14"

  environment {
    variables = {
      ENVIRONMENT      = "production"
      LOG_LEVEL        = "info"
      WAF_LOG_GROUP    = aws_cloudwatch_log_group.waf_logs.name
      DYNAMODB_TABLE   = aws_dynamodb_table.dynamoDb_waf_events.name
      BEDROCK_MODEL_ID = "us.anthropic.claude-sonnet-4-6"
    }
  }
}

data "archive_file" "waf_bedrock_analyzer" {
  type        = "zip"
  source_file = "${path.module}/source/waf_bedrock_analyzer.py"
  output_path = "${path.module}/lambda/waf_bedrock_analyzer.zip"
}