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
      SNS_TOPIC_ARN              = aws_sns_topic.critical_alerts.arn
      BEDROCK_MODEL_ID           = "us.anthropic.claude-sonnet-4-6"
      ENABLE_BEDROCK             = "true"
    }
  }
}