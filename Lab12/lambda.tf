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
  timeout       = 60

  runtime = "python3.14"

  environment {
    variables = {
      CORRELATION_FINDINGS_TABLE = aws_dynamodb_table.asgard_waf_correlation_findings.name
      SECURITY_INCIDENTS_TABLE   = aws_dynamodb_table.asgard_security_incidents.name
      WAF_EVENTS_TABLE           = aws_dynamodb_table.asgard_waf_events.name
      SNS_TOPIC_ARN              = aws_sns_topic.asgard_critical_alerts_topic.arn

      BEDROCK_MODEL_ID = "us.anthropic.claude-sonnet-4-6"
      ENABLE_BEDROCK   = "true"
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
      WAF_LOG_GROUP    = aws_cloudwatch_log_group.asgard_waf_logs.name
      DYNAMODB_TABLE   = aws_dynamodb_table.asgard_waf_events.name
      BEDROCK_MODEL_ID = "us.anthropic.claude-sonnet-4-6"
    }
  }
}

data "archive_file" "waf_bedrock_analyzer" {
  type        = "zip"
  source_file = "${path.module}/Lambda_Src/waf_bedrock_analyzer.py"
  output_path = "${path.module}/Lambda_Src/waf_bedrock_analyzer.zip"
}

data "archive_file" "node_archive" {
  type        = "zip"
  source_file = "${path.module}/Lambda_Src/auth.js"
  output_path = "${path.module}/Lambda_Src/node.zip"
}

# Lambda function
resource "aws_lambda_function" "node_auth" {
  filename      = data.archive_file.node_archive.output_path
  function_name = "node_lambda_function"
  role          = aws_iam_role.asgard_lambda_role.arn
  handler       = "auth.handler"
  code_sha256   = data.archive_file.node_archive.output_base64sha256

  runtime = "nodejs24.x"

  environment {
    variables = {
      ENVIRONMENT = "production"
      LOG_LEVEL   = "info"
    }
  }
}

///Python

# Package the Lambda function code
data "archive_file" "python_archive" {
  type        = "zip"
  source_file = "${path.module}/Lambda_Src/auth.py"
  output_path = "${path.module}/Lambda_Src/python.zip"
}

# Lambda function
resource "aws_lambda_function" "python_auth" {
  filename      = data.archive_file.python_archive.output_path
  function_name = "python_lambda_function"
  role          = aws_iam_role.asgard_lambda_role.arn
  handler       = "auth.lambda_handler"
  code_sha256   = data.archive_file.python_archive.output_base64sha256

  runtime = "python3.14"

  environment {
    variables = {
      ENVIRONMENT = "production"
      LOG_LEVEL   = "info"
    }
  }
}

//Executive Dashboard Agent

data "archive_file" "executive_dashboard_agent" {
  type        = "zip"
  source_dir  = "${path.module}/Lambda_Src/Reports/executive_dashboard_package"
  output_path = "${path.module}/Lambda_Src/executive_dashboard_agent.zip"
}

resource "aws_lambda_function" "executive_dashboard_agent" {
  filename      = data.archive_file.executive_dashboard_agent.output_path
  function_name = "executive_dashboard_agent"
  role          = aws_iam_role.asgard_lambda_role.arn
  handler       = "executive_dashboard_agent.lambda_handler"
  code_sha256   = data.archive_file.executive_dashboard_agent.output_base64sha256

  runtime       = "python3.14"
  architectures = ["x86_64"] // Specify the architecture on Mac M1/M2 machines to avoid the Unable to import module 'executive_dashboard_agent': cannot import name '_imaging' from 'PIL error when running the Lambda function.  Solution is to use Docker as a temporary Linux build environment for python 3.14 and x86_64 architecture.
  timeout       = 120
  memory_size   = 512
  ephemeral_storage {
    size = 512
  }

  environment {
    variables = {
      WAF_EVENTS_TABLE           = aws_dynamodb_table.asgard_waf_events.name
      CORRELATION_FINDINGS_TABLE = aws_dynamodb_table.asgard_waf_correlation_findings.name
      SECURITY_INCIDENTS_TABLE   = aws_dynamodb_table.asgard_security_incidents.name

      REPORT_BUCKET = aws_s3_bucket.asgard_executive_report.bucket
      REPORT_PREFIX = "executive-reports"

      BEDROCK_MODEL_ID = "us.anthropic.claude-sonnet-4-6"
      ENABLE_BEDROCK   = "true"

      REPORT_PERIOD_HOURS = "24"
      MAX_ITEMS_PER_TABLE = "5000"

      ORGANIZATION_NAME = "Asgard Cloud Security"
      REPORT_TITLE      = "Executive Security Report"
    }
  }
}

data "archive_file" "compliance_agent" {
  type        = "zip"
  source_dir  = "${path.module}/Lambda_Src/Reports/compliance_package"
  output_path = "${path.module}/Lambda_Src/compliance_agent.zip"
  
}

resource "aws_lambda_function" "compliance_agent" {
  filename      = data.archive_file.compliance_agent.output_path
  function_name = "compliance_agent"
  role          = aws_iam_role.asgard_lambda_role.arn
  handler       = "compliance.lambda_handler"
  code_sha256   = data.archive_file.compliance_agent.output_base64sha256

  runtime       = "python3.14"
  architectures = ["x86_64"] // Specify the architecture on Mac M1/M2 machines to avoid the Unable to import module 'executive_dashboard_agent': cannot import name '_imaging' from 'PIL error when running the Lambda function.  Solution is to use Docker as a temporary Linux build environment for python 3.14 and x86_64 architecture.
  timeout       = 180
  memory_size   = 512
  ephemeral_storage {
    size = 512
  }

  environment {
    variables = {
      CONTROLS_FILE             = "/var/task/controls.json"
      COMPLIANCE_EVIDENCE_TABLE = aws_dynamodb_table.asgard_compliance_evidence.name

      REPORT_BUCKET = aws_s3_bucket.asgard_compliance_report.bucket
      REPORT_PREFIX = "compliance-reports"

      COMPLIANCE_FRAMEWORKS = "NIST CSF 2.0"

      BEDROCK_MODEL_ID = "us.anthropic.claude-sonnet-4-6"
      ENABLE_BEDROCK   = "true"

      ORGANIZATION_NAME  = "Asgard Cloud Security"
      REPORT_TITLE       = "Compliance Evidence Report"
      UNEVALUATED_STATUS = "REVIEW"
    }
  }
}