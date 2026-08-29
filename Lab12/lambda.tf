// Preserve the deployed Lambda while adopting the clearer Terraform address.
// Without this declaration, Terraform may plan a destroy/create replacement.
moved {
  from = aws_lambda_function.asgard_lambda_function
  to   = aws_lambda_function.asgard_response_agent_function
}

data "archive_file" "asgard_response_agent_function" {
  type = "zip"
  # source_file = "${path.module}/Lambda_Src/response_agent_package/response_agent.py"
  output_path = "${path.module}/Lambda_Src/response_agent.zip"
  source_dir  = "${path.module}/Lambda_Src/response_agent_package"

}

# Lambda function
resource "aws_lambda_function" "asgard_response_agent_function" {
  filename      = data.archive_file.asgard_response_agent_function.output_path
  function_name = "asgard_response_agent"
  role          = aws_iam_role.asgard_lambda_role.arn
  handler       = "response_agent.lambda_handler"
  code_sha256   = data.archive_file.asgard_response_agent_function.output_base64sha256
  timeout       = 60

  runtime = var.lambda_python_runtime

  environment {
    variables = {
      CORRELATION_FINDINGS_TABLE = aws_dynamodb_table.asgard_waf_correlation_findings.name
      SECURITY_INCIDENTS_TABLE   = aws_dynamodb_table.asgard_security_incidents.name
      WAF_EVENTS_TABLE           = aws_dynamodb_table.asgard_waf_events.name
      SNS_TOPIC_ARN              = aws_sns_topic.asgard_critical_alerts_topic.arn
      THREAT_EVIDENCE_BUCKET     = aws_s3_bucket.asgard_threat_evidence.bucket

      BEDROCK_MODEL_ID = var.bedrock_model_id
      ENABLE_BEDROCK   = tostring(var.enable_bedrock)
    }
  }
  lifecycle {
    precondition {
      condition     = var.lambda_python_runtime == "python3.14"
      error_message = "Runtime must be python3.14"
    }

    precondition {
      condition     = var.enable_bedrock == true
      error_message = "Bedrock must be enabled for this Lambda function."
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

  runtime = var.lambda_python_runtime

  environment {
    variables = {
      ENVIRONMENT      = "production"
      LOG_LEVEL        = "info"
      WAF_LOG_GROUP    = aws_cloudwatch_log_group.asgard_waf_logs.name
      DYNAMODB_TABLE   = aws_dynamodb_table.asgard_waf_events.name
      BEDROCK_MODEL_ID = var.bedrock_model_id
    }
  }
  lifecycle {
    precondition {
      condition     = var.lambda_python_runtime == "python3.14"
      error_message = "Runtime must be python3.14"
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

  runtime = var.lambda_python_runtime

  environment {
    variables = {
      ENVIRONMENT = "production"
      LOG_LEVEL   = "info"
    }
  }

  lifecycle {
    precondition {
      condition     = var.lambda_python_runtime == "python3.14"
      error_message = "Runtime must be python3.14"
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

  runtime       = var.lambda_python_runtime
  architectures = [var.lambda_architecture] // Specify the architecture on Mac M1/M2 machines to avoid the Unable to import module 'executive_dashboard_agent': cannot import name '_imaging' from 'PIL error when running the Lambda function.  Solution is to use Docker as a temporary Linux build environment for python 3.14 and x86_64 architecture.
  timeout       = 120
  memory_size   = var.lambda_memory_size
  ephemeral_storage {
    size = var.lambda_memory_size
  }

  environment {
    variables = {
      WAF_EVENTS_TABLE           = aws_dynamodb_table.asgard_waf_events.name
      CORRELATION_FINDINGS_TABLE = aws_dynamodb_table.asgard_waf_correlation_findings.name
      SECURITY_INCIDENTS_TABLE   = aws_dynamodb_table.asgard_security_incidents.name

      REPORT_BUCKET = aws_s3_bucket.asgard_executive_report.bucket
      REPORT_PREFIX = "executive-reports"

      BEDROCK_MODEL_ID = var.bedrock_model_id
      ENABLE_BEDROCK   = tostring(var.enable_bedrock)

      REPORT_PERIOD_HOURS = "24"
      MAX_ITEMS_PER_TABLE = "5000"

      ORGANIZATION_NAME = "Asgard Cloud Security"
      REPORT_TITLE      = "Executive Security Report"
    }
  }

  lifecycle {
    precondition {
      condition     = var.lambda_architecture == "x86_64"
      error_message = "Architecture must be x86_64"
    }

    precondition {
      condition     = var.lambda_python_runtime == "python3.14"
      error_message = "Runtime must be python3.14"
    }

    precondition {
      condition     = var.enable_bedrock == true
      error_message = "Bedrock must be enabled for this Lambda function."
    }

    precondition {
      condition     = var.bedrock_model_id == "us.anthropic.claude-sonnet-4-6"
      error_message = "Bedrock model ID must be 'us.anthropic.claude-sonnet-4-6'"
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

  runtime       = var.lambda_python_runtime
  architectures = [var.lambda_architecture] // Specify the architecture on Mac M1/M2 machines to avoid the Unable to import module 'executive_dashboard_agent': cannot import name '_imaging' from 'PIL error when running the Lambda function.  Solution is to use Docker as a temporary Linux build environment for python 3.14 and x86_64 architecture.
  timeout       = 180
  memory_size   = var.lambda_memory_size
  ephemeral_storage {
    size = var.lambda_memory_size
  }

  environment {
    variables = {
      CONTROLS_FILE             = "/var/task/controls.json"
      COMPLIANCE_EVIDENCE_TABLE = aws_dynamodb_table.asgard_compliance_evidence.name
      COMPLIANCE_FINDINGS_TABLE = aws_dynamodb_table.asgard_compliance_findings.name

      REPORT_BUCKET = aws_s3_bucket.asgard_compliance_report.bucket
      REPORT_PREFIX = "compliance-reports"

      COMPLIANCE_FRAMEWORKS = "NIST CSF 2.0"

      BEDROCK_MODEL_ID = var.bedrock_model_id
      ENABLE_BEDROCK   = tostring(var.enable_bedrock)

      ORGANIZATION_NAME  = "Asgard Cloud Security"
      REPORT_TITLE       = "Compliance Evidence Report"
      UNEVALUATED_STATUS = "REVIEW"
    }
  }
  lifecycle {
    precondition {
      condition     = var.lambda_architecture == "x86_64"
      error_message = "Architecture must be x86_64"
    }

    precondition {
      condition     = var.lambda_python_runtime == "python3.14"
      error_message = "Runtime must be python3.14"
    }

    precondition {
      condition     = var.enable_bedrock == true
      error_message = "Bedrock must be enabled for this Lambda function."
    }

    precondition {
      condition     = var.bedrock_model_id == "us.anthropic.claude-sonnet-4-6"
      error_message = "Bedrock model ID must be 'us.anthropic.claude-sonnet-4-6'"
    }
  }
}
