### Checks for Lambda function configuration

check "lambda_uses_expected_deployment_package" {
  # Given the Lambda deployment archive,
  # when Terraform evaluates the function package and source hash,
  # then the function must use the generated response agent archive
  # and its hash must match the archive data source.

  assert {
    condition = (
      aws_lambda_function.asgard_lambda_function.filename ==
      data.archive_file.asgard_lambda_function.output_path
      &&
      aws_lambda_function.asgard_lambda_function.code_sha256 ==
      data.archive_file.asgard_lambda_function.output_base64sha256
    )

    error_message = "The Asgard Lambda function must use the generated response agent archive and its matching source hash."
  }
}

check "lambda_uses_expected_execution_role" {
  # Given the Asgard Lambda execution role,
  # when Terraform evaluates the function role assignment,
  # then the function must use the Asgard Lambda role ARN.

  assert {
    condition = (
      aws_lambda_function.asgard_lambda_function.role ==
      aws_iam_role.asgard_lambda_role.arn
    )

    error_message = "The Asgard Lambda function must use the Asgard Lambda execution role."
  }
}

check "lambda_uses_expected_runtime_and_handler" {
  # Given the response agent Python source file,
  # when Terraform evaluates the Lambda runtime and entry point,
  # then the function must use Python 3.14 and response_agent.lambda_handler.

  assert {
    condition = (
      aws_lambda_function.asgard_lambda_function.runtime == "python3.14"
      &&
      aws_lambda_function.asgard_lambda_function.handler ==
      "response_agent.lambda_handler"
    )

    error_message = "The Asgard Lambda function must use the python3.14 runtime and response_agent.lambda_handler handler."
  }
}

check "lambda_uses_only_expected_environment_variables" {
  # Given the response agent configuration requirements,
  # when Terraform evaluates the Lambda environment variable names,
  # then the function must contain only the five required variables.

  assert {
    condition = toset(
      keys(
        aws_lambda_function.asgard_lambda_function.environment[0].variables
      )
      ) == toset([
        "CORRELATION_FINDINGS_TABLE",
        "SECURITY_INCIDENTS_TABLE",
        "SNS_TOPIC_ARN",
        "BEDROCK_MODEL_ID",
        "ENABLE_BEDROCK"
    ])

    error_message = "The Asgard Lambda function must contain only the required DynamoDB, SNS, and Bedrock environment variables."
  }
}

check "lambda_environment_variables_reference_expected_resources" {
  # Given the DynamoDB tables, SNS topic, and Bedrock configuration,
  # when Terraform evaluates the Lambda environment variable values,
  # then each variable must reference the intended resource or approved value.

  assert {
    condition = (
      aws_lambda_function.asgard_lambda_function.environment[0].variables["CORRELATION_FINDINGS_TABLE"] ==
      aws_dynamodb_table.asgard_waf_correlation_findings.name
      &&
      aws_lambda_function.asgard_lambda_function.environment[0].variables["SECURITY_INCIDENTS_TABLE"] ==
      aws_dynamodb_table.asgard_security_incidents.name
      &&
      aws_lambda_function.asgard_lambda_function.environment[0].variables["SNS_TOPIC_ARN"] ==
      aws_sns_topic.asgard_critical_alerts_topic.arn
      &&
      aws_lambda_function.asgard_lambda_function.environment[0].variables["BEDROCK_MODEL_ID"] ==
      "us.anthropic.claude-sonnet-4-6"
      &&
      aws_lambda_function.asgard_lambda_function.environment[0].variables["ENABLE_BEDROCK"] ==
      "true"
    )

    error_message = "The Asgard Lambda environment variables must reference the expected tables, SNS topic, Bedrock model, and enablement value."
  }
}

###############################################################################
# WAF Bedrock Analyzer Checks
###############################################################################

check "waf_bedrock_archive_uses_expected_source" {
  # Given the WAF Bedrock analyzer source code,
  # when Terraform evaluates the archive configuration,
  # then it must package the expected Python file into the expected ZIP file.

  assert {
    condition = (
      data.archive_file.waf_bedrock_analyzer.type == "zip"
      &&
      data.archive_file.waf_bedrock_analyzer.source_file ==
      "${path.module}/Lambda_Src/waf_bedrock_analyzer.py"
      &&
      data.archive_file.waf_bedrock_analyzer.output_path ==
      "${path.module}/Lambda_Src/waf_bedrock_analyzer.zip"
    )

    error_message = "The WAF Bedrock analyzer archive must package the expected source file into the expected deployment package."
  }
}

check "waf_bedrock_lambda_uses_expected_package" {
  # Given the WAF Bedrock analyzer deployment package,
  # when Terraform evaluates the Lambda package,
  # then the function must use the generated ZIP archive and matching source hash.

  assert {
    condition = (
      aws_lambda_function.waf_bedrock_analyzer.filename ==
      data.archive_file.waf_bedrock_analyzer.output_path
      &&
      aws_lambda_function.waf_bedrock_analyzer.code_sha256 ==
      data.archive_file.waf_bedrock_analyzer.output_base64sha256
    )

    error_message = "The WAF Bedrock analyzer Lambda must use the generated deployment package."
  }
}

check "waf_bedrock_lambda_uses_expected_execution_role" {
  # Given the analyzer Lambda,
  # when Terraform evaluates its execution role,
  # then it must use the Asgard Lambda IAM role.

  assert {
    condition = (
      aws_lambda_function.waf_bedrock_analyzer.role ==
      aws_iam_role.asgard_lambda_role.arn
    )

    error_message = "The WAF Bedrock analyzer Lambda must use the Asgard Lambda IAM role."
  }
}

check "waf_bedrock_lambda_uses_expected_runtime_and_handler" {
  # Given the analyzer Lambda,
  # when Terraform evaluates the runtime and handler,
  # then it must use Python 3.14 and the expected entry point.

  assert {
    condition = (
      aws_lambda_function.waf_bedrock_analyzer.runtime == "python3.14"
      &&
      aws_lambda_function.waf_bedrock_analyzer.handler ==
      "waf_bedrock_analyzer.lambda_handler"
    )

    error_message = "The WAF Bedrock analyzer Lambda must use the expected runtime and handler."
  }
}

check "waf_bedrock_lambda_timeout_is_60_seconds" {
  # Given the analyzer Lambda,
  # when Terraform evaluates the timeout,
  # then it must be configured for exactly 60 seconds.

  assert {
    condition = (
      aws_lambda_function.waf_bedrock_analyzer.timeout == 60
    )

    error_message = "The WAF Bedrock analyzer Lambda timeout must be 60 seconds."
  }
}

check "waf_bedrock_lambda_uses_only_expected_environment_variables" {
  # Given the analyzer Lambda,
  # when Terraform evaluates the environment variable names,
  # then only the approved variables may exist.

  assert {
    condition = (
      toset(
        keys(
          aws_lambda_function.waf_bedrock_analyzer.environment[0].variables
        )
        ) == toset([
          "ENVIRONMENT",
          "LOG_LEVEL",
          "WAF_LOG_GROUP",
          "DYNAMODB_TABLE",
          "BEDROCK_MODEL_ID"
      ])
    )

    error_message = "The WAF Bedrock analyzer Lambda contains unexpected environment variables."
  }
}

check "waf_bedrock_lambda_environment_references_expected_resources" {
  # Given the analyzer Lambda,
  # when Terraform evaluates the environment variable values,
  # then every variable must reference the expected resource or approved value.

  assert {
    condition = (
      aws_lambda_function.waf_bedrock_analyzer.environment[0].variables["ENVIRONMENT"] ==
      "production"
      &&
      aws_lambda_function.waf_bedrock_analyzer.environment[0].variables["LOG_LEVEL"] ==
      "info"
      &&
      aws_lambda_function.waf_bedrock_analyzer.environment[0].variables["WAF_LOG_GROUP"] ==
      aws_cloudwatch_log_group.asgard_logs.name
      &&
      aws_lambda_function.waf_bedrock_analyzer.environment[0].variables["DYNAMODB_TABLE"] ==
      aws_dynamodb_table.asgard_waf_correlation_findings.name
      &&
      aws_lambda_function.waf_bedrock_analyzer.environment[0].variables["BEDROCK_MODEL_ID"] ==
      "us.anthropic.claude-sonnet-4-6"
    )

    error_message = "The WAF Bedrock analyzer Lambda environment variables must reference the expected resources and approved values."
  }
}

###############################################################################
# Node.js Authentication Lambda Checks
###############################################################################

check "node_auth_uses_expected_archive" {
  # Given the Node.js authentication Lambda package,
  # when Terraform evaluates the deployment artifact,
  # then the function must use the archive generated from auth.js.

  assert {
    condition = (
      data.archive_file.node_archive.type == "zip"
      &&
      data.archive_file.node_archive.source_file ==
      "${path.module}/Lambda_Src/auth.js"
      &&
      data.archive_file.node_archive.output_path ==
      "${path.module}/Lambda_Src/node.zip"
      &&
      aws_lambda_function.node_auth.filename ==
      data.archive_file.node_archive.output_path
      &&
      aws_lambda_function.node_auth.code_sha256 ==
      data.archive_file.node_archive.output_base64sha256
    )

    error_message = "The Node.js authentication Lambda must use the ZIP archive generated from Lambda_Src/auth.js."
  }
}

check "node_auth_uses_expected_execution_role" {
  # Given the Node.js authentication Lambda,
  # when Terraform evaluates its execution role,
  # then it must use the Asgard Lambda IAM role.

  assert {
    condition = (
      aws_lambda_function.node_auth.role ==
      aws_iam_role.asgard_lambda_role.arn
    )

    error_message = "The Node.js authentication Lambda must use the Asgard Lambda execution role."
  }
}

check "node_auth_uses_expected_runtime_and_handler" {
  # Given the Node.js authentication Lambda,
  # when Terraform evaluates its runtime configuration,
  # then it must use Node.js 24 and the auth.handler entry point.

  assert {
    condition = (
      aws_lambda_function.node_auth.runtime == "nodejs24.x"
      &&
      aws_lambda_function.node_auth.handler == "auth.handler"
    )

    error_message = "The Node.js authentication Lambda must use runtime nodejs24.x and handler auth.handler."
  }
}

check "node_auth_uses_expected_environment_variables" {
  # Given the Node.js authentication Lambda,
  # when Terraform evaluates its environment configuration,
  # then it must contain only the approved environment and log-level variables.

  assert {
    condition = (
      toset(
        keys(
          aws_lambda_function.node_auth.environment[0].variables
        )
      ) ==
      toset([
        "ENVIRONMENT",
        "LOG_LEVEL"
      ])
      &&
      aws_lambda_function.node_auth.environment[0].variables["ENVIRONMENT"] ==
      "production"
      &&
      aws_lambda_function.node_auth.environment[0].variables["LOG_LEVEL"] ==
      "info"
    )

    error_message = "The Node.js authentication Lambda must use ENVIRONMENT=production and LOG_LEVEL=info with no unexpected environment variables."
  }
}

###############################################################################
# Python Authentication Lambda Checks
###############################################################################

check "python_auth_uses_expected_archive" {
  # Given the Python authentication Lambda package,
  # when Terraform evaluates the deployment artifact,
  # then the function must use the archive generated from auth.py.

  assert {
    condition = (
      data.archive_file.python_archive.type == "zip"
      &&
      data.archive_file.python_archive.source_file ==
      "${path.module}/Lambda_Src/auth.py"
      &&
      data.archive_file.python_archive.output_path ==
      "${path.module}/Lambda_Src/python.zip"
      &&
      aws_lambda_function.python_auth.filename ==
      data.archive_file.python_archive.output_path
      &&
      aws_lambda_function.python_auth.code_sha256 ==
      data.archive_file.python_archive.output_base64sha256
    )

    error_message = "The Python authentication Lambda must use the ZIP archive generated from Lambda_Src/auth.py."
  }
}

check "python_auth_uses_expected_execution_role" {
  # Given the Python authentication Lambda,
  # when Terraform evaluates its execution role,
  # then it must use the Asgard Lambda IAM role.

  assert {
    condition = (
      aws_lambda_function.python_auth.role ==
      aws_iam_role.asgard_lambda_role.arn
    )

    error_message = "The Python authentication Lambda must use the Asgard Lambda execution role."
  }
}

check "python_auth_uses_expected_runtime_and_handler" {
  # Given the Python authentication Lambda,
  # when Terraform evaluates its runtime configuration,
  # then it must use Python 3.14 and the auth.lambda_handler entry point.

  assert {
    condition = (
      aws_lambda_function.python_auth.runtime == "python3.14"
      &&
      aws_lambda_function.python_auth.handler == "auth.lambda_handler"
    )

    error_message = "The Python authentication Lambda must use runtime python3.14 and handler auth.lambda_handler."
  }
}

check "python_auth_uses_expected_environment_variables" {
  # Given the Python authentication Lambda,
  # when Terraform evaluates its environment configuration,
  # then it must contain only the approved environment and log-level variables.

  assert {
    condition = (
      toset(
        keys(
          aws_lambda_function.python_auth.environment[0].variables
        )
      ) ==
      toset([
        "ENVIRONMENT",
        "LOG_LEVEL"
      ])
      &&
      aws_lambda_function.python_auth.environment[0].variables["ENVIRONMENT"] ==
      "production"
      &&
      aws_lambda_function.python_auth.environment[0].variables["LOG_LEVEL"] ==
      "info"
    )

    error_message = "The Python authentication Lambda must use ENVIRONMENT=production and LOG_LEVEL=info with no unexpected environment variables."
  }
}