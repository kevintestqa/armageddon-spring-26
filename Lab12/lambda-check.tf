### Checks for Lambda function configuration

check "lambda_uses_expected_deployment_package" {
  # Given the Asgard Lambda is configured with a deployment package,
  # when the deployment package and source hash are checked,
  # then the function should use the generated response agent archive and matching source hash.

  assert {
    condition = (
      aws_lambda_function.asgard_response_agent_function.filename ==
      data.archive_file.asgard_response_agent_function.output_path
      &&
      aws_lambda_function.asgard_response_agent_function.code_sha256 ==
      data.archive_file.asgard_response_agent_function.output_base64sha256
    )

    error_message = "The Asgard Lambda function must use the generated response agent archive and its matching source hash."
  }
}

check "lambda_uses_expected_execution_role" {
  # Given the Asgard Lambda is configured with an execution role,
  # when the role assignment is checked,
  # then the function should use its dedicated Response Agent role.

  assert {
    condition = (
      aws_lambda_function.asgard_response_agent_function.role ==
      aws_iam_role.asgard_response_agent.arn
    )

    error_message = "The Response Agent must use its dedicated execution role."
  }
}

check "lambda_uses_expected_runtime_and_handler" {
  # Given the Asgard Lambda is configured with a runtime and handler,
  # when the runtime configuration is checked,
  # then it should use Python 3.14 and response_agent.lambda_handler.

  assert {
    condition = (
      aws_lambda_function.asgard_response_agent_function.runtime == "python3.14"
      &&
      aws_lambda_function.asgard_response_agent_function.handler ==
      "response_agent.lambda_handler"
    )

    error_message = "The Asgard Lambda function must use the python3.14 runtime and response_agent.lambda_handler handler."
  }
}

check "lambda_environment_variables_reference_expected_resources" {
  # Given the Asgard Lambda is configured with environment variables,
  # when the environment variable values are checked,
  # then they should reference the expected tables, archive, and Bedrock configuration.

  assert {
    condition = (
      aws_lambda_function.asgard_response_agent_function.environment[0].variables["CORRELATION_FINDINGS_TABLE"] ==
      aws_dynamodb_table.asgard_waf_correlation_findings.name
      &&
      aws_lambda_function.asgard_response_agent_function.environment[0].variables["SECURITY_INCIDENTS_TABLE"] ==
      aws_dynamodb_table.asgard_security_incidents.name
      &&
      aws_lambda_function.asgard_response_agent_function.environment[0].variables["WAF_EVENTS_TABLE"] ==
      aws_dynamodb_table.asgard_waf_events.name
      &&
      aws_lambda_function.asgard_response_agent_function.environment[0].variables["THREAT_EVIDENCE_BUCKET"] ==
      aws_s3_bucket.asgard_threat_evidence.bucket
      &&
      aws_lambda_function.asgard_response_agent_function.environment[0].variables["BEDROCK_MODEL_ID"] ==
      "us.anthropic.claude-sonnet-4-6"
      &&
      aws_lambda_function.asgard_response_agent_function.environment[0].variables["ENABLE_BEDROCK"] ==
      "true"
    )

    error_message = "The Response Agent environment must reference the expected tables, archive, Bedrock model, and enablement value."
  }
}

###############################################################################
# WAF Bedrock Analyzer Checks
###############################################################################

check "waf_bedrock_archive_uses_expected_source" {
  # Given the WAF Bedrock analyzer archive is configured,
  # when the archive source and output are checked,
  # then it should package waf_bedrock_analyzer.py into the expected ZIP file.

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
  # Given the WAF Bedrock analyzer Lambda is configured with a deployment package,
  # when the deployment package and source hash are checked,
  # then it should use the generated WAF Bedrock analyzer archive and matching source hash.

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
  # Given the WAF Bedrock analyzer Lambda is configured with an execution role,
  # when the role assignment is checked,
  # then it should use the Asgard Lambda role.

  assert {
    condition = (
      aws_lambda_function.waf_bedrock_analyzer.role ==
      aws_iam_role.asgard_lambda_role.arn
    )

    error_message = "The WAF Bedrock analyzer Lambda must use the Asgard Lambda IAM role."
  }
}

check "waf_bedrock_lambda_uses_expected_runtime_and_handler" {
  # Given the WAF Bedrock analyzer Lambda is configured with a runtime and handler,
  # when the runtime configuration is checked,
  # then it should use Python 3.14 and waf_bedrock_analyzer.lambda_handler.

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
  # Given the WAF Bedrock analyzer Lambda is configured with a timeout,
  # when the timeout is checked,
  # then it should be set to 60 seconds.

  assert {
    condition = (
      aws_lambda_function.waf_bedrock_analyzer.timeout == 60
    )

    error_message = "The WAF Bedrock analyzer Lambda timeout must be 60 seconds."
  }
}

check "lambda_uses_only_expected_environment_variables" {
  # Given the Asgard Lambda is configured with environment variables,
  # when the environment variable names are checked,
  # then only the six approved variables should be present.

  assert {
    condition = toset(
      keys(
        aws_lambda_function.asgard_response_agent_function.environment[0].variables
      )
      ) == toset([
        "CORRELATION_FINDINGS_TABLE",
        "SECURITY_INCIDENTS_TABLE",
        "WAF_EVENTS_TABLE",
        "THREAT_EVIDENCE_BUCKET",
        "BEDROCK_MODEL_ID",
        "ENABLE_BEDROCK"
    ])

    error_message = "The Response Agent must contain only the required DynamoDB, threat-evidence archive, and Bedrock environment variables."
  }
}

check "waf_bedrock_lambda_environment_references_expected_resources" {
  # Given the WAF Bedrock analyzer Lambda is configured with environment variables,
  # when the environment variable values are checked,
  # then they should reference the expected resources and approved values.

  assert {
    condition = (
      aws_lambda_function.waf_bedrock_analyzer.environment[0].variables["ENVIRONMENT"] ==
      "production"
      &&
      aws_lambda_function.waf_bedrock_analyzer.environment[0].variables["LOG_LEVEL"] ==
      "info"
      &&
      aws_lambda_function.waf_bedrock_analyzer.environment[0].variables["WAF_LOG_GROUP"] ==
      aws_cloudwatch_log_group.asgard_waf_logs.name
      &&
      aws_lambda_function.waf_bedrock_analyzer.environment[0].variables["DYNAMODB_TABLE"] ==
      aws_dynamodb_table.asgard_waf_events.name
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
  # Given the Node.js authentication Lambda is configured with a deployment archive,
  # when the archive source, output, and source hash are checked,
  # then it should use the ZIP archive generated from auth.js.

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
  # Given the Node.js authentication Lambda is configured with an execution role,
  # when the role assignment is checked,
  # then it should use the Asgard Lambda role.

  assert {
    condition = (
      aws_lambda_function.node_auth.role ==
      aws_iam_role.asgard_lambda_role.arn
    )

    error_message = "The Node.js authentication Lambda must use the Asgard Lambda execution role."
  }
}

check "node_auth_uses_expected_runtime_and_handler" {
  # Given the Node.js authentication Lambda is configured with a runtime and handler,
  # when the runtime configuration is checked,
  # then it should use Node.js 24 and auth.handler.

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
  # Given the Node.js authentication Lambda is configured with environment variables,
  # when the environment configuration is checked,
  # then only ENVIRONMENT=production and LOG_LEVEL=info should be present.

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
  # Given the Python authentication Lambda is configured with a deployment archive,
  # when the archive source, output, and source hash are checked,
  # then it should use the ZIP archive generated from auth.py.

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
  # Given the Python authentication Lambda is configured with an execution role,
  # when the role assignment is checked,
  # then it should use the Asgard Lambda role.

  assert {
    condition = (
      aws_lambda_function.python_auth.role ==
      aws_iam_role.asgard_lambda_role.arn
    )

    error_message = "The Python authentication Lambda must use the Asgard Lambda execution role."
  }
}

check "python_auth_uses_expected_runtime_and_handler" {
  # Given the Python authentication Lambda is configured with a runtime and handler,
  # when the runtime configuration is checked,
  # then it should use Python 3.14 and auth.lambda_handler.

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
  # Given the Python authentication Lambda is configured with environment variables,
  # when the environment configuration is checked,
  # then only ENVIRONMENT=production and LOG_LEVEL=info should be present.

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

###############################################################################
# Executive Dashboard Agent Checks
###############################################################################

check "executive_dashboard_archive_uses_expected_source" {
  # Given the Executive Dashboard archive is configured,
  # when the archive source and output are checked,
  # then it should package the executive dashboard directory into the expected ZIP file.

  assert {
    condition = (
      data.archive_file.executive_dashboard_agent.type == "zip"
      &&
      data.archive_file.executive_dashboard_agent.source_dir ==
      "${path.module}/Lambda_Src/Reports/executive_dashboard_package"
      &&
      data.archive_file.executive_dashboard_agent.output_path ==
      "${path.module}/Lambda_Src/executive_dashboard_agent.zip"
    )

    error_message = "The Executive Dashboard archive must package Lambda_Src/Reports/executive_dashboard_package into Lambda_Src/executive_dashboard_agent.zip."
  }
}

check "executive_dashboard_lambda_uses_expected_package" {
  # Given the Executive Dashboard Lambda is configured with a deployment package,
  # when the deployment package and source hash are checked,
  # then it should use the generated Executive Dashboard archive and matching source hash.

  assert {
    condition = (
      aws_lambda_function.executive_dashboard_agent.filename ==
      data.archive_file.executive_dashboard_agent.output_path
      &&
      aws_lambda_function.executive_dashboard_agent.code_sha256 ==
      data.archive_file.executive_dashboard_agent.output_base64sha256
    )

    error_message = "The Executive Dashboard Lambda must use the generated deployment package."
  }
}

check "executive_dashboard_lambda_uses_expected_execution_role" {
  # Given the Executive Dashboard Lambda is configured with an execution role,
  # when the role assignment is checked,
  # then it should use the Asgard Lambda role.

  assert {
    condition = (
      aws_lambda_function.executive_dashboard_agent.role ==
      aws_iam_role.asgard_lambda_role.arn
    )

    error_message = "The Executive Dashboard Lambda must use the Asgard Lambda execution role."
  }
}

check "executive_dashboard_lambda_uses_expected_runtime_and_handler" {
  # Given the Executive Dashboard Lambda is configured with a runtime and handler,
  # when the runtime configuration is checked,
  # then it should use Python 3.14 and executive_dashboard_agent.lambda_handler.

  assert {
    condition = (
      aws_lambda_function.executive_dashboard_agent.runtime == "python3.14"
      &&
      aws_lambda_function.executive_dashboard_agent.handler ==
      "executive_dashboard_agent.lambda_handler"
    )

    error_message = "The Executive Dashboard Lambda must use runtime python3.14 and handler executive_dashboard_agent.lambda_handler."
  }
}

check "executive_dashboard_lambda_uses_expected_compute_settings" {
  # Given the Executive Dashboard Lambda is configured with compute settings,
  # when the timeout, memory, and ephemeral storage are checked,
  # then they should be set to 120 seconds, 512 MB, and 512 MB respectively.

  assert {
    condition = (
      aws_lambda_function.executive_dashboard_agent.timeout == 120
      &&
      aws_lambda_function.executive_dashboard_agent.memory_size == 512
      &&
      aws_lambda_function.executive_dashboard_agent.ephemeral_storage[0].size == 512
    )

    error_message = "The Executive Dashboard Lambda must use a 120 second timeout, 512 MB memory, and 512 MB ephemeral storage."
  }
}

check "executive_dashboard_lambda_uses_only_expected_environment_variables" {
  # Given the Executive Dashboard Lambda is configured with environment variables,
  # when the environment variable names are checked,
  # then only the approved Executive Dashboard variables should be present.

  assert {
    condition = (
      toset(
        keys(
          aws_lambda_function.executive_dashboard_agent.environment[0].variables
        )
        ) == toset([
          "WAF_EVENTS_TABLE",
          "CORRELATION_FINDINGS_TABLE",
          "SECURITY_INCIDENTS_TABLE",
          "REPORT_BUCKET",
          "REPORT_PREFIX",
          "BEDROCK_MODEL_ID",
          "ENABLE_BEDROCK",
          "REPORT_PERIOD_HOURS",
          "MAX_ITEMS_PER_TABLE",
          "ORGANIZATION_NAME",
          "REPORT_TITLE"
      ])
    )

    error_message = "The Executive Dashboard Lambda contains unexpected environment variables."
  }
}

check "executive_dashboard_lambda_environment_references_expected_resources" {
  # Given the Executive Dashboard Lambda is configured with environment variables,
  # when the environment variable values are checked,
  # then they should reference the expected resources and approved report settings.

  assert {
    condition = (
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["WAF_EVENTS_TABLE"] ==
      aws_dynamodb_table.asgard_waf_events.name
      &&
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["CORRELATION_FINDINGS_TABLE"] ==
      aws_dynamodb_table.asgard_waf_correlation_findings.name
      &&
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["SECURITY_INCIDENTS_TABLE"] ==
      aws_dynamodb_table.asgard_security_incidents.name
      &&
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["REPORT_BUCKET"] ==
      aws_s3_bucket.asgard_executive_report.bucket
      &&
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["REPORT_PREFIX"] ==
      "executive-reports"
      &&
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["BEDROCK_MODEL_ID"] ==
      "us.anthropic.claude-sonnet-4-6"
      &&
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["ENABLE_BEDROCK"] ==
      "true"
      &&
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["REPORT_PERIOD_HOURS"] ==
      "24"
      &&
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["MAX_ITEMS_PER_TABLE"] ==
      "5000"
      &&
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["ORGANIZATION_NAME"] ==
      "Asgard Cloud Security"
      &&
      aws_lambda_function.executive_dashboard_agent.environment[0].variables["REPORT_TITLE"] ==
      "Executive Security Report"
    )

    error_message = "The Executive Dashboard Lambda environment variables must reference the expected resources and approved values."
  }
}

###############################################################################
# Compliance Agent Checks
###############################################################################

check "compliance_agent_archive_uses_expected_source" {
  # Given the Compliance Agent archive is configured,
  # when the archive source and output are checked,
  # then it should package the compliance directory into the expected ZIP file.

  assert {
    condition = (
      data.archive_file.compliance_agent.type == "zip"
      &&
      data.archive_file.compliance_agent.source_dir ==
      "${path.module}/Lambda_Src/Reports/compliance_package"
      &&
      data.archive_file.compliance_agent.output_path ==
      "${path.module}/Lambda_Src/compliance_agent.zip"
    )

    error_message = "The Compliance Agent archive must package Lambda_Src/Reports/compliance_package into Lambda_Src/compliance_agent.zip."
  }
}

check "compliance_agent_lambda_uses_expected_package" {
  # Given the Compliance Agent Lambda is configured with a deployment package,
  # when the deployment package and source hash are checked,
  # then it should use the generated Compliance Agent archive and matching source hash.

  assert {
    condition = (
      aws_lambda_function.compliance_agent.filename ==
      data.archive_file.compliance_agent.output_path
      &&
      aws_lambda_function.compliance_agent.code_sha256 ==
      data.archive_file.compliance_agent.output_base64sha256
    )

    error_message = "The Compliance Agent Lambda must use the generated compliance deployment package and matching source hash."
  }
}

check "compliance_agent_lambda_uses_expected_execution_role" {
  # Given the Compliance Agent Lambda is configured with an execution role,
  # when the role assignment is checked,
  # then it should use the Asgard Lambda role.

  assert {
    condition = (
      aws_lambda_function.compliance_agent.role ==
      aws_iam_role.asgard_lambda_role.arn
    )

    error_message = "The Compliance Agent Lambda must use the Asgard Lambda execution role."
  }
}

check "compliance_agent_lambda_uses_expected_runtime_and_handler" {
  # Given the Compliance Agent Lambda is configured with a runtime and handler,
  # when the runtime configuration is checked,
  # then it should use Python 3.14 and compliance.lambda_handler.

  assert {
    condition = (
      aws_lambda_function.compliance_agent.runtime == "python3.14"
      &&
      aws_lambda_function.compliance_agent.handler ==
      "compliance.lambda_handler"
    )

    error_message = "The Compliance Agent Lambda must use runtime python3.14 and handler compliance.lambda_handler."
  }
}

check "compliance_agent_lambda_uses_expected_compute_settings" {
  # Given the Compliance Agent Lambda is configured with compute settings,
  # when the timeout, memory, and architecture are checked,
  # then they should be set to 180 seconds, 512 MB, and x86_64 respectively.

  assert {
    condition = (
      aws_lambda_function.compliance_agent.timeout == 180
      &&
      aws_lambda_function.compliance_agent.memory_size == 512
      &&
      toset(aws_lambda_function.compliance_agent.architectures) ==
      toset(["x86_64"])
    )

    error_message = "The Compliance Agent Lambda must use a 180 second timeout, 512 MB memory, and x86_64 architecture."
  }
}
