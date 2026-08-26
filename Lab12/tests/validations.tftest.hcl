//tests the rule

//Solves the issue of "Provider "registry.terraform.io/hashicorp/aws" requires explicit
# │ configuration. Add a provider block to the root module and configure the
# │ provider's required arguments as described in the provider documentation."
# Mock will use version 6.55 of the AWS provider(which I defined), which is compatible with Terraform 1.5.0 and above.
mock_provider "aws" {}

run "valid_executive_dashboard_agent_memory" {
  command = plan

  variables {
    lambda_memory_size = 512
  }

  assert {
    condition     = aws_lambda_function.executive_dashboard_agent.memory_size >= 128 && aws_lambda_function.executive_dashboard_agent.memory_size <= 10240
    error_message = "Memory size must be between 128 MB and 10,240 MB"
  }
}

run "invalid_executive_dashboard_agent_memory" {
  command = plan

  variables {
    lambda_memory_size = 64
  }

  expect_failures = [
    var.lambda_memory_size
  ]
}

run "valid_executive_dashboard_agent_architecture" {
  command = plan

  variables {
    lambda_architecture = "x86_64"
  }

  assert {
    condition     = aws_lambda_function.executive_dashboard_agent.architectures[0] == var.lambda_architecture
    error_message = "Architecture must be x86_64"
  }
}

run "invalid_executive_dashboard_agent_architecture" {
  command = plan

  variables {
    lambda_architecture = "arm64"
  }

  expect_failures = [
    var.lambda_architecture
  ]
}

run "valid_python_lambda_runtime" {
  command = plan

  variables {
    lambda_python_runtime = "python3.14"
  }

  assert {
    condition     = aws_lambda_function.executive_dashboard_agent.runtime == var.lambda_python_runtime
    error_message = "Runtime must be python3.14"
  }
}

run "invalid_python_lambda_runtime" {
  command = plan

  variables {
    lambda_python_runtime = "python3.13"
  }

  expect_failures = [
    var.lambda_python_runtime
  ]
}

run "valid_s3_executive_report_bucket_name" {
  command = plan

  variables {
    executive_report_bucket_name = "asgard-executive-report"
  }

  assert {
    condition     = aws_s3_bucket.asgard_executive_report.bucket == var.executive_report_bucket_name
    error_message = "Executive report bucket name must be 'asgard-executive-report'"
  }
}

run "invalid_s3_executive_report_bucket_name" {
  command = plan

  variables {
    executive_report_bucket_name = "asgard-executive-repor"
  }

  expect_failures = [
    var.executive_report_bucket_name
  ]
}

run "valid_s3_compliance_report_bucket_name" {
  command = plan

  variables {
    compliance_report_bucket_name = "asgard-compliance-report"
  }

  assert {
    condition     = aws_s3_bucket.asgard_compliance_report.bucket == var.compliance_report_bucket_name
    error_message = "Compliance report bucket name must be 'asgard-compliance-report'"
  }
}

run "invalid_s3_compliance_report_bucket_name" {
  command = plan

  variables {
    compliance_report_bucket_name = "asgard-compliance-repor"
  }

  expect_failures = [
    var.compliance_report_bucket_name
  ]
}

run "valid_dynamodb_table_encryption" {
  command = plan

  assert {
    condition     = one(aws_dynamodb_table.asgard_waf_events.server_side_encryption).enabled == true
    error_message = "DynamoDB table asgard_waf_events must have server-side encryption enabled"
  }

  assert {
    condition     = one(aws_dynamodb_table.asgard_compliance_findings.server_side_encryption).enabled == true
    error_message = "DynamoDB table asgard_compliance_findings must have server-side encryption enabled"
  }

  assert {
    condition     = one(aws_dynamodb_table.asgard_compliance_evidence.server_side_encryption).enabled == true
    error_message = "DynamoDB table asgard_compliance_evidence must have server-side encryption enabled"
  }
}

run "valid_dynamodb_table_billing_mode" {
  command = plan

  assert {
    condition     = aws_dynamodb_table.asgard_waf_events.billing_mode == "PAY_PER_REQUEST"
    error_message = "DynamoDB table asgard_waf_events must have billing mode set to PAY_PER_REQUEST"
  }

  assert {
    condition     = aws_dynamodb_table.asgard_compliance_findings.billing_mode == "PAY_PER_REQUEST"
    error_message = "DynamoDB table asgard_compliance_findings must have billing mode set to PAY_PER_REQUEST"
  }

  assert {
    condition     = aws_dynamodb_table.asgard_compliance_evidence.billing_mode == "PAY_PER_REQUEST"
    error_message = "DynamoDB table asgard_compliance_evidence must have billing mode set to PAY_PER_REQUEST"
  }
}

run "valid_dynamodb_table_hash_key" {
  command = plan

  assert {
    condition     = aws_dynamodb_table.asgard_waf_events.hash_key == "event_id"
    error_message = "DynamoDB table asgard_waf_events must have hash key set to event_id"
  }

  assert {
    condition     = aws_dynamodb_table.asgard_compliance_findings.hash_key == "finding_id"
    error_message = "DynamoDB table asgard_compliance_findings must have hash key set to finding_id"
  }

  assert {
    condition     = aws_dynamodb_table.asgard_compliance_evidence.hash_key == "evidence_id"
    error_message = "DynamoDB table asgard_compliance_evidence must have hash key set to evidence_id"
  }
}

run "valid_dynamodb_table_attribute" {
  command = plan

  assert {
    //One is a terraform function that means "This collection should contain exactly one item. Give me that item.”
    condition     = one(aws_dynamodb_table.asgard_waf_events.attribute).name == "event_id"
    error_message = "DynamoDB table asgard_waf_events must have attribute name set to event_id"
  }

  assert {
    condition     = one(aws_dynamodb_table.asgard_compliance_findings.attribute).name == "finding_id"
    error_message = "DynamoDB table asgard_compliance_findings must have attribute name set to finding_id"
  }

  assert {
    condition     = one(aws_dynamodb_table.asgard_compliance_evidence.attribute).name == "evidence_id"
    error_message = "DynamoDB table asgard_compliance_evidence must have attribute name set to evidence_id"
  }
}

run "valid_dynamodb_table_attribute_type" {
  command = plan

  assert {
    condition     = one(aws_dynamodb_table.asgard_waf_events.attribute).type == "S"
    error_message = "DynamoDB table asgard_waf_events must have attribute type set to S"
  }

  assert {
    condition     = one(aws_dynamodb_table.asgard_compliance_findings.attribute).type == "S"
    error_message = "DynamoDB table asgard_compliance_findings must have attribute type set to S"
  }

  assert {
    condition     = one(aws_dynamodb_table.asgard_compliance_evidence.attribute).type == "S"
    error_message = "DynamoDB table asgard_compliance_evidence must have attribute type set to S"
  }
}

run "project_cost_allocation_tag_is_active" {
  command = plan

  assert {
    condition = (
      aws_ce_cost_allocation_tag.asgard_project.tag_key == "Project"
    )

    error_message = "The Project tag key must be activated for cost allocation."
  }

  assert {
    condition = (
      aws_ce_cost_allocation_tag.asgard_project.status == "Active"
    )

    error_message = "The Project cost allocation tag must have Active status."
  }
}

run "project_tag_value_is_asgard" {
  command = plan

  assert {
    condition = (
      local.common_tags["Project"] == "Asgard"
    )

    error_message = "The Project tag value must be exactly 'Asgard'."
  }
}

run "valid_budget_configuration" {
  command = plan

  assert {
    condition = (
      aws_budgets_budget.asgard_budget.budget_type == "COST"
      &&
      aws_budgets_budget.asgard_budget.time_unit == "MONTHLY"
      &&
      aws_budgets_budget.asgard_budget.limit_amount == var.budget_limit
    )

    error_message = "AWS Budget must use the configured monthly cost limit."
  }
}

run "valid_cost_anomaly_monitor_configuration" {
  command = plan

  assert {
    condition = (
      aws_ce_anomaly_monitor.asgard_service_anomaly_monitor.monitor_type ==
      "DIMENSIONAL"
      &&
      aws_ce_anomaly_monitor.asgard_service_anomaly_monitor.monitor_dimension ==
      "SERVICE"
    )

    error_message = "Cost anomaly monitor must detect anomalies by AWS service."
  }
}