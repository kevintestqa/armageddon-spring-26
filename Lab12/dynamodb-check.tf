###############################################################################
# DynamoDB Checks
###############################################################################

check "waf_correlation_table_uses_expected_name" {
  # Given the WAF correlation findings table,
  # when Terraform evaluates the table name,
  # then it must use the approved waf-correlation-findings name.

  assert {
    condition = (
      aws_dynamodb_table.asgard_waf_correlation_findings.name ==
      "waf-correlation-findings"
    )

    error_message = "The WAF correlation findings table must be named waf-correlation-findings."
  }
}

check "waf_correlation_table_uses_expected_partition_key" {
  # Given the WAF correlation findings table,
  # when Terraform evaluates the partition key,
  # then it must use finding_id as a string attribute.

  assert {
    condition = (
      aws_dynamodb_table.asgard_waf_correlation_findings.hash_key ==
      "finding_id"
      &&
      length([
        for attribute in aws_dynamodb_table.asgard_waf_correlation_findings.attribute : attribute
        if attribute.name == "finding_id" && attribute.type == "S"
      ]) == 1
    )

    error_message = "The WAF correlation findings table must use finding_id as its string partition key."
  }
}

check "waf_correlation_table_uses_on_demand_billing" {
  # Given the WAF correlation findings workload,
  # when Terraform evaluates the billing configuration,
  # then the table must use on-demand capacity.

  assert {
    condition = (
      aws_dynamodb_table.asgard_waf_correlation_findings.billing_mode ==
      "PAY_PER_REQUEST"
    )

    error_message = "The WAF correlation findings table must use PAY_PER_REQUEST billing."
  }
}

check "waf_correlation_table_uses_expected_ttl" {
  # Given the WAF correlation findings retention requirement,
  # when Terraform evaluates the TTL configuration,
  # then TTL must be enabled using the TimeToExist attribute.

  assert {
    condition = (
      length(
        aws_dynamodb_table.asgard_waf_correlation_findings.ttl
      ) == 1
      &&
      aws_dynamodb_table.asgard_waf_correlation_findings.ttl[0].enabled == true
      &&
      aws_dynamodb_table.asgard_waf_correlation_findings.ttl[0].attribute_name ==
      "TimeToExist"
    )

    error_message = "The WAF correlation findings table must enable TTL using the TimeToExist attribute."
  }
}

check "waf_correlation_table_uses_server_side_encryption" {
  # Given the WAF correlation findings table,
  # when Terraform evaluates data protection settings,
  # then server-side encryption must be enabled.

  assert {
    condition = (
      length(
        aws_dynamodb_table.asgard_waf_correlation_findings.server_side_encryption
      ) == 1
      &&
      aws_dynamodb_table.asgard_waf_correlation_findings.server_side_encryption[0].enabled == true
    )

    error_message = "The WAF correlation findings table must have server-side encryption enabled."
  }
}

check "security_incidents_table_uses_expected_name" {
  # Given the security incidents table,
  # when Terraform evaluates the table name,
  # then it must use the approved security-incidents name.

  assert {
    condition = (
      aws_dynamodb_table.asgard_security_incidents.name ==
      "security-incidents"
    )

    error_message = "The security incidents table must be named security-incidents."
  }
}

check "security_incidents_table_uses_expected_partition_key" {
  # Given the security incidents table,
  # when Terraform evaluates the partition key,
  # then it must use incident_id as a string attribute.

  assert {
    condition = (
      aws_dynamodb_table.asgard_security_incidents.hash_key ==
      "incident_id"
      &&
      length([
        for attribute in aws_dynamodb_table.asgard_security_incidents.attribute : attribute
        if attribute.name == "incident_id" && attribute.type == "S"
      ]) == 1
    )

    error_message = "The security incidents table must use incident_id as its string partition key."
  }
}

check "security_incidents_table_uses_on_demand_billing" {
  # Given the security incidents workload,
  # when Terraform evaluates the billing configuration,
  # then the table must use on-demand capacity.

  assert {
    condition = (
      aws_dynamodb_table.asgard_security_incidents.billing_mode ==
      "PAY_PER_REQUEST"
    )

    error_message = "The security incidents table must use PAY_PER_REQUEST billing."
  }
}

check "security_incidents_table_uses_server_side_encryption" {
  # Given the security incidents table,
  # when Terraform evaluates data protection settings,
  # then server-side encryption must be enabled.

  assert {
    condition = (
      length(
        aws_dynamodb_table.asgard_security_incidents.server_side_encryption
      ) == 1
      &&
      aws_dynamodb_table.asgard_security_incidents.server_side_encryption[0].enabled == true
    )

    error_message = "The security incidents table must have server-side encryption enabled."
  }
}

###############################################################################
# Token Tracking Table Checks
###############################################################################

check "token_tracking_table_uses_expected_name" {
  # Given the token tracking table,
  # when Terraform evaluates the table name,
  # then it must use the approved token-trackingv2 name.

  assert {
    condition = (
      aws_dynamodb_table.asgard_token_tracking.name ==
      "token-trackingv2"
    )

    error_message = "The token tracking table must be named token-trackingv2."
  }
}

check "token_tracking_table_uses_expected_partition_key" {
  # Given the token tracking table,
  # when Terraform evaluates the partition key,
  # then it must use token_id as a string attribute.

  assert {
    condition = (
      aws_dynamodb_table.asgard_token_tracking.hash_key ==
      "token_id"
      &&
      length([
        for attribute in aws_dynamodb_table.asgard_token_tracking.attribute : attribute
        if attribute.name == "token_id" && attribute.type == "S"
      ]) == 1
    )

    error_message = "The token tracking table must use token_id as its string partition key."
  }
}

check "token_tracking_table_uses_on_demand_billing" {
  # Given the token tracking workload,
  # when Terraform evaluates the billing configuration,
  # then the table must use on-demand capacity.

  assert {
    condition = (
      aws_dynamodb_table.asgard_token_tracking.billing_mode ==
      "PAY_PER_REQUEST"
    )

    error_message = "The token tracking table must use PAY_PER_REQUEST billing."
  }
}

check "token_tracking_table_uses_expected_ttl" {
  # Given the token tracking retention requirement,
  # when Terraform evaluates the TTL configuration,
  # then TTL must be enabled using the TimeToExist attribute.

  assert {
    condition = (
      length(
        aws_dynamodb_table.asgard_token_tracking.ttl
      ) == 1
      &&
      aws_dynamodb_table.asgard_token_tracking.ttl[0].enabled == true
      &&
      aws_dynamodb_table.asgard_token_tracking.ttl[0].attribute_name ==
      "TimeToExist"
    )

    error_message = "The token tracking table must enable TTL using the TimeToExist attribute."
  }
}

check "token_tracking_table_uses_server_side_encryption" {
  # Given the token tracking table,
  # when Terraform evaluates the data protection settings,
  # then server-side encryption must be enabled.

  assert {
    condition = (
      length(
        aws_dynamodb_table.asgard_token_tracking.server_side_encryption
      ) == 1
      &&
      aws_dynamodb_table.asgard_token_tracking.server_side_encryption[0].enabled == true
    )

    error_message = "The token tracking table must have server-side encryption enabled."
  }
}

check "token_tracking_table_uses_expected_global_secondary_index" {
  # Given the token tracking table,
  # when Terraform evaluates its global secondary indexes,
  # then it must contain satellite-DB-Index with username as its HASH key
  # and project all table attributes.

  assert {
    condition = length([
      for index in aws_dynamodb_table.asgard_token_tracking.global_secondary_index : index
      if index.name == "satellite-DB-Index"
      && index.projection_type == "ALL"
      && length([
        for key in index.key_schema : key
        if key.attribute_name == "username"
        && key.key_type == "HASH"
      ]) == 1
    ]) == 1

    error_message = "The token tracking table must define satellite-DB-Index with username as its HASH key and use ALL projection."
  }
}