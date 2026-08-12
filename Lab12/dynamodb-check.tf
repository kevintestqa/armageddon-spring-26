###############################################################################
# DynamoDB Checks
###############################################################################

check "waf_correlation_table_uses_expected_name" {
  # Given the WAF correlation findings table is configured,
  # when the table name is checked,
  # then the name should be waf-correlation-findings.

  assert {
    condition = (
      aws_dynamodb_table.asgard_waf_correlation_findings.name ==
      "waf-correlation-findings"
    )

    error_message = "The WAF correlation findings table must be named waf-correlation-findings."
  }
}

check "waf_correlation_table_uses_expected_partition_key" {
  # Given the WAF correlation findings table is configured with a partition key,
  # when the partition key is checked,
  # then finding_id should be configured as a string partition key.

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
  # Given the WAF correlation findings table is configured with a billing mode,
  # when the billing mode is checked,
  # then it should be set to PAY_PER_REQUEST.

  assert {
    condition = (
      aws_dynamodb_table.asgard_waf_correlation_findings.billing_mode ==
      "PAY_PER_REQUEST"
    )

    error_message = "The WAF correlation findings table must use PAY_PER_REQUEST billing."
  }
}

check "waf_correlation_table_uses_expected_ttl" {
  # Given the WAF correlation findings table is configured with TTL,
  # when the TTL settings are checked,
  # then TTL should be enabled using the TimeToExist attribute.

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
  # Given the WAF correlation findings table is configured with server-side encryption,
  # when the encryption settings are checked,
  # then server-side encryption should be enabled.

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
  # Given the security incidents table is configured,
  # when the table name is checked,
  # then the name should be security-incidents.

  assert {
    condition = (
      aws_dynamodb_table.asgard_security_incidents.name ==
      "security-incidents"
    )

    error_message = "The security incidents table must be named security-incidents."
  }
}

check "security_incidents_table_uses_expected_partition_key" {
  # Given the security incidents table is configured with a partition key,
  # when the partition key is checked,
  # then incident_id should be configured as a string partition key.

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
  # Given the security incidents table is configured with a billing mode,
  # when the billing mode is checked,
  # then it should be set to PAY_PER_REQUEST.

  assert {
    condition = (
      aws_dynamodb_table.asgard_security_incidents.billing_mode ==
      "PAY_PER_REQUEST"
    )

    error_message = "The security incidents table must use PAY_PER_REQUEST billing."
  }
}

check "security_incidents_table_uses_server_side_encryption" {
  # Given the security incidents table is configured with server-side encryption,
  # when the encryption settings are checked,
  # then server-side encryption should be enabled.

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
# Compliance Findings Table Checks
###############################################################################

check "compliance_findings_table_uses_expected_name" {
  # Given the compliance findings table is configured,
  # when the table name is checked,
  # then the name should be compliance-findings.

  assert {
    condition = (
      aws_dynamodb_table.asgard_compliance_findings.name ==
      "compliance-findings"
    )

    error_message = "The compliance findings table must be named compliance-findings."
  }
}

check "compliance_findings_table_uses_expected_partition_key" {
  # Given the compliance findings table is configured with a partition key,
  # when the partition key is checked,
  # then finding_id should be configured as a string partition key.

  assert {
    condition = (
      aws_dynamodb_table.asgard_compliance_findings.hash_key ==
      "finding_id"
      &&
      length([
        for attribute in aws_dynamodb_table.asgard_compliance_findings.attribute : attribute
        if attribute.name == "finding_id" && attribute.type == "S"
      ]) == 1
    )

    error_message = "The compliance findings table must use finding_id as its string partition key."
  }
}

check "compliance_findings_table_uses_on_demand_billing" {
  # Given the compliance findings table is configured with a billing mode,
  # when the billing mode is checked,
  # then it should be set to PAY_PER_REQUEST.

  assert {
    condition = (
      aws_dynamodb_table.asgard_compliance_findings.billing_mode ==
      "PAY_PER_REQUEST"
    )

    error_message = "The compliance findings table must use PAY_PER_REQUEST billing."
  }
}

check "compliance_findings_table_uses_server_side_encryption" {
  # Given the compliance findings table is configured with server-side encryption,
  # when the encryption settings are checked,
  # then server-side encryption should be enabled.

  assert {
    condition = (
      length(
        aws_dynamodb_table.asgard_compliance_findings.server_side_encryption
      ) == 1
      &&
      aws_dynamodb_table.asgard_compliance_findings.server_side_encryption[0].enabled == true
    )

    error_message = "The compliance findings table must have server-side encryption enabled."
  }
}

###############################################################################
# Compliance Evidence Table Checks
###############################################################################

check "compliance_evidence_table_uses_expected_name" {
  # Given the compliance evidence table is configured,
  # when the table name is checked,
  # then the name should be compliance-evidence.

  assert {
    condition = (
      aws_dynamodb_table.asgard_compliance_evidence.name ==
      "compliance-evidence"
    )

    error_message = "The compliance evidence table must be named compliance-evidence."
  }
}

check "compliance_evidence_table_uses_expected_partition_key" {
  # Given the compliance evidence table is configured with a partition key,
  # when the partition key is checked,
  # then evidence_id should be configured as a string partition key.

  assert {
    condition = (
      aws_dynamodb_table.asgard_compliance_evidence.hash_key ==
      "evidence_id"
      &&
      length([
        for attribute in aws_dynamodb_table.asgard_compliance_evidence.attribute : attribute
        if attribute.name == "evidence_id" && attribute.type == "S"
      ]) == 1
    )

    error_message = "The compliance evidence table must use evidence_id as its string partition key."
  }
}

check "compliance_evidence_table_uses_on_demand_billing" {
  # Given the compliance evidence table is configured with a billing mode,
  # when the billing mode is checked,
  # then it should be set to PAY_PER_REQUEST.

  assert {
    condition = (
      aws_dynamodb_table.asgard_compliance_evidence.billing_mode ==
      "PAY_PER_REQUEST"
    )

    error_message = "The compliance evidence table must use PAY_PER_REQUEST billing."
  }
}

check "compliance_evidence_table_uses_server_side_encryption" {
  # Given the compliance evidence table is configured with server-side encryption,
  # when the encryption settings are checked,
  # then server-side encryption should be enabled.

  assert {
    condition = (
      length(
        aws_dynamodb_table.asgard_compliance_evidence.server_side_encryption
      ) == 1
      &&
      aws_dynamodb_table.asgard_compliance_evidence.server_side_encryption[0].enabled == true
    )

    error_message = "The compliance evidence table must have server-side encryption enabled."
  }
}