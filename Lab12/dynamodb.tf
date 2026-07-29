# Table Name: waf-correlation-findings
# Partition Key: finding_id
# Type:: String
# Capacity Mode: On-demand
# https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html


resource "aws_dynamodb_table" "asgard_waf_correlation_findings" {
  name         = "waf-correlation-findings"
  hash_key     = "finding_id"
  billing_mode = "PAY_PER_REQUEST"
  attribute {
    name = "finding_id"
    type = "S"
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }
}

# Table 2 Security Incidents
# Table Name: security-incidents
# Partition Key: incident_id
# Type:: String
# Capacity Mode: On-demand
resource "aws_dynamodb_table" "asgard_security_incidents" {
  name         = "security-incidents"
  hash_key     = "incident_id"
  billing_mode = "PAY_PER_REQUEST"
  attribute {
    name = "incident_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}

//TODO: DELETE THIS TABLE
resource "aws_dynamodb_table" "asgard_token_tracking" {
  name         = "token-trackingv2"
  hash_key     = "token_id"
  billing_mode = "PAY_PER_REQUEST"
  attribute {
    name = "token_id"
    type = "S"
  }

  attribute {
    name = "username"
    type = "S"
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

  global_secondary_index {
    name = "satellite-DB-Index"
    key_schema {
      attribute_name = "username"
      key_type       = "HASH"
    }
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled = true
  }
}

resource "aws_dynamodb_table" "asgard_waf_events" {
  name         = "asgard-waf-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"
  attribute {
    name = "event_id"
    type = "S"
  }
  server_side_encryption {
    enabled = true
  }
  tags = {
    Name      = "asgard-waf-events"
    Component = "waf"
  }
}