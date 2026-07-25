resource "aws_wafv2_web_acl" "asgard_waf_v2" {
  name        = "asgard_waf_v2"
  description = "Production WAF for Asgard"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "rule-1"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        rule_action_override {
          action_to_use {
            count {}
          }

          name = "SizeRestrictions_QUERYSTRING"
        }

        rule_action_override {
          action_to_use {
            count {}
          }

          name = "NoUserAgent_HEADER"
        }

        scope_down_statement {
          geo_match_statement {
            country_codes = ["US", "NL"]
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aesir-common-rule-set"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "aesir-api-waf"
    sampled_requests_enabled   = false
  }
}

resource "aws_wafv2_web_acl_rule" "asgard_block" {
  name        = "asgard_block"
  priority    = 0
  web_acl_arn = aws_wafv2_web_acl.asgard_waf_v2.arn
  override_action {
    none {}
  }

  statement {
    managed_rule_group_statement {
      name        = "AWSManagedRulesCommonRuleSet"
      vendor_name = "AWS"
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "asgard_block"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "asgard_waf_association" {
  resource_arn = aws_api_gateway_stage.qa_environment.arn
  web_acl_arn  = aws_wafv2_web_acl.asgard_waf_v2.arn
}

check "waf_attached_to_qa_stage" {
  assert {
    condition = strcontains(
      aws_wafv2_web_acl_association.asgard_waf_association.resource_arn,
      "/stages/qa"
    )

    error_message = "The WAF must be associated with the QA API Gateway stage."
  }
}