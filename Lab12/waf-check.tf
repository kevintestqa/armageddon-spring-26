check "waf_attached_to_qa_stage" {
  assert {
    condition = strcontains(
      aws_wafv2_web_acl_association.asgard_waf_association.resource_arn,
      "/stages/qa"
    )

    error_message = "The WAF must be associated with the QA API Gateway stage."
  }
}