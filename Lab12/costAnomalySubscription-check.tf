###############################################################################
# Cost Anomaly Subscription Checks
###############################################################################

check "asgard_anomaly_subscription_uses_expected_configuration" {
  # Given the Asgard cost anomaly subscription is active,
  # when Terraform evaluates the subscription configuration,
  # then it must use the expected name, daily frequency, and service anomaly monitor.

  assert {
    condition = (
      aws_ce_anomaly_subscription.asgard_anomaly_subscription.name ==
      "${var.project_name}-anomaly-subscription"
      && aws_ce_anomaly_subscription.asgard_anomaly_subscription.frequency ==
      "DAILY"
      && one(
        aws_ce_anomaly_subscription.asgard_anomaly_subscription.monitor_arn_list
      ) == aws_ce_anomaly_monitor.asgard_service_anomaly_monitor.arn
    )

    error_message = "The Asgard anomaly subscription must use the expected project name, DAILY frequency, and service anomaly monitor."
  }
}

check "asgard_anomaly_subscription_uses_expected_email_subscriber" {
  # Given the Asgard cost anomaly subscription sends notifications,
  # when Terraform evaluates the subscriber configuration,
  # then it must use the configured email endpoint.

  assert {
    condition = (
      one(
        aws_ce_anomaly_subscription.asgard_anomaly_subscription.subscriber
      ).type == "EMAIL"
      && one(
        aws_ce_anomaly_subscription.asgard_anomaly_subscription.subscriber
      ).address == var.sns_email_endpoint
    )

    error_message = "The Asgard anomaly subscription must notify the configured email subscriber."
  }
}

check "asgard_anomaly_subscription_uses_expected_threshold" {
  # Given the Asgard cost anomaly subscription evaluates anomaly impact,
  # when Terraform evaluates the threshold expression,
  # then it must use the configured absolute anomaly threshold.

  assert {
    condition = (
      one(
        one(
          aws_ce_anomaly_subscription.asgard_anomaly_subscription.threshold_expression
        ).dimension
      ).key == "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      && one(
        one(
          aws_ce_anomaly_subscription.asgard_anomaly_subscription.threshold_expression
        ).dimension
      ).match_options == ["GREATER_THAN_OR_EQUAL"]
      && one(
        one(
          aws_ce_anomaly_subscription.asgard_anomaly_subscription.threshold_expression
        ).dimension
      ).values == [tostring(var.anomaly_threshold_absolute)]
    )

    error_message = "The Asgard anomaly subscription must trigger when absolute anomaly impact meets or exceeds the configured threshold."
  }
}