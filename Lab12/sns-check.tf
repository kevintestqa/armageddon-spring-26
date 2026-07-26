###############################################################################
# SNS Checks
###############################################################################

check "sns_topics_use_expected_names" {
  # Given the two Asgard alert channels,
  # when Terraform evaluates the SNS topic names,
  # then the critical and medium/high topics must use their expected names.

  assert {
    condition = (
      aws_sns_topic.asgard_critical_alerts_topic.name ==
      "${local.name_prefix}-critical-incidents"
      &&
      aws_sns_topic.asgard_medium_high_alerts_topic.name ==
      "${local.name_prefix}-medium-high-incidents"
    )

    error_message = "The SNS topics must use the expected critical and medium/high incident names."
  }
}

check "sns_topics_use_distinct_names" {
  # Given separate alert channels,
  # when Terraform evaluates the SNS topic names,
  # then each channel must use a unique SNS topic.

  assert {
    condition = (
      aws_sns_topic.asgard_critical_alerts_topic.name !=
      aws_sns_topic.asgard_medium_high_alerts_topic.name
    )

    error_message = "The critical and medium/high SNS topics must have different names."
  }
}

check "critical_subscription_targets_critical_topic" {
  # Given the critical alert subscription,
  # when Terraform evaluates the subscription,
  # then it must publish to the critical SNS topic.

  assert {
    condition = (
      aws_sns_topic_subscription.asgard_critical_alerts_sub.topic_arn ==
      aws_sns_topic.asgard_critical_alerts_topic.arn
    )

    error_message = "The critical alert subscription must reference the critical SNS topic."
  }
}

check "medium_high_subscription_targets_medium_high_topic" {
  # Given the medium/high alert subscription,
  # when Terraform evaluates the subscription,
  # then it must publish to the medium/high SNS topic.

  assert {
    condition = (
      aws_sns_topic_subscription.asgard_medium_high_alerts_sub.topic_arn ==
      aws_sns_topic.asgard_medium_high_alerts_topic.arn
    )

    error_message = "The medium/high alert subscription must reference the medium/high SNS topic."
  }
}

check "sns_subscriptions_use_email_protocol" {
  # Given the SNS subscriptions,
  # when Terraform evaluates the delivery protocol,
  # then both subscriptions must use email.

  assert {
    condition = (
      aws_sns_topic_subscription.asgard_critical_alerts_sub.protocol == "email"
      &&
      aws_sns_topic_subscription.asgard_medium_high_alerts_sub.protocol == "email"
    )

    error_message = "All SNS subscriptions must use the email protocol."
  }
}

check "sns_subscriptions_use_expected_endpoint" {
  # Given the configured notification email,
  # when Terraform evaluates the subscription endpoint,
  # then both subscriptions must use var.sns_email_endpoint.

  assert {
    condition = (
      aws_sns_topic_subscription.asgard_critical_alerts_sub.endpoint ==
      var.sns_email_endpoint
      &&
      aws_sns_topic_subscription.asgard_medium_high_alerts_sub.endpoint ==
      var.sns_email_endpoint
    )

    error_message = "All SNS subscriptions must use the configured SNS email endpoint."
  }
}