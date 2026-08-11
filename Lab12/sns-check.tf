###############################################################################
# SNS Checks
###############################################################################

check "sns_topics_use_expected_names" {
  # Given the critical and medium/high SNS topics are configured,
  # when the topic names are checked,
  # then they should use the expected critical and medium/high incident names.

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
  # Given the critical and medium/high SNS topics are configured,
  # when their topic names are compared,
  # then each alert channel should use a unique SNS topic name.

  assert {
    condition = (
      aws_sns_topic.asgard_critical_alerts_topic.name !=
      aws_sns_topic.asgard_medium_high_alerts_topic.name
    )

    error_message = "The critical and medium/high SNS topics must have different names."
  }
}

check "critical_subscription_targets_critical_topic" {
  # Given the critical alert subscription is configured,
  # when its target topic is checked,
  # then it should reference the critical SNS topic.

  assert {
    condition = (
      aws_sns_topic_subscription.asgard_critical_alerts_sub.topic_arn ==
      aws_sns_topic.asgard_critical_alerts_topic.arn
    )

    error_message = "The critical alert subscription must reference the critical SNS topic."
  }
}

check "medium_high_subscription_targets_medium_high_topic" {
  # Given the medium/high alert subscription is configured,
  # when its target topic is checked,
  # then it should reference the medium/high SNS topic.

  assert {
    condition = (
      aws_sns_topic_subscription.asgard_medium_high_alerts_sub.topic_arn ==
      aws_sns_topic.asgard_medium_high_alerts_topic.arn
    )

    error_message = "The medium/high alert subscription must reference the medium/high SNS topic."
  }
}

check "sns_subscriptions_use_email_protocol" {
  # Given the SNS subscriptions are configured with a delivery protocol,
  # when the protocol is checked,
  # then both subscriptions should use email.

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
  # Given the SNS subscriptions are configured with notification endpoints,
  # when the subscription endpoints are checked,
  # then both subscriptions should use var.sns_email_endpoint.

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