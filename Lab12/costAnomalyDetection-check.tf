###############################################################################
# Cost Anomaly Detection Checks
###############################################################################

check "asgard_service_anomaly_monitor_uses_expected_configuration" {
  # Given the Asgard service cost anomaly monitor is active,
  # when Terraform evaluates the monitor configuration,
  # then it must either reuse the configured external monitor without creating
  # a duplicate, or create a SERVICE monitor with the expected project name.

  assert {
    condition = var.existing_service_monitor_arn != null ? length(aws_ce_anomaly_monitor.asgard_service_anomaly_monitor) == 0 : (
      aws_ce_anomaly_monitor.asgard_service_anomaly_monitor[0].name ==
      "${var.project_name}-service-anomaly-monitor"
      && aws_ce_anomaly_monitor.asgard_service_anomaly_monitor[0].monitor_type ==
      "DIMENSIONAL"
      && aws_ce_anomaly_monitor.asgard_service_anomaly_monitor[0].monitor_dimension ==
      "SERVICE"
    )

    error_message = "The Asgard cost anomaly monitor must use the expected project name, DIMENSIONAL monitor type, and SERVICE dimension."
  }
}
