###############################################################################
# Cost Anomaly Detection Checks
###############################################################################

check "asgard_service_anomaly_monitor_uses_expected_configuration" {
  # Given the Asgard service cost anomaly monitor is active,
  # when Terraform evaluates the monitor configuration,
  # then it must detect anomalies by AWS service using the expected project name.

  assert {
    condition = (
      aws_ce_anomaly_monitor.asgard_service_anomaly_monitor.name ==
      "${var.project_name}-service-anomaly-monitor"
      && aws_ce_anomaly_monitor.asgard_service_anomaly_monitor.monitor_type ==
      "DIMENSIONAL"
      && aws_ce_anomaly_monitor.asgard_service_anomaly_monitor.monitor_dimension ==
      "SERVICE"
    )

    error_message = "The Asgard cost anomaly monitor must use the expected project name, DIMENSIONAL monitor type, and SERVICE dimension."
  }
}