resource "aws_ce_anomaly_monitor" "asgard_service_anomaly_monitor" {
  name              = "${var.project_name}-service-anomaly-monitor"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"

  tags = local.common_tags
}