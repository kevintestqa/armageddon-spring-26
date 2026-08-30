resource "aws_ce_anomaly_monitor" "asgard_service_anomaly_monitor" {
  count             = var.existing_service_monitor_arn == null ? 1 : 0
  name              = "${var.project_name}-service-anomaly-monitor"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"

  tags = local.common_tags
}

# Preserve the address of a previously managed monitor in other deployments.
moved {
  from = aws_ce_anomaly_monitor.asgard_service_anomaly_monitor
  to   = aws_ce_anomaly_monitor.asgard_service_anomaly_monitor[0]
}

variable "existing_service_monitor_arn" {
  description = "Reuse an existing account-wide SERVICE monitor without managing its lifecycle. Null creates a new monitor."
  type        = string
  default     = null
  validation {
    condition     = var.existing_service_monitor_arn == null ? true : can(regex("^arn:aws:ce::[0-9]{12}:anomalymonitor/.+$", var.existing_service_monitor_arn))
    error_message = "Supply a Cost Explorer anomaly monitor ARN, or null."
  }
}

locals {
  service_monitor_arn = var.existing_service_monitor_arn != null ? var.existing_service_monitor_arn : aws_ce_anomaly_monitor.asgard_service_anomaly_monitor[0].arn
}
