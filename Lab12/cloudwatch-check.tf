# Given the Asgard pipeline is deployed,
# when Terraform plans its dashboard,
# then all metric widgets must target the deployment region.
check "asgard_dashboard_region" {
  assert {
    condition     = alltrue([for widget in local.monitoring_widgets : widget.properties.region == "us-east-1" if widget.type == "metric"])
    error_message = "All Asgard dashboard metrics must use us-east-1."
  }
}
# Given bounded operational counters are available,
# when constructing the dashboard,
# then the full pipeline and all three enrichment providers are represented.
check "asgard_dashboard_coverage" {
  assert {
    condition     = length(local.monitored_functions) == 4 && length(local.monitoring_widgets) == 12 && local.threat_metric_namespace == "Asgard/ThreatMonitoring"
    error_message = "Expected four Lambda functions and eleven metric widgets plus documentation."
  }
}
