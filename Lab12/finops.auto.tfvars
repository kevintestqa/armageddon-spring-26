# Existing account-wide SERVICE monitor, verified via read-only AWS inspection.
# Guardian remains externally managed; Asgard only subscribes to its findings.
# For a different account, replace this ARN or set null if no service monitor exists.
existing_service_monitor_arn = "arn:aws:ce::461593447802:anomalymonitor/1a786081-bcfc-4256-9331-183d02ad458e"
enable_threat_enrichment     = true