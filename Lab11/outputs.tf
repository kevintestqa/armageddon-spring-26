output "db_endpoint" {
  description = "Midgard's RDS endpoint."
  value       = aws_db_instance.odin_rds.endpoint
}

output "db_port" {
  description = "Midgard's RDS port."
  value       = aws_db_instance.odin_rds.port
}