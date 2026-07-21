resource "aws_secretsmanager_secret" "odin_db_secret01" {
  name                    = "lab11a/rds/mysql"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "satellite_db_secret_version01" {
  secret_id = aws_secretsmanager_secret.odin_db_secret01.id

  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    host     = aws_db_instance.odin_rds01.address
    port     = aws_db_instance.odin_rds01.port
    dbname   = var.db_name
  })
}