resource "aws_secretsmanager_secret" "odin_db_secret" {
  name                    = "lab11a/rds/mysql"
  recovery_window_in_days = 0 //Days AWS can wait before permanently deleting the secret. 0 means delete immediately.
}

resource "aws_secretsmanager_secret_version" "odin_db_secret_version01" {
  secret_id = aws_secretsmanager_secret.odin_db_secret.id

  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    host     = aws_db_instance.odin_rds.address
    port     = aws_db_instance.odin_rds.port
    dbname   = var.db_name
  })
}