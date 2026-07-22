resource "aws_db_instance" "odin_rds" {
  identifier               = "${local.name_prefix}-rds"
  engine                   = var.db_engine
  instance_class           = var.db_instance_class
  storage_type             = var.storage_type
  allocated_storage        = 20
  backup_retention_period  = 7
  db_name                  = var.db_name
  username                 = var.db_username
  password                 = var.db_password
  multi_az                 = true
  delete_automated_backups = false

  db_subnet_group_name   = aws_db_subnet_group.odin_rds_subnet_group.name
  vpc_security_group_ids = [aws_security_group.odin_rds_sg.id]

  publicly_accessible = false
  skip_final_snapshot = true

  tags = {
    Name = "${local.name_prefix}-rds"
  }
}