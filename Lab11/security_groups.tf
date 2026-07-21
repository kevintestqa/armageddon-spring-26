resource "aws_security_group" "odin_lambda_sg01" {
  name        = "${local.name_prefix}-lambda-sg01"
  description = "Lambda app security group"
  vpc_id      = aws_vpc.odin_vpc01.id

  tags = {
    Name = "${local.name_prefix}-lambda-sg01"
  }
}

//Maybe I need tihs
resource "aws_vpc_security_group_ingress_rule" "odin_lambda_sg_ingress_http" {
  ip_protocol       = local.tcp_protocol
  security_group_id = aws_security_group.odin_lambda_sg01.id
  from_port         = local.ports_http
  to_port           = local.ports_http
  cidr_ipv4         = local.all_ip_address
}

resource "aws_security_group" "odin_rds_sg01" {
  name        = "${local.name_prefix}-rds-sg01"
  description = "RDS security group"
  vpc_id      = aws_vpc.odin_vpc01.id

  tags = {
    Name = "${local.name_prefix}-rds-sg01"
  }
}

resource "aws_vpc_security_group_ingress_rule" "odin_rds_sg_ingress_mysql" {
  ip_protocol                  = local.tcp_protocol
  security_group_id            = aws_security_group.odin_rds_sg01.id
  from_port                    = local.db_port
  to_port                      = local.db_port
  referenced_security_group_id = aws_security_group.odin_lambda_sg01.id #allow traffic ONLY from specified SG
}

resource "aws_db_subnet_group" "odin_rds_subnet_group01" {
  name       = "${local.name_prefix}-rds-subnet-group01"
  subnet_ids = aws_subnet.odin_private_subnets[*].id

  tags = {
    Name = "${local.name_prefix}-rds-subnet-group01"
  }
}