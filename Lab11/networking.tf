locals {
  name_prefix    = var.project_name
  ports_http     = 80
  ports_ssh      = 22
  ports_https    = 443
  ports_dns      = 53
  db_port        = 3306
  tcp_protocol   = "tcp"
  udp_protocol   = "udp"
  all_ip_address = "0.0.0.0/0"
  all_ports      = "-1"
  all_protocol   = "All"
  http           = "http"
  https          = "https"
}

resource "aws_vpc" "odin_vpc01" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "odin_private_subnets" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.odin_vpc01.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]

  tags = {
    Name = "${local.name_prefix}-private-subnet0${count.index + 1}"
  }
}