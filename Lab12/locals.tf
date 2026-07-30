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