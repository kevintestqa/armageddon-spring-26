variable "db_engine" {
  description = "RDS engine."
  type        = string
  default     = "mysql"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t3.micro"
}

variable "db_name" {
  description = "Initial database name."
  type        = string
  default     = "midgard"
}

variable "db_username" {
  description = "DB master username."
  type        = string
  default     = "thor"
}

variable "db_password" {
  description = "DB master password."
  type        = string
  sensitive   = true
  default     = "asgard"
}

variable "storage_type" {
  default = "gp2"
  type    = string
}

variable "project_name" {
  type        = string
  default     = "odin"
}