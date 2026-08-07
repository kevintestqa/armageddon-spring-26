variable "project_name" {
  type    = string
  default = "asgard"
}

variable "vpc_cidr" {
  description = "VPC CIDR (use 10.x.x.x/xx as instructed)."
  type        = string
  default     = "10.40.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDRs (use 10.x.x.x/xx)."
  type        = list(string)
  default     = ["10.40.11.0/24", "10.40.12.0/24"]
}

variable "azs" {
  description = "Availability Zones list"
  type        = list(string)
  default     = ["us-east-1a", "us-west-1a"]
}

variable "sns_email_endpoint" {
  description = "Email for SNS subscription"
  type        = string
  default     = "kevindevops0920@gmail.com"
}

variable "odin_password" {
  description = "Password for the Odin Cognito user"
  type        = string
  default     = "Gungnir!"
  sensitive   = true
}

variable "thor_password" {
  description = "Password for the Thor Cognito user"
  type        = string
  default     = "Mjolnir1234!"
  sensitive   = true
}

variable "lambda_architecture" {
  type    = string
  default = "x86_64"

  validation {
    condition = var.lambda_architecture == "x86_64"
    error_message = "Architecture must be x86_64"
  }
}

variable "lambda_python_runtime" {
  type    = string
  default = "python3.14"

  validation {
    condition = var.lambda_python_runtime == "python3.14"
    error_message = "Runtime must be python3.14"
  }
}

