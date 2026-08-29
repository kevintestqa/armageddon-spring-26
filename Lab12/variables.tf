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
    condition     = var.lambda_architecture == "x86_64"
    error_message = "Architecture must be x86_64"
  }
}

variable "lambda_python_runtime" {
  type    = string
  default = "python3.14"

  validation {
    condition     = var.lambda_python_runtime == "python3.14"
    error_message = "Runtime must be python3.14"
  }
}

//validations define the rule
variable "lambda_memory_size" {
  type    = number
  default = 512

  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Memory size must be between 128 MB and 10,240 MB"
  }
}

variable "executive_report_bucket_name" {
  type    = string
  default = "asgard-executive-report"

  validation {
    condition     = var.executive_report_bucket_name == "asgard-executive-report"
    error_message = "Executive report bucket name must be 'asgard-executive-report'"
  }
}

variable "compliance_report_bucket_name" {
  type    = string
  default = "asgard-compliance-report"

  validation {
    condition     = var.compliance_report_bucket_name == "asgard-compliance-report"
    error_message = "Compliance report bucket name must be 'asgard-compliance-report'"
  }
}

variable "threat_evidence_bucket_prefix" {
  description = "Globally unique bucket-name prefix for immutable threat evidence."
  type        = string
  default     = "asgard-threat-evidence-"

  validation {
    condition = (
      startswith(var.threat_evidence_bucket_prefix, "asgard-") &&
      endswith(var.threat_evidence_bucket_prefix, "-")
    )
    error_message = "Threat evidence bucket prefix must start with 'asgard-' and end with '-'."
  }
}

variable "threat_evidence_retention_days" {
  description = "Default S3 Object Lock governance retention period."
  type        = number
  default     = 365

  validation {
    condition = (
      var.threat_evidence_retention_days >= 1 &&
      var.threat_evidence_retention_days <= 3650
    )
    error_message = "Threat evidence retention must be between 1 and 3650 days."
  }
}

variable "enable_bedrock" {
  type    = bool
  default = true
}

variable "bedrock_model_id" {
  type    = string
  default = "us.anthropic.claude-sonnet-4-6"

  validation {
    condition     = var.bedrock_model_id == "us.anthropic.claude-sonnet-4-6"
    error_message = "Bedrock model ID must be 'us.anthropic.claude-sonnet-4-6'"
  }
}

variable "environment" {
  type    = string
  default = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod"
  }
}

variable "cost_center" {
  type    = string
  default = "asgard-cc"

  validation {
    condition     = var.cost_center == "asgard-cc"
    error_message = "Cost center must be 'asgard-cc'"
  }
}

variable "budget_limit" {
  type    = number
  default = 1000

  validation {
    condition     = var.budget_limit > 0
    error_message = "Budget limit must be a positive number"
  }
}

variable "budget_start_date" {
  type    = string
  default = "2026-01-01"

  validation {
    condition     = can(regex("^\\d{4}-\\d{2}-\\d{2}$", var.budget_start_date))
    error_message = "Budget start date must be in the format YYYY-MM-DD"
  }
}

variable "anomaly_threshold_absolute" {
  type    = number
  default = 100

  validation {
    condition     = var.anomaly_threshold_absolute > 0
    error_message = "Anomaly threshold (absolute) must be a positive number"
  }
}
