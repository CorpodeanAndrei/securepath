variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment name (dev/staging/prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name used as resource prefix"
  type        = string
  default     = "securepath"
}

variable "account_id" {
  description = "AWS Account ID — run: aws sts get-caller-identity"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository in owner/repo format"
  type        = string
}

variable "findings_retention_days" {
  description = "Days to retain security findings in DynamoDB"
  type        = number
  default     = 90
}

variable "chaos_schedule" {
  description = "Cron expression for chaos experiments (UTC)"
  type        = string
  default     = "cron(0 2 ? * SAT *)"
}

variable "drift_check_interval_minutes" {
  description = "How often to check for infrastructure drift"
  type        = number
  default     = 30
}

variable "csps_block_threshold" {
  description = "Cloud Security Posture Score below which deploy is blocked (0-100)"
  type        = number
  default     = 70
}
