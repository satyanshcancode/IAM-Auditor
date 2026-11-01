variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS Region for deployment"
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment environment name"
}

variable "schedule_expression" {
  type        = string
  default     = "cron(0 6 * * ? *)" # Daily at 06:00 UTC
  description = "EventBridge cron or rate expression for scheduled audit execution"
}

variable "container_image" {
  type        = string
  default     = "public.ecr.aws/iam-auditor/iam-audit:latest"
  description = "Container image URI for IAM Auditor CLI"
}

variable "cpu" {
  type        = string
  default     = "256"
  description = "Fargate CPU units (256 = 0.25 vCPU)"
}

variable "memory" {
  type        = string
  default     = "512"
  description = "Fargate Memory (512 = 512 MB)"
}

variable "subnet_ids" {
  type        = list(string)
  default     = []
  description = "List of VPC subnet IDs for ECS task execution"
}

variable "security_group_ids" {
  type        = list(string)
  default     = []
  description = "List of VPC security group IDs for ECS task execution"
}
