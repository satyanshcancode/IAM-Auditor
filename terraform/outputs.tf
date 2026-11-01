output "s3_bucket_name" {
  value       = aws_s3_bucket.audit_reports.id
  description = "Encrypted S3 bucket name for audit reports"
}

output "ecs_cluster_arn" {
  value       = aws_ecs_cluster.audit_cluster.arn
  description = "ECS cluster ARN"
}

output "ecs_task_definition_arn" {
  value       = aws_ecs_task_definition.iam_auditor.arn
  description = "ECS task definition ARN"
}

output "iam_task_role_arn" {
  value       = aws_iam_role.task_role.arn
  description = "IAM Task Role ARN for runtime execution"
}

output "eventbridge_rule_arn" {
  value       = aws_cloudwatch_event_rule.scheduled_audit.arn
  description = "EventBridge cron schedule rule ARN"
}
