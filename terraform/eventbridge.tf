# EventBridge Rule & Target for Scheduled ECS Execution
resource "aws_cloudwatch_event_rule" "scheduled_audit" {
  name                = "iam-auditor-daily-schedule"
  description         = "Triggers IAM Auditor CLI container daily via ECS Fargate"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "ecs_scheduled_target" {
  rule      = aws_cloudwatch_event_rule.scheduled_audit.name
  target_id = "IAMAuditorFargateTask"
  arn       = aws_ecs_cluster.audit_cluster.arn
  role_arn  = aws_iam_role.eventbridge_ecs_role.arn

  ecs_target {
    task_count          = 1
    task_definition_arn = aws_ecs_task_definition.iam_auditor.arn
    launch_type         = "FARGATE"

    network_configuration {
      subnets          = var.subnet_ids
      security_groups  = var.security_group_ids
      assign_public_ip = true
    }
  }
}
