# ECS Cluster and Task Definition for Scheduled Audit Run
resource "aws_ecs_cluster" "audit_cluster" {
  name = "iam-auditor-cluster"
}

resource "aws_cloudwatch_log_group" "audit_logs" {
  name              = "/ecs/iam-auditor"
  retention_in_days = 30
}

resource "aws_ecs_task_definition" "iam_auditor" {
  family                   = "iam-auditor-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.task_role.arn

  container_definitions = jsonencode([
    {
      name      = "iam-auditor"
      image     = var.container_image
      essential = true
      command   = ["audit", "--format", "json", "--output", "/tmp/audit_report.json"]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.audit_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "iam-auditor"
        }
      }
    }
  ])
}
