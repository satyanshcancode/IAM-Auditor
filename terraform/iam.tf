# IAM Roles for ECS Fargate Scheduled IAM Auditor Task

# 1. ECS Task Execution Role (Pulling container image & pushing CloudWatch logs)
resource "aws_iam_role" "ecs_execution_role" {
  name = "iam-auditor-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_policy" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# 2. IAM Auditor Task Role (Used by container at runtime for read-only audit & S3 export)
resource "aws_iam_role" "task_role" {
  name = "iam-auditor-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# Read-only Security Audit Policy Attachment
resource "aws_iam_role_policy_attachment" "security_audit_attach" {
  role       = aws_iam_role.task_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Custom Policy for S3 Report Export & STS AssumeRole for Multi-Account
resource "aws_iam_policy" "task_custom_policy" {
  name        = "iam-auditor-task-policy"
  description = "Allows IAM Auditor to write reports to S3 and assume cross-account audit roles"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.audit_reports.arn,
          "${aws_s3_bucket.audit_reports.arn}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/IAMAuditorRole"
      },
      {
        Effect   = "Allow"
        Action   = "iam:GenerateServiceLastAccessedDetails"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "task_custom_attach" {
  role       = aws_iam_role.task_role.name
  policy_arn = aws_iam_policy.task_custom_policy.arn
}

# 3. EventBridge IAM Role to trigger ECS task execution
resource "aws_iam_role" "eventbridge_ecs_role" {
  name = "iam-auditor-eventbridge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "eventbridge_ecs_policy" {
  name = "iam-auditor-eventbridge-ecs-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "ecs:RunTask"
        Resource = aws_ecs_task_definition.iam_auditor.arn
      },
      {
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          aws_iam_role.ecs_execution_role.arn,
          aws_iam_role.task_role.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eventbridge_ecs_attach" {
  role       = aws_iam_role.eventbridge_ecs_role.name
  policy_arn = aws_iam_policy.eventbridge_ecs_policy.arn
}
