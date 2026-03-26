# =============================================================
# Layer 5 — Chaos Engineering & Resilience Validation
# FIS nu e disponibil pe Free Tier — folosim simulator Lambda nativ
# Injectează erori prin SDK direct pe resurse taguite ChaosTarget=true
# =============================================================

locals {
  fis_template_arn = "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:${var.project_name}-chaos-prober"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

data "archive_file" "chaos" {
  type        = "zip"
  source_file = "${path.root}/../lambdas/chaos_prober/handler.py"
  output_path = "${path.module}/chaos.zip"
}

resource "aws_lambda_function" "chaos_prober" {
  filename         = data.archive_file.chaos.output_path
  source_code_hash = data.archive_file.chaos.output_base64sha256
  function_name    = "${var.project_name}-chaos-prober"
  role             = var.lambda_role_arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 600

  environment {
    variables = {
      FINDINGS_TABLE       = var.findings_table
      ALERTS_TOPIC_ARN     = var.alerts_topic
      ENVIRONMENT          = var.environment
      FIS_TEMPLATE_ARN     = ""
      TARGET_SLA_RTO_SECS  = "300"
      TARGET_SLA_MTTR_SECS = "600"
    }
  }
}

resource "aws_cloudwatch_event_rule" "chaos_schedule" {
  name                = "${var.project_name}-chaos-schedule"
  description         = "Weekly chaos experiment"
  schedule_expression = var.chaos_schedule
}

resource "aws_cloudwatch_event_target" "chaos_schedule" {
  rule      = aws_cloudwatch_event_rule.chaos_schedule.name
  target_id = "ChaosProber"
  arn       = aws_lambda_function.chaos_prober.arn
}

resource "aws_lambda_permission" "chaos_schedule" {
  statement_id  = "AllowChaosSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.chaos_prober.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.chaos_schedule.arn
}

resource "aws_iam_role_policy" "chaos_perms" {
  name = "${var.project_name}-chaos-perms"
  role = split("/", var.lambda_role_arn)[1]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Chaos"
        Effect = "Allow"
        Action = [
          "ec2:StopInstances",
          "ec2:StartInstances",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/ChaosTarget" = "true"
          }
        }
      },
      {
        Sid    = "CloudWatch"
        Effect = "Allow"
        Action = ["cloudwatch:GetMetricStatistics", "cloudwatch:PutMetricData"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_cloudwatch_metric_alarm" "rto_breach" {
  alarm_name          = "${var.project_name}-rto-sla-breach"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ExperimentRTO"
  namespace           = "SecurePath"
  period              = 600
  statistic           = "Maximum"
  threshold           = 300
  alarm_description   = "RTO exceeded 5-minute SLA during chaos experiment"
  alarm_actions       = [var.alerts_topic]
  treat_missing_data  = "notBreaching"
}
