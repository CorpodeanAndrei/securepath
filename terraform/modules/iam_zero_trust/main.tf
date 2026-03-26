# =============================================================
# Layer 2 â€” Zero-Trust IAM Monitoring
# IAM Access Analyzer + CloudTrail event processing
# Graph-based blast radius calculation
# =============================================================

# IAM Access Analyzer â€” detects public/cross-account access
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.project_name}-analyzer"
  type          = "ACCOUNT"

  tags = {
    Name = "${var.project_name}-iam-analyzer"
  }
}

# Lambda â€” processes IAM change events + builds graph
data "archive_file" "iam_graph" {
  type        = "zip"
  source_file = "${path.root}/../lambdas/iam_graph_analyzer/handler.py"
  output_path = "${path.module}/iam_graph.zip"
}

resource "aws_lambda_function" "iam_graph" {
  filename         = data.archive_file.iam_graph.output_path
  source_code_hash = data.archive_file.iam_graph.output_base64sha256
  function_name    = "${var.project_name}-iam-graph-analyzer"
  role             = var.lambda_role_arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60

  environment {
    variables = {
      FINDINGS_TABLE   = var.findings_table
      ALERTS_TOPIC_ARN = var.alerts_topic
      ENVIRONMENT      = var.environment
      ACCOUNT_ID       = var.account_id
    }
  }
}

# EventBridge â€” IAM mutation events from CloudTrail
resource "aws_cloudwatch_event_rule" "iam_changes" {
  name        = "${var.project_name}-iam-changes"
  description = "Captures IAM role, policy, and user mutations"

  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = [
        "AttachRolePolicy", "DetachRolePolicy",
        "PutRolePolicy", "DeleteRolePolicy",
        "CreateRole", "DeleteRole",
        "CreateUser", "DeleteUser",
        "AttachUserPolicy", "CreatePolicyVersion",
        "AddUserToGroup", "CreateAccessKey"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "iam_changes" {
  rule      = aws_cloudwatch_event_rule.iam_changes.name
  target_id = "IamGraphAnalyzer"
  arn       = aws_lambda_function.iam_graph.arn
}

resource "aws_lambda_permission" "iam_changes" {
  statement_id  = "AllowEventBridgeIam"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_graph.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_changes.arn
}

# IAM â€” extra permissions for graph analysis
resource "aws_iam_role_policy" "iam_graph_perms" {
  name = "${var.project_name}-iam-graph-perms"
  role = split("/", var.lambda_role_arn)[1]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMRead"
        Effect = "Allow"
        Action = [
          "iam:ListRoles", "iam:ListUsers", "iam:ListGroups",
          "iam:ListPolicies", "iam:GetPolicy", "iam:GetPolicyVersion",
          "iam:ListAttachedRolePolicies", "iam:ListRolePolicies",
          "iam:GetRolePolicy", "iam:SimulatePrincipalPolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "AccessAnalyzer"
        Effect = "Allow"
        Action = [
          "access-analyzer:ListFindings",
          "access-analyzer:GetFinding"
        ]
        Resource = aws_accessanalyzer_analyzer.main.arn
      }
    ]
  })
}

# CloudWatch alarm â€” spike in IAM mutations
resource "aws_cloudwatch_metric_alarm" "iam_mutation_spike" {
  alarm_name          = "${var.project_name}-iam-mutation-spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "IamMutationCount"
  namespace           = "SecurePath"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "More than 10 IAM mutations in 5 minutes"
  alarm_actions       = [var.alerts_topic]
  treat_missing_data  = "notBreaching"
}

