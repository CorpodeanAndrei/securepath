# =============================================================
# SecurePath — Root Module
# Orchestrates all 5 security layers
# =============================================================

# ------ Shared Infrastructure --------------------------------

resource "aws_dynamodb_table" "findings" {
  name           = "${var.project_name}-findings"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "finding_id"
  range_key      = "detected_at"

  attribute {
    name = "finding_id"
    type = "S"
  }
  attribute {
    name = "detected_at"
    type = "S"
  }
  attribute {
    name = "layer"
    type = "S"
  }
  attribute {
    name = "severity"
    type = "S"
  }

  global_secondary_index {
    name            = "layer-severity-index"
    hash_key        = "layer"
    range_key       = "severity"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-findings"
  }
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.project_name}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_cloudwatch_log_group" "securepath" {
  name              = "/securepath/findings"
  retention_in_days = var.findings_retention_days
}

# IAM Role shared by all Lambda functions
resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-lambda-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_base" {
  name = "base-permissions"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Logs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "DynamoDB"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Sid      = "SNS"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

# ------ Module: Layer 1 — Supply Chain -----------------------

module "ecr_supply_chain" {
  source = "./modules/ecr_supply_chain"

  project_name    = var.project_name
  environment     = var.environment
  lambda_role_arn = aws_iam_role.lambda_exec.arn
  findings_table  = aws_dynamodb_table.findings.name
  alerts_topic    = aws_sns_topic.alerts.arn
}

# ------ Module: Layer 2 — Zero-Trust IAM ---------------------

module "iam_zero_trust" {
  source = "./modules/iam_zero_trust"

  project_name    = var.project_name
  environment     = var.environment
  account_id      = var.account_id
  lambda_role_arn = aws_iam_role.lambda_exec.arn
  findings_table  = aws_dynamodb_table.findings.name
  alerts_topic    = aws_sns_topic.alerts.arn
}

# ------ Module: Layer 3 — Drift Detector ---------------------

module "drift_detector" {
  source = "./modules/drift_detector"

  project_name           = var.project_name
  environment            = var.environment
  lambda_role_arn        = aws_iam_role.lambda_exec.arn
  findings_table         = aws_dynamodb_table.findings.name
  alerts_topic           = aws_sns_topic.alerts.arn
  check_interval_minutes = var.drift_check_interval_minutes
}

# ------ Module: Layer 4 — Policy Engine ----------------------

module "policy_engine" {
  source = "./modules/policy_engine"

  project_name    = var.project_name
  environment     = var.environment
  account_id      = var.account_id
  lambda_role_arn = aws_iam_role.lambda_exec.arn
  findings_table  = aws_dynamodb_table.findings.name
  alerts_topic    = aws_sns_topic.alerts.arn
}

# ------ Module: Layer 5 — Chaos Prober -----------------------

module "chaos_prober" {
  source = "./modules/chaos_prober"

  project_name    = var.project_name
  environment     = var.environment
  lambda_role_arn = aws_iam_role.lambda_exec.arn
  findings_table  = aws_dynamodb_table.findings.name
  alerts_topic    = aws_sns_topic.alerts.arn
  chaos_schedule  = var.chaos_schedule
}

# ------ CloudWatch Dashboard ---------------------------------

resource "aws_cloudwatch_dashboard" "securepath" {
  dashboard_name = "${var.project_name}-posture"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Findings by Severity"
          region  = var.aws_region
          period  = 3600
          stat    = "Sum"
          view    = "timeSeries"
          metrics = [
            ["SecurePath", "FindingsCritical", "Project", var.project_name],
            ["SecurePath", "FindingsHigh",     "Project", var.project_name],
            ["SecurePath", "FindingsMedium",   "Project", var.project_name],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Drift Events"
          region  = var.aws_region
          period  = 3600
          stat    = "Sum"
          view    = "timeSeries"
          metrics = [
            ["SecurePath", "DriftDetected",   "Project", var.project_name],
            ["SecurePath", "DriftRemediated", "Project", var.project_name],
          ]
        }
      },
    ]
  })
}
