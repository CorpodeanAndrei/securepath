# =============================================================
# Layer 3 â€” Infrastructure Drift Detection
# AWS Config records all resource changes
# Lambda compares against Terraform desired state
# Auto-remediates minor drift; opens PR for major
# =============================================================

# S3 bucket for Config delivery
resource "aws_s3_bucket" "config" {
  bucket        = "${var.project_name}-config-${var.environment}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM role for Config service
resource "aws_iam_role" "config" {
  name = "${var.project_name}-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = ["s3:PutObject", "s3:GetBucketAcl"]
      Resource  = [
        aws_s3_bucket.config.arn,
        "${aws_s3_bucket.config.arn}/*"
      ]
    }]
  })
}

# AWS Config recorder
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.project_name}-delivery"
  s3_bucket_name = aws_s3_bucket.config.bucket
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# Config rules â€” security baseline checks
resource "aws_config_config_rule" "s3_public_access" {
  name = "${var.project_name}-s3-no-public-access"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "ec2_encrypted_volumes" {
  name = "${var.project_name}-ec2-encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "iam_no_root_access_key" {
  name = "${var.project_name}-no-root-access-key"
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "rds_encrypted" {
  name = "${var.project_name}-rds-encrypted"
  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# Lambda drift detector â€” runs on schedule + Config change events
data "archive_file" "drift" {
  type        = "zip"
  source_file = "${path.root}/../lambdas/drift_detector/handler.py"
  output_path = "${path.module}/drift.zip"
}

resource "aws_lambda_function" "drift_detector" {
  filename         = data.archive_file.drift.output_path
  source_code_hash = data.archive_file.drift.output_base64sha256
  function_name    = "${var.project_name}-drift-detector"
  role             = var.lambda_role_arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 300

  environment {
    variables = {
      FINDINGS_TABLE   = var.findings_table
      ALERTS_TOPIC_ARN = var.alerts_topic
      ENVIRONMENT      = var.environment
      CONFIG_BUCKET    = aws_s3_bucket.config.bucket
    }
  }
}

# Periodic drift check
resource "aws_cloudwatch_event_rule" "drift_schedule" {
  name                = "${var.project_name}-drift-schedule"
  description         = "Periodic infrastructure drift detection"
  schedule_expression = "rate(${var.check_interval_minutes} minutes)"
}

resource "aws_cloudwatch_event_target" "drift_schedule" {
  rule      = aws_cloudwatch_event_rule.drift_schedule.name
  target_id = "DriftDetector"
  arn       = aws_lambda_function.drift_detector.arn
}

resource "aws_lambda_permission" "drift_schedule" {
  statement_id  = "AllowSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.drift_schedule.arn
}

# Config change event trigger
resource "aws_cloudwatch_event_rule" "config_change" {
  name        = "${var.project_name}-config-change"
  description = "Triggers drift detector on Config compliance change"

  event_pattern = jsonencode({
    source        = ["aws.config"]
    "detail-type" = ["Config Rules Compliance Change"]
    detail        = { complianceType = ["NON_COMPLIANT"] }
  })
}

resource "aws_cloudwatch_event_target" "config_change" {
  rule      = aws_cloudwatch_event_rule.config_change.name
  target_id = "DriftDetectorConfig"
  arn       = aws_lambda_function.drift_detector.arn
}

resource "aws_lambda_permission" "config_change" {
  statement_id  = "AllowConfigEvent"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_change.arn
}

# Extra IAM permissions for drift detector
resource "aws_iam_role_policy" "drift_perms" {
  name = "${var.project_name}-drift-perms"
  role = split("/", var.lambda_role_arn)[1]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ConfigRead"
        Effect = "Allow"
        Action = [
          "config:GetComplianceDetailsByConfigRule",
          "config:ListDiscoveredResources",
          "config:GetResourceConfigHistory",
          "config:DescribeConfigRules"
        ]
        Resource = "*"
      },
      {
        Sid      = "S3Config"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.config.arn, "${aws_s3_bucket.config.arn}/*"]
      }
    ]
  })
}

