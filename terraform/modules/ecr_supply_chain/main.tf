# =============================================================
# Layer 1 â€” Supply Chain Security
# ECR repository with mandatory image scanning
# Lambda triggers on every push to verify SBOM + CVE
# =============================================================

# ECR repository â€” scan on push enforced by Terraform
resource "aws_ecr_repository" "app" {
  name                 = "${var.project_name}-app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true  # Drift: if manually disabled, detected immediately
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep only last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

# Lambda â€” triggered by ECR scan completion
data "archive_file" "scanner" {
  type        = "zip"
  source_file = "${path.root}/../lambdas/supply_chain_scanner/handler.py"
  output_path = "${path.module}/scanner.zip"
}

resource "aws_lambda_function" "scanner" {
  filename         = data.archive_file.scanner.output_path
  source_code_hash = data.archive_file.scanner.output_base64sha256
  function_name    = "${var.project_name}-supply-chain-scanner"
  role             = var.lambda_role_arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 120

  environment {
    variables = {
      FINDINGS_TABLE   = var.findings_table
      ALERTS_TOPIC_ARN = var.alerts_topic
      ENVIRONMENT      = var.environment
      SEVERITY_BLOCK   = "CRITICAL,HIGH"
    }
  }
}

# EventBridge rule â€” fires when ECR scan completes
resource "aws_cloudwatch_event_rule" "ecr_scan" {
  name        = "${var.project_name}-ecr-scan-complete"
  description = "Triggers supply chain scanner after ECR image scan"

  event_pattern = jsonencode({
    source        = ["aws.ecr"]
    "detail-type" = ["ECR Image Scan"]
    detail = {
      "scan-status"    = ["COMPLETE"]
      "repository-name" = [aws_ecr_repository.app.name]
    }
  })
}

resource "aws_cloudwatch_event_target" "ecr_scan" {
  rule      = aws_cloudwatch_event_rule.ecr_scan.name
  target_id = "SupplyChainScanner"
  arn       = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "ecr_scan" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ecr_scan.arn
}

# IAM â€” extra permission: ECR describe findings
resource "aws_iam_role_policy" "scanner_ecr" {
  name = "${var.project_name}-scanner-ecr"
  role = split("/", var.lambda_role_arn)[1]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [
        "ecr:DescribeImageScanFindings",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ]
      Resource = aws_ecr_repository.app.arn
    }]
  })
}

