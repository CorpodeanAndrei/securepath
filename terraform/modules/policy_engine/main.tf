# =============================================================
# Layer 4 â€” Policy Engine
# Auto-remediates: public S3, open SGs, missing tags,
# unencrypted resources, IAM without MFA
# =============================================================

data "archive_file" "enforcer" {
  type        = "zip"
  source_file = "${path.root}/../lambdas/policy_enforcer/handler.py"
  output_path = "${path.module}/enforcer.zip"
}

resource "aws_lambda_function" "policy_enforcer" {
  filename         = data.archive_file.enforcer.output_path
  source_code_hash = data.archive_file.enforcer.output_base64sha256
  function_name    = "${var.project_name}-policy-enforcer"
  role             = var.lambda_role_arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 120

  environment {
    variables = {
      FINDINGS_TABLE      = var.findings_table
      ALERTS_TOPIC_ARN    = var.alerts_topic
      ENVIRONMENT         = var.environment
      REQUIRED_TAGS       = "Owner,Environment,Project"
      ALLOWED_REGIONS     = "eu-west-1,eu-west-1"
    }
  }
}

# Trigger on S3 bucket becoming public
resource "aws_cloudwatch_event_rule" "s3_public" {
  name        = "${var.project_name}-s3-public-detected"
  description = "Triggers remediation when S3 bucket becomes public"

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutBucketAcl", "PutBucketPolicy", "DeletePublicAccessBlock"]
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_public" {
  rule      = aws_cloudwatch_event_rule.s3_public.name
  target_id = "PolicyEnforcer"
  arn       = aws_lambda_function.policy_enforcer.arn
}

resource "aws_lambda_permission" "s3_public" {
  statement_id  = "AllowS3Event"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.policy_enforcer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public.arn
}

# Trigger on security group becoming too permissive
resource "aws_cloudwatch_event_rule" "sg_open" {
  name        = "${var.project_name}-sg-open-detected"
  description = "Triggers remediation when security group opens 0.0.0.0/0"

  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sg_open" {
  rule      = aws_cloudwatch_event_rule.sg_open.name
  target_id = "PolicyEnforcerSG"
  arn       = aws_lambda_function.policy_enforcer.arn
}

resource "aws_lambda_permission" "sg_open" {
  statement_id  = "AllowSGEvent"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.policy_enforcer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_open.arn
}

# IAM permissions for remediation
resource "aws_iam_role_policy" "enforcer_perms" {
  name = "${var.project_name}-enforcer-perms"
  role = split("/", var.lambda_role_arn)[1]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Remediate"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketPolicy",
          "s3:GetBucketPolicy",
          "s3:GetBucketPublicAccessBlock",
          "s3:ListAllMyBuckets"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2Remediate"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      },
      {
        Sid    = "TagsRead"
        Effect = "Allow"
        Action = ["tag:GetResources", "resourcegroupstaggingapi:GetResources"]
        Resource = "*"
      }
    ]
  })
}

