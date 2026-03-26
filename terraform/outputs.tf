output "findings_table_name" {
  description = "DynamoDB table storing all SecurePath findings"
  value       = aws_dynamodb_table.findings.name
}

output "findings_table_arn" {
  description = "ARN of the findings DynamoDB table"
  value       = aws_dynamodb_table.findings.arn
}

output "alerts_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.alerts.arn
}

output "ecr_repository_url" {
  description = "ECR repository URL for container images"
  value       = module.ecr_supply_chain.repository_url
}

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home#dashboards:name=${aws_cloudwatch_dashboard.securepath.dashboard_name}"
}
