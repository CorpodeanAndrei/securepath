output "repository_url" {
  value = aws_ecr_repository.app.repository_url
}
output "scanner_function_arn" {
  value = aws_lambda_function.scanner.arn
}
