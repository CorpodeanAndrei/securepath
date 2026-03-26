output "analyzer_arn" {
  value = aws_accessanalyzer_analyzer.main.arn
}
output "graph_function_arn" {
  value = aws_lambda_function.iam_graph.arn
}
