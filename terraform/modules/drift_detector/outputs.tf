output "detector_function_arn" {
  value = aws_lambda_function.drift_detector.arn
}
output "config_recorder_id" {
  value = aws_config_configuration_recorder.main.id
}
