output "health_check_url" {
  description = "URL for the /health endpoint"
  value       = "${aws_api_gateway_stage.opsagent.invoke_url}/health"
}

output "api_base_url" {
  description = "Base invoke URL for the deployed API stage"
  value       = aws_api_gateway_stage.opsagent.invoke_url
}

output "lambda_function_name" {
  value = aws_lambda_function.opsagent_controller.function_name
}

output "lambda_execution_role_arn" {
  value = aws_iam_role.opsagent_execution.arn
}

output "audit_table_name" {
  value = aws_dynamodb_table.audit.name
}

output "incident_table_name" {
  value = aws_dynamodb_table.incidents.name
}

output "approval_gate_table_name" {
  value = aws_dynamodb_table.approval_gate.name
}

output "notification_topic_arn" {
  value = aws_sns_topic.notifications.arn
}

output "kms_key_id" {
  value = aws_kms_key.opsagent.key_id
}

output "dashboard_url" {
  value = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.opsagent.dashboard_name}"
}

output "plugin_api_key_ssm_param" {
  description = "Retrieve the API key value with: aws apigateway get-api-key --api-key <id> --include-value"
  value       = aws_ssm_parameter.plugin_api_key.name
}
