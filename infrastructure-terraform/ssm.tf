# Value is a placeholder; rotate it after apply:
#   aws ssm put-parameter --name "${var.api_key_parameter_name}" --value "<real-key>" --type SecureString --overwrite
resource "aws_ssm_parameter" "api_key" {
  name        = var.api_key_parameter_name
  type        = "String"
  value       = "changeme-${data.aws_caller_identity.current.account_id}-${var.environment}"
  description = "API key for OpsAgent Controller authentication"

  lifecycle {
    ignore_changes = [value]
  }
}

# Stores the API Gateway key ID (not the secret). Retrieve the actual value with:
#   aws apigateway get-api-key --api-key <id> --include-value
resource "aws_ssm_parameter" "plugin_api_key" {
  name        = "/opsagent/plugin-api-key-${var.environment}"
  type        = "String"
  value       = aws_api_gateway_api_key.opsagent_plugin.id
  description = "API Key ID for Amazon Q Business OpsAgent Plugin (use apigateway get-api-key --include-value to retrieve the secret)"
}
