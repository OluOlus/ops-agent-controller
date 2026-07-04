resource "aws_api_gateway_api_key" "opsagent_plugin" {
  name        = "opsagent-plugin-key-${var.environment}"
  description = "API Key for Amazon Q Business OpsAgent Plugin"
  enabled     = true
}

resource "aws_api_gateway_usage_plan" "opsagent" {
  name        = "opsagent-usage-plan-${var.environment}"
  description = "Usage plan for OpsAgent Plugin API"

  api_stages {
    api_id = aws_api_gateway_rest_api.opsagent.id
    stage  = aws_api_gateway_stage.opsagent.stage_name
  }

  throttle_settings {
    rate_limit  = 100
    burst_limit = 200
  }

  quota_settings {
    limit  = 10000
    period = "DAY"
  }
}

resource "aws_api_gateway_usage_plan_key" "opsagent" {
  key_id        = aws_api_gateway_api_key.opsagent_plugin.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.opsagent.id
}
