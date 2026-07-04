# REST API (v1), matching what SAM's AWS::Serverless::Api generated, so that
# Stage 2 can add a Usage Plan + API Key (api_key_required is a v1-only
# feature; HTTP API/v2 has no equivalent).

locals {
  routes = {
    health                = { path_part = "health", parent = "root", method = "GET", api_key_required = false }
    operations_diagnostic = { path_part = "diagnostic", parent = "operations", method = "POST", api_key_required = true }
    operations_propose    = { path_part = "propose", parent = "operations", method = "POST", api_key_required = true }
    operations_approve    = { path_part = "approve", parent = "operations", method = "POST", api_key_required = true }
    operations_workflow   = { path_part = "workflow", parent = "operations", method = "POST", api_key_required = true }
    chat                  = { path_part = "chat", parent = "root", method = "POST", api_key_required = true }
  }
}

resource "aws_api_gateway_rest_api" "opsagent" {
  name        = "opsagent-controller-${var.environment}"
  description = "OpsAgent Controller API"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_resource" "operations" {
  rest_api_id = aws_api_gateway_rest_api.opsagent.id
  parent_id   = aws_api_gateway_rest_api.opsagent.root_resource_id
  path_part   = "operations"
}

resource "aws_api_gateway_resource" "route" {
  for_each = local.routes

  rest_api_id = aws_api_gateway_rest_api.opsagent.id
  parent_id   = each.value.parent == "operations" ? aws_api_gateway_resource.operations.id : aws_api_gateway_rest_api.opsagent.root_resource_id
  path_part   = each.value.path_part
}

resource "aws_api_gateway_method" "route" {
  for_each = local.routes

  rest_api_id      = aws_api_gateway_rest_api.opsagent.id
  resource_id      = aws_api_gateway_resource.route[each.key].id
  http_method      = each.value.method
  authorization    = "NONE"
  api_key_required = each.value.api_key_required
}

resource "aws_api_gateway_integration" "route" {
  for_each = local.routes

  rest_api_id             = aws_api_gateway_rest_api.opsagent.id
  resource_id             = aws_api_gateway_resource.route[each.key].id
  http_method             = aws_api_gateway_method.route[each.key].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.opsagent_controller.invoke_arn
}

resource "aws_lambda_permission" "apigw_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.opsagent_controller.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.opsagent.execution_arn}/*/*"
}

resource "aws_api_gateway_deployment" "opsagent" {
  rest_api_id = aws_api_gateway_rest_api.opsagent.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.operations.id,
      { for k, v in aws_api_gateway_resource.route : k => v.id },
      { for k, v in aws_api_gateway_method.route : k => v.id },
      { for k, v in aws_api_gateway_integration.route : k => v.id },
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_api_gateway_integration.route]
}

resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/opsagent-${var.environment}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.opsagent.arn
}

resource "aws_api_gateway_stage" "opsagent" {
  deployment_id        = aws_api_gateway_deployment.opsagent.id
  rest_api_id          = aws_api_gateway_rest_api.opsagent.id
  stage_name           = var.environment
  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      caller         = "$context.identity.caller"
      user           = "$context.identity.user"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }
}

resource "aws_api_gateway_method_settings" "opsagent" {
  rest_api_id = aws_api_gateway_rest_api.opsagent.id
  stage_name  = aws_api_gateway_stage.opsagent.stage_name
  method_path = "*/*"

  settings {
    logging_level          = "INFO"
    data_trace_enabled     = true
    metrics_enabled        = true
    throttling_rate_limit  = 100
    throttling_burst_limit = 200
  }
}
