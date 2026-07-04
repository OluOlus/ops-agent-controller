# Run ./build.sh before `terraform apply` (and again after any src/ or
# requirements.txt change) — it produces lambda.zip, which this file reads
# directly. Terraform doesn't build the package itself because it needs
# pip's cross-platform resolution (--platform/--python-version) to fetch
# manylinux wheels matching the Lambda runtime, which isn't something a
# local arm64/py3.9 interpreter can produce natively.

locals {
  lambda_zip_path = "${path.module}/lambda.zip"
}

resource "aws_lambda_function" "opsagent_controller" {
  function_name = "opsagent-controller-${var.environment}"
  description   = "OpsAgent Controller - Main Lambda function"

  filename         = local.lambda_zip_path
  source_code_hash = filebase64sha256(local.lambda_zip_path)

  handler = "src.main.lambda_handler"
  runtime = var.lambda_runtime

  architectures = [var.lambda_architecture]

  role        = aws_iam_role.opsagent_execution.arn
  timeout     = 60
  memory_size = 1024

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  environment {
    variables = {
      ENVIRONMENT              = var.environment
      EXECUTION_MODE           = var.execution_mode
      LLM_PROVIDER             = var.llm_provider
      BEDROCK_MODEL_ID         = var.bedrock_model_id
      AUDIT_LOG_GROUP          = aws_cloudwatch_log_group.audit.name
      CLOUDWATCH_LOG_GROUP     = aws_cloudwatch_log_group.audit.name
      AUDIT_TABLE_NAME         = aws_dynamodb_table.audit.name
      INCIDENT_TABLE_NAME      = aws_dynamodb_table.incidents.name
      APPROVAL_GATE_TABLE_NAME = aws_dynamodb_table.approval_gate.name
      NOTIFICATION_TOPIC_ARN   = aws_sns_topic.notifications.arn
      KMS_KEY_ID               = aws_kms_key.opsagent.key_id
      API_KEY_PARAMETER        = var.api_key_parameter_name
      PLUGIN_API_KEY_PARAMETER = aws_ssm_parameter.plugin_api_key.name
      AWS_ACCOUNT_ID           = data.aws_caller_identity.current.account_id
      CORS_ALLOWED_ORIGIN      = var.cors_allowed_origin
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.opsagent_basic_execution,
    aws_iam_role_policy.audit_logging,
    aws_iam_role_policy.diagnosis_tools,
    aws_iam_role_policy.remediation_tools,
    aws_iam_role_policy.llm_provider,
    aws_iam_role_policy.system,
  ]
}

resource "aws_cloudwatch_log_group" "opsagent_lambda" {
  name              = "/aws/lambda/${aws_lambda_function.opsagent_controller.function_name}"
  retention_in_days = 14
}
