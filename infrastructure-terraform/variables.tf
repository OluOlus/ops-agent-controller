variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-west-2"
}

variable "environment" {
  description = "Deployment environment name (sandbox, staging, production)"
  type        = string
  default     = "sandbox"
}

variable "execution_mode" {
  description = "OpsAgent execution mode: DRY_RUN (no real remediation actions) or SANDBOX_LIVE"
  type        = string
  default     = "DRY_RUN"
}

variable "lambda_architecture" {
  description = "Lambda instruction set architecture; must match build.sh's --platform target"
  type        = string
  default     = "arm64"
}

variable "lambda_runtime" {
  description = "Lambda Python runtime; must match build.sh's --python-version target"
  type        = string
  default     = "python3.13"
}

variable "llm_provider" {
  description = "LLM provider to use"
  type        = string
  default     = "bedrock"
}

variable "bedrock_model_id" {
  description = "Bedrock model ID for LLM provider"
  type        = string
  default     = "anthropic.claude-3-7-sonnet-20250219-v1:0"
}

variable "api_key_parameter_name" {
  description = "SSM Parameter name for the OpsAgent API key"
  type        = string
  default     = "/opsagent/api-key"
}

variable "cors_allowed_origin" {
  description = "Allowed CORS origin for browser clients. Use 'null' to restrict all cross-origin requests."
  type        = string
  default     = "null"
}
