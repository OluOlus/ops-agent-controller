# =============================================================================
# OpsAgent Controller - Terraform Variables
# =============================================================================
# Copy terraform.tfvars.example to terraform.tfvars and fill in your values.
# All variables have sensible defaults for a sandbox deployment.
# =============================================================================

# -----------------------------------------------------------------------------
# Core deployment settings
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region to deploy into. Must have Bedrock model access enabled."
  type        = string
  default     = "eu-west-2"
}

variable "environment" {
  description = "Deployment environment name. Used in resource naming (e.g. opsagent-controller-prod)."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["sandbox", "staging", "prod", "production"], var.environment)
    error_message = "Environment must be one of: sandbox, staging, prod, production."
  }
}

variable "execution_mode" {
  description = <<-EOT
    Controls whether the agent performs real AWS operations:
    - SANDBOX_LIVE: Real AWS API calls (use for production and live testing)
    - DRY_RUN: Validates inputs but does not mutate resources (CI/CD testing)
  EOT
  type        = string
  default     = "SANDBOX_LIVE"

  validation {
    condition     = contains(["SANDBOX_LIVE", "DRY_RUN", "LOCAL_MOCK"], var.execution_mode)
    error_message = "Execution mode must be one of: SANDBOX_LIVE, DRY_RUN, LOCAL_MOCK."
  }
}

# -----------------------------------------------------------------------------
# Lambda configuration
# -----------------------------------------------------------------------------

variable "lambda_runtime" {
  description = "Lambda Python runtime version. Must match build.sh target."
  type        = string
  default     = "python3.13"
}

variable "lambda_architecture" {
  description = "Lambda CPU architecture. Must match build.sh --platform target (arm64 = Graviton, cheaper)."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.lambda_architecture)
    error_message = "Architecture must be arm64 or x86_64."
  }
}

variable "lambda_memory_size" {
  description = "Lambda memory in MB. More memory = faster cold starts and LLM calls."
  type        = number
  default     = 1024
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds. Bedrock calls can take 10-30s."
  type        = number
  default     = 60
}

# -----------------------------------------------------------------------------
# LLM / Bedrock configuration
# -----------------------------------------------------------------------------

variable "llm_provider" {
  description = "LLM provider backend."
  type        = string
  default     = "bedrock"

  validation {
    condition     = contains(["bedrock", "openai", "azure_openai"], var.llm_provider)
    error_message = "LLM provider must be one of: bedrock, openai, azure_openai."
  }
}

variable "bedrock_model_id" {
  description = <<-EOT
    Bedrock foundation model ID. Recommended options:
    - amazon.nova-pro-v1:0 (works immediately, no marketplace subscription needed)
    - anthropic.claude-3-7-sonnet-20250219-v1:0 (better quality, requires Anthropic use case form)
  EOT
  type        = string
  default     = "amazon.nova-pro-v1:0"
}

# -----------------------------------------------------------------------------
# Security & authentication
# -----------------------------------------------------------------------------

variable "api_key_parameter_name" {
  description = "SSM Parameter Store path for the API key used by the Lambda to validate requests."
  type        = string
  default     = "/opsagent/api-key"
}

variable "cors_allowed_origin" {
  description = "CORS Access-Control-Allow-Origin value. Use 'null' (restrictive) or a specific origin like 'https://app.company.com'."
  type        = string
  default     = "null"
}

variable "user_allow_list" {
  description = "List of email addresses or domain wildcards allowed to use the bot. Set via SSM after deploy."
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Teams / Azure Bot integration (optional)
# -----------------------------------------------------------------------------

variable "teams_bot_app_id" {
  description = "Azure AD App Registration ID for the Teams bot. Leave empty to skip Teams integration."
  type        = string
  default     = ""
}

variable "teams_bot_app_secret" {
  description = "Azure AD App secret for the Teams bot. Stored as SecureString in SSM. Leave empty to skip."
  type        = string
  default     = ""
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Monitoring & alerting
# -----------------------------------------------------------------------------

variable "alarm_email" {
  description = "Email address for CloudWatch alarm notifications. Leave empty to skip email subscription."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days for the audit log group."
  type        = number
  default     = 90
}

# -----------------------------------------------------------------------------
# Amazon Q Business integration (optional)
# -----------------------------------------------------------------------------

variable "amazon_q_app_id" {
  description = "Amazon Q Business Application ID for hybrid LLM mode. Leave empty to disable."
  type        = string
  default     = ""
}
