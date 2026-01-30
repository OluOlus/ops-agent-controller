#!/bin/bash
# OpsAgent Controller - Configuration Loader
# This script loads environment variables from .env file

# Check if .env file exists
if [ -f ".env" ]; then
    echo "Loading configuration from .env file..."
    export $(cat .env | grep -v '^#' | grep -v '^\s*$' | xargs)
    echo "✅ Configuration loaded"
else
    echo "⚠️  No .env file found. Using default/environment values."
    echo "   Copy .env.example to .env and configure your values."
fi

# Set defaults if not provided
export AWS_REGION=${AWS_REGION:-eu-west-2}
export ENVIRONMENT=${ENVIRONMENT:-sandbox}
export EXECUTION_MODE=${EXECUTION_MODE:-DRY_RUN}
export LLM_PROVIDER=${LLM_PROVIDER:-bedrock}
export BEDROCK_MODEL_ID=${BEDROCK_MODEL_ID:-anthropic.claude-3-sonnet-20240229-v1:0}
export ENABLE_DYNAMODB_ENCRYPTION=${ENABLE_DYNAMODB_ENCRYPTION:-true}
export CREATE_TEST_RESOURCES=${CREATE_TEST_RESOURCES:-true}
export STACK_NAME=${STACK_NAME:-opsagent-controller}

# Validate required variables
REQUIRED_VARS="TEAMS_BOT_APP_ID AZURE_TENANT_ID AWS_ACCOUNT_ID"
MISSING_VARS=""

for var in $REQUIRED_VARS; do
    if [ -z "${!var}" ]; then
        MISSING_VARS="$MISSING_VARS $var"
    fi
done

if [ -n "$MISSING_VARS" ]; then
    echo ""
    echo "❌ ERROR: Missing required environment variables:"
    for var in $MISSING_VARS; do
        echo "   - $var"
    done
    echo ""
    echo "Please set these variables in your .env file or environment."
    echo "See .env.example for a template."
    exit 1
fi

# Display configuration
echo ""
echo "Current Configuration:"
echo "  Azure Tenant ID: ${AZURE_TENANT_ID:0:8}..."
echo "  Teams Bot App ID: ${TEAMS_BOT_APP_ID:0:8}..."
echo "  AWS Account ID: $AWS_ACCOUNT_ID"
echo "  AWS Region: $AWS_REGION"
echo "  Environment: $ENVIRONMENT"
echo "  Execution Mode: $EXECUTION_MODE"
echo "  LLM Provider: $LLM_PROVIDER"
echo ""
