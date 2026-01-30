#!/bin/bash

# Deploy Amazon Q integration to OpsAgent Controller
# This script updates the existing Lambda function with Amazon Q hybrid capabilities

set -e

# Configuration
FUNCTION_NAME="opsagent-controller-sandbox"
REGION="${AWS_REGION:-us-east-1}"
STACK_NAME="opsagent-controller-sandbox"

echo "🚀 Deploying Amazon Q integration to OpsAgent Controller..."

# Check if AWS CLI is available
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI is required but not installed. Please install AWS CLI first."
    exit 1
fi

# Check if SAM CLI is available
if ! command -v sam &> /dev/null; then
    echo "❌ SAM CLI is required but not installed. Please install SAM CLI first."
    exit 1
fi

# Verify AWS credentials
echo "🔍 Verifying AWS credentials..."
if ! aws sts get-caller-identity > /dev/null 2>&1; then
    echo "❌ AWS credentials not configured. Please run 'aws configure' first."
    exit 1
fi

# Get current account and region info
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
CURRENT_REGION=$(aws configure get region || echo "us-east-1")

echo "✅ AWS Account: $ACCOUNT_ID"
echo "✅ Region: $CURRENT_REGION"

# Check if the stack exists
echo "🔍 Checking if OpsAgent stack exists..."
if ! aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$CURRENT_REGION" > /dev/null 2>&1; then
    echo "❌ Stack '$STACK_NAME' not found. Please deploy the base OpsAgent stack first."
    echo "   Run: sam deploy --guided"
    exit 1
fi

echo "✅ Found existing stack: $STACK_NAME"

# Build the SAM application
echo "🔨 Building SAM application..."
sam build

# Deploy with Amazon Q parameters
echo "🚀 Deploying with Amazon Q integration..."

# Check if user wants to configure Amazon Q
read -p "Do you want to configure Amazon Q Developer integration? (y/N): " configure_q

if [[ $configure_q =~ ^[Yy]$ ]]; then
    echo ""
    echo "📝 Amazon Q Developer Configuration:"
    echo "   You'll need to provide your Amazon Q Developer Application ID."
    echo "   This can be found in the Amazon Q Developer console."
    echo ""
    
    read -p "Enter Amazon Q Application ID: " amazon_q_app_id
    read -p "Enter Amazon Q User ID (default: opsagent-user): " amazon_q_user_id
    amazon_q_user_id=${amazon_q_user_id:-opsagent-user}
    
    # Deploy with Amazon Q configuration
    sam deploy \
        --stack-name "$STACK_NAME" \
        --region "$CURRENT_REGION" \
        --capabilities CAPABILITY_IAM \
        --parameter-overrides \
            "AmazonQAppId=$amazon_q_app_id" \
            "AmazonQUserId=$amazon_q_user_id" \
        --no-confirm-changeset
else
    # Deploy without Amazon Q (removes any existing configuration)
    sam deploy \
        --stack-name "$STACK_NAME" \
        --region "$CURRENT_REGION" \
        --capabilities CAPABILITY_IAM \
        --parameter-overrides \
            "AmazonQAppId=" \
        --no-confirm-changeset
fi

# Get the API Gateway URL
API_URL=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$CURRENT_REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`ApiGatewayUrl`].OutputValue' \
    --output text)

echo ""
echo "✅ Deployment completed successfully!"
echo ""
echo "📋 Deployment Summary:"
echo "   Stack Name: $STACK_NAME"
echo "   Region: $CURRENT_REGION"
echo "   API URL: $API_URL"

if [[ $configure_q =~ ^[Yy]$ ]]; then
    echo "   Amazon Q App ID: $amazon_q_app_id"
    echo "   Amazon Q User ID: $amazon_q_user_id"
    echo "   Hybrid Mode: Enabled"
    echo ""
    echo "🎯 Amazon Q Integration Features:"
    echo "   • Knowledge queries → Amazon Q Developer"
    echo "   • Operational tasks → OpsAgent approval workflows"
    echo "   • Diagnostic tasks → Enhanced with Q context"
    echo "   • Automatic fallback to Bedrock if Q unavailable"
else
    echo "   Amazon Q: Not configured (Bedrock only)"
fi

echo ""
echo "🧪 Test the integration:"
echo "   Health check: curl -H \"X-API-Key: your-api-key\" $API_URL/health"
echo ""
echo "   Knowledge query (Amazon Q):"
echo "   curl -X POST -H \"Content-Type: application/json\" -H \"X-API-Key: your-api-key\" \\"
echo "        -d '{\"userId\":\"test-user\",\"messageText\":\"What is Amazon EC2?\",\"channel\":\"web\"}' \\"
echo "        $API_URL/chat"
echo ""
echo "   Operational task (OpsAgent):"
echo "   curl -X POST -H \"Content-Type: application/json\" -H \"X-API-Key: your-api-key\" \\"
echo "        -d '{\"userId\":\"test-user\",\"messageText\":\"reboot instance i-1234567890abcdef0\",\"channel\":\"web\"}' \\"
echo "        $API_URL/chat"
echo ""

# Check if Teams integration is configured
TEAMS_BOT_ID=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$CURRENT_REGION" \
    --query 'Stacks[0].Parameters[?ParameterKey==`TeamsBotAppId`].ParameterValue' \
    --output text 2>/dev/null || echo "")

if [[ -n "$TEAMS_BOT_ID" && "$TEAMS_BOT_ID" != "" ]]; then
    echo "🤖 Teams Integration:"
    echo "   Bot App ID: $TEAMS_BOT_ID"
    echo "   Messaging Endpoint: $API_URL/chat"
    echo "   Test in Teams: Send 'what is EC2?' or 'health' to your bot"
fi

echo ""
echo "📚 Next Steps:"
echo "   1. Update your API key if needed:"
echo "      aws ssm put-parameter --name '/opsagent/api-key' --value 'your-secure-key' --type SecureString --overwrite"
echo ""
echo "   2. For Teams integration, ensure your bot's messaging endpoint is set to:"
echo "      $API_URL/chat"
echo ""
echo "   3. Test both Amazon Q knowledge queries and OpsAgent operational tasks"
echo ""
echo "🎉 Amazon Q integration deployment complete!"