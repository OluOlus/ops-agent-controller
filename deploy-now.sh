#!/bin/bash
set -e

echo "=================================================="
echo "OpsAgent Controller - Quick Deployment Script"
echo "=================================================="
echo ""

# Load configuration from .env file
if [ -f "./config.sh" ]; then
    source ./config.sh
else
    echo "⚠️  config.sh not found, using environment variables"
fi

# Use environment variables or defaults
AWS_REGION=${AWS_REGION:-eu-west-2}
ENVIRONMENT=${ENVIRONMENT:-sandbox}
EXECUTION_MODE=${EXECUTION_MODE:-DRY_RUN}
TEAMS_BOT_APP_ID=${TEAMS_BOT_APP_ID}
AZURE_TENANT_ID=${AZURE_TENANT_ID}
AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID}

echo "Configuration:"
echo "  AWS Region: $AWS_REGION"
echo "  AWS Account: $AWS_ACCOUNT_ID"
echo "  Environment: $ENVIRONMENT"
echo "  Execution Mode: $EXECUTION_MODE"
echo "  Teams Bot App ID: ${TEAMS_BOT_APP_ID:0:8}..."
echo "  Azure Tenant ID: ${AZURE_TENANT_ID:0:8}..."
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found. Please install AWS CLI first."
    exit 1
fi

if ! command -v sam &> /dev/null; then
    echo "❌ AWS SAM CLI not found. Please install SAM CLI first."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.11+."
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# Check AWS credentials
echo "Checking AWS credentials..."
if ! aws sts get-caller-identity --region $AWS_REGION &> /dev/null; then
    echo "❌ AWS credentials not configured. Please run 'aws configure'."
    exit 1
fi

CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
echo "✅ Authenticated with AWS Account: $CURRENT_ACCOUNT"
echo ""

# Navigate to infrastructure directory
cd infrastructure

# Step 1: Build
echo "Step 1: Building SAM application..."
sam build
echo "✅ Build completed"
echo ""

# Step 2: Deploy
echo "Step 2: Deploying to AWS..."
echo "This will deploy the OpsAgent Controller to $AWS_REGION"
echo ""

sam deploy \
  --config-env $ENVIRONMENT \
  --region $AWS_REGION \
  --resolve-s3 \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    "Environment=$ENVIRONMENT" \
    "ExecutionMode=$EXECUTION_MODE" \
    "TeamsBotAppId=$TEAMS_BOT_APP_ID" \
    "AzureTenantId=$AZURE_TENANT_ID" \
    "AwsAccountId=$AWS_ACCOUNT_ID" \
  --no-confirm-changeset \
  --no-fail-on-empty-changeset

echo "✅ Deployment completed"
echo ""

# Step 3: Get outputs
echo "Step 3: Retrieving deployment outputs..."
STACK_NAME="opsagent-controller-$ENVIRONMENT"

API_URL=$(aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --region $AWS_REGION \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiGatewayUrl`].OutputValue' \
  --output text 2>/dev/null || echo "Not available")

HEALTH_URL=$(aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --region $AWS_REGION \
  --query 'Stacks[0].Outputs[?OutputKey==`HealthEndpointUrl`].OutputValue' \
  --output text 2>/dev/null || echo "Not available")

CHAT_URL=$(aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --region $AWS_REGION \
  --query 'Stacks[0].Outputs[?OutputKey==`ChatEndpointUrl`].OutputValue' \
  --output text 2>/dev/null || echo "Not available")

LAMBDA_NAME=$(aws cloudformation describe-stacks \
  --stack-name $STACK_NAME \
  --region $AWS_REGION \
  --query 'Stacks[0].Outputs[?OutputKey==`LambdaFunctionName`].OutputValue' \
  --output text 2>/dev/null || echo "Not available")

echo ""
echo "=================================================="
echo "Deployment Summary"
echo "=================================================="
echo ""
echo "Stack Name: $STACK_NAME"
echo "Region: $AWS_REGION"
echo ""
echo "Endpoints:"
echo "  API Gateway URL: $API_URL"
echo "  Health Check: $HEALTH_URL"
echo "  Chat Endpoint: $CHAT_URL"
echo ""
echo "Lambda Function: $LAMBDA_NAME"
echo ""

# Step 4: Test health endpoint
echo "Step 4: Testing health endpoint..."
if [ "$HEALTH_URL" != "Not available" ]; then
    echo "Testing: $HEALTH_URL"
    HEALTH_RESPONSE=$(curl -s "$HEALTH_URL" || echo '{"error": "Failed to connect"}')
    echo "Response: $HEALTH_RESPONSE"
    echo ""
fi

# Step 5: Next steps
echo "=================================================="
echo "Next Steps"
echo "=================================================="
echo ""
echo "1. Update Azure Bot Service messaging endpoint:"
echo "   Go to: https://portal.azure.com"
echo "   Navigate to: Resource Groups > opsagent-rg > opsagent-live"
echo "   Set messaging endpoint to: $CHAT_URL"
echo ""
echo "2. Install Teams App:"
echo "   - Upload teams-app/opsagent-teams-app.zip to Microsoft Teams"
echo "   - Go to Apps > Upload a custom app"
echo "   - Select the zip file and click Add"
echo ""
echo "3. Test in Teams:"
echo "   - Start a chat with 'OpsAgent AWS'"
echo "   - Send: login"
echo "   - Send: health"
echo "   - Send: help"
echo ""
echo "4. View Lambda logs:"
echo "   aws logs tail /aws/lambda/$LAMBDA_NAME --follow --region $AWS_REGION"
echo ""
echo "=================================================="
echo "Deployment Complete! 🎉"
echo "=================================================="
