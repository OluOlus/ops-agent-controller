#!/bin/bash

# OpsAgent Controller Deployment Script
# This script deploys the OpsAgent Controller to AWS using SAM

set -e

# Configuration
STACK_NAME="opsagent-controller"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
ENVIRONMENT="${ENVIRONMENT:-sandbox}"
EXECUTION_MODE="${EXECUTION_MODE:-LOCAL_MOCK}"
LLM_PROVIDER="${LLM_PROVIDER:-bedrock}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Deploying OpsAgent Controller${NC}"
echo "Stack Name: $STACK_NAME"
echo "Region: $REGION"
echo "Environment: $ENVIRONMENT"
echo "Execution Mode: $EXECUTION_MODE"
echo "LLM Provider: $LLM_PROVIDER"
echo ""

# Check prerequisites
echo -e "${YELLOW}📋 Checking prerequisites...${NC}"

if ! command -v sam &> /dev/null; then
    echo -e "${RED}❌ AWS SAM CLI is not installed. Please install it first.${NC}"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    echo -e "${RED}❌ AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}❌ AWS credentials not configured. Please run 'aws configure' first.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites check passed${NC}"
echo ""

# Build and deploy
echo -e "${YELLOW}🔨 Building SAM application...${NC}"
sam build

echo -e "${YELLOW}🚀 Deploying to AWS...${NC}"
sam deploy \
    --stack-name "$STACK_NAME-$ENVIRONMENT" \
    --region "$REGION" \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
        Environment="$ENVIRONMENT" \
        ExecutionMode="$EXECUTION_MODE" \
        LLMProvider="$LLM_PROVIDER" \
    --tags \
        Project=OpsAgent \
        Environment="$ENVIRONMENT" \
        Owner=Platform-Team \
    --confirm-changeset

echo ""
echo -e "${GREEN}✅ Deployment completed successfully!${NC}"

# Get stack outputs
echo -e "${YELLOW}📊 Stack Outputs:${NC}"
aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME-$ENVIRONMENT" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
    --output table

echo ""
echo -e "${GREEN}🎉 OpsAgent Controller is now deployed!${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Update the API key:"
echo "   aws ssm put-parameter --name '/opsagent/api-key' --value 'your-secure-api-key' --type SecureString --overwrite --region $REGION"
echo ""
echo "2. Test the health endpoint:"
echo "   HEALTH_URL=\$(aws cloudformation describe-stacks --stack-name '$STACK_NAME-$ENVIRONMENT' --region '$REGION' --query 'Stacks[0].Outputs[?OutputKey==\`HealthEndpoint\`].OutputValue' --output text)"
echo "   curl -H 'X-API-Key: your-api-key' \$HEALTH_URL"
echo ""
echo "3. Test the chat endpoint:"
echo "   CHAT_URL=\$(aws cloudformation describe-stacks --stack-name '$STACK_NAME-$ENVIRONMENT' --region '$REGION' --query 'Stacks[0].Outputs[?OutputKey==\`ChatEndpoint\`].OutputValue' --output text)"
echo "   curl -X POST -H 'Content-Type: application/json' -H 'X-API-Key: your-api-key' -d '{\"userId\":\"test-user\",\"messageText\":\"Check system status\",\"channel\":\"web\"}' \$CHAT_URL"
echo ""
echo "4. For Teams integration, configure the bot endpoint to point to the Chat URL above"
echo ""
echo -e "${YELLOW}⚠️  Important Security Notes:${NC}"
echo "- Change the default API key immediately after deployment"
echo "- Review IAM permissions and adjust as needed for your environment"
echo "- Enable CloudTrail for additional audit logging"
echo "- Consider using AWS WAF for API Gateway protection"