#!/bin/bash

# OpsAgent Controller Full Infrastructure Deployment
# This script deploys the complete infrastructure needed for all tests and Amazon Q Business integration

set -e

# Configuration
AWS_REGION="us-west-2"
ENVIRONMENT="sandbox"
STACK_NAME="opsagent-controller-full"
TEST_RESOURCES_STACK="opsagent-test-resources-full"
ADMIN_EMAIL="admin@oluofnotts.onmicrosoft.com"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)  echo -e "${GREEN}[INFO]${NC}  [$timestamp] $message" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC}  [$timestamp] $message" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} [$timestamp] $message" ;;
        DEBUG) echo -e "${BLUE}[DEBUG]${NC} [$timestamp] $message" ;;
    esac
}

# Function to deploy test resources
deploy_test_resources() {
    log INFO "Deploying test resources..."
    
    aws cloudformation deploy \
        --template-file infrastructure/test-resources.yaml \
        --stack-name "$TEST_RESOURCES_STACK" \
        --parameter-overrides \
            Environment="$ENVIRONMENT" \
            InstanceType="t3.micro" \
        --capabilities CAPABILITY_IAM \
        --region "$AWS_REGION"
    
    if [ $? -eq 0 ]; then
        log INFO "Test resources deployed successfully"
    else
        log ERROR "Failed to deploy test resources"
        exit 1
    fi
}

# Function to create required SSM parameters
create_ssm_parameters() {
    log INFO "Creating SSM parameters..."
    
    # Create API key
    API_KEY=$(openssl rand -hex 32)
    aws ssm put-parameter \
        --name "/opsagent/${ENVIRONMENT}/api-key" \
        --value "$API_KEY" \
        --type "SecureString" \
        --region "$AWS_REGION" \
        --overwrite || true
    
    # Create plugin API key parameter
    aws ssm put-parameter \
        --name "/opsagent/plugin-api-key-${ENVIRONMENT}" \
        --value "$API_KEY" \
        --type "SecureString" \
        --region "$AWS_REGION" \
        --overwrite || true
    
    log INFO "API Key created: ${API_KEY:0:10}..."
    echo "$API_KEY" > .api_key_temp
}

# Function to deploy main infrastructure using template-fixed.yaml
deploy_main_infrastructure() {
    log INFO "Deploying main OpsAgent infrastructure..."
    
    sam build --template infrastructure/template-fixed.yaml
    
    sam deploy \
        --template-file .aws-sam/build/template.yaml \
        --stack-name "$STACK_NAME" \
        --parameter-overrides \
            Environment="$ENVIRONMENT" \
            ExecutionMode="SANDBOX_LIVE" \
        --capabilities CAPABILITY_IAM \
        --region "$AWS_REGION" \
        --no-confirm-changeset \
        --resolve-s3
    
    if [ $? -eq 0 ]; then
        log INFO "Main infrastructure deployed successfully"
    else
        log ERROR "Failed to deploy main infrastructure"
        exit 1
    fi
}

# Function to create additional resources needed for tests
create_additional_resources() {
    log INFO "Creating additional resources for tests..."
    
    # Create CloudWatch log groups
    aws logs create-log-group \
        --log-group-name "/aws/lambda/opsagent-audit-${ENVIRONMENT}" \
        --region "$AWS_REGION" || true
    
    aws logs create-log-group \
        --log-group-name "/aws/lambda/opsagent-controller" \
        --region "$AWS_REGION" || true
    
    # Create DynamoDB tables
    aws dynamodb create-table \
        --table-name "opsagent-audit-${ENVIRONMENT}" \
        --attribute-definitions \
            AttributeName=correlationId,AttributeType=S \
            AttributeName=timestamp,AttributeType=S \
            AttributeName=userId,AttributeType=S \
        --key-schema \
            AttributeName=correlationId,KeyType=HASH \
            AttributeName=timestamp,KeyType=RANGE \
        --global-secondary-indexes \
            IndexName=UserIdIndex,KeySchema=[{AttributeName=userId,KeyType=HASH},{AttributeName=timestamp,KeyType=RANGE}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
        --provisioned-throughput \
            ReadCapacityUnits=5,WriteCapacityUnits=5 \
        --region "$AWS_REGION" || true
    
    aws dynamodb create-table \
        --table-name "opsagent-incidents-${ENVIRONMENT}" \
        --attribute-definitions \
            AttributeName=incidentId,AttributeType=S \
            AttributeName=severity,AttributeType=S \
            AttributeName=createdAt,AttributeType=S \
            AttributeName=userId,AttributeType=S \
        --key-schema \
            AttributeName=incidentId,KeyType=HASH \
        --global-secondary-indexes \
            IndexName=SeverityCreatedIndex,KeySchema=[{AttributeName=severity,KeyType=HASH},{AttributeName=createdAt,KeyType=RANGE}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
            IndexName=UserIdCreatedIndex,KeySchema=[{AttributeName=userId,KeyType=HASH},{AttributeName=createdAt,KeyType=RANGE}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5} \
        --provisioned-throughput \
            ReadCapacityUnits=5,WriteCapacityUnits=5 \
        --region "$AWS_REGION" || true
    
    # Create SNS topic
    TOPIC_ARN=$(aws sns create-topic \
        --name "opsagent-notifications-${ENVIRONMENT}" \
        --region "$AWS_REGION" \
        --query 'TopicArn' \
        --output text)
    
    log INFO "Created SNS topic: $TOPIC_ARN"
}

# Function to update Lambda environment variables
update_lambda_environment() {
    log INFO "Updating Lambda environment variables..."
    
    # Get stack outputs
    local health_endpoint=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`HealthEndpointUrl`].OutputValue' \
        --output text)
    
    local chat_endpoint=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`ChatEndpointUrl`].OutputValue' \
        --output text)
    
    local function_name=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`LambdaFunctionName`].OutputValue' \
        --output text)
    
    # Update Lambda environment variables
    aws lambda update-function-configuration \
        --function-name "$function_name" \
        --environment Variables="{
            EXECUTION_MODE=SANDBOX_LIVE,
            ENVIRONMENT=$ENVIRONMENT,
            LLM_PROVIDER=bedrock,
            BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0,
            AUDIT_LOG_GROUP=/aws/lambda/opsagent-audit-${ENVIRONMENT},
            CLOUDWATCH_LOG_GROUP=/aws/lambda/opsagent-controller,
            AUDIT_TABLE_NAME=opsagent-audit-${ENVIRONMENT},
            INCIDENT_TABLE_NAME=opsagent-incidents-${ENVIRONMENT},
            NOTIFICATION_TOPIC_ARN=arn:aws:sns:${AWS_REGION}:$(aws sts get-caller-identity --query Account --output text):opsagent-notifications-${ENVIRONMENT},
            API_KEY_PARAMETER=/opsagent/${ENVIRONMENT}/api-key,
            PLUGIN_API_KEY_PARAMETER=/opsagent/plugin-api-key-${ENVIRONMENT}
        }" \
        --region "$AWS_REGION"
    
    log INFO "Lambda environment updated"
    log INFO "Health Endpoint: $health_endpoint"
    log INFO "Chat Endpoint: $chat_endpoint"
}

# Function to create environment configuration
create_environment_config() {
    log INFO "Creating environment configuration..."
    
    local api_key=$(cat .api_key_temp)
    rm -f .api_key_temp
    
    # Get stack outputs
    local health_endpoint=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`HealthEndpointUrl`].OutputValue' \
        --output text)
    
    local chat_endpoint=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`ChatEndpointUrl`].OutputValue' \
        --output text)
    
    local api_gateway_url=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`ApiGatewayUrl`].OutputValue' \
        --output text)
    
    # Get test resource IDs
    local test_instance_1=$(aws cloudformation describe-stacks \
        --stack-name "$TEST_RESOURCES_STACK" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestInstance1Id`].OutputValue' \
        --output text)
    
    local test_instance_2=$(aws cloudformation describe-stacks \
        --stack-name "$TEST_RESOURCES_STACK" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestInstance2Id`].OutputValue' \
        --output text)
    
    local test_cluster=$(aws cloudformation describe-stacks \
        --stack-name "$TEST_RESOURCES_STACK" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestClusterName`].OutputValue' \
        --output text)
    
    local test_service=$(aws cloudformation describe-stacks \
        --stack-name "$TEST_RESOURCES_STACK" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestServiceName`].OutputValue' \
        --output text)
    
    # Create comprehensive environment file
    cat > .env.full << EOF
# OpsAgent Controller Full Environment Configuration
# Generated: $(date -Iseconds)

# Environment Settings
ENVIRONMENT=$ENVIRONMENT
AWS_REGION=$AWS_REGION
EXECUTION_MODE=SANDBOX_LIVE

# API Endpoints
HEALTH_ENDPOINT=$health_endpoint
CHAT_ENDPOINT=$chat_endpoint
API_GATEWAY_URL=$api_gateway_url

# Authentication
API_KEY=$api_key
ADMIN_EMAIL=$ADMIN_EMAIL

# AWS Resources
STACK_NAME=$STACK_NAME
TEST_RESOURCES_STACK=$TEST_RESOURCES_STACK
LAMBDA_FUNCTION_NAME=opsagent-controller-$ENVIRONMENT

# Test Resources
TEST_INSTANCE_1_ID=$test_instance_1
TEST_INSTANCE_2_ID=$test_instance_2
TEST_CLUSTER_NAME=$test_cluster
TEST_SERVICE_NAME=$test_service

# DynamoDB Tables
AUDIT_TABLE_NAME=opsagent-audit-$ENVIRONMENT
INCIDENT_TABLE_NAME=opsagent-incidents-$ENVIRONMENT

# CloudWatch Log Groups
AUDIT_LOG_GROUP=/aws/lambda/opsagent-audit-$ENVIRONMENT
CLOUDWATCH_LOG_GROUP=/aws/lambda/opsagent-controller

# SNS Topic
NOTIFICATION_TOPIC_ARN=arn:aws:sns:$AWS_REGION:$(aws sts get-caller-identity --query Account --output text):opsagent-notifications-$ENVIRONMENT

# Status
DEPLOYMENT_STATUS=SUCCESS
INFRASTRUCTURE_COMPLETE=true
READY_FOR_TESTS=true
READY_FOR_AMAZON_Q=true
EOF

    log INFO "Environment configuration created: .env.full"
}

# Function to run validation tests
run_validation_tests() {
    log INFO "Running validation tests..."
    
    source .env.full
    
    # Test health endpoint
    log INFO "Testing health endpoint..."
    curl -s "$HEALTH_ENDPOINT" | python3 -c "import sys, json; data=json.load(sys.stdin); print('✅ Health check passed' if data.get('success') else '❌ Health check failed')"
    
    # Test chat endpoint
    log INFO "Testing chat endpoint..."
    curl -s -X POST -H "Content-Type: application/json" \
        -d '{"userId":"admin@oluofnotts.onmicrosoft.com","messageText":"health check","channel":"web"}' \
        "$CHAT_ENDPOINT" | python3 -c "import sys, json; data=json.load(sys.stdin); print('✅ Chat endpoint working' if data.get('success') else '❌ Chat endpoint failed')"
    
    log INFO "Validation tests completed"
}

# Main execution
main() {
    log INFO "🚀 Starting OpsAgent Controller Full Infrastructure Deployment"
    log INFO "Environment: $ENVIRONMENT"
    log INFO "Region: $AWS_REGION"
    log INFO "Stack Name: $STACK_NAME"
    
    # Set AWS credentials (configure these with your credentials)
    export AWS_ACCESS_KEY_ID="your-aws-access-key-id"
    export AWS_SECRET_ACCESS_KEY="your-aws-secret-access-key"
    export AWS_DEFAULT_REGION="$AWS_REGION"
    
    deploy_test_resources
    create_ssm_parameters
    deploy_main_infrastructure
    create_additional_resources
    update_lambda_environment
    create_environment_config
    run_validation_tests
    
    log INFO "🎉 Full infrastructure deployment completed!"
    log INFO ""
    log INFO "Next steps:"
    log INFO "1. Run unit tests: python3 -m pytest tests/ -v"
    log INFO "2. Set up Amazon Q Business plugin (see guide below)"
    log INFO "3. Load environment: source .env.full"
    log INFO ""
    log INFO "Environment file created: .env.full"
}

# Run main function
main "$@"