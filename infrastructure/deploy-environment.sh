#!/bin/bash

# OpsAgent Controller Environment-Specific Deployment Script
# This script provides environment-specific deployment with configuration management

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_REGION="us-east-1"
DEFAULT_STACK_NAME="opsagent-controller"

# Environment configurations
declare -A ENV_CONFIGS
ENV_CONFIGS[sandbox]="LOCAL_MOCK:bedrock:true:true"
ENV_CONFIGS[staging]="DRY_RUN:bedrock:true:false"
ENV_CONFIGS[production]="SANDBOX_LIVE:bedrock:false:false"

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS] <environment>"
    echo ""
    echo "Environments:"
    echo "  sandbox     - Development environment with mocked responses"
    echo "  staging     - Testing environment with dry-run mode"
    echo "  production  - Production environment with live execution"
    echo ""
    echo "Options:"
    echo "  -r, --region REGION         AWS region (default: $DEFAULT_REGION)"
    echo "  -s, --stack-name NAME       CloudFormation stack name (default: $DEFAULT_STACK_NAME)"
    echo "  -m, --execution-mode MODE   Execution mode (LOCAL_MOCK|DRY_RUN|SANDBOX_LIVE)"
    echo "  -l, --llm-provider PROVIDER LLM provider (bedrock|openai|azure_openai)"
    echo "  -k, --api-key KEY           API key for external LLM providers"
    echo "  --no-test-resources         Skip creating test resources"
    echo "  --validate-only             Only validate template, don't deploy"
    echo "  --cleanup                   Delete the stack instead of deploying"
    echo "  -h, --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 sandbox                                    # Deploy to sandbox with defaults"
    echo "  $0 staging --region us-west-2                # Deploy to staging in us-west-2"
    echo "  $0 production --execution-mode SANDBOX_LIVE  # Deploy to production"
    echo "  $0 sandbox --cleanup                         # Delete sandbox stack"
    echo ""
}

# Function to log messages
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

# Function to check prerequisites
check_prerequisites() {
    log INFO "Checking prerequisites..."
    
    local missing_tools=()
    
    if ! command -v sam &> /dev/null; then
        missing_tools+=("AWS SAM CLI")
    fi
    
    if ! command -v aws &> /dev/null; then
        missing_tools+=("AWS CLI")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log ERROR "Missing required tools: ${missing_tools[*]}"
        log ERROR "Please install the missing tools and try again"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log ERROR "AWS credentials not configured. Please run 'aws configure' first"
        exit 1
    fi
    
    # Check if we're in the right directory
    if [ ! -f "$SCRIPT_DIR/template.yaml" ]; then
        log ERROR "SAM template not found. Please run this script from the infrastructure directory"
        exit 1
    fi
    
    log INFO "Prerequisites check passed"
}

# Function to validate environment
validate_environment() {
    local env=$1
    
    if [[ ! "${!ENV_CONFIGS[@]}" =~ $env ]]; then
        log ERROR "Invalid environment: $env"
        log ERROR "Valid environments: ${!ENV_CONFIGS[@]}"
        exit 1
    fi
}

# Function to get environment configuration
get_env_config() {
    local env=$1
    local config="${ENV_CONFIGS[$env]}"
    
    IFS=':' read -r exec_mode llm_provider enable_encryption create_test_resources <<< "$config"
    
    echo "$exec_mode:$llm_provider:$enable_encryption:$create_test_resources"
}

# Function to validate template
validate_template() {
    log INFO "Validating SAM template..."
    
    if ! sam validate --template-file "$SCRIPT_DIR/template.yaml"; then
        log ERROR "SAM template validation failed"
        exit 1
    fi
    
    log INFO "Building SAM application for validation..."
    if ! sam build --template-file "$SCRIPT_DIR/template.yaml"; then
        log ERROR "SAM build failed"
        exit 1
    fi
    
    log INFO "Validating CloudFormation template..."
    if ! aws cloudformation validate-template --template-body file://.aws-sam/build/template.yaml > /dev/null; then
        log ERROR "CloudFormation template validation failed"
        exit 1
    fi
    
    log INFO "Template validation successful"
}

# Function to deploy stack
deploy_stack() {
    local env=$1
    local region=$2
    local stack_name=$3
    local execution_mode=$4
    local llm_provider=$5
    local enable_encryption=$6
    local create_test_resources=$7
    local api_key=$8
    
    local full_stack_name="$stack_name-$env"
    
    log INFO "Deploying stack: $full_stack_name"
    log INFO "Region: $region"
    log INFO "Environment: $env"
    log INFO "Execution Mode: $execution_mode"
    log INFO "LLM Provider: $llm_provider"
    
    # Build the application
    log INFO "Building SAM application..."
    sam build --template-file "$SCRIPT_DIR/template.yaml"
    
    # Prepare parameter overrides
    local param_overrides=(
        "Environment=$env"
        "ExecutionMode=$execution_mode"
        "LLMProvider=$llm_provider"
        "EnableDynamoDBEncryption=$enable_encryption"
        "CreateTestResources=$create_test_resources"
    )
    
    # Add API key parameter if provided
    if [ -n "$api_key" ]; then
        param_overrides+=("ApiKeyParameterName=/opsagent/$env/api-key")
    fi
    
    # Deploy the stack
    log INFO "Deploying to AWS..."
    sam deploy \
        --stack-name "$full_stack_name" \
        --region "$region" \
        --capabilities CAPABILITY_NAMED_IAM \
        --parameter-overrides "${param_overrides[@]}" \
        --tags \
            Project=OpsAgent \
            Environment="$env" \
            Owner=Platform-Team \
            DeployedBy="$(aws sts get-caller-identity --query 'Arn' --output text)" \
            DeployedAt="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --confirm-changeset
    
    log INFO "Deployment completed successfully!"
    
    # Store API key if provided
    if [ -n "$api_key" ]; then
        log INFO "Storing API key in SSM Parameter Store..."
        aws ssm put-parameter \
            --name "/opsagent/$env/api-key" \
            --value "$api_key" \
            --type SecureString \
            --overwrite \
            --region "$region" \
            --description "API key for OpsAgent Controller ($env environment)"
    fi
    
    # Display stack outputs
    log INFO "Stack outputs:"
    aws cloudformation describe-stacks \
        --stack-name "$full_stack_name" \
        --region "$region" \
        --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
        --output table
}

# Function to cleanup stack
cleanup_stack() {
    local env=$1
    local region=$2
    local stack_name=$3
    
    local full_stack_name="$stack_name-$env"
    
    log WARN "Deleting stack: $full_stack_name"
    read -p "Are you sure you want to delete the stack? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log INFO "Deleting CloudFormation stack..."
        aws cloudformation delete-stack \
            --stack-name "$full_stack_name" \
            --region "$region"
        
        log INFO "Waiting for stack deletion to complete..."
        aws cloudformation wait stack-delete-complete \
            --stack-name "$full_stack_name" \
            --region "$region"
        
        log INFO "Stack deleted successfully"
        
        # Clean up API key parameter
        log INFO "Cleaning up API key parameter..."
        aws ssm delete-parameter \
            --name "/opsagent/$env/api-key" \
            --region "$region" 2>/dev/null || true
        
        log INFO "Cleanup completed"
    else
        log INFO "Cleanup cancelled"
    fi
}

# Function to display post-deployment instructions
post_deployment_instructions() {
    local env=$1
    local region=$2
    local stack_name=$3
    
    local full_stack_name="$stack_name-$env"
    
    log INFO "Post-deployment instructions:"
    echo ""
    echo -e "${YELLOW}1. Test the health endpoint:${NC}"
    echo "   HEALTH_URL=\$(aws cloudformation describe-stacks --stack-name '$full_stack_name' --region '$region' --query 'Stacks[0].Outputs[?OutputKey==\`HealthEndpoint\`].OutputValue' --output text)"
    echo "   curl -H 'X-API-Key: your-api-key' \$HEALTH_URL"
    echo ""
    echo -e "${YELLOW}2. Test the chat endpoint:${NC}"
    echo "   CHAT_URL=\$(aws cloudformation describe-stacks --stack-name '$full_stack_name' --region '$region' --query 'Stacks[0].Outputs[?OutputKey==\`ChatEndpoint\`].OutputValue' --output text)"
    echo "   curl -X POST -H 'Content-Type: application/json' -H 'X-API-Key: your-api-key' -d '{\"userId\":\"test-user\",\"messageText\":\"Check system status\",\"channel\":\"web\"}' \$CHAT_URL"
    echo ""
    echo -e "${YELLOW}3. For Teams integration:${NC}"
    echo "   - Configure the bot endpoint to point to the Chat URL above"
    echo "   - See docs/teams-integration.md for detailed setup instructions"
    echo ""
    echo -e "${YELLOW}4. Monitor the deployment:${NC}"
    echo "   - CloudWatch Logs: /aws/lambda/opsagent-controller-$env"
    echo "   - Audit Logs: /aws/lambda/opsagent-audit-$env"
    echo "   - DynamoDB Table: opsagent-audit-$env"
    echo ""
    echo -e "${RED}⚠️  Security Reminders:${NC}"
    echo "   - Change the default API key immediately"
    echo "   - Review IAM permissions for your use case"
    echo "   - Enable CloudTrail for additional audit logging"
    echo "   - Consider using AWS WAF for API Gateway protection"
}

# Main function
main() {
    local environment=""
    local region="$DEFAULT_REGION"
    local stack_name="$DEFAULT_STACK_NAME"
    local execution_mode=""
    local llm_provider=""
    local api_key=""
    local create_test_resources=""
    local validate_only=false
    local cleanup=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--region)
                region="$2"
                shift 2
                ;;
            -s|--stack-name)
                stack_name="$2"
                shift 2
                ;;
            -m|--execution-mode)
                execution_mode="$2"
                shift 2
                ;;
            -l|--llm-provider)
                llm_provider="$2"
                shift 2
                ;;
            -k|--api-key)
                api_key="$2"
                shift 2
                ;;
            --no-test-resources)
                create_test_resources="false"
                shift
                ;;
            --validate-only)
                validate_only=true
                shift
                ;;
            --cleanup)
                cleanup=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                log ERROR "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [ -z "$environment" ]; then
                    environment="$1"
                else
                    log ERROR "Multiple environments specified: $environment and $1"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [ -z "$environment" ]; then
        log ERROR "Environment is required"
        usage
        exit 1
    fi
    
    # Validate environment
    validate_environment "$environment"
    
    # Get environment configuration
    local env_config
    env_config=$(get_env_config "$environment")
    IFS=':' read -r default_exec_mode default_llm_provider default_enable_encryption default_create_test_resources <<< "$env_config"
    
    # Use defaults if not specified
    execution_mode="${execution_mode:-$default_exec_mode}"
    llm_provider="${llm_provider:-$default_llm_provider}"
    create_test_resources="${create_test_resources:-$default_create_test_resources}"
    
    # Check prerequisites
    check_prerequisites
    
    # Validate template
    validate_template
    
    if [ "$validate_only" = true ]; then
        log INFO "Template validation completed successfully"
        exit 0
    fi
    
    if [ "$cleanup" = true ]; then
        cleanup_stack "$environment" "$region" "$stack_name"
        exit 0
    fi
    
    # Deploy stack
    deploy_stack "$environment" "$region" "$stack_name" "$execution_mode" "$llm_provider" "$default_enable_encryption" "$create_test_resources" "$api_key"
    
    # Show post-deployment instructions
    post_deployment_instructions "$environment" "$region" "$stack_name"
}

# Run main function with all arguments
main "$@"