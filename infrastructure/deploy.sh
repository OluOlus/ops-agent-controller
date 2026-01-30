#!/bin/bash

# OpsAgent Controller Deployment Script
# Deploys the OpsAgent Controller infrastructure using AWS SAM

set -e  # Exit on any error

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEMPLATE_FILE="$SCRIPT_DIR/template.yaml"
CONFIG_DIR="$SCRIPT_DIR/config"

# Default values
ENVIRONMENT="sandbox"
EXECUTION_MODE="SANDBOX_LIVE"
AWS_REGION="us-east-1"
CREATE_TEST_RESOURCES="true"
ENABLE_ENCRYPTION="true"
GUIDED_DEPLOY="false"
CONFIRM_CHANGESET="true"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
OpsAgent Controller Deployment Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -e, --environment ENVIRONMENT    Deployment environment (sandbox, staging, production)
                                    Default: sandbox
    
    -m, --execution-mode MODE       Execution mode (LOCAL_MOCK, DRY_RUN, SANDBOX_LIVE)
                                    Default: SANDBOX_LIVE
    
    -r, --region REGION             AWS region for deployment
                                    Default: us-east-1
    
    -t, --test-resources BOOL       Create test resources (true/false)
                                    Default: true
    
    --encryption BOOL               Enable DynamoDB encryption (true/false)
                                    Default: true
    
    -g, --guided                    Use SAM guided deployment
                                    Default: false
    
    -y, --yes                       Skip changeset confirmation
                                    Default: false (will prompt)
    
    --config-file FILE              Use custom configuration file
                                    Default: config/{environment}.yaml
    
    -h, --help                      Show this help message

EXAMPLES:
    # Deploy to sandbox environment
    $0 --environment sandbox
    
    # Deploy to production with confirmation
    $0 --environment production --execution-mode SANDBOX_LIVE
    
    # Deploy with guided setup
    $0 --guided
    
    # Deploy without test resources
    $0 --environment production --test-resources false

PREREQUISITES:
    - AWS CLI configured with appropriate permissions
    - SAM CLI installed
    - Python 3.11 runtime available
    - Valid AWS credentials for target account

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -m|--execution-mode)
                EXECUTION_MODE="$2"
                shift 2
                ;;
            -r|--region)
                AWS_REGION="$2"
                shift 2
                ;;
            -t|--test-resources)
                CREATE_TEST_RESOURCES="$2"
                shift 2
                ;;
            --encryption)
                ENABLE_ENCRYPTION="$2"
                shift 2
                ;;
            -g|--guided)
                GUIDED_DEPLOY="true"
                shift
                ;;
            -y|--yes)
                CONFIRM_CHANGESET="false"
                shift
                ;;
            --config-file)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Validate prerequisites
validate_prerequisites() {
    log_info "Validating prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed or not in PATH"
        exit 1
    fi
    
    # Check SAM CLI
    if ! command -v sam &> /dev/null; then
        log_error "SAM CLI is not installed or not in PATH"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured or invalid"
        exit 1
    fi
    
    # Check template file exists
    if [[ ! -f "$TEMPLATE_FILE" ]]; then
        log_error "SAM template not found: $TEMPLATE_FILE"
        exit 1
    fi
    
    # Validate environment
    if [[ ! "$ENVIRONMENT" =~ ^(sandbox|staging|production)$ ]]; then
        log_error "Invalid environment: $ENVIRONMENT. Must be sandbox, staging, or production"
        exit 1
    fi
    
    # Validate execution mode
    if [[ ! "$EXECUTION_MODE" =~ ^(LOCAL_MOCK|DRY_RUN|SANDBOX_LIVE)$ ]]; then
        log_error "Invalid execution mode: $EXECUTION_MODE"
        exit 1
    fi
    
    # Production-specific validations
    if [[ "$ENVIRONMENT" == "production" ]]; then
        if [[ "$EXECUTION_MODE" == "LOCAL_MOCK" ]]; then
            log_error "LOCAL_MOCK execution mode not allowed in production"
            exit 1
        fi
        
        if [[ "$CREATE_TEST_RESOURCES" == "true" ]]; then
            log_warning "Test resources should not be created in production"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
    
    log_success "Prerequisites validated"
}

# Load configuration
load_configuration() {
    local config_file="${CONFIG_FILE:-$CONFIG_DIR/$ENVIRONMENT.yaml}"
    
    if [[ -f "$config_file" ]]; then
        log_info "Loading configuration from: $config_file"
        # Configuration loading logic would go here
        # For now, we'll use the command line parameters
    else
        log_warning "Configuration file not found: $config_file"
        log_info "Using command line parameters and defaults"
    fi
}

# Build the application
build_application() {
    log_info "Building SAM application..."
    
    cd "$SCRIPT_DIR"
    
    if ! sam build --template-file template.yaml; then
        log_error "SAM build failed"
        exit 1
    fi
    
    log_success "Application built successfully"
}

# Deploy the application
deploy_application() {
    log_info "Deploying OpsAgent Controller to $ENVIRONMENT environment..."
    
    local stack_name="opsagent-controller-$ENVIRONMENT"
    local s3_bucket="opsagent-deployments-$ENVIRONMENT-$(aws sts get-caller-identity --query Account --output text)"
    
    # Create S3 bucket if it doesn't exist
    if ! aws s3 ls "s3://$s3_bucket" &> /dev/null; then
        log_info "Creating deployment bucket: $s3_bucket"
        aws s3 mb "s3://$s3_bucket" --region "$AWS_REGION"
        
        # Enable versioning
        aws s3api put-bucket-versioning \
            --bucket "$s3_bucket" \
            --versioning-configuration Status=Enabled
    fi
    
    # Prepare SAM deploy command
    local sam_deploy_cmd="sam deploy"
    
    if [[ "$GUIDED_DEPLOY" == "true" ]]; then
        sam_deploy_cmd="$sam_deploy_cmd --guided"
    else
        sam_deploy_cmd="$sam_deploy_cmd \
            --template-file .aws-sam/build/template.yaml \
            --stack-name $stack_name \
            --s3-bucket $s3_bucket \
            --capabilities CAPABILITY_IAM \
            --region $AWS_REGION \
            --parameter-overrides \
                Environment=$ENVIRONMENT \
                ExecutionMode=$EXECUTION_MODE \
                CreateTestResources=$CREATE_TEST_RESOURCES \
                EnableDynamoDBEncryption=$ENABLE_ENCRYPTION"
        
        if [[ "$CONFIRM_CHANGESET" == "false" ]]; then
            sam_deploy_cmd="$sam_deploy_cmd --no-confirm-changeset"
        fi
    fi
    
    # Execute deployment
    log_info "Executing: $sam_deploy_cmd"
    
    if eval "$sam_deploy_cmd"; then
        log_success "Deployment completed successfully"
    else
        log_error "Deployment failed"
        exit 1
    fi
}

# Post-deployment configuration
post_deployment_setup() {
    log_info "Running post-deployment setup..."
    
    local stack_name="opsagent-controller-$ENVIRONMENT"
    
    # Get stack outputs
    local api_endpoint
    api_endpoint=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`PluginApiEndpointUrl`].OutputValue' \
        --output text \
        --region "$AWS_REGION")
    
    local api_key_param
    api_key_param=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`PluginApiKey`].OutputValue' \
        --output text \
        --region "$AWS_REGION")
    
    if [[ -z "$api_endpoint" ]]; then
        log_error "Could not retrieve API endpoint from stack outputs"
        exit 1
    fi
    
    # Update API key if needed
    log_info "Configuring API key..."
    local api_key_value
    if [[ "$ENVIRONMENT" == "production" ]]; then
        # Generate secure API key for production
        api_key_value=$(openssl rand -base64 32)
    else
        # Use predictable key for non-production
        api_key_value="opsagent-${ENVIRONMENT}-$(date +%Y%m%d)"
    fi
    
    aws ssm put-parameter \
        --name "/opsagent/api-key" \
        --value "$api_key_value" \
        --type "SecureString" \
        --overwrite \
        --region "$AWS_REGION"
    
    # Configure user allow-list
    log_info "Configuring user allow-list..."
    local allowed_users
    case "$ENVIRONMENT" in
        sandbox)
            allowed_users="platform-engineer@company.com,ops-engineer@company.com,sandbox-user@company.com"
            ;;
        staging)
            allowed_users="platform-engineer@company.com,ops-engineer@company.com"
            ;;
        production)
            allowed_users="senior-platform-engineer@company.com,ops-lead@company.com"
            ;;
    esac
    
    aws ssm put-parameter \
        --name "/opsagent/allowed-users" \
        --value "$allowed_users" \
        --type "StringList" \
        --overwrite \
        --region "$AWS_REGION"
    
    # Test health endpoint
    log_info "Testing health endpoint..."
    local health_url="$api_endpoint/health"
    
    if curl -f -s "$health_url" > /dev/null; then
        log_success "Health endpoint is responding"
    else
        log_warning "Health endpoint test failed - this may be normal if API Gateway is still deploying"
    fi
    
    # Display deployment summary
    echo
    log_success "=== Deployment Summary ==="
    echo "Environment: $ENVIRONMENT"
    echo "Execution Mode: $EXECUTION_MODE"
    echo "AWS Region: $AWS_REGION"
    echo "Stack Name: $stack_name"
    echo "API Endpoint: $api_endpoint"
    echo "API Key Parameter: $api_key_param"
    echo
    
    log_info "Next Steps:"
    echo "1. Retrieve API key: aws ssm get-parameter --name '$api_key_param' --with-decryption --query 'Parameter.Value' --output text"
    echo "2. Update OpenAPI schema with endpoint URL: $api_endpoint"
    echo "3. Create Amazon Q Business plugin using infrastructure/amazon-q-plugin-schema.yaml"
    echo "4. Test plugin integration using infrastructure/plugin-validation.md"
    echo
}

# Cleanup function
cleanup() {
    if [[ $? -ne 0 ]]; then
        log_error "Deployment failed. Check the logs above for details."
    fi
}

# Main execution
main() {
    trap cleanup EXIT
    
    log_info "Starting OpsAgent Controller deployment..."
    
    parse_arguments "$@"
    validate_prerequisites
    load_configuration
    build_application
    deploy_application
    post_deployment_setup
    
    log_success "OpsAgent Controller deployment completed successfully!"
}

# Execute main function with all arguments
main "$@"