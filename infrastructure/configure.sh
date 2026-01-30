#!/bin/bash

# OpsAgent Controller Configuration Management Script
# Manages configuration for different environments and execution modes

set -e

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/config"

# Default values
ENVIRONMENT="sandbox"
AWS_REGION="us-east-1"
DRY_RUN="false"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
OpsAgent Controller Configuration Management

USAGE:
    $0 COMMAND [OPTIONS]

COMMANDS:
    init                Initialize configuration for environment
    update              Update existing configuration
    validate            Validate configuration
    show                Display current configuration
    set-mode            Change execution mode
    rotate-keys         Rotate API keys
    update-users        Update user allow-list
    backup              Backup current configuration
    restore             Restore configuration from backup

OPTIONS:
    -e, --environment ENV       Target environment (sandbox, staging, production)
    -r, --region REGION         AWS region
    -n, --dry-run              Show what would be done without making changes
    -h, --help                 Show this help message

EXAMPLES:
    # Initialize sandbox environment
    $0 init --environment sandbox
    
    # Update production configuration
    $0 update --environment production
    
    # Change execution mode
    $0 set-mode --environment sandbox DRY_RUN
    
    # Rotate API keys
    $0 rotate-keys --environment production
    
    # Update user allow-list
    $0 update-users --environment production "user1@company.com,user2@company.com"

EOF
}

# Parse command line arguments
parse_arguments() {
    COMMAND="$1"
    shift
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -r|--region)
                AWS_REGION="$2"
                shift 2
                ;;
            -n|--dry-run)
                DRY_RUN="true"
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                # Store remaining arguments for command-specific parsing
                REMAINING_ARGS+=("$1")
                shift
                ;;
        esac
    done
}

# Validate prerequisites
validate_prerequisites() {
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed"
        exit 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured"
        exit 1
    fi
    
    if [[ ! "$ENVIRONMENT" =~ ^(sandbox|staging|production)$ ]]; then
        log_error "Invalid environment: $ENVIRONMENT"
        exit 1
    fi
}

# Get stack name
get_stack_name() {
    echo "opsagent-controller-$ENVIRONMENT"
}

# Check if stack exists
stack_exists() {
    local stack_name="$1"
    aws cloudformation describe-stacks --stack-name "$stack_name" --region "$AWS_REGION" &> /dev/null
}

# Initialize configuration
init_configuration() {
    log_info "Initializing configuration for $ENVIRONMENT environment..."
    
    local stack_name
    stack_name=$(get_stack_name)
    
    if ! stack_exists "$stack_name"; then
        log_error "Stack $stack_name does not exist. Deploy first using deploy.sh"
        exit 1
    fi
    
    # Set default API key
    log_info "Setting up API key..."
    local api_key_value
    if [[ "$ENVIRONMENT" == "production" ]]; then
        api_key_value=$(openssl rand -base64 32)
        log_warning "Generated secure API key for production"
    else
        api_key_value="opsagent-${ENVIRONMENT}-$(date +%Y%m%d)"
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would set API key parameter"
    else
        aws ssm put-parameter \
            --name "/opsagent/api-key" \
            --value "$api_key_value" \
            --type "SecureString" \
            --overwrite \
            --region "$AWS_REGION"
        log_success "API key configured"
    fi
    
    # Set default user allow-list
    log_info "Setting up user allow-list..."
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
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would set allowed users: $allowed_users"
    else
        aws ssm put-parameter \
            --name "/opsagent/allowed-users" \
            --value "$allowed_users" \
            --type "StringList" \
            --overwrite \
            --region "$AWS_REGION"
        log_success "User allow-list configured"
    fi
    
    # Set execution mode
    local execution_mode
    case "$ENVIRONMENT" in
        sandbox)
            execution_mode="SANDBOX_LIVE"
            ;;
        staging)
            execution_mode="SANDBOX_LIVE"
            ;;
        production)
            execution_mode="SANDBOX_LIVE"
            ;;
    esac
    
    set_execution_mode "$execution_mode"
    
    log_success "Configuration initialized for $ENVIRONMENT"
}

# Update configuration
update_configuration() {
    log_info "Updating configuration for $ENVIRONMENT environment..."
    
    local stack_name
    stack_name=$(get_stack_name)
    
    if ! stack_exists "$stack_name"; then
        log_error "Stack $stack_name does not exist"
        exit 1
    fi
    
    # Update Lambda environment variables if needed
    local function_name="opsagent-controller-$ENVIRONMENT"
    
    log_info "Checking Lambda function configuration..."
    
    if aws lambda get-function --function-name "$function_name" --region "$AWS_REGION" &> /dev/null; then
        log_success "Lambda function found: $function_name"
        
        # Get current environment variables
        local current_env
        current_env=$(aws lambda get-function-configuration \
            --function-name "$function_name" \
            --region "$AWS_REGION" \
            --query 'Environment.Variables' \
            --output json)
        
        log_info "Current environment variables:"
        echo "$current_env" | jq .
    else
        log_warning "Lambda function not found: $function_name"
    fi
    
    log_success "Configuration update completed"
}

# Validate configuration
validate_configuration() {
    log_info "Validating configuration for $ENVIRONMENT environment..."
    
    local stack_name
    stack_name=$(get_stack_name)
    
    if ! stack_exists "$stack_name"; then
        log_error "Stack $stack_name does not exist"
        exit 1
    fi
    
    local errors=0
    
    # Check API key parameter
    log_info "Checking API key parameter..."
    if aws ssm get-parameter --name "/opsagent/api-key" --region "$AWS_REGION" &> /dev/null; then
        log_success "API key parameter exists"
    else
        log_error "API key parameter missing"
        ((errors++))
    fi
    
    # Check user allow-list parameter
    log_info "Checking user allow-list parameter..."
    if aws ssm get-parameter --name "/opsagent/allowed-users" --region "$AWS_REGION" &> /dev/null; then
        log_success "User allow-list parameter exists"
        
        local users
        users=$(aws ssm get-parameter \
            --name "/opsagent/allowed-users" \
            --region "$AWS_REGION" \
            --query 'Parameter.Value' \
            --output text)
        log_info "Allowed users: $users"
    else
        log_error "User allow-list parameter missing"
        ((errors++))
    fi
    
    # Check Lambda function
    local function_name="opsagent-controller-$ENVIRONMENT"
    log_info "Checking Lambda function..."
    if aws lambda get-function --function-name "$function_name" --region "$AWS_REGION" &> /dev/null; then
        log_success "Lambda function exists: $function_name"
        
        # Check execution mode
        local execution_mode
        execution_mode=$(aws lambda get-function-configuration \
            --function-name "$function_name" \
            --region "$AWS_REGION" \
            --query 'Environment.Variables.EXECUTION_MODE' \
            --output text)
        
        if [[ "$execution_mode" != "None" ]]; then
            log_success "Execution mode: $execution_mode"
        else
            log_error "Execution mode not set"
            ((errors++))
        fi
    else
        log_error "Lambda function not found: $function_name"
        ((errors++))
    fi
    
    # Check API Gateway
    log_info "Checking API Gateway..."
    local api_endpoint
    api_endpoint=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`PluginApiEndpointUrl`].OutputValue' \
        --output text \
        --region "$AWS_REGION")
    
    if [[ -n "$api_endpoint" && "$api_endpoint" != "None" ]]; then
        log_success "API endpoint: $api_endpoint"
        
        # Test health endpoint
        log_info "Testing health endpoint..."
        if curl -f -s "$api_endpoint/health" > /dev/null; then
            log_success "Health endpoint responding"
        else
            log_warning "Health endpoint not responding"
        fi
    else
        log_error "API endpoint not found"
        ((errors++))
    fi
    
    # Summary
    if [[ $errors -eq 0 ]]; then
        log_success "Configuration validation passed"
    else
        log_error "Configuration validation failed with $errors errors"
        exit 1
    fi
}

# Show current configuration
show_configuration() {
    log_info "Current configuration for $ENVIRONMENT environment:"
    
    local stack_name
    stack_name=$(get_stack_name)
    
    if ! stack_exists "$stack_name"; then
        log_error "Stack $stack_name does not exist"
        exit 1
    fi
    
    echo
    echo "=== Stack Information ==="
    echo "Stack Name: $stack_name"
    echo "Region: $AWS_REGION"
    
    # Stack outputs
    echo
    echo "=== Stack Outputs ==="
    aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
        --output table
    
    # Parameters
    echo
    echo "=== SSM Parameters ==="
    
    # API key (don't show value)
    if aws ssm get-parameter --name "/opsagent/api-key" --region "$AWS_REGION" &> /dev/null; then
        echo "API Key: [CONFIGURED]"
    else
        echo "API Key: [NOT CONFIGURED]"
    fi
    
    # User allow-list
    if aws ssm get-parameter --name "/opsagent/allowed-users" --region "$AWS_REGION" &> /dev/null; then
        local users
        users=$(aws ssm get-parameter \
            --name "/opsagent/allowed-users" \
            --region "$AWS_REGION" \
            --query 'Parameter.Value' \
            --output text)
        echo "Allowed Users: $users"
    else
        echo "Allowed Users: [NOT CONFIGURED]"
    fi
    
    # Lambda configuration
    echo
    echo "=== Lambda Configuration ==="
    local function_name="opsagent-controller-$ENVIRONMENT"
    
    if aws lambda get-function --function-name "$function_name" --region "$AWS_REGION" &> /dev/null; then
        aws lambda get-function-configuration \
            --function-name "$function_name" \
            --region "$AWS_REGION" \
            --query '{
                Runtime: Runtime,
                MemorySize: MemorySize,
                Timeout: Timeout,
                ExecutionMode: Environment.Variables.EXECUTION_MODE,
                Environment: Environment.Variables.ENVIRONMENT,
                LLMProvider: Environment.Variables.LLM_PROVIDER
            }' \
            --output table
    else
        echo "Lambda function not found: $function_name"
    fi
}

# Set execution mode
set_execution_mode() {
    local new_mode="$1"
    
    if [[ -z "$new_mode" ]]; then
        if [[ ${#REMAINING_ARGS[@]} -gt 0 ]]; then
            new_mode="${REMAINING_ARGS[0]}"
        else
            log_error "Execution mode not specified"
            exit 1
        fi
    fi
    
    if [[ ! "$new_mode" =~ ^(LOCAL_MOCK|DRY_RUN|SANDBOX_LIVE)$ ]]; then
        log_error "Invalid execution mode: $new_mode"
        exit 1
    fi
    
    # Production validation
    if [[ "$ENVIRONMENT" == "production" && "$new_mode" == "LOCAL_MOCK" ]]; then
        log_error "LOCAL_MOCK mode not allowed in production"
        exit 1
    fi
    
    log_info "Setting execution mode to $new_mode for $ENVIRONMENT..."
    
    local function_name="opsagent-controller-$ENVIRONMENT"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would update Lambda environment variable EXECUTION_MODE=$new_mode"
    else
        # Get current environment variables
        local current_env
        current_env=$(aws lambda get-function-configuration \
            --function-name "$function_name" \
            --region "$AWS_REGION" \
            --query 'Environment.Variables' \
            --output json)
        
        # Update execution mode
        local updated_env
        updated_env=$(echo "$current_env" | jq --arg mode "$new_mode" '.EXECUTION_MODE = $mode')
        
        aws lambda update-function-configuration \
            --function-name "$function_name" \
            --environment "Variables=$updated_env" \
            --region "$AWS_REGION" > /dev/null
        
        log_success "Execution mode updated to $new_mode"
    fi
}

# Rotate API keys
rotate_keys() {
    log_info "Rotating API keys for $ENVIRONMENT environment..."
    
    local new_api_key
    if [[ "$ENVIRONMENT" == "production" ]]; then
        new_api_key=$(openssl rand -base64 32)
    else
        new_api_key="opsagent-${ENVIRONMENT}-$(date +%Y%m%d-%H%M%S)"
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would rotate API key"
    else
        # Update API key
        aws ssm put-parameter \
            --name "/opsagent/api-key" \
            --value "$new_api_key" \
            --type "SecureString" \
            --overwrite \
            --region "$AWS_REGION"
        
        # Update plugin API key
        local plugin_key_param="/opsagent/plugin-api-key-$ENVIRONMENT"
        if aws ssm get-parameter --name "$plugin_key_param" --region "$AWS_REGION" &> /dev/null; then
            local plugin_api_key
            plugin_api_key=$(aws ssm get-parameter \
                --name "$plugin_key_param" \
                --with-decryption \
                --region "$AWS_REGION" \
                --query 'Parameter.Value' \
                --output text)
            
            log_info "Plugin API key: $plugin_api_key (retrieve for Amazon Q Business plugin update)"
        fi
        
        log_success "API keys rotated"
        log_warning "Update Amazon Q Business plugin with new API key"
    fi
}

# Update user allow-list
update_users() {
    local new_users="$1"
    
    if [[ -z "$new_users" ]]; then
        if [[ ${#REMAINING_ARGS[@]} -gt 0 ]]; then
            new_users="${REMAINING_ARGS[0]}"
        else
            log_error "User list not specified"
            exit 1
        fi
    fi
    
    log_info "Updating user allow-list for $ENVIRONMENT..."
    log_info "New users: $new_users"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would update user allow-list"
    else
        aws ssm put-parameter \
            --name "/opsagent/allowed-users" \
            --value "$new_users" \
            --type "StringList" \
            --overwrite \
            --region "$AWS_REGION"
        
        log_success "User allow-list updated"
    fi
}

# Main execution
main() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi
    
    parse_arguments "$@"
    validate_prerequisites
    
    case "$COMMAND" in
        init)
            init_configuration
            ;;
        update)
            update_configuration
            ;;
        validate)
            validate_configuration
            ;;
        show)
            show_configuration
            ;;
        set-mode)
            set_execution_mode
            ;;
        rotate-keys)
            rotate_keys
            ;;
        update-users)
            update_users
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            show_help
            exit 1
            ;;
    esac
}

main "$@"