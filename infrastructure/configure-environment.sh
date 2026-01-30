#!/bin/bash

# OpsAgent Controller Configuration Management Script
# This script manages environment-specific configuration and credentials

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_REGION="us-east-1"

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS] <command> <environment>"
    echo ""
    echo "Commands:"
    echo "  setup-credentials    Set up AWS and LLM provider credentials"
    echo "  setup-teams         Set up Microsoft Teams integration"
    echo "  setup-slack         Set up Slack integration (future)"
    echo "  update-config       Update environment configuration"
    echo "  validate-config     Validate current configuration"
    echo "  export-config       Export configuration for backup"
    echo "  import-config       Import configuration from backup"
    echo ""
    echo "Environments:"
    echo "  sandbox     - Development environment"
    echo "  staging     - Testing environment"
    echo "  production  - Production environment"
    echo ""
    echo "Options:"
    echo "  -r, --region REGION    AWS region (default: $DEFAULT_REGION)"
    echo "  -f, --file FILE        Configuration file for import/export"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup-credentials sandbox"
    echo "  $0 setup-teams production --region us-west-2"
    echo "  $0 validate-config staging"
    echo "  $0 export-config production --file prod-config.json"
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
    
    if ! command -v aws &> /dev/null; then
        missing_tools+=("AWS CLI")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log ERROR "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log ERROR "AWS credentials not configured. Please run 'aws configure' first"
        exit 1
    fi
    
    log INFO "Prerequisites check passed"
}

# Function to setup credentials
setup_credentials() {
    local env=$1
    local region=$2
    
    log INFO "Setting up credentials for environment: $env"
    
    # Setup API key for authentication
    echo -e "${YELLOW}Setting up API key for authentication...${NC}"
    read -s -p "Enter API key for $env environment (leave empty to generate): " api_key
    echo
    
    if [ -z "$api_key" ]; then
        # Generate a secure API key
        api_key=$(openssl rand -base64 32)
        log INFO "Generated secure API key"
    fi
    
    # Store API key in SSM Parameter Store
    aws ssm put-parameter \
        --name "/opsagent/$env/api-key" \
        --value "$api_key" \
        --type SecureString \
        --overwrite \
        --region "$region" \
        --description "API key for OpsAgent Controller ($env environment)" \
        --tags "Key=Project,Value=OpsAgent" "Key=Environment,Value=$env"
    
    log INFO "API key stored in SSM Parameter Store: /opsagent/$env/api-key"
    
    # Setup LLM provider credentials
    echo -e "${YELLOW}Setting up LLM provider credentials...${NC}"
    echo "1. Bedrock (AWS native)"
    echo "2. OpenAI"
    echo "3. Azure OpenAI"
    read -p "Select LLM provider (1-3): " llm_choice
    
    case $llm_choice in
        1)
            log INFO "Using AWS Bedrock - no additional credentials needed"
            log INFO "Ensure Bedrock model access is enabled in your AWS account"
            ;;
        2)
            read -s -p "Enter OpenAI API key: " openai_key
            echo
            aws ssm put-parameter \
                --name "/opsagent/$env/openai-api-key" \
                --value "$openai_key" \
                --type SecureString \
                --overwrite \
                --region "$region" \
                --description "OpenAI API key for OpsAgent Controller ($env environment)" \
                --tags "Key=Project,Value=OpsAgent" "Key=Environment,Value=$env"
            log INFO "OpenAI API key stored in SSM Parameter Store"
            ;;
        3)
            read -s -p "Enter Azure OpenAI API key: " azure_key
            echo
            read -p "Enter Azure OpenAI endpoint: " azure_endpoint
            aws ssm put-parameter \
                --name "/opsagent/$env/azure-openai-api-key" \
                --value "$azure_key" \
                --type SecureString \
                --overwrite \
                --region "$region" \
                --description "Azure OpenAI API key for OpsAgent Controller ($env environment)" \
                --tags "Key=Project,Value=OpsAgent" "Key=Environment,Value=$env"
            aws ssm put-parameter \
                --name "/opsagent/$env/azure-openai-endpoint" \
                --value "$azure_endpoint" \
                --type String \
                --overwrite \
                --region "$region" \
                --description "Azure OpenAI endpoint for OpsAgent Controller ($env environment)" \
                --tags "Key=Project,Value=OpsAgent" "Key=Environment,Value=$env"
            log INFO "Azure OpenAI credentials stored in SSM Parameter Store"
            ;;
        *)
            log ERROR "Invalid choice"
            exit 1
            ;;
    esac
    
    log INFO "Credentials setup completed for environment: $env"
}

# Function to setup Teams integration
setup_teams() {
    local env=$1
    local region=$2
    
    log INFO "Setting up Microsoft Teams integration for environment: $env"
    
    echo -e "${YELLOW}Microsoft Teams Bot Setup${NC}"
    echo "You'll need to create a bot registration in Azure Portal first."
    echo "Visit: https://portal.azure.com/#create/Microsoft.BotService"
    echo ""
    
    read -p "Enter Teams Bot App ID: " bot_app_id
    read -s -p "Enter Teams Bot App Secret: " bot_app_secret
    echo
    read -p "Enter Teams Bot Name: " bot_name
    
    # Store Teams credentials
    aws ssm put-parameter \
        --name "/opsagent/$env/teams-bot-app-id" \
        --value "$bot_app_id" \
        --type String \
        --overwrite \
        --region "$region" \
        --description "Teams Bot App ID for OpsAgent Controller ($env environment)" \
        --tags "Key=Project,Value=OpsAgent" "Key=Environment,Value=$env"
    
    aws ssm put-parameter \
        --name "/opsagent/$env/teams-bot-app-secret" \
        --value "$bot_app_secret" \
        --type SecureString \
        --overwrite \
        --region "$region" \
        --description "Teams Bot App Secret for OpsAgent Controller ($env environment)" \
        --tags "Key=Project,Value=OpsAgent" "Key=Environment,Value=$env"
    
    aws ssm put-parameter \
        --name "/opsagent/$env/teams-bot-name" \
        --value "$bot_name" \
        --type String \
        --overwrite \
        --region "$region" \
        --description "Teams Bot Name for OpsAgent Controller ($env environment)" \
        --tags "Key=Project,Value=OpsAgent" "Key=Environment,Value=$env"
    
    log INFO "Teams credentials stored in SSM Parameter Store"
    
    # Get the chat endpoint URL
    local stack_name="opsagent-controller-$env"
    local chat_url
    chat_url=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --region "$region" \
        --query 'Stacks[0].Outputs[?OutputKey==`ChatEndpoint`].OutputValue' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$chat_url" ]; then
        echo -e "${YELLOW}Next Steps for Teams Integration:${NC}"
        echo "1. In Azure Portal, configure the messaging endpoint:"
        echo "   $chat_url"
        echo ""
        echo "2. Create a Teams app manifest with the following details:"
        echo "   - Bot ID: $bot_app_id"
        echo "   - Bot Name: $bot_name"
        echo ""
        echo "3. Install the app in your Teams tenant"
        echo ""
        echo "4. Test the integration by sending a message to the bot"
    else
        log WARN "Could not retrieve chat endpoint URL. Deploy the stack first."
    fi
    
    log INFO "Teams integration setup completed"
}

# Function to update configuration
update_config() {
    local env=$1
    local region=$2
    
    log INFO "Updating configuration for environment: $env"
    
    echo -e "${YELLOW}Current Configuration Parameters:${NC}"
    
    # List current parameters
    aws ssm get-parameters-by-path \
        --path "/opsagent/$env/" \
        --region "$region" \
        --query 'Parameters[*].[Name,Type,LastModifiedDate]' \
        --output table 2>/dev/null || log WARN "No parameters found for environment: $env"
    
    echo ""
    echo "Configuration options:"
    echo "1. Update API key"
    echo "2. Update LLM provider settings"
    echo "3. Update Teams integration"
    echo "4. Update execution mode"
    echo "5. Exit"
    
    read -p "Select option (1-5): " config_choice
    
    case $config_choice in
        1)
            read -s -p "Enter new API key: " new_api_key
            echo
            aws ssm put-parameter \
                --name "/opsagent/$env/api-key" \
                --value "$new_api_key" \
                --type SecureString \
                --overwrite \
                --region "$region"
            log INFO "API key updated"
            ;;
        2)
            setup_credentials "$env" "$region"
            ;;
        3)
            setup_teams "$env" "$region"
            ;;
        4)
            echo "Execution modes:"
            echo "1. LOCAL_MOCK - Mock responses for testing"
            echo "2. DRY_RUN - Real reads, simulated writes"
            echo "3. SANDBOX_LIVE - Full execution on tagged resources"
            read -p "Select execution mode (1-3): " mode_choice
            
            case $mode_choice in
                1) execution_mode="LOCAL_MOCK" ;;
                2) execution_mode="DRY_RUN" ;;
                3) execution_mode="SANDBOX_LIVE" ;;
                *) log ERROR "Invalid choice"; exit 1 ;;
            esac
            
            aws ssm put-parameter \
                --name "/opsagent/$env/execution-mode" \
                --value "$execution_mode" \
                --type String \
                --overwrite \
                --region "$region" \
                --description "Execution mode for OpsAgent Controller ($env environment)"
            log INFO "Execution mode updated to: $execution_mode"
            ;;
        5)
            log INFO "Configuration update cancelled"
            ;;
        *)
            log ERROR "Invalid choice"
            exit 1
            ;;
    esac
}

# Function to validate configuration
validate_config() {
    local env=$1
    local region=$2
    
    log INFO "Validating configuration for environment: $env"
    
    local errors=0
    
    # Check required parameters
    local required_params=(
        "/opsagent/$env/api-key"
    )
    
    for param in "${required_params[@]}"; do
        if ! aws ssm get-parameter --name "$param" --region "$region" &>/dev/null; then
            log ERROR "Missing required parameter: $param"
            ((errors++))
        else
            log INFO "✓ Found parameter: $param"
        fi
    done
    
    # Check stack exists
    local stack_name="opsagent-controller-$env"
    if ! aws cloudformation describe-stacks --stack-name "$stack_name" --region "$region" &>/dev/null; then
        log ERROR "Stack not found: $stack_name"
        ((errors++))
    else
        log INFO "✓ Stack exists: $stack_name"
        
        # Check stack status
        local stack_status
        stack_status=$(aws cloudformation describe-stacks \
            --stack-name "$stack_name" \
            --region "$region" \
            --query 'Stacks[0].StackStatus' \
            --output text)
        
        if [ "$stack_status" != "CREATE_COMPLETE" ] && [ "$stack_status" != "UPDATE_COMPLETE" ]; then
            log WARN "Stack status is not healthy: $stack_status"
        else
            log INFO "✓ Stack status is healthy: $stack_status"
        fi
    fi
    
    # Test endpoints if stack exists
    if [ $errors -eq 0 ]; then
        log INFO "Testing endpoints..."
        
        local health_url
        health_url=$(aws cloudformation describe-stacks \
            --stack-name "$stack_name" \
            --region "$region" \
            --query 'Stacks[0].Outputs[?OutputKey==`HealthEndpoint`].OutputValue' \
            --output text 2>/dev/null)
        
        if [ -n "$health_url" ]; then
            local api_key
            api_key=$(aws ssm get-parameter \
                --name "/opsagent/$env/api-key" \
                --with-decryption \
                --region "$region" \
                --query 'Parameter.Value' \
                --output text)
            
            if curl -s -H "X-API-Key: $api_key" "$health_url" | jq -e '.status == "healthy"' &>/dev/null; then
                log INFO "✓ Health endpoint is responding correctly"
            else
                log ERROR "Health endpoint is not responding correctly"
                ((errors++))
            fi
        fi
    fi
    
    if [ $errors -eq 0 ]; then
        log INFO "Configuration validation passed"
    else
        log ERROR "Configuration validation failed with $errors errors"
        exit 1
    fi
}

# Function to export configuration
export_config() {
    local env=$1
    local region=$2
    local file=$3
    
    log INFO "Exporting configuration for environment: $env"
    
    # Get all parameters
    local params
    params=$(aws ssm get-parameters-by-path \
        --path "/opsagent/$env/" \
        --recursive \
        --with-decryption \
        --region "$region" \
        --query 'Parameters[*].{Name:Name,Value:Value,Type:Type}' \
        --output json 2>/dev/null || echo "[]")
    
    # Get stack outputs
    local stack_name="opsagent-controller-$env"
    local outputs
    outputs=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --region "$region" \
        --query 'Stacks[0].Outputs[*].{OutputKey:OutputKey,OutputValue:OutputValue}' \
        --output json 2>/dev/null || echo "[]")
    
    # Create export file
    local export_data
    export_data=$(jq -n \
        --arg env "$env" \
        --arg region "$region" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson params "$params" \
        --argjson outputs "$outputs" \
        '{
            environment: $env,
            region: $region,
            exportedAt: $timestamp,
            parameters: $params,
            stackOutputs: $outputs
        }')
    
    echo "$export_data" > "$file"
    log INFO "Configuration exported to: $file"
}

# Function to import configuration
import_config() {
    local env=$1
    local region=$2
    local file=$3
    
    log INFO "Importing configuration for environment: $env"
    
    if [ ! -f "$file" ]; then
        log ERROR "Configuration file not found: $file"
        exit 1
    fi
    
    # Read configuration file
    local config_data
    config_data=$(cat "$file")
    
    # Extract parameters
    local params
    params=$(echo "$config_data" | jq -r '.parameters[]')
    
    # Import parameters
    while IFS= read -r param; do
        local name
        local value
        local type
        
        name=$(echo "$param" | jq -r '.Name')
        value=$(echo "$param" | jq -r '.Value')
        type=$(echo "$param" | jq -r '.Type')
        
        # Update parameter name for new environment
        local new_name
        new_name=$(echo "$name" | sed "s|/opsagent/[^/]*/|/opsagent/$env/|")
        
        aws ssm put-parameter \
            --name "$new_name" \
            --value "$value" \
            --type "$type" \
            --overwrite \
            --region "$region" \
            --description "Imported parameter for OpsAgent Controller ($env environment)"
        
        log INFO "Imported parameter: $new_name"
    done <<< "$params"
    
    log INFO "Configuration import completed"
}

# Main function
main() {
    local command=""
    local environment=""
    local region="$DEFAULT_REGION"
    local file=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--region)
                region="$2"
                shift 2
                ;;
            -f|--file)
                file="$2"
                shift 2
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
                if [ -z "$command" ]; then
                    command="$1"
                elif [ -z "$environment" ]; then
                    environment="$1"
                else
                    log ERROR "Too many arguments"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [ -z "$command" ] || [ -z "$environment" ]; then
        log ERROR "Command and environment are required"
        usage
        exit 1
    fi
    
    # Check prerequisites
    check_prerequisites
    
    # Execute command
    case $command in
        setup-credentials)
            setup_credentials "$environment" "$region"
            ;;
        setup-teams)
            setup_teams "$environment" "$region"
            ;;
        setup-slack)
            log ERROR "Slack integration not yet implemented"
            exit 1
            ;;
        update-config)
            update_config "$environment" "$region"
            ;;
        validate-config)
            validate_config "$environment" "$region"
            ;;
        export-config)
            if [ -z "$file" ]; then
                file="opsagent-config-$environment-$(date +%Y%m%d-%H%M%S).json"
            fi
            export_config "$environment" "$region" "$file"
            ;;
        import-config)
            if [ -z "$file" ]; then
                log ERROR "Configuration file is required for import"
                exit 1
            fi
            import_config "$environment" "$region" "$file"
            ;;
        *)
            log ERROR "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"