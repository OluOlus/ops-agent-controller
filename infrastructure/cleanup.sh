#!/bin/bash

# OpsAgent Controller Cleanup Script
# This script safely removes OpsAgent Controller resources from AWS

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
    echo "Usage: $0 [OPTIONS] <environment>"
    echo ""
    echo "Environments:"
    echo "  sandbox     - Clean up sandbox environment"
    echo "  staging     - Clean up staging environment"
    echo "  production  - Clean up production environment"
    echo "  all         - Clean up all environments (use with caution!)"
    echo ""
    echo "Options:"
    echo "  -r, --region REGION     AWS region (default: $DEFAULT_REGION)"
    echo "  --force                 Skip confirmation prompts"
    echo "  --keep-data             Keep audit logs and DynamoDB data"
    echo "  --keep-params           Keep SSM parameters"
    echo "  --dry-run               Show what would be deleted without actually deleting"
    echo "  --verbose               Enable verbose output"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 sandbox                    # Clean up sandbox with confirmation"
    echo "  $0 staging --force            # Clean up staging without confirmation"
    echo "  $0 production --keep-data     # Clean up production but keep audit data"
    echo "  $0 all --dry-run              # Show what would be deleted in all environments"
    echo ""
    echo "⚠️  WARNING: This script will permanently delete AWS resources!"
    echo "   Make sure you have backups of any important data before proceeding."
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
    
    if ! command -v aws &> /dev/null; then
        log ERROR "AWS CLI is not installed"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log ERROR "AWS credentials not configured"
        exit 1
    fi
    
    log INFO "Prerequisites check passed"
}

# Function to confirm deletion
confirm_deletion() {
    local env=$1
    local force=$2
    
    if [ "$force" = true ]; then
        return 0
    fi
    
    echo ""
    log WARN "You are about to delete OpsAgent Controller resources for environment: $env"
    log WARN "This action cannot be undone!"
    echo ""
    
    if [ "$env" = "all" ]; then
        log ERROR "You are about to delete ALL environments!"
        echo "Type 'DELETE ALL ENVIRONMENTS' to confirm:"
        read -r confirmation
        if [ "$confirmation" != "DELETE ALL ENVIRONMENTS" ]; then
            log INFO "Cleanup cancelled"
            exit 0
        fi
    else
        echo "Type 'DELETE' to confirm:"
        read -r confirmation
        if [ "$confirmation" != "DELETE" ]; then
            log INFO "Cleanup cancelled"
            exit 0
        fi
    fi
    
    echo ""
    log INFO "Proceeding with cleanup..."
}

# Function to list resources to be deleted
list_resources() {
    local env=$1
    local region=$2
    local dry_run=$3
    
    local stack_name="opsagent-controller-$env"
    
    if [ "$dry_run" = true ]; then
        log INFO "DRY RUN: Resources that would be deleted for environment: $env"
    else
        log INFO "Listing resources for environment: $env"
    fi
    
    # Check if stack exists
    if aws cloudformation describe-stacks --stack-name "$stack_name" --region "$region" &>/dev/null; then
        log INFO "CloudFormation Stack: $stack_name"
        
        # List stack resources
        if [ "$VERBOSE" = true ]; then
            aws cloudformation list-stack-resources \
                --stack-name "$stack_name" \
                --region "$region" \
                --query 'StackResourceSummaries[*].[ResourceType,LogicalResourceId,PhysicalResourceId]' \
                --output table
        fi
    else
        log WARN "CloudFormation stack not found: $stack_name"
    fi
    
    # List SSM parameters
    local params
    params=$(aws ssm get-parameters-by-path \
        --path "/opsagent/$env/" \
        --region "$region" \
        --query 'Parameters[*].Name' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$params" ]; then
        log INFO "SSM Parameters:"
        for param in $params; do
            log INFO "  - $param"
        done
    fi
    
    # Check for additional resources that might not be in the stack
    log INFO "Checking for additional resources..."
    
    # Check for Lambda functions
    local lambda_functions
    lambda_functions=$(aws lambda list-functions \
        --region "$region" \
        --query "Functions[?starts_with(FunctionName, 'opsagent-controller-$env')].FunctionName" \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$lambda_functions" ]; then
        log INFO "Lambda Functions:"
        for func in $lambda_functions; do
            log INFO "  - $func"
        done
    fi
    
    # Check for API Gateways
    local api_gateways
    api_gateways=$(aws apigateway get-rest-apis \
        --region "$region" \
        --query "items[?contains(name, 'opsagent') && contains(name, '$env')].{name:name,id:id}" \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$api_gateways" ]; then
        log INFO "API Gateways:"
        echo "$api_gateways" | while read -r name id; do
            log INFO "  - $name ($id)"
        done
    fi
}

# Function to backup data before deletion
backup_data() {
    local env=$1
    local region=$2
    
    log INFO "Creating backup of audit data for environment: $env"
    
    local backup_dir="opsagent-backup-$env-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup SSM parameters
    log INFO "Backing up SSM parameters..."
    aws ssm get-parameters-by-path \
        --path "/opsagent/$env/" \
        --recursive \
        --with-decryption \
        --region "$region" \
        --query 'Parameters[*].{Name:Name,Value:Value,Type:Type}' \
        --output json > "$backup_dir/ssm-parameters.json" 2>/dev/null || true
    
    # Backup DynamoDB data
    local audit_table="opsagent-audit-$env"
    if aws dynamodb describe-table --table-name "$audit_table" --region "$region" &>/dev/null; then
        log INFO "Backing up DynamoDB audit data..."
        aws dynamodb scan \
            --table-name "$audit_table" \
            --region "$region" \
            --output json > "$backup_dir/dynamodb-audit-data.json" 2>/dev/null || true
    fi
    
    # Backup CloudWatch logs (recent entries)
    local log_groups=(
        "/aws/lambda/opsagent-controller-$env"
        "/aws/lambda/opsagent-audit-$env"
        "/aws/apigateway/opsagent-$env"
    )
    
    for log_group in "${log_groups[@]}"; do
        if aws logs describe-log-groups --log-group-name-prefix "$log_group" --region "$region" &>/dev/null; then
            log INFO "Backing up CloudWatch logs: $log_group"
            aws logs filter-log-events \
                --log-group-name "$log_group" \
                --region "$region" \
                --start-time $(date -d '30 days ago' +%s)000 \
                --output json > "$backup_dir/cloudwatch-logs-$(basename "$log_group").json" 2>/dev/null || true
        fi
    done
    
    # Create backup summary
    cat > "$backup_dir/backup-info.txt" << EOF
OpsAgent Controller Backup
Environment: $env
Region: $region
Created: $(date)
Created by: $(aws sts get-caller-identity --query 'Arn' --output text)

Files in this backup:
- ssm-parameters.json: SSM Parameter Store values
- dynamodb-audit-data.json: DynamoDB audit table data
- cloudwatch-logs-*.json: Recent CloudWatch log entries

To restore SSM parameters:
aws ssm put-parameter --cli-input-json file://ssm-parameters.json

To restore DynamoDB data:
aws dynamodb batch-write-item --request-items file://dynamodb-restore.json
EOF
    
    log INFO "Backup created in directory: $backup_dir"
    
    # Compress backup
    tar -czf "$backup_dir.tar.gz" "$backup_dir"
    rm -rf "$backup_dir"
    
    log INFO "Backup compressed to: $backup_dir.tar.gz"
}

# Function to delete CloudFormation stack
delete_stack() {
    local env=$1
    local region=$2
    local dry_run=$3
    
    local stack_name="opsagent-controller-$env"
    
    if [ "$dry_run" = true ]; then
        log INFO "DRY RUN: Would delete CloudFormation stack: $stack_name"
        return 0
    fi
    
    if aws cloudformation describe-stacks --stack-name "$stack_name" --region "$region" &>/dev/null; then
        log INFO "Deleting CloudFormation stack: $stack_name"
        
        aws cloudformation delete-stack \
            --stack-name "$stack_name" \
            --region "$region"
        
        log INFO "Waiting for stack deletion to complete..."
        aws cloudformation wait stack-delete-complete \
            --stack-name "$stack_name" \
            --region "$region"
        
        log INFO "Stack deleted successfully: $stack_name"
    else
        log WARN "Stack not found: $stack_name"
    fi
}

# Function to delete SSM parameters
delete_parameters() {
    local env=$1
    local region=$2
    local dry_run=$3
    local keep_params=$4
    
    if [ "$keep_params" = true ]; then
        log INFO "Keeping SSM parameters as requested"
        return 0
    fi
    
    local params
    params=$(aws ssm get-parameters-by-path \
        --path "/opsagent/$env/" \
        --region "$region" \
        --query 'Parameters[*].Name' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$params" ]; then
        for param in $params; do
            if [ "$dry_run" = true ]; then
                log INFO "DRY RUN: Would delete SSM parameter: $param"
            else
                log INFO "Deleting SSM parameter: $param"
                aws ssm delete-parameter \
                    --name "$param" \
                    --region "$region" 2>/dev/null || true
            fi
        done
    else
        log INFO "No SSM parameters found for environment: $env"
    fi
}

# Function to delete additional resources
delete_additional_resources() {
    local env=$1
    local region=$2
    local dry_run=$3
    local keep_data=$4
    
    # Delete CloudWatch log groups (if not keeping data)
    if [ "$keep_data" = false ]; then
        local log_groups=(
            "/aws/lambda/opsagent-controller-$env"
            "/aws/lambda/opsagent-audit-$env"
            "/aws/apigateway/opsagent-$env"
        )
        
        for log_group in "${log_groups[@]}"; do
            if aws logs describe-log-groups --log-group-name-prefix "$log_group" --region "$region" &>/dev/null; then
                if [ "$dry_run" = true ]; then
                    log INFO "DRY RUN: Would delete CloudWatch log group: $log_group"
                else
                    log INFO "Deleting CloudWatch log group: $log_group"
                    aws logs delete-log-group \
                        --log-group-name "$log_group" \
                        --region "$region" 2>/dev/null || true
                fi
            fi
        done
    fi
    
    # Check for orphaned resources
    log INFO "Checking for orphaned resources..."
    
    # Check for Lambda functions not deleted by CloudFormation
    local lambda_functions
    lambda_functions=$(aws lambda list-functions \
        --region "$region" \
        --query "Functions[?starts_with(FunctionName, 'opsagent-controller-$env')].FunctionName" \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$lambda_functions" ]; then
        for func in $lambda_functions; do
            if [ "$dry_run" = true ]; then
                log INFO "DRY RUN: Would delete orphaned Lambda function: $func"
            else
                log WARN "Found orphaned Lambda function: $func"
                log WARN "Manual deletion may be required"
            fi
        done
    fi
}

# Function to clean up single environment
cleanup_environment() {
    local env=$1
    local region=$2
    local dry_run=$3
    local keep_data=$4
    local keep_params=$5
    local force=$6
    
    log INFO "Starting cleanup for environment: $env"
    
    # List resources
    list_resources "$env" "$region" "$dry_run"
    
    if [ "$dry_run" = true ]; then
        log INFO "DRY RUN completed for environment: $env"
        return 0
    fi
    
    # Confirm deletion
    confirm_deletion "$env" "$force"
    
    # Create backup if not keeping data
    if [ "$keep_data" = false ]; then
        backup_data "$env" "$region"
    fi
    
    # Delete resources
    delete_stack "$env" "$region" "$dry_run"
    delete_parameters "$env" "$region" "$dry_run" "$keep_params"
    delete_additional_resources "$env" "$region" "$dry_run" "$keep_data"
    
    log INFO "Cleanup completed for environment: $env"
}

# Function to clean up all environments
cleanup_all_environments() {
    local region=$1
    local dry_run=$2
    local keep_data=$3
    local keep_params=$4
    local force=$5
    
    local environments=("sandbox" "staging" "production")
    
    if [ "$dry_run" = false ]; then
        confirm_deletion "all" "$force"
    fi
    
    for env in "${environments[@]}"; do
        log INFO "Processing environment: $env"
        
        # Check if environment exists
        local stack_name="opsagent-controller-$env"
        if aws cloudformation describe-stacks --stack-name "$stack_name" --region "$region" &>/dev/null; then
            cleanup_environment "$env" "$region" "$dry_run" "$keep_data" "$keep_params" true
        else
            log INFO "Environment $env not found, skipping"
        fi
        
        echo ""
    done
}

# Main function
main() {
    local environment=""
    local region="$DEFAULT_REGION"
    local force=false
    local keep_data=false
    local keep_params=false
    local dry_run=false
    local verbose=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--region)
                region="$2"
                shift 2
                ;;
            --force)
                force=true
                shift
                ;;
            --keep-data)
                keep_data=true
                shift
                ;;
            --keep-params)
                keep_params=true
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --verbose)
                verbose=true
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
                    log ERROR "Multiple environments specified"
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
    
    # Set global variables
    VERBOSE=$verbose
    
    # Check prerequisites
    check_prerequisites
    
    log INFO "OpsAgent Controller Cleanup"
    log INFO "Environment: $environment"
    log INFO "Region: $region"
    log INFO "Dry run: $dry_run"
    log INFO "Keep data: $keep_data"
    log INFO "Keep parameters: $keep_params"
    log INFO "Force: $force"
    
    # Execute cleanup
    if [ "$environment" = "all" ]; then
        cleanup_all_environments "$region" "$dry_run" "$keep_data" "$keep_params" "$force"
    else
        cleanup_environment "$environment" "$region" "$dry_run" "$keep_data" "$keep_params" "$force"
    fi
    
    if [ "$dry_run" = false ]; then
        log INFO "Cleanup completed successfully!"
        
        if [ "$keep_data" = false ]; then
            log INFO "Backup files have been created for your records"
        fi
        
        log INFO "You may want to check for any remaining resources manually"
    else
        log INFO "Dry run completed - no resources were actually deleted"
    fi
}

# Run main function with all arguments
main "$@"