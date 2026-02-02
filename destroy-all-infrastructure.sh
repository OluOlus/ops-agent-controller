#!/bin/bash

# OpsAgent Controller Infrastructure Destruction Script
# This script removes ALL infrastructure created during deployment

set -e

# Configuration
AWS_REGION="us-west-2"
ENVIRONMENT="sandbox"
STACK_NAME="opsagent-controller-full"
TEST_RESOURCES_STACK="opsagent-test-resources-full"
OLD_STACK_NAME="opsagent-controller-test"
OLD_TEST_RESOURCES_STACK="opsagent-test-resources-test"

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

# Function to delete CloudFormation stack
delete_stack() {
    local stack_name=$1
    local description=$2
    
    log INFO "Checking if stack exists: $stack_name"
    
    if aws cloudformation describe-stacks --stack-name "$stack_name" --region "$AWS_REGION" >/dev/null 2>&1; then
        log INFO "Deleting $description: $stack_name"
        aws cloudformation delete-stack --stack-name "$stack_name" --region "$AWS_REGION"
        
        log INFO "Waiting for stack deletion to complete: $stack_name"
        aws cloudformation wait stack-delete-complete --stack-name "$stack_name" --region "$AWS_REGION"
        
        if [ $? -eq 0 ]; then
            log INFO "$description deleted successfully: $stack_name"
        else
            log ERROR "Failed to delete $description: $stack_name"
        fi
    else
        log WARN "Stack not found: $stack_name"
    fi
}

# Function to delete DynamoDB tables
delete_dynamodb_tables() {
    log INFO "Deleting DynamoDB tables..."
    
    local tables=(
        "opsagent-audit-${ENVIRONMENT}"
        "opsagent-incidents-${ENVIRONMENT}"
        "opsagent-approvals-${ENVIRONMENT}"
    )
    
    for table in "${tables[@]}"; do
        if aws dynamodb describe-table --table-name "$table" --region "$AWS_REGION" >/dev/null 2>&1; then
            log INFO "Deleting DynamoDB table: $table"
            aws dynamodb delete-table --table-name "$table" --region "$AWS_REGION" || true
        else
            log WARN "DynamoDB table not found: $table"
        fi
    done
}

# Function to delete CloudWatch log groups
delete_cloudwatch_logs() {
    log INFO "Deleting CloudWatch log groups..."
    
    local log_groups=(
        "/aws/lambda/opsagent-audit-${ENVIRONMENT}"
        "/aws/lambda/opsagent-controller"
        "/aws/lambda/opsagent-controller-${ENVIRONMENT}"
        "/aws/apigateway/opsagent-${ENVIRONMENT}"
        "/ecs/opsagent-test-${ENVIRONMENT}"
    )
    
    for log_group in "${log_groups[@]}"; do
        if aws logs describe-log-groups --log-group-name-prefix "$log_group" --region "$AWS_REGION" --query 'logGroups[0].logGroupName' --output text 2>/dev/null | grep -q "$log_group"; then
            log INFO "Deleting CloudWatch log group: $log_group"
            aws logs delete-log-group --log-group-name "$log_group" --region "$AWS_REGION" || true
        else
            log WARN "CloudWatch log group not found: $log_group"
        fi
    done
}

# Function to delete SNS topics
delete_sns_topics() {
    log INFO "Deleting SNS topics..."
    
    local topic_name="opsagent-notifications-${ENVIRONMENT}"
    local topic_arn="arn:aws:sns:${AWS_REGION}:$(aws sts get-caller-identity --query Account --output text):${topic_name}"
    
    if aws sns get-topic-attributes --topic-arn "$topic_arn" --region "$AWS_REGION" >/dev/null 2>&1; then
        log INFO "Deleting SNS topic: $topic_name"
        aws sns delete-topic --topic-arn "$topic_arn" --region "$AWS_REGION" || true
    else
        log WARN "SNS topic not found: $topic_name"
    fi
}

# Function to delete SSM parameters
delete_ssm_parameters() {
    log INFO "Deleting SSM parameters..."
    
    local parameters=(
        "/opsagent/${ENVIRONMENT}/api-key"
        "/opsagent/plugin-api-key-${ENVIRONMENT}"
        "/opsagent/api-key"
        "/opsagent/sandbox/api-key"
        "/opsagent/teams-bot-app-secret"
    )
    
    for param in "${parameters[@]}"; do
        if aws ssm get-parameter --name "$param" --region "$AWS_REGION" >/dev/null 2>&1; then
            log INFO "Deleting SSM parameter: $param"
            aws ssm delete-parameter --name "$param" --region "$AWS_REGION" || true
        else
            log WARN "SSM parameter not found: $param"
        fi
    done
}

# Function to delete S3 buckets (SAM deployment artifacts)
delete_s3_buckets() {
    log INFO "Deleting S3 buckets..."
    
    # Find SAM deployment buckets
    local buckets=$(aws s3api list-buckets --query 'Buckets[?contains(Name, `sam-cli-managed`) || contains(Name, `opsagent`)].Name' --output text --region "$AWS_REGION" 2>/dev/null || true)
    
    if [ -n "$buckets" ]; then
        for bucket in $buckets; do
            log INFO "Emptying and deleting S3 bucket: $bucket"
            aws s3 rm "s3://$bucket" --recursive --region "$AWS_REGION" || true
            aws s3api delete-bucket --bucket "$bucket" --region "$AWS_REGION" || true
        done
    else
        log WARN "No SAM deployment buckets found"
    fi
}

# Function to clean up local files
cleanup_local_files() {
    log INFO "Cleaning up local files..."
    
    local files_to_remove=(
        ".env.full"
        ".env.test"
        ".api_key_temp"
        "live_environment_report_*.md"
        "validation_report_*.json"
        "setup.log"
        "live_tests.log"
        "validation.log"
        "unit_tests.log"
        "smoke_test_report.json"
    )
    
    for file_pattern in "${files_to_remove[@]}"; do
        if ls $file_pattern 1> /dev/null 2>&1; then
            log INFO "Removing local files: $file_pattern"
            rm -f $file_pattern
        fi
    done
    
    # Remove SAM build artifacts
    if [ -d ".aws-sam" ]; then
        log INFO "Removing SAM build artifacts"
        rm -rf .aws-sam
    fi
}

# Main execution
main() {
    log INFO "🔥 Starting OpsAgent Controller Infrastructure Destruction"
    log INFO "Environment: $ENVIRONMENT"
    log INFO "Region: $AWS_REGION"
    
    # Set AWS credentials (configure these with your credentials)
    export AWS_ACCESS_KEY_ID="your-aws-access-key-id"
    export AWS_SECRET_ACCESS_KEY="your-aws-secret-access-key"
    export AWS_DEFAULT_REGION="$AWS_REGION"
    
    log WARN "This will delete ALL OpsAgent infrastructure. Proceeding in 5 seconds..."
    sleep 5
    
    # Delete CloudFormation stacks (order matters - main stack first, then test resources)
    delete_stack "$STACK_NAME" "Main OpsAgent stack"
    delete_stack "$OLD_STACK_NAME" "Old OpsAgent stack"
    delete_stack "$TEST_RESOURCES_STACK" "Test resources stack"
    delete_stack "$OLD_TEST_RESOURCES_STACK" "Old test resources stack"
    
    # Delete individual resources that might not be in stacks
    delete_dynamodb_tables
    delete_cloudwatch_logs
    delete_sns_topics
    delete_ssm_parameters
    delete_s3_buckets
    
    # Clean up local files
    cleanup_local_files
    
    log INFO "🎉 Infrastructure destruction completed!"
    log INFO ""
    log INFO "Summary of deleted resources:"
    log INFO "- CloudFormation stacks: Main and test resource stacks"
    log INFO "- DynamoDB tables: Audit, incidents, approvals"
    log INFO "- CloudWatch log groups: Lambda and API Gateway logs"
    log INFO "- SNS topics: Notification topics"
    log INFO "- SSM parameters: API keys and configuration"
    log INFO "- S3 buckets: SAM deployment artifacts"
    log INFO "- Local files: Environment configs and logs"
    log INFO ""
    log INFO "All OpsAgent infrastructure has been destroyed."
}

# Confirmation prompt
echo -e "${RED}WARNING: This will destroy ALL OpsAgent infrastructure!${NC}"
echo "This includes:"
echo "  - CloudFormation stacks"
echo "  - DynamoDB tables"
echo "  - CloudWatch log groups"
echo "  - SNS topics"
echo "  - SSM parameters"
echo "  - S3 buckets"
echo "  - Local configuration files"
echo ""
read -p "Are you sure you want to proceed? (yes/no): " confirm

if [ "$confirm" = "yes" ]; then
    main "$@"
else
    echo "Infrastructure destruction cancelled."
    exit 0
fi