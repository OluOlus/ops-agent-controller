#!/bin/bash

# OpsAgent Controller Deployment Validation Script
# This script validates a deployed OpsAgent Controller by running comprehensive tests
# Requirements: 11.6, 11.8, 11.10, 11.11, 11.14

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_REGION="us-east-1"
DEFAULT_ENVIRONMENT="sandbox"

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS] [environment]"
    echo ""
    echo "Environments:"
    echo "  sandbox     - Validate sandbox environment (default)"
    echo "  staging     - Validate staging environment"
    echo "  production  - Validate production environment"
    echo ""
    echo "Options:"
    echo "  -r, --region REGION     AWS region (default: $DEFAULT_REGION)"
    echo "  --stack-name NAME       CloudFormation stack name (auto-detected if not provided)"
    echo "  --api-key KEY           API key for authentication (auto-retrieved if not provided)"
    echo "  --smoke-only            Run only smoke tests (no deployed infrastructure tests)"
    echo "  --readiness-only        Run only readiness validation tests"
    echo "  --report-file FILE      Output report file (default: validation_report.json)"
    echo "  --verbose               Enable verbose output"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 sandbox                           # Full validation for sandbox"
    echo "  $0 staging --smoke-only              # Smoke tests only for staging"
    echo "  $0 production --readiness-only       # Readiness tests for production"
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
    
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("Python 3")
    fi
    
    if ! command -v aws &> /dev/null; then
        missing_tools+=("AWS CLI")
    fi
    
    if ! command -v pip3 &> /dev/null; then
        missing_tools+=("pip3")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log ERROR "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log ERROR "AWS credentials not configured"
        exit 1
    fi
    
    # Check Python packages
    local required_packages=("boto3" "requests" "pytest")
    for package in "${required_packages[@]}"; do
        if ! python3 -c "import $package" &> /dev/null; then
            log WARN "Python package $package not found, attempting to install..."
            pip3 install "$package" || {
                log ERROR "Failed to install $package"
                exit 1
            }
        fi
    done
    
    log INFO "Prerequisites check passed"
}

# Function to get stack information
get_stack_info() {
    local environment=$1
    local region=$2
    local stack_name=${3:-"opsagent-controller-$environment"}
    
    log INFO "Getting stack information for $stack_name in $region..."
    
    # Check if stack exists
    if ! aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --region "$region" &> /dev/null; then
        log ERROR "Stack $stack_name not found in region $region"
        exit 1
    fi
    
    # Get stack outputs
    local outputs
    outputs=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --region "$region" \
        --query 'Stacks[0].Outputs' \
        --output json)
    
    if [ "$outputs" = "null" ] || [ -z "$outputs" ]; then
        log ERROR "No outputs found for stack $stack_name"
        exit 1
    fi
    
    # Extract key outputs
    HEALTH_ENDPOINT=$(echo "$outputs" | jq -r '.[] | select(.OutputKey=="HealthEndpoint") | .OutputValue')
    CHAT_ENDPOINT=$(echo "$outputs" | jq -r '.[] | select(.OutputKey=="ChatEndpoint") | .OutputValue')
    AUDIT_LOG_GROUP=$(echo "$outputs" | jq -r '.[] | select(.OutputKey=="AuditLogGroupName") | .OutputValue')
    AUDIT_TABLE=$(echo "$outputs" | jq -r '.[] | select(.OutputKey=="AuditTableName") | .OutputValue')
    TEST_INSTANCE_ID=$(echo "$outputs" | jq -r '.[] | select(.OutputKey=="TestInstanceId") | .OutputValue')
    
    # Validate required outputs
    if [ "$HEALTH_ENDPOINT" = "null" ] || [ -z "$HEALTH_ENDPOINT" ]; then
        log ERROR "Health endpoint not found in stack outputs"
        exit 1
    fi
    
    if [ "$CHAT_ENDPOINT" = "null" ] || [ -z "$CHAT_ENDPOINT" ]; then
        log ERROR "Chat endpoint not found in stack outputs"
        exit 1
    fi
    
    log INFO "Stack information retrieved successfully"
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Health endpoint: $HEALTH_ENDPOINT"
        log DEBUG "Chat endpoint: $CHAT_ENDPOINT"
        log DEBUG "Audit log group: $AUDIT_LOG_GROUP"
        log DEBUG "Audit table: $AUDIT_TABLE"
        log DEBUG "Test instance: $TEST_INSTANCE_ID"
    fi
}

# Function to get API key
get_api_key() {
    local environment=$1
    local region=$2
    local provided_key=$3
    
    if [ -n "$provided_key" ]; then
        API_KEY="$provided_key"
        log INFO "Using provided API key"
        return
    fi
    
    # Try to get API key from SSM Parameter Store
    local param_name="/opsagent/$environment/api-key"
    
    log INFO "Retrieving API key from SSM Parameter Store..."
    
    if API_KEY=$(aws ssm get-parameter \
        --name "$param_name" \
        --with-decryption \
        --region "$region" \
        --query 'Parameter.Value' \
        --output text 2>/dev/null); then
        log INFO "API key retrieved from SSM Parameter Store"
    else
        log WARN "Could not retrieve API key from SSM Parameter Store"
        log WARN "Some tests may fail if authentication is required"
        API_KEY=""
    fi
}

# Function to set up environment variables for tests
setup_test_environment() {
    export EXECUTION_MODE="${EXECUTION_MODE:-LOCAL_MOCK}"
    export ENVIRONMENT="$ENVIRONMENT"
    export AWS_REGION="$REGION"
    export HEALTH_ENDPOINT="$HEALTH_ENDPOINT"
    export CHAT_ENDPOINT="$CHAT_ENDPOINT"
    export API_KEY="$API_KEY"
    export AUDIT_LOG_GROUP="$AUDIT_LOG_GROUP"
    export AUDIT_TABLE="$AUDIT_TABLE"
    export TEST_INSTANCE_ID="$TEST_INSTANCE_ID"
    export STACK_NAME="$STACK_NAME"
    
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Test environment variables set:"
        log DEBUG "  EXECUTION_MODE=$EXECUTION_MODE"
        log DEBUG "  ENVIRONMENT=$ENVIRONMENT"
        log DEBUG "  AWS_REGION=$AWS_REGION"
        log DEBUG "  HEALTH_ENDPOINT=$HEALTH_ENDPOINT"
        log DEBUG "  CHAT_ENDPOINT=$CHAT_ENDPOINT"
        log DEBUG "  API_KEY=${API_KEY:+[SET]}${API_KEY:-[NOT SET]}"
        log DEBUG "  AUDIT_LOG_GROUP=$AUDIT_LOG_GROUP"
        log DEBUG "  AUDIT_TABLE=$AUDIT_TABLE"
        log DEBUG "  TEST_INSTANCE_ID=$TEST_INSTANCE_ID"
    fi
}

# Function to run validation tests
run_validation_tests() {
    local test_suite=$1
    local report_file=$2
    
    log INFO "Running validation tests..."
    log INFO "Test suite: $test_suite"
    log INFO "Report file: $report_file"
    
    # Change to tests directory
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0")")
    local tests_dir="$script_dir/../tests"
    
    if [ ! -d "$tests_dir" ]; then
        log ERROR "Tests directory not found: $tests_dir"
        exit 1
    fi
    
    cd "$tests_dir"
    
    # Run the test runner
    local cmd="python3 run_smoke_tests.py --suite $test_suite --report-file $report_file"
    
    if [ "$VERBOSE" = true ]; then
        cmd="$cmd --verbose"
    fi
    
    log INFO "Executing: $cmd"
    
    if $cmd; then
        log INFO "✅ Validation tests completed successfully"
        return 0
    else
        log ERROR "❌ Validation tests failed"
        return 1
    fi
}

# Function to display results summary
display_results_summary() {
    local report_file=$1
    
    if [ ! -f "$report_file" ]; then
        log WARN "Report file not found: $report_file"
        return
    fi
    
    log INFO "Validation Results Summary:"
    log INFO "=========================="
    
    # Extract key information from JSON report
    if command -v jq &> /dev/null; then
        local total_tests
        local passed_tests
        local failed_tests
        local skipped_tests
        local duration
        
        total_tests=$(jq -r '.summary.total_tests // 0' "$report_file")
        passed_tests=$(jq -r '.summary.passed_tests // 0' "$report_file")
        failed_tests=$(jq -r '.summary.failed_tests // 0' "$report_file")
        skipped_tests=$(jq -r '.summary.skipped_tests // 0' "$report_file")
        duration=$(jq -r '.total_duration_seconds // 0' "$report_file")
        
        log INFO "Total Tests: $total_tests"
        log INFO "Passed: $passed_tests"
        log INFO "Failed: $failed_tests"
        log INFO "Skipped: $skipped_tests"
        log INFO "Duration: ${duration}s"
        
        # Show test suite results
        log INFO ""
        log INFO "Test Suite Results:"
        jq -r '.test_suites | to_entries[] | "  \(.key): \(.value.status | ascii_upcase)"' "$report_file" 2>/dev/null || true
        
        if [ "$failed_tests" -gt 0 ]; then
            log ERROR "❌ VALIDATION FAILED - $failed_tests test(s) failed"
            return 1
        else
            log INFO "✅ VALIDATION PASSED - All tests successful"
            return 0
        fi
    else
        log WARN "jq not available, cannot parse detailed results"
        log INFO "Check report file for details: $report_file"
    fi
}

# Main function
main() {
    local environment="$DEFAULT_ENVIRONMENT"
    local region="$DEFAULT_REGION"
    local stack_name=""
    local api_key=""
    local test_suite="all"
    local report_file="validation_report.json"
    local verbose=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--region)
                region="$2"
                shift 2
                ;;
            --stack-name)
                stack_name="$2"
                shift 2
                ;;
            --api-key)
                api_key="$2"
                shift 2
                ;;
            --smoke-only)
                test_suite="smoke"
                shift
                ;;
            --readiness-only)
                test_suite="readiness"
                shift
                ;;
            --report-file)
                report_file="$2"
                shift 2
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
                if [ -z "$environment" ] || [ "$environment" = "$DEFAULT_ENVIRONMENT" ]; then
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
    
    # Set global variables
    ENVIRONMENT="$environment"
    REGION="$region"
    STACK_NAME="${stack_name:-opsagent-controller-$environment}"
    VERBOSE="$verbose"
    
    log INFO "Starting OpsAgent Controller deployment validation"
    log INFO "Environment: $ENVIRONMENT"
    log INFO "Region: $REGION"
    log INFO "Stack: $STACK_NAME"
    log INFO "Test suite: $test_suite"
    
    # Check prerequisites
    check_prerequisites
    
    # Get stack information
    get_stack_info "$ENVIRONMENT" "$REGION" "$STACK_NAME"
    
    # Get API key
    get_api_key "$ENVIRONMENT" "$REGION" "$api_key"
    
    # Set up test environment
    setup_test_environment
    
    # Run validation tests
    if run_validation_tests "$test_suite" "$report_file"; then
        # Display results summary
        if display_results_summary "$report_file"; then
            log INFO "🎉 Deployment validation completed successfully!"
            exit 0
        else
            log ERROR "💥 Deployment validation failed!"
            exit 1
        fi
    else
        log ERROR "💥 Failed to run validation tests!"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"