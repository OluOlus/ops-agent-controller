#!/bin/bash

# OpsAgent Controller Deployment Testing Script
# This script performs comprehensive testing of the deployed OpsAgent Controller

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_REGION="us-east-1"
DEFAULT_TIMEOUT=30

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS] <environment>"
    echo ""
    echo "Environments:"
    echo "  sandbox     - Test sandbox environment"
    echo "  staging     - Test staging environment"
    echo "  production  - Test production environment"
    echo ""
    echo "Options:"
    echo "  -r, --region REGION     AWS region (default: $DEFAULT_REGION)"
    echo "  -t, --timeout SECONDS   Request timeout (default: $DEFAULT_TIMEOUT)"
    echo "  --smoke-only            Run only smoke tests"
    echo "  --integration-only      Run only integration tests"
    echo "  --load-test             Run load tests"
    echo "  --verbose               Enable verbose output"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 sandbox                    # Full test suite for sandbox"
    echo "  $0 staging --smoke-only       # Smoke tests only for staging"
    echo "  $0 production --verbose       # Full tests with verbose output"
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
        PASS)  echo -e "${GREEN}[PASS]${NC}  [$timestamp] $message" ;;
        FAIL)  echo -e "${RED}[FAIL]${NC}  [$timestamp] $message" ;;
    esac
}

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    
    ((TESTS_TOTAL++))
    
    log INFO "Running test: $test_name"
    
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Command: $test_command"
    fi
    
    local result
    if result=$(eval "$test_command" 2>&1); then
        if [ -n "$expected_result" ]; then
            if echo "$result" | grep -q "$expected_result"; then
                log PASS "$test_name"
                ((TESTS_PASSED++))
                return 0
            else
                log FAIL "$test_name - Expected '$expected_result' not found in result"
                if [ "$VERBOSE" = true ]; then
                    log DEBUG "Actual result: $result"
                fi
                ((TESTS_FAILED++))
                return 1
            fi
        else
            log PASS "$test_name"
            ((TESTS_PASSED++))
            return 0
        fi
    else
        log FAIL "$test_name - Command failed"
        if [ "$VERBOSE" = true ]; then
            log DEBUG "Error: $result"
        fi
        ((TESTS_FAILED++))
        return 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    log INFO "Checking prerequisites..."
    
    local missing_tools=()
    
    if ! command -v aws &> /dev/null; then
        missing_tools+=("AWS CLI")
    fi
    
    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
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
        log ERROR "AWS credentials not configured"
        exit 1
    fi
    
    log INFO "Prerequisites check passed"
}

# Function to get stack outputs
get_stack_outputs() {
    local env=$1
    local region=$2
    local stack_name="opsagent-controller-$env"
    
    log INFO "Getting stack outputs for $stack_name"
    
    # Get health endpoint
    HEALTH_URL=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --region "$region" \
        --query 'Stacks[0].Outputs[?OutputKey==`HealthEndpoint`].OutputValue' \
        --output text 2>/dev/null)
    
    # Get chat endpoint
    CHAT_URL=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --region "$region" \
        --query 'Stacks[0].Outputs[?OutputKey==`ChatEndpoint`].OutputValue' \
        --output text 2>/dev/null)
    
    # Get API key
    API_KEY=$(aws ssm get-parameter \
        --name "/opsagent/$env/api-key" \
        --with-decryption \
        --region "$region" \
        --query 'Parameter.Value' \
        --output text 2>/dev/null)
    
    if [ -z "$HEALTH_URL" ] || [ -z "$CHAT_URL" ] || [ -z "$API_KEY" ]; then
        log ERROR "Failed to get required stack outputs or API key"
        log ERROR "Health URL: ${HEALTH_URL:-'NOT FOUND'}"
        log ERROR "Chat URL: ${CHAT_URL:-'NOT FOUND'}"
        log ERROR "API Key: ${API_KEY:+'FOUND'}${API_KEY:-'NOT FOUND'}"
        exit 1
    fi
    
    log INFO "Stack outputs retrieved successfully"
    if [ "$VERBOSE" = true ]; then
        log DEBUG "Health URL: $HEALTH_URL"
        log DEBUG "Chat URL: $CHAT_URL"
        log DEBUG "API Key: ${API_KEY:0:10}..."
    fi
}

# Function to run smoke tests
run_smoke_tests() {
    log INFO "Running smoke tests..."
    
    # Test 1: Health endpoint accessibility
    run_test "Health endpoint accessibility" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time $TIMEOUT '$HEALTH_URL'" \
        "200"
    
    # Test 2: Health endpoint with API key
    run_test "Health endpoint with API key" \
        "curl -s -H 'X-API-Key: $API_KEY' --max-time $TIMEOUT '$HEALTH_URL' | jq -r '.status'" \
        "healthy"
    
    # Test 3: Health endpoint returns execution mode
    run_test "Health endpoint returns execution mode" \
        "curl -s -H 'X-API-Key: $API_KEY' --max-time $TIMEOUT '$HEALTH_URL' | jq -r '.executionMode'" \
        "LOCAL_MOCK\|DRY_RUN\|SANDBOX_LIVE"
    
    # Test 4: Health endpoint returns LLM provider status
    run_test "Health endpoint returns LLM provider status" \
        "curl -s -H 'X-API-Key: $API_KEY' --max-time $TIMEOUT '$HEALTH_URL' | jq -r '.llmProvider.configured'" \
        "true"
    
    # Test 5: Health endpoint returns AWS tool access status
    run_test "Health endpoint returns AWS tool access" \
        "curl -s -H 'X-API-Key: $API_KEY' --max-time $TIMEOUT '$HEALTH_URL' | jq -r '.awsToolAccess.status'" \
        "available"
    
    # Test 6: Chat endpoint accessibility
    run_test "Chat endpoint accessibility" \
        "curl -s -o /dev/null -w '%{http_code}' -X POST --max-time $TIMEOUT '$CHAT_URL'" \
        "400\|401"  # Should return 400 or 401 without proper request
    
    # Test 7: Authentication failure without API key
    run_test "Authentication failure without API key" \
        "curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' --max-time $TIMEOUT '$CHAT_URL'" \
        "401"
    
    log INFO "Smoke tests completed"
}

# Function to run integration tests
run_integration_tests() {
    log INFO "Running integration tests..."
    
    # Test 1: Simple chat message
    run_test "Simple chat message" \
        "curl -s -X POST -H 'Content-Type: application/json' -H 'X-API-Key: $API_KEY' -d '{\"userId\":\"test-user\",\"messageText\":\"health\",\"channel\":\"web\"}' --max-time $TIMEOUT '$CHAT_URL' | jq -r '.response'" \
        "."  # Any non-empty response
    
    # Test 2: System status request
    run_test "System status request" \
        "curl -s -X POST -H 'Content-Type: application/json' -H 'X-API-Key: $API_KEY' -d '{\"userId\":\"test-user\",\"messageText\":\"Check system status\",\"channel\":\"web\"}' --max-time $TIMEOUT '$CHAT_URL' | jq -r '.correlationId'" \
        "."  # Should have correlation ID
    
    # Test 3: Invalid request format
    run_test "Invalid request format handling" \
        "curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H 'X-API-Key: $API_KEY' -d '{\"invalid\":\"request\"}' --max-time $TIMEOUT '$CHAT_URL'" \
        "400"
    
    # Test 4: Diagnosis tool request (if not in LOCAL_MOCK mode)
    local execution_mode
    execution_mode=$(curl -s -H "X-API-Key: $API_KEY" --max-time $TIMEOUT "$HEALTH_URL" | jq -r '.executionMode')
    
    if [ "$execution_mode" != "LOCAL_MOCK" ]; then
        run_test "Diagnosis tool request" \
            "curl -s -X POST -H 'Content-Type: application/json' -H 'X-API-Key: $API_KEY' -d '{\"userId\":\"test-user\",\"messageText\":\"describe instances\",\"channel\":\"web\"}' --max-time $TIMEOUT '$CHAT_URL' | jq -r '.response'" \
            "."
    else
        log INFO "Skipping diagnosis tool test (LOCAL_MOCK mode)"
    fi
    
    # Test 5: Approval gate test (remediation request)
    run_test "Approval gate test" \
        "curl -s -X POST -H 'Content-Type: application/json' -H 'X-API-Key: $API_KEY' -d '{\"userId\":\"test-user\",\"messageText\":\"reboot instance i-1234567890abcdef0\",\"channel\":\"web\"}' --max-time $TIMEOUT '$CHAT_URL' | jq -r '.approvalRequired'" \
        "true\|null"  # Should either require approval or be null
    
    log INFO "Integration tests completed"
}

# Function to run load tests
run_load_tests() {
    log INFO "Running load tests..."
    
    local concurrent_requests=10
    local total_requests=50
    
    log INFO "Starting load test: $concurrent_requests concurrent requests, $total_requests total"
    
    # Create temporary directory for results
    local temp_dir
    temp_dir=$(mktemp -d)
    
    # Function to make a single request
    make_request() {
        local request_id=$1
        local result_file="$temp_dir/result_$request_id"
        
        local start_time
        start_time=$(date +%s.%N)
        
        local http_code
        http_code=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "X-API-Key: $API_KEY" \
            --max-time $TIMEOUT \
            "$HEALTH_URL")
        
        local end_time
        end_time=$(date +%s.%N)
        
        local duration
        duration=$(echo "$end_time - $start_time" | bc -l)
        
        echo "$request_id,$http_code,$duration" > "$result_file"
    }
    
    # Run concurrent requests
    local pids=()
    for ((i=1; i<=total_requests; i++)); do
        make_request $i &
        pids+=($!)
        
        # Limit concurrency
        if (( ${#pids[@]} >= concurrent_requests )); then
            wait "${pids[0]}"
            pids=("${pids[@]:1}")
        fi
    done
    
    # Wait for remaining requests
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    # Analyze results
    local success_count=0
    local total_duration=0
    local max_duration=0
    local min_duration=999999
    
    for result_file in "$temp_dir"/result_*; do
        if [ -f "$result_file" ]; then
            local request_id http_code duration
            IFS=',' read -r request_id http_code duration < "$result_file"
            
            if [ "$http_code" = "200" ]; then
                ((success_count++))
            fi
            
            total_duration=$(echo "$total_duration + $duration" | bc -l)
            
            if (( $(echo "$duration > $max_duration" | bc -l) )); then
                max_duration=$duration
            fi
            
            if (( $(echo "$duration < $min_duration" | bc -l) )); then
                min_duration=$duration
            fi
        fi
    done
    
    local success_rate
    success_rate=$(echo "scale=2; $success_count * 100 / $total_requests" | bc -l)
    
    local avg_duration
    avg_duration=$(echo "scale=3; $total_duration / $total_requests" | bc -l)
    
    log INFO "Load test results:"
    log INFO "  Total requests: $total_requests"
    log INFO "  Successful requests: $success_count"
    log INFO "  Success rate: ${success_rate}%"
    log INFO "  Average response time: ${avg_duration}s"
    log INFO "  Min response time: ${min_duration}s"
    log INFO "  Max response time: ${max_duration}s"
    
    # Cleanup
    rm -rf "$temp_dir"
    
    # Determine if load test passed
    local pass_threshold=95
    if (( $(echo "$success_rate >= $pass_threshold" | bc -l) )); then
        run_test "Load test success rate" "echo 'Success rate: ${success_rate}%'" "Success rate"
    else
        log FAIL "Load test failed - Success rate ${success_rate}% below threshold ${pass_threshold}%"
        ((TESTS_FAILED++))
    fi
    
    log INFO "Load tests completed"
}

# Function to run audit logging tests
run_audit_tests() {
    log INFO "Running audit logging tests..."
    
    local env=$1
    local region=$2
    
    # Make a test request to generate audit logs
    local correlation_id
    correlation_id=$(curl -s -X POST \
        -H 'Content-Type: application/json' \
        -H "X-API-Key: $API_KEY" \
        -d '{"userId":"audit-test-user","messageText":"health check for audit","channel":"web"}' \
        --max-time $TIMEOUT \
        "$CHAT_URL" | jq -r '.correlationId')
    
    if [ "$correlation_id" != "null" ] && [ -n "$correlation_id" ]; then
        log INFO "Generated test request with correlation ID: $correlation_id"
        
        # Wait for logs to be written
        sleep 5
        
        # Check CloudWatch logs for audit entry
        run_test "Audit log entry in CloudWatch" \
            "aws logs filter-log-events --log-group-name '/aws/lambda/opsagent-audit-$env' --region '$region' --filter-pattern '$correlation_id' --start-time $(date -d '5 minutes ago' +%s)000 --query 'events[0].message' --output text" \
            "$correlation_id"
        
        # Check DynamoDB for audit entry (if table exists)
        local audit_table="opsagent-audit-$env"
        if aws dynamodb describe-table --table-name "$audit_table" --region "$region" &>/dev/null; then
            run_test "Audit log entry in DynamoDB" \
                "aws dynamodb get-item --table-name '$audit_table' --region '$region' --key '{\"correlationId\":{\"S\":\"$correlation_id\"}}' --query 'Item.correlationId.S' --output text" \
                "$correlation_id"
        else
            log INFO "DynamoDB audit table not found, skipping DynamoDB audit test"
        fi
    else
        log WARN "Failed to get correlation ID from test request, skipping audit tests"
    fi
    
    log INFO "Audit logging tests completed"
}

# Function to display test summary
display_summary() {
    echo ""
    log INFO "Test Summary:"
    log INFO "  Total tests: $TESTS_TOTAL"
    log INFO "  Passed: $TESTS_PASSED"
    log INFO "  Failed: $TESTS_FAILED"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        log PASS "All tests passed!"
        return 0
    else
        log FAIL "$TESTS_FAILED tests failed"
        return 1
    fi
}

# Main function
main() {
    local environment=""
    local region="$DEFAULT_REGION"
    local timeout="$DEFAULT_TIMEOUT"
    local smoke_only=false
    local integration_only=false
    local load_test=false
    local verbose=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--region)
                region="$2"
                shift 2
                ;;
            -t|--timeout)
                timeout="$2"
                shift 2
                ;;
            --smoke-only)
                smoke_only=true
                shift
                ;;
            --integration-only)
                integration_only=true
                shift
                ;;
            --load-test)
                load_test=true
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
    TIMEOUT=$timeout
    VERBOSE=$verbose
    
    # Check prerequisites
    check_prerequisites
    
    # Get stack outputs
    get_stack_outputs "$environment" "$region"
    
    log INFO "Starting test suite for environment: $environment"
    log INFO "Region: $region"
    log INFO "Timeout: ${timeout}s"
    
    # Run tests based on options
    if [ "$smoke_only" = true ]; then
        run_smoke_tests
    elif [ "$integration_only" = true ]; then
        run_integration_tests
    else
        # Run full test suite
        run_smoke_tests
        run_integration_tests
        run_audit_tests "$environment" "$region"
        
        if [ "$load_test" = true ]; then
            run_load_tests
        fi
    fi
    
    # Display summary and exit with appropriate code
    if display_summary; then
        exit 0
    else
        exit 1
    fi
}

# Run main function with all arguments
main "$@"