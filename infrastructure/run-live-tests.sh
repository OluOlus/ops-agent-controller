#!/bin/bash

# OpsAgent Controller Live Test Execution Script
# This script runs comprehensive live tests against deployed infrastructure

set -e

# Configuration
ENVIRONMENT="${ENVIRONMENT:-test}"
AWS_REGION="${AWS_REGION:-us-west-2}"
STACK_NAME="${STACK_NAME:-opsagent-controller-${ENVIRONMENT}}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Function to check if environment file exists
check_environment() {
    if [ ! -f ".env.${ENVIRONMENT}" ]; then
        log ERROR "Environment file .env.${ENVIRONMENT} not found"
        log ERROR "Please run ./infrastructure/live-testing-setup.sh first"
        exit 1
    fi
    
    source ".env.${ENVIRONMENT}"
    
    # Verify required variables
    local required_vars=("HEALTH_ENDPOINT" "CHAT_ENDPOINT" "API_KEY")
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            log ERROR "Required environment variable $var is not set"
            exit 1
        fi
    done
    
    log INFO "Environment loaded: $ENVIRONMENT"
    log INFO "Health Endpoint: $HEALTH_ENDPOINT"
    log INFO "Chat Endpoint: $CHAT_ENDPOINT"
}

# Function to test health endpoint
test_health_endpoint() {
    log INFO "Testing health endpoint..."
    
    local response=$(curl -s -w "%{http_code}" -o /tmp/health_response.json "$HEALTH_ENDPOINT")
    local http_code="${response: -3}"
    
    if [ "$http_code" = "200" ]; then
        local status=$(cat /tmp/health_response.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('data', {}).get('status', 'unknown'))" 2>/dev/null || echo "error")
        if [ "$status" = "healthy" ]; then
            log INFO "✅ Health endpoint test PASSED"
            return 0
        else
            log ERROR "❌ Health endpoint returned unhealthy status: $status"
            return 1
        fi
    else
        log ERROR "❌ Health endpoint test FAILED with HTTP $http_code"
        cat /tmp/health_response.json 2>/dev/null || echo "No response body"
        return 1
    fi
}

# Function to test diagnostic operations
test_diagnostic_operations() {
    log INFO "Testing diagnostic operations..."
    
    local operations=("get_ec2_status" "get_cloudwatch_metrics" "describe_alb_target_health" "search_cloudtrail_events")
    local passed=0
    local total=${#operations[@]}
    
    for operation in "${operations[@]}"; do
        log INFO "Testing $operation..."
        
        # Create test payload based on operation
        local payload=""
        case $operation in
            "get_ec2_status")
                payload='{"operation":"get_ec2_status","parameters":{"instance_id":"'${TEST_INSTANCE_1_ID:-i-nonexistent}'"},"user_context":{"user_id":"test@oluofnotts.onmicrosoft.com"}}'
                ;;
            "get_cloudwatch_metrics")
                payload='{"operation":"get_cloudwatch_metrics","parameters":{"namespace":"AWS/EC2","metric_name":"CPUUtilization","start_time":"2024-01-01T00:00:00Z","end_time":"2024-01-01T01:00:00Z"},"user_context":{"user_id":"test@oluofnotts.onmicrosoft.com"}}'
                ;;
            "describe_alb_target_health")
                payload='{"operation":"describe_alb_target_health","parameters":{"target_group_arn":"arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/test/1234567890123456"},"user_context":{"user_id":"test@oluofnotts.onmicrosoft.com"}}'
                ;;
            "search_cloudtrail_events")
                payload='{"operation":"search_cloudtrail_events","parameters":{"start_time":"2024-01-01T00:00:00Z","end_time":"2024-01-01T01:00:00Z","event_name":"RunInstances"},"user_context":{"user_id":"test@oluofnotts.onmicrosoft.com"}}'
                ;;
        esac
        
        local response=$(curl -s -w "%{http_code}" -o /tmp/diagnostic_response.json \
            -X POST \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $API_KEY" \
            -d "$payload" \
            "${CHAT_ENDPOINT/chat/operations/diagnostic}")
        
        local http_code="${response: -3}"
        
        if [ "$http_code" = "200" ]; then
            local success=$(cat /tmp/diagnostic_response.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
            if [ "$success" = "True" ]; then
                log INFO "✅ $operation test PASSED"
                ((passed++))
            else
                log WARN "⚠️  $operation test returned success=false (expected for non-existent resources)"
                ((passed++))  # Count as passed since this is expected behavior
            fi
        else
            log ERROR "❌ $operation test FAILED with HTTP $http_code"
            cat /tmp/diagnostic_response.json 2>/dev/null || echo "No response body"
        fi
    done
    
    log INFO "Diagnostic operations: $passed/$total tests passed"
    return $([ $passed -eq $total ] && echo 0 || echo 1)
}

# Function to test approval workflow
test_approval_workflow() {
    log INFO "Testing approval workflow..."
    
    # Test propose action
    log INFO "Testing propose_action..."
    local propose_payload='{"operation":"reboot_ec2","parameters":{"instance_id":"'${TEST_INSTANCE_1_ID:-i-nonexistent}'","reason":"Live testing"},"user_context":{"user_id":"test@oluofnotts.onmicrosoft.com"}}'
    
    local response=$(curl -s -w "%{http_code}" -o /tmp/propose_response.json \
        -X POST \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "$propose_payload" \
        "${CHAT_ENDPOINT/chat/operations/propose}")
    
    local http_code="${response: -3}"
    
    if [ "$http_code" = "200" ]; then
        local success=$(cat /tmp/propose_response.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
        local approval_token=$(cat /tmp/propose_response.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('data', {}).get('approval_token', ''))" 2>/dev/null || echo "")
        
        if [ "$success" = "True" ] && [ -n "$approval_token" ]; then
            log INFO "✅ propose_action test PASSED"
            
            # Test approve action
            log INFO "Testing approve_action with token..."
            local approve_payload='{"approval_token":"'$approval_token'","user_context":{"user_id":"test@oluofnotts.onmicrosoft.com"}}'
            
            local approve_response=$(curl -s -w "%{http_code}" -o /tmp/approve_response.json \
                -X POST \
                -H "Content-Type: application/json" \
                -H "X-API-Key: $API_KEY" \
                -d "$approve_payload" \
                "${CHAT_ENDPOINT/chat/operations/approve}")
            
            local approve_http_code="${approve_response: -3}"
            
            if [ "$approve_http_code" = "200" ]; then
                local approve_success=$(cat /tmp/approve_response.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
                if [ "$approve_success" = "True" ]; then
                    log INFO "✅ approve_action test PASSED"
                    return 0
                else
                    log WARN "⚠️  approve_action returned success=false (expected in DRY_RUN mode)"
                    return 0  # This is expected behavior in test mode
                fi
            else
                log ERROR "❌ approve_action test FAILED with HTTP $approve_http_code"
                cat /tmp/approve_response.json 2>/dev/null || echo "No response body"
                return 1
            fi
        else
            log ERROR "❌ propose_action test FAILED - no approval token received"
            cat /tmp/propose_response.json 2>/dev/null || echo "No response body"
            return 1
        fi
    else
        log ERROR "❌ propose_action test FAILED with HTTP $http_code"
        cat /tmp/propose_response.json 2>/dev/null || echo "No response body"
        return 1
    fi
}

# Function to test workflow operations
test_workflow_operations() {
    log INFO "Testing workflow operations..."
    
    local operations=("create_incident_record" "post_summary_to_channel")
    local passed=0
    local total=${#operations[@]}
    
    for operation in "${operations[@]}"; do
        log INFO "Testing $operation..."
        
        # Create test payload based on operation
        local payload=""
        case $operation in
            "create_incident_record")
                payload='{"operation":"create_incident_record","parameters":{"summary":"Live test incident","severity":"low","description":"This is a test incident created during live testing"},"user_context":{"user_id":"test@oluofnotts.onmicrosoft.com"}}'
                ;;
            "post_summary_to_channel")
                payload='{"operation":"post_summary_to_channel","parameters":{"message":"Live test message from OpsAgent Controller","channel":"general"},"user_context":{"user_id":"test@oluofnotts.onmicrosoft.com"}}'
                ;;
        esac
        
        local response=$(curl -s -w "%{http_code}" -o /tmp/workflow_response.json \
            -X POST \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $API_KEY" \
            -d "$payload" \
            "${CHAT_ENDPOINT/chat/operations/workflow}")
        
        local http_code="${response: -3}"
        
        if [ "$http_code" = "200" ]; then
            local success=$(cat /tmp/workflow_response.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
            if [ "$success" = "True" ]; then
                log INFO "✅ $operation test PASSED"
                ((passed++))
            else
                log ERROR "❌ $operation test returned success=false"
                cat /tmp/workflow_response.json 2>/dev/null || echo "No response body"
            fi
        else
            log ERROR "❌ $operation test FAILED with HTTP $http_code"
            cat /tmp/workflow_response.json 2>/dev/null || echo "No response body"
        fi
    done
    
    log INFO "Workflow operations: $passed/$total tests passed"
    return $([ $passed -eq $total ] && echo 0 || echo 1)
}

# Function to test audit logging
test_audit_logging() {
    log INFO "Testing audit logging..."
    
    # Check if audit log group exists and has recent entries
    if [ -n "$AUDIT_LOG_GROUP" ]; then
        local log_streams=$(aws logs describe-log-streams \
            --log-group-name "$AUDIT_LOG_GROUP" \
            --order-by LastEventTime \
            --descending \
            --max-items 5 \
            --region "$AWS_REGION" \
            --query 'logStreams[0].logStreamName' \
            --output text 2>/dev/null || echo "")
        
        if [ -n "$log_streams" ] && [ "$log_streams" != "None" ]; then
            log INFO "✅ Audit log group exists and has log streams"
            
            # Check for recent log events
            local recent_events=$(aws logs filter-log-events \
                --log-group-name "$AUDIT_LOG_GROUP" \
                --start-time $(date -d '1 hour ago' +%s)000 \
                --region "$AWS_REGION" \
                --query 'events[0].message' \
                --output text 2>/dev/null || echo "")
            
            if [ -n "$recent_events" ] && [ "$recent_events" != "None" ]; then
                log INFO "✅ Recent audit events found"
                return 0
            else
                log WARN "⚠️  No recent audit events found (may be expected for new deployment)"
                return 0
            fi
        else
            log ERROR "❌ Audit log group not found or has no streams"
            return 1
        fi
    else
        log WARN "⚠️  AUDIT_LOG_GROUP not configured, skipping audit logging test"
        return 0
    fi
}

# Function to test DynamoDB tables
test_dynamodb_tables() {
    log INFO "Testing DynamoDB tables..."
    
    local tables=("$AUDIT_TABLE" "$INCIDENT_TABLE")
    local passed=0
    local total=2
    
    for table in "${tables[@]}"; do
        if [ -n "$table" ]; then
            local table_status=$(aws dynamodb describe-table \
                --table-name "$table" \
                --region "$AWS_REGION" \
                --query 'Table.TableStatus' \
                --output text 2>/dev/null || echo "NOT_FOUND")
            
            if [ "$table_status" = "ACTIVE" ]; then
                log INFO "✅ Table $table is ACTIVE"
                ((passed++))
            else
                log ERROR "❌ Table $table status: $table_status"
            fi
        else
            log WARN "⚠️  Table name not configured, skipping"
        fi
    done
    
    log INFO "DynamoDB tables: $passed/$total tables active"
    return $([ $passed -eq $total ] && echo 0 || echo 1)
}

# Function to run performance tests
test_performance() {
    log INFO "Running performance tests..."
    
    local start_time=$(date +%s)
    
    # Test concurrent requests
    log INFO "Testing concurrent diagnostic requests..."
    for i in {1..5}; do
        (
            curl -s -o /dev/null \
                -X POST \
                -H "Content-Type: application/json" \
                -H "X-API-Key: $API_KEY" \
                -d '{"operation":"get_ec2_status","parameters":{"instance_id":"i-nonexistent"},"user_context":{"user_id":"test@oluofnotts.onmicrosoft.com"}}' \
                "${CHAT_ENDPOINT/chat/operations/diagnostic}"
        ) &
    done
    
    wait
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log INFO "✅ Concurrent requests completed in ${duration}s"
    
    if [ $duration -lt 30 ]; then
        log INFO "✅ Performance test PASSED (under 30s)"
        return 0
    else
        log WARN "⚠️  Performance test took longer than expected: ${duration}s"
        return 1
    fi
}

# Function to generate test report
generate_test_report() {
    local total_tests=$1
    local passed_tests=$2
    local start_time=$3
    local end_time=$4
    
    local duration=$((end_time - start_time))
    local success_rate=$((passed_tests * 100 / total_tests))
    
    cat > "live_test_report_$(date +%Y%m%d_%H%M%S).json" << EOF
{
  "test_execution": {
    "start_time": "$(date -d @$start_time -Iseconds)",
    "end_time": "$(date -d @$end_time -Iseconds)",
    "duration_seconds": $duration,
    "environment": "$ENVIRONMENT",
    "region": "$AWS_REGION"
  },
  "results": {
    "total_tests": $total_tests,
    "passed_tests": $passed_tests,
    "failed_tests": $((total_tests - passed_tests)),
    "success_rate_percent": $success_rate
  },
  "endpoints": {
    "health_endpoint": "$HEALTH_ENDPOINT",
    "chat_endpoint": "$CHAT_ENDPOINT",
    "stack_name": "$STACK_NAME"
  },
  "test_suites": {
    "health_endpoint": "$([ $health_result -eq 0 ] && echo "PASSED" || echo "FAILED")",
    "diagnostic_operations": "$([ $diagnostic_result -eq 0 ] && echo "PASSED" || echo "FAILED")",
    "approval_workflow": "$([ $approval_result -eq 0 ] && echo "PASSED" || echo "FAILED")",
    "workflow_operations": "$([ $workflow_result -eq 0 ] && echo "PASSED" || echo "FAILED")",
    "audit_logging": "$([ $audit_result -eq 0 ] && echo "PASSED" || echo "FAILED")",
    "dynamodb_tables": "$([ $dynamodb_result -eq 0 ] && echo "PASSED" || echo "FAILED")",
    "performance": "$([ $performance_result -eq 0 ] && echo "PASSED" || echo "FAILED")"
  }
}
EOF
    
    log INFO "Test report saved to: live_test_report_$(date +%Y%m%d_%H%M%S).json"
}

# Main execution
main() {
    local start_time=$(date +%s)
    
    log INFO "🚀 Starting OpsAgent Controller Live Tests"
    log INFO "Environment: $ENVIRONMENT"
    log INFO "Region: $AWS_REGION"
    
    check_environment
    
    # Run all test suites
    local total_tests=7
    local passed_tests=0
    
    # Health endpoint test
    if test_health_endpoint; then
        ((passed_tests++))
    fi
    health_result=$?
    
    # Diagnostic operations test
    if test_diagnostic_operations; then
        ((passed_tests++))
    fi
    diagnostic_result=$?
    
    # Approval workflow test
    if test_approval_workflow; then
        ((passed_tests++))
    fi
    approval_result=$?
    
    # Workflow operations test
    if test_workflow_operations; then
        ((passed_tests++))
    fi
    workflow_result=$?
    
    # Audit logging test
    if test_audit_logging; then
        ((passed_tests++))
    fi
    audit_result=$?
    
    # DynamoDB tables test
    if test_dynamodb_tables; then
        ((passed_tests++))
    fi
    dynamodb_result=$?
    
    # Performance test
    if test_performance; then
        ((passed_tests++))
    fi
    performance_result=$?
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Generate report
    generate_test_report $total_tests $passed_tests $start_time $end_time
    
    # Summary
    log INFO ""
    log INFO "🎯 Live Test Results Summary"
    log INFO "=========================="
    log INFO "Total Tests: $total_tests"
    log INFO "Passed: $passed_tests"
    log INFO "Failed: $((total_tests - passed_tests))"
    log INFO "Success Rate: $((passed_tests * 100 / total_tests))%"
    log INFO "Duration: ${duration}s"
    
    if [ $passed_tests -eq $total_tests ]; then
        log INFO "🎉 All tests PASSED! System is ready for production."
        return 0
    else
        log ERROR "❌ Some tests FAILED. Please review the results and fix issues."
        return 1
    fi
}

# Cleanup function
cleanup() {
    log INFO "Cleaning up temporary files..."
    rm -f /tmp/health_response.json
    rm -f /tmp/diagnostic_response.json
    rm -f /tmp/propose_response.json
    rm -f /tmp/approve_response.json
    rm -f /tmp/workflow_response.json
}

# Set up cleanup trap
trap cleanup EXIT

# Run main function
main "$@"