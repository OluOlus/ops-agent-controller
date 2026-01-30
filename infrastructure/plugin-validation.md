# Amazon Q Business Plugin Testing and Validation Procedures

This document provides comprehensive testing and validation procedures for the OpsAgent Actions plugin in Amazon Q Business.

## Overview

The validation process ensures that:
1. Plugin integration works correctly with Amazon Q Business
2. All 8 operations function as expected
3. Security controls are properly enforced
4. Audit logging captures all activities
5. Error handling provides meaningful feedback

## Pre-Validation Checklist

### Infrastructure Deployment
- [ ] SAM stack deployed successfully
- [ ] API Gateway endpoint accessible
- [ ] Lambda function running without errors
- [ ] DynamoDB tables created and accessible
- [ ] CloudWatch logs configured
- [ ] SNS topic created for notifications

### Configuration Verification
- [ ] API key retrieved from SSM Parameter Store
- [ ] OpenAPI schema file updated with correct endpoint URL
- [ ] User allow-list configured in SSM
- [ ] Test resources tagged with `OpsAgentManaged=true`
- [ ] Execution mode set appropriately for environment

### Amazon Q Business Setup
- [ ] Plugin created in Amazon Q Business console
- [ ] OpenAPI schema uploaded successfully
- [ ] API key configured in plugin settings
- [ ] Plugin enabled and accessible

## Validation Test Suite

### Test 1: Health Check Validation

**Objective**: Verify basic connectivity and system health

**Steps**:
1. Test direct API endpoint:
   ```bash
   curl -X GET "https://YOUR_API_ENDPOINT/health"
   ```

2. Expected Response:
   ```json
   {
     "status": "healthy",
     "execution_mode": "SANDBOX_LIVE",
     "version": "1.0.0",
     "timestamp": "2024-01-15T10:00:00Z",
     "services": {
       "aws_connectivity": "ok",
       "dynamodb": "ok",
       "cloudwatch": "ok"
     }
   }
   ```

3. Test through Amazon Q Business:
   - Send message: "Check OpsAgent health"
   - Verify plugin responds with health status

**Success Criteria**:
- [ ] Direct API call returns 200 OK
- [ ] All services show "ok" status
- [ ] Amazon Q Business can invoke health check
- [ ] Response time < 5 seconds

### Test 2: Authentication and Authorization

**Objective**: Verify security controls are working

**Steps**:
1. Test without API key:
   ```bash
   curl -X POST "https://YOUR_API_ENDPOINT/operations/diagnostic" \
     -H "Content-Type: application/json" \
     -d '{"operation":"get_ec2_status","parameters":{"instance_id":"i-123"},"user_context":{"user_id":"test@company.com"}}'
   ```

2. Expected Response: 401 Unauthorized

3. Test with invalid API key:
   ```bash
   curl -X POST "https://YOUR_API_ENDPOINT/operations/diagnostic" \
     -H "Content-Type: application/json" \
     -H "X-API-Key: invalid-key" \
     -d '{"operation":"get_ec2_status","parameters":{"instance_id":"i-123"},"user_context":{"user_id":"test@company.com"}}'
   ```

4. Expected Response: 401 Unauthorized

5. Test with unauthorized user:
   ```bash
   curl -X POST "https://YOUR_API_ENDPOINT/operations/diagnostic" \
     -H "Content-Type: application/json" \
     -H "X-API-Key: YOUR_VALID_API_KEY" \
     -d '{"operation":"get_ec2_status","parameters":{"instance_id":"i-123"},"user_context":{"user_id":"unauthorized@company.com"}}'
   ```

6. Expected Response: 403 Forbidden

**Success Criteria**:
- [ ] Requests without API key are rejected
- [ ] Requests with invalid API key are rejected
- [ ] Unauthorized users are rejected
- [ ] Error messages are informative but not revealing

### Test 3: Diagnostic Operations

**Objective**: Verify all 4 diagnostic operations work correctly

#### Test 3.1: get_ec2_status

**Steps**:
1. Through Amazon Q Business, send:
   ```
   "Get status of EC2 instance i-1234567890abcdef0"
   ```

2. Verify response includes:
   - Instance state
   - CPU utilization
   - Memory utilization (if available)
   - Network metrics
   - Execution mode indicator

**Success Criteria**:
- [ ] Operation completes without errors
- [ ] Response includes structured data
- [ ] Summary is human-readable
- [ ] Correlation ID is present

#### Test 3.2: get_cloudwatch_metrics

**Steps**:
1. Send message:
   ```
   "Show CloudWatch CPU metrics for instance i-1234567890abcdef0 over last hour"
   ```

2. Verify response includes:
   - Metric values
   - Time range
   - Statistical data
   - Proper units

**Success Criteria**:
- [ ] Metrics data is retrieved
- [ ] Time window is respected
- [ ] Data is properly formatted
- [ ] No sensitive information exposed

#### Test 3.3: describe_alb_target_health

**Steps**:
1. Send message:
   ```
   "Check target health for ALB arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456"
   ```

2. Verify response includes:
   - Target health status
   - Healthy/unhealthy counts
   - Target details

**Success Criteria**:
- [ ] Target health data retrieved
- [ ] Health status clearly indicated
- [ ] Unhealthy targets identified
- [ ] Response is actionable

#### Test 3.4: search_cloudtrail_events

**Steps**:
1. Send message:
   ```
   "Search CloudTrail for RunInstances events in last 24 hours"
   ```

2. Verify response includes:
   - Event details
   - Timestamps
   - User information
   - Resource information

**Success Criteria**:
- [ ] CloudTrail events retrieved
- [ ] Time filter applied correctly
- [ ] Event data is complete
- [ ] Sensitive data is sanitized

### Test 4: Write Operations (Approval Workflow)

**Objective**: Verify approval workflow for write operations

#### Test 4.1: Propose Action

**Steps**:
1. Send message:
   ```
   "Reboot EC2 instance i-1234567890abcdef0 due to high CPU utilization"
   ```

2. Verify response includes:
   - Approval token
   - Expiration time (15 minutes)
   - Action summary
   - Risk assessment
   - Approval instructions

**Success Criteria**:
- [ ] Approval token generated
- [ ] Token format is correct (approve-[alphanumeric])
- [ ] Expiration time is 15 minutes from now
- [ ] Instructions are clear
- [ ] Risk level is assessed

#### Test 4.2: Approve Action

**Steps**:
1. Using token from previous test, send:
   ```
   "Approve action with token approve-abc123def456"
   ```

2. Verify response includes:
   - Execution confirmation
   - Target resource
   - Execution status
   - Timestamp

**Success Criteria**:
- [ ] Action executes successfully (or simulates in DRY_RUN)
- [ ] Token is consumed (cannot be reused)
- [ ] Execution status is clear
- [ ] Audit log entry created

#### Test 4.3: Token Expiration

**Steps**:
1. Generate approval token
2. Wait 16 minutes
3. Attempt to use expired token

**Success Criteria**:
- [ ] Expired token is rejected
- [ ] Error message indicates expiration
- [ ] No action is executed

#### Test 4.4: Resource Tag Validation

**Steps**:
1. Attempt to reboot instance without `OpsAgentManaged=true` tag:
   ```
   "Reboot EC2 instance i-untagged-instance due to issues"
   ```

**Success Criteria**:
- [ ] Request is rejected at proposal stage
- [ ] Error message indicates missing tag
- [ ] No approval token is generated

### Test 5: Workflow Operations

**Objective**: Verify workflow operations function correctly

#### Test 5.1: Create Incident Record

**Steps**:
1. Send message:
   ```
   "Create incident record for high CPU utilization with medium severity"
   ```

2. Verify response includes:
   - Incident ID
   - Creation timestamp
   - Notification status

**Success Criteria**:
- [ ] Incident record created in DynamoDB
- [ ] Incident ID is unique and properly formatted
- [ ] SNS notification sent (if configured)
- [ ] Audit log entry created

#### Test 5.2: Post Summary to Channel

**Steps**:
1. Send message:
   ```
   "Post summary to channel: Resolved high CPU issue on production instances"
   ```

2. Verify response includes:
   - Message delivery status
   - Timestamp
   - Channel/webhook confirmation

**Success Criteria**:
- [ ] Message posted successfully
- [ ] Delivery confirmation received
- [ ] Proper formatting maintained
- [ ] Audit log entry created

### Test 6: Error Handling

**Objective**: Verify proper error handling and user feedback

#### Test 6.1: Invalid Parameters

**Steps**:
1. Send malformed request:
   ```
   "Get status of EC2 instance invalid-instance-id"
   ```

**Success Criteria**:
- [ ] Validation error returned
- [ ] Error message is helpful
- [ ] No system information leaked
- [ ] Correlation ID provided

#### Test 6.2: AWS API Errors

**Steps**:
1. Request status for non-existent instance:
   ```
   "Get status of EC2 instance i-nonexistent123456"
   ```

**Success Criteria**:
- [ ] AWS error handled gracefully
- [ ] User-friendly error message
- [ ] Technical details logged but not exposed
- [ ] Retry guidance provided if applicable

### Test 7: Audit Logging

**Objective**: Verify comprehensive audit trail

**Steps**:
1. Perform various operations (diagnostic, propose, approve, workflow)
2. Check audit logs in DynamoDB table
3. Verify CloudWatch logs

**Success Criteria**:
- [ ] All operations logged
- [ ] Correlation IDs consistent
- [ ] User information captured
- [ ] Timestamps accurate
- [ ] Sensitive data sanitized
- [ ] Log entries immutable

### Test 8: Performance and Scalability

**Objective**: Verify system performance under load

#### Test 8.1: Response Time

**Steps**:
1. Measure response times for each operation type
2. Test with concurrent requests

**Success Criteria**:
- [ ] Diagnostic operations < 5 seconds
- [ ] Approval operations < 3 seconds
- [ ] Workflow operations < 10 seconds
- [ ] No degradation with concurrent requests

#### Test 8.2: Rate Limiting

**Steps**:
1. Send requests exceeding rate limits
2. Verify throttling behavior

**Success Criteria**:
- [ ] Rate limits enforced
- [ ] 429 status code returned
- [ ] Retry-After header provided
- [ ] System remains stable

## Validation Automation

### Automated Test Script

Create a comprehensive test script:

```python
#!/usr/bin/env python3
"""
OpsAgent Plugin Validation Script
Automated testing for Amazon Q Business plugin integration
"""

import requests
import json
import time
import uuid
from datetime import datetime, timedelta

class OpsAgentValidator:
    def __init__(self, api_endpoint, api_key):
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.headers = {
            'Content-Type': 'application/json',
            'X-API-Key': api_key
        }
        self.test_results = []
    
    def run_all_tests(self):
        """Run complete validation suite"""
        print("Starting OpsAgent Plugin Validation...")
        
        # Test 1: Health Check
        self.test_health_check()
        
        # Test 2: Authentication
        self.test_authentication()
        
        # Test 3: Diagnostic Operations
        self.test_diagnostic_operations()
        
        # Test 4: Approval Workflow
        self.test_approval_workflow()
        
        # Test 5: Workflow Operations
        self.test_workflow_operations()
        
        # Test 6: Error Handling
        self.test_error_handling()
        
        # Generate Report
        self.generate_report()
    
    def test_health_check(self):
        """Test health endpoint"""
        print("\n=== Testing Health Check ===")
        
        try:
            response = requests.get(f"{self.api_endpoint}/health", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'healthy':
                    self.log_success("Health check passed")
                else:
                    self.log_failure("Health check returned unhealthy status")
            else:
                self.log_failure(f"Health check failed with status {response.status_code}")
                
        except Exception as e:
            self.log_failure(f"Health check exception: {str(e)}")
    
    def test_diagnostic_operations(self):
        """Test all diagnostic operations"""
        print("\n=== Testing Diagnostic Operations ===")
        
        # Test get_ec2_status
        self.test_operation("get_ec2_status", {
            "instance_id": "i-1234567890abcdef0",
            "metrics": ["cpu", "memory"],
            "time_window": "15m"
        })
        
        # Add other diagnostic tests...
    
    def test_operation(self, operation, parameters):
        """Test a specific operation"""
        payload = {
            "operation": operation,
            "parameters": parameters,
            "user_context": {
                "user_id": "test@company.com",
                "teams_tenant": "company.onmicrosoft.com"
            }
        }
        
        try:
            response = requests.post(
                f"{self.api_endpoint}/operations/diagnostic",
                headers=self.headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    self.log_success(f"Operation {operation} succeeded")
                else:
                    self.log_failure(f"Operation {operation} returned success=false")
            else:
                self.log_failure(f"Operation {operation} failed with status {response.status_code}")
                
        except Exception as e:
            self.log_failure(f"Operation {operation} exception: {str(e)}")
    
    def log_success(self, message):
        """Log successful test"""
        self.test_results.append({"status": "PASS", "message": message, "timestamp": datetime.now()})
        print(f"✅ {message}")
    
    def log_failure(self, message):
        """Log failed test"""
        self.test_results.append({"status": "FAIL", "message": message, "timestamp": datetime.now()})
        print(f"❌ {message}")
    
    def generate_report(self):
        """Generate validation report"""
        print("\n=== Validation Report ===")
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r["status"] == "PASS"])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\nFailed Tests:")
            for result in self.test_results:
                if result["status"] == "FAIL":
                    print(f"  - {result['message']}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python validate_plugin.py <api_endpoint> <api_key>")
        sys.exit(1)
    
    validator = OpsAgentValidator(sys.argv[1], sys.argv[2])
    validator.run_all_tests()
```

### Continuous Validation

Set up automated validation:

1. **CI/CD Integration**: Run validation tests on every deployment
2. **Scheduled Testing**: Daily validation runs to catch drift
3. **Monitoring Integration**: Alert on validation failures
4. **Performance Tracking**: Track response times and success rates

## Troubleshooting Guide

### Common Issues and Solutions

#### Plugin Not Responding
- **Symptoms**: Amazon Q Business shows plugin timeout
- **Causes**: Lambda cold start, API Gateway issues, network problems
- **Solutions**: Check CloudWatch logs, verify API endpoint, test direct API calls

#### Authentication Failures
- **Symptoms**: 401/403 errors
- **Causes**: Invalid API key, user not in allow-list, expired credentials
- **Solutions**: Verify API key in SSM, check user allow-list, rotate credentials

#### Approval Workflow Issues
- **Symptoms**: Tokens not working, approval failures
- **Causes**: Token expiration, user mismatch, resource not tagged
- **Solutions**: Check token expiry, verify user identity, validate resource tags

#### Performance Issues
- **Symptoms**: Slow responses, timeouts
- **Causes**: Cold starts, AWS API throttling, resource constraints
- **Solutions**: Increase Lambda memory, implement warming, check AWS service limits

## Validation Checklist

Use this checklist for manual validation:

### Pre-Deployment
- [ ] Infrastructure code reviewed
- [ ] Security configurations verified
- [ ] Test resources prepared
- [ ] Monitoring configured

### Post-Deployment
- [ ] Health check passes
- [ ] Authentication working
- [ ] All 8 operations tested
- [ ] Approval workflow validated
- [ ] Error handling verified
- [ ] Audit logging confirmed
- [ ] Performance acceptable
- [ ] Documentation updated

### Production Readiness
- [ ] Security review completed
- [ ] Load testing passed
- [ ] Disaster recovery tested
- [ ] Monitoring alerts configured
- [ ] User training completed
- [ ] Support procedures documented

This validation framework ensures the OpsAgent Actions plugin is thoroughly tested and ready for production use with Amazon Q Business.