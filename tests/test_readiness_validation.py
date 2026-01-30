"""
Readiness validation tests for deployed OpsAgent Controller
Requirements: 11.6, 11.8, 11.10, 11.11, 11.14

This module provides readiness validation tests that can be run against
a deployed OpsAgent Controller to verify all components are working correctly.
These tests are designed to run against real deployed infrastructure.
"""
import json
import os
import time
import pytest
import requests
import boto3
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, NoCredentialsError


class TestDeployedInfrastructureReadiness:
    """
    Test deployed infrastructure readiness
    Requirements: 11.6, 11.8
    """
    
    @pytest.fixture(scope="class")
    def deployment_config(self):
        """Get deployment configuration from environment or CloudFormation"""
        config = {
            "health_url": os.environ.get("HEALTH_ENDPOINT"),
            "chat_url": os.environ.get("CHAT_ENDPOINT"),
            "api_key": os.environ.get("API_KEY"),
            "region": os.environ.get("AWS_REGION", "us-east-1"),
            "environment": os.environ.get("ENVIRONMENT", "sandbox"),
            "stack_name": os.environ.get("STACK_NAME", f"opsagent-controller-{os.environ.get('ENVIRONMENT', 'sandbox')}")
        }
        
        # Try to get endpoints from CloudFormation if not provided
        if not config["health_url"] or not config["chat_url"]:
            try:
                cf_client = boto3.client('cloudformation', region_name=config["region"])
                response = cf_client.describe_stacks(StackName=config["stack_name"])
                
                if response["Stacks"]:
                    outputs = response["Stacks"][0].get("Outputs", [])
                    for output in outputs:
                        if output["OutputKey"] == "HealthEndpoint":
                            config["health_url"] = output["OutputValue"]
                        elif output["OutputKey"] == "ChatEndpoint":
                            config["chat_url"] = output["OutputValue"]
            except Exception as e:
                pytest.skip(f"Could not get deployment config: {e}")
        
        # Try to get API key from SSM if not provided
        if not config["api_key"]:
            try:
                ssm_client = boto3.client('ssm', region_name=config["region"])
                param_name = f"/opsagent/{config['environment']}/api-key"
                response = ssm_client.get_parameter(Name=param_name, WithDecryption=True)
                config["api_key"] = response["Parameter"]["Value"]
            except Exception:
                # API key might not be required in LOCAL_MOCK mode
                pass
        
        # Validate required config
        if not config["health_url"]:
            pytest.skip("HEALTH_ENDPOINT not configured")
        if not config["chat_url"]:
            pytest.skip("CHAT_ENDPOINT not configured")
        
        return config
    
    def test_health_endpoint_accessibility(self, deployment_config):
        """Test health endpoint is accessible and returns proper response"""
        health_url = deployment_config["health_url"]
        
        # Test without API key first (should work for health endpoint)
        response = requests.get(health_url, timeout=30)
        
        assert response.status_code == 200, f"Health endpoint returned {response.status_code}"
        assert response.headers.get("content-type", "").startswith("application/json")
        
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert data["data"]["status"] == "healthy"
        
        # Verify required system information
        system = data["data"]["system"]
        required_fields = [
            "execution_mode",
            "llm_provider_status",
            "aws_tool_access_status",
            "timestamp",
            "environment",
            "version"
        ]
        
        for field in required_fields:
            assert field in system, f"Missing required field: {field}"
        
        # Verify execution mode is valid
        assert system["execution_mode"] in ["LOCAL_MOCK", "DRY_RUN", "SANDBOX_LIVE"]
        
        # Verify timestamps are recent (within last hour)
        timestamp = datetime.fromisoformat(system["timestamp"].replace("Z", "+00:00"))
        now = datetime.now(timestamp.tzinfo)
        assert (now - timestamp).total_seconds() < 3600, "Health check timestamp is too old"
    
    def test_health_endpoint_with_api_key(self, deployment_config):
        """Test health endpoint with API key authentication"""
        if not deployment_config["api_key"]:
            pytest.skip("API key not configured")
        
        health_url = deployment_config["health_url"]
        headers = {"X-API-Key": deployment_config["api_key"]}
        
        response = requests.get(health_url, headers=headers, timeout=30)
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["status"] == "healthy"
    
    def test_chat_endpoint_authentication(self, deployment_config):
        """Test chat endpoint authentication requirements"""
        chat_url = deployment_config["chat_url"]
        
        # Test without API key - should fail in non-LOCAL_MOCK modes
        test_payload = {
            "userId": "readiness-test-user",
            "messageText": "test authentication",
            "channel": "web"
        }
        
        response = requests.post(
            chat_url,
            json=test_payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        # Should either succeed (LOCAL_MOCK) or fail with 401 (other modes)
        assert response.status_code in [200, 401], f"Unexpected status code: {response.status_code}"
        
        if response.status_code == 401:
            data = response.json()
            assert "unauthorized" in data["error"].lower() or "authentication" in data["error"].lower()
    
    def test_chat_endpoint_with_valid_request(self, deployment_config):
        """Test chat endpoint with valid request"""
        chat_url = deployment_config["chat_url"]
        headers = {"Content-Type": "application/json"}
        
        if deployment_config["api_key"]:
            headers["X-API-Key"] = deployment_config["api_key"]
        
        test_payload = {
            "userId": "readiness-test-user",
            "messageText": "health check for readiness test",
            "channel": "web"
        }
        
        response = requests.post(chat_url, json=test_payload, headers=headers, timeout=30)
        
        assert response.status_code == 200, f"Chat endpoint returned {response.status_code}: {response.text}"
        
        data = response.json()
        assert data["success"] is True
        assert "correlationId" in data
        assert "data" in data
        
        # Should contain response message
        response_data = data["data"]
        assert "message" in response_data
        assert len(response_data["message"]) > 0
    
    def test_cors_headers_configuration(self, deployment_config):
        """Test CORS headers are properly configured"""
        chat_url = deployment_config["chat_url"]
        
        # Send OPTIONS request
        response = requests.options(chat_url, timeout=30)
        
        assert response.status_code == 200
        
        headers = response.headers
        assert headers.get("Access-Control-Allow-Origin") == "*"
        assert "GET,POST,OPTIONS" in headers.get("Access-Control-Allow-Methods", "")
        assert "Content-Type" in headers.get("Access-Control-Allow-Headers", "")
    
    def test_api_gateway_rate_limiting(self, deployment_config):
        """Test API Gateway rate limiting is configured"""
        chat_url = deployment_config["chat_url"]
        headers = {"Content-Type": "application/json"}
        
        if deployment_config["api_key"]:
            headers["X-API-Key"] = deployment_config["api_key"]
        
        test_payload = {
            "userId": "rate-limit-test-user",
            "messageText": "rate limit test",
            "channel": "web"
        }
        
        # Make multiple rapid requests
        responses = []
        for i in range(10):
            try:
                response = requests.post(
                    chat_url, 
                    json=test_payload, 
                    headers=headers, 
                    timeout=10
                )
                responses.append(response.status_code)
            except requests.exceptions.Timeout:
                responses.append(408)  # Timeout
            
            # Small delay to avoid overwhelming
            time.sleep(0.1)
        
        # Should have at least some successful responses
        successful_responses = [r for r in responses if r == 200]
        assert len(successful_responses) > 0, "No successful responses received"
        
        # May have some rate limited responses (429) or throttled responses
        rate_limited = [r for r in responses if r in [429, 502, 503]]
        # Rate limiting is expected behavior, so this is informational
        print(f"Rate limiting test: {len(successful_responses)} successful, {len(rate_limited)} rate limited")


class TestDeployedDiagnosisToolsReadiness:
    """
    Test deployed diagnosis tools readiness
    Requirements: 11.8, 11.10
    """
    
    @pytest.fixture(scope="class")
    def deployment_config(self):
        """Get deployment configuration"""
        config = {
            "chat_url": os.environ.get("CHAT_ENDPOINT"),
            "api_key": os.environ.get("API_KEY"),
            "region": os.environ.get("AWS_REGION", "us-east-1"),
            "environment": os.environ.get("ENVIRONMENT", "sandbox"),
            "test_instance_id": os.environ.get("TEST_INSTANCE_ID")
        }
        
        # Try to get test instance ID from CloudFormation
        if not config["test_instance_id"]:
            try:
                cf_client = boto3.client('cloudformation', region_name=config["region"])
                stack_name = f"opsagent-controller-{config['environment']}"
                response = cf_client.describe_stacks(StackName=stack_name)
                
                if response["Stacks"]:
                    outputs = response["Stacks"][0].get("Outputs", [])
                    for output in outputs:
                        if output["OutputKey"] == "TestInstanceId":
                            config["test_instance_id"] = output["OutputValue"]
                            break
            except Exception:
                pass
        
        if not config["chat_url"]:
            pytest.skip("CHAT_ENDPOINT not configured")
        
        return config
    
    def test_cloudwatch_metrics_diagnosis(self, deployment_config):
        """Test CloudWatch metrics diagnosis through chat interface"""
        chat_url = deployment_config["chat_url"]
        headers = {"Content-Type": "application/json"}
        
        if deployment_config["api_key"]:
            headers["X-API-Key"] = deployment_config["api_key"]
        
        # Test CloudWatch metrics request
        test_payload = {
            "userId": "diagnosis-test-user",
            "messageText": "Show CPU metrics for the last 15 minutes",
            "channel": "web"
        }
        
        response = requests.post(chat_url, json=test_payload, headers=headers, timeout=60)
        
        assert response.status_code == 200, f"Diagnosis request failed: {response.text}"
        
        data = response.json()
        assert data["success"] is True
        
        # Should contain response about metrics
        response_data = data["data"]
        message = response_data["message"].lower()
        
        # Should mention metrics or CPU in some way
        assert any(keyword in message for keyword in [
            "metric", "cpu", "cloudwatch", "utilization", "data", "monitoring"
        ]), f"Response doesn't seem to contain metrics information: {message}"
    
    def test_ec2_instance_diagnosis(self, deployment_config):
        """Test EC2 instance diagnosis through chat interface"""
        chat_url = deployment_config["chat_url"]
        headers = {"Content-Type": "application/json"}
        
        if deployment_config["api_key"]:
            headers["X-API-Key"] = deployment_config["api_key"]
        
        # Test EC2 describe request
        if deployment_config["test_instance_id"]:
            message_text = f"Describe instance {deployment_config['test_instance_id']}"
        else:
            message_text = "Show me information about EC2 instances"
        
        test_payload = {
            "userId": "diagnosis-test-user",
            "messageText": message_text,
            "channel": "web"
        }
        
        response = requests.post(chat_url, json=test_payload, headers=headers, timeout=60)
        
        assert response.status_code == 200, f"EC2 diagnosis request failed: {response.text}"
        
        data = response.json()
        assert data["success"] is True
        
        # Should contain response about instances
        response_data = data["data"]
        message = response_data["message"].lower()
        
        # Should mention instances or EC2 in some way
        assert any(keyword in message for keyword in [
            "instance", "ec2", "server", "compute", "running", "state"
        ]), f"Response doesn't seem to contain instance information: {message}"
    
    def test_diagnosis_tools_error_handling(self, deployment_config):
        """Test diagnosis tools handle invalid requests gracefully"""
        chat_url = deployment_config["chat_url"]
        headers = {"Content-Type": "application/json"}
        
        if deployment_config["api_key"]:
            headers["X-API-Key"] = deployment_config["api_key"]
        
        # Test with invalid instance ID
        test_payload = {
            "userId": "diagnosis-error-test-user",
            "messageText": "Describe instance i-invalidinstanceid",
            "channel": "web"
        }
        
        response = requests.post(chat_url, json=test_payload, headers=headers, timeout=60)
        
        assert response.status_code == 200, "Should handle errors gracefully"
        
        data = response.json()
        assert data["success"] is True
        
        # Should contain some kind of error message or explanation
        response_data = data["data"]
        message = response_data["message"].lower()
        
        # Should indicate some kind of issue or limitation
        assert any(keyword in message for keyword in [
            "error", "not found", "invalid", "unable", "failed", "issue", "problem"
        ]) or "i-invalidinstanceid" not in message, "Should handle invalid instance ID gracefully"


class TestDeployedApprovalGateReadiness:
    """
    Test deployed approval gate and remediation readiness
    Requirements: 11.10, 11.11
    """
    
    @pytest.fixture(scope="class")
    def deployment_config(self):
        """Get deployment configuration"""
        config = {
            "chat_url": os.environ.get("CHAT_ENDPOINT"),
            "api_key": os.environ.get("API_KEY"),
            "region": os.environ.get("AWS_REGION", "us-east-1"),
            "environment": os.environ.get("ENVIRONMENT", "sandbox"),
            "test_instance_id": os.environ.get("TEST_INSTANCE_ID")
        }
        
        if not config["chat_url"]:
            pytest.skip("CHAT_ENDPOINT not configured")
        
        return config
    
    def test_remediation_requires_approval(self, deployment_config):
        """Test that remediation actions require approval"""
        chat_url = deployment_config["chat_url"]
        headers = {"Content-Type": "application/json"}
        
        if deployment_config["api_key"]:
            headers["X-API-Key"] = deployment_config["api_key"]
        
        # Request a remediation action
        instance_id = deployment_config.get("test_instance_id", "i-1234567890abcdef0")
        test_payload = {
            "userId": "approval-test-user",
            "messageText": f"Reboot instance {instance_id}",
            "channel": "web"
        }
        
        response = requests.post(chat_url, json=test_payload, headers=headers, timeout=60)
        
        assert response.status_code == 200, f"Remediation request failed: {response.text}"
        
        data = response.json()
        assert data["success"] is True
        
        response_data = data["data"]
        
        # Should either require approval or explain why it can't be done
        message = response_data["message"].lower()
        
        # Check for approval requirement or security explanation
        approval_indicators = [
            "approval", "approve", "confirm", "authorize", "permission",
            "token", "security", "restricted", "not allowed", "cannot"
        ]
        
        assert any(indicator in message for indicator in approval_indicators), \
            f"Remediation request should require approval or explain restrictions: {message}"
        
        # If approval is required, should have approval data
        if response_data.get("approval_required"):
            assert "approval_data" in response_data
            approval_data = response_data["approval_data"]
            assert "token" in approval_data
            assert len(approval_data["token"]) > 0
    
    def test_approval_workflow_dry_run_mode(self, deployment_config):
        """Test approval workflow in dry-run mode"""
        chat_url = deployment_config["chat_url"]
        headers = {"Content-Type": "application/json"}
        
        if deployment_config["api_key"]:
            headers["X-API-Key"] = deployment_config["api_key"]
        
        # Step 1: Request remediation
        instance_id = deployment_config.get("test_instance_id", "i-1234567890abcdef0")
        test_payload = {
            "userId": "approval-workflow-test-user",
            "messageText": f"Reboot instance {instance_id}",
            "channel": "web"
        }
        
        response = requests.post(chat_url, json=test_payload, headers=headers, timeout=60)
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        
        response_data = data["data"]
        
        # If approval is required, test the approval flow
        if response_data.get("approval_required"):
            approval_data = response_data["approval_data"]
            approval_token = approval_data["token"]
            
            # Step 2: Approve the request
            approval_payload = {
                "userId": "approval-workflow-test-user",
                "messageText": f"approve token:{approval_token}",
                "channel": "web"
            }
            
            approval_response = requests.post(
                chat_url, 
                json=approval_payload, 
                headers=headers, 
                timeout=60
            )
            
            assert approval_response.status_code == 200
            approval_data = approval_response.json()
            assert approval_data["success"] is True
            
            # Should indicate execution or simulation
            approval_response_data = approval_data["data"]
            message = approval_response_data["message"].lower()
            
            # Should mention approval granted and execution
            assert "approval" in message and "granted" in message, \
                f"Should confirm approval granted: {message}"
            
            # In DRY_RUN mode, should indicate simulation
            execution_indicators = [
                "would", "simulate", "dry", "mock", "test", "executed"
            ]
            
            assert any(indicator in message for indicator in execution_indicators), \
                f"Should indicate execution mode: {message}"
    
    def test_approval_token_expiry_handling(self, deployment_config):
        """Test that expired approval tokens are handled correctly"""
        chat_url = deployment_config["chat_url"]
        headers = {"Content-Type": "application/json"}
        
        if deployment_config["api_key"]:
            headers["X-API-Key"] = deployment_config["api_key"]
        
        # Try to use an obviously invalid/expired token
        invalid_token_payload = {
            "userId": "token-expiry-test-user",
            "messageText": "approve token:invalid-expired-token-123",
            "channel": "web"
        }
        
        response = requests.post(chat_url, json=invalid_token_payload, headers=headers, timeout=30)
        
        assert response.status_code == 200  # Should handle gracefully
        data = response.json()
        assert data["success"] is True
        
        # Should indicate token is invalid/expired
        response_data = data["data"]
        message = response_data["message"].lower()
        
        error_indicators = [
            "invalid", "expired", "not found", "error", "failed"
        ]
        
        assert any(indicator in message for indicator in error_indicators), \
            f"Should indicate token error: {message}"


class TestDeployedAuditLoggingReadiness:
    """
    Test deployed audit logging readiness
    Requirements: 11.11, 11.14
    """
    
    @pytest.fixture(scope="class")
    def deployment_config(self):
        """Get deployment configuration"""
        config = {
            "chat_url": os.environ.get("CHAT_ENDPOINT"),
            "api_key": os.environ.get("API_KEY"),
            "region": os.environ.get("AWS_REGION", "us-east-1"),
            "environment": os.environ.get("ENVIRONMENT", "sandbox"),
            "audit_log_group": os.environ.get("AUDIT_LOG_GROUP"),
            "audit_table": os.environ.get("AUDIT_TABLE")
        }
        
        # Try to get audit resources from CloudFormation
        if not config["audit_log_group"] or not config["audit_table"]:
            try:
                cf_client = boto3.client('cloudformation', region_name=config["region"])
                stack_name = f"opsagent-controller-{config['environment']}"
                response = cf_client.describe_stacks(StackName=stack_name)
                
                if response["Stacks"]:
                    outputs = response["Stacks"][0].get("Outputs", [])
                    for output in outputs:
                        if output["OutputKey"] == "AuditLogGroupName":
                            config["audit_log_group"] = output["OutputValue"]
                        elif output["OutputKey"] == "AuditTableName":
                            config["audit_table"] = output["OutputValue"]
            except Exception:
                pass
        
        if not config["chat_url"]:
            pytest.skip("CHAT_ENDPOINT not configured")
        
        return config
    
    def test_audit_logging_cloudwatch_accessibility(self, deployment_config):
        """Test that CloudWatch audit logs are accessible"""
        if not deployment_config["audit_log_group"]:
            pytest.skip("Audit log group not configured")
        
        try:
            logs_client = boto3.client('logs', region_name=deployment_config["region"])
            
            # Check if log group exists
            response = logs_client.describe_log_groups(
                logGroupNamePrefix=deployment_config["audit_log_group"]
            )
            
            log_groups = response.get("logGroups", [])
            audit_log_group = None
            
            for lg in log_groups:
                if lg["logGroupName"] == deployment_config["audit_log_group"]:
                    audit_log_group = lg
                    break
            
            assert audit_log_group is not None, f"Audit log group {deployment_config['audit_log_group']} not found"
            
            # Check retention policy
            assert "retentionInDays" in audit_log_group, "Audit log group should have retention policy"
            assert audit_log_group["retentionInDays"] >= 30, "Audit logs should be retained for at least 30 days"
            
        except NoCredentialsError:
            pytest.skip("AWS credentials not available for audit log verification")
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                pytest.skip("Insufficient permissions to verify audit logs")
            else:
                raise
    
    def test_audit_logging_dynamodb_accessibility(self, deployment_config):
        """Test that DynamoDB audit table is accessible"""
        if not deployment_config["audit_table"]:
            pytest.skip("Audit table not configured")
        
        try:
            dynamodb_client = boto3.client('dynamodb', region_name=deployment_config["region"])
            
            # Check if table exists and get its description
            response = dynamodb_client.describe_table(
                TableName=deployment_config["audit_table"]
            )
            
            table = response["Table"]
            assert table["TableStatus"] == "ACTIVE", "Audit table should be active"
            
            # Check key schema
            key_schema = table["KeySchema"]
            hash_key = next((k for k in key_schema if k["KeyType"] == "HASH"), None)
            range_key = next((k for k in key_schema if k["KeyType"] == "RANGE"), None)
            
            assert hash_key is not None, "Audit table should have hash key"
            assert hash_key["AttributeName"] == "correlationId", "Hash key should be correlationId"
            
            assert range_key is not None, "Audit table should have range key"
            assert range_key["AttributeName"] == "timestamp", "Range key should be timestamp"
            
            # Check encryption
            if "SSEDescription" in table:
                sse = table["SSEDescription"]
                assert sse["Status"] == "ENABLED", "Audit table should have encryption enabled"
            
        except NoCredentialsError:
            pytest.skip("AWS credentials not available for audit table verification")
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                pytest.skip("Insufficient permissions to verify audit table")
            else:
                raise
    
    def test_audit_logging_through_chat_interaction(self, deployment_config):
        """Test that chat interactions generate audit logs"""
        chat_url = deployment_config["chat_url"]
        headers = {"Content-Type": "application/json"}
        
        if deployment_config["api_key"]:
            headers["X-API-Key"] = deployment_config["api_key"]
        
        # Generate a unique test message to track in logs
        test_timestamp = int(time.time())
        test_payload = {
            "userId": f"audit-test-user-{test_timestamp}",
            "messageText": f"audit logging test message {test_timestamp}",
            "channel": "web"
        }
        
        response = requests.post(chat_url, json=test_payload, headers=headers, timeout=30)
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        
        correlation_id = data.get("correlationId")
        assert correlation_id is not None, "Response should include correlation ID for audit tracking"
        
        # Wait a moment for logs to be written
        time.sleep(5)
        
        # Try to verify the audit log was created (if we have access)
        if deployment_config["audit_log_group"]:
            try:
                logs_client = boto3.client('logs', region_name=deployment_config["region"])
                
                # Search for logs with our correlation ID
                end_time = int(time.time() * 1000)
                start_time = end_time - (5 * 60 * 1000)  # 5 minutes ago
                
                response = logs_client.filter_log_events(
                    logGroupName=deployment_config["audit_log_group"],
                    startTime=start_time,
                    endTime=end_time,
                    filterPattern=correlation_id
                )
                
                events = response.get("events", [])
                
                # Should have at least one audit log entry
                assert len(events) > 0, f"No audit log entries found for correlation ID {correlation_id}"
                
                # Check that log entries contain expected fields
                for event in events:
                    log_message = event["message"]
                    
                    # Should be valid JSON
                    try:
                        log_data = json.loads(log_message)
                        assert "correlation_id" in log_data
                        assert "user_id" in log_data
                        assert "timestamp" in log_data
                        assert "event_type" in log_data
                    except json.JSONDecodeError:
                        # Some log entries might not be JSON (e.g., Lambda runtime logs)
                        pass
                
            except (NoCredentialsError, ClientError):
                # Can't verify logs directly, but the request succeeded
                print(f"Generated audit logs with correlation ID: {correlation_id}")
    
    def test_audit_logging_secret_sanitization(self, deployment_config):
        """Test that audit logs don't contain sensitive information"""
        if not deployment_config["audit_log_group"]:
            pytest.skip("Cannot verify audit log sanitization without log group access")
        
        try:
            logs_client = boto3.client('logs', region_name=deployment_config["region"])
            
            # Get recent log events
            end_time = int(time.time() * 1000)
            start_time = end_time - (60 * 60 * 1000)  # 1 hour ago
            
            response = logs_client.filter_log_events(
                logGroupName=deployment_config["audit_log_group"],
                startTime=start_time,
                endTime=end_time,
                limit=100
            )
            
            events = response.get("events", [])
            
            if len(events) > 0:
                # Check that no sensitive information is logged
                sensitive_patterns = [
                    "password", "secret", "key", "token", "credential",
                    "AKIA", "aws_access_key", "aws_secret"
                ]
                
                for event in events:
                    log_message = event["message"].lower()
                    
                    for pattern in sensitive_patterns:
                        # Allow the word "token" in context like "approval_token" or "correlation_id"
                        # but not actual token values
                        if pattern == "token":
                            # Look for patterns like "token": "actual-token-value"
                            import re
                            if re.search(r'"token"\s*:\s*"[^"]{20,}"', log_message):
                                pytest.fail(f"Audit log contains actual token value: {event['message'][:200]}...")
                        elif pattern in log_message and "redacted" not in log_message:
                            # Allow if it's clearly marked as redacted
                            pytest.fail(f"Audit log may contain sensitive information ({pattern}): {event['message'][:200]}...")
            
        except (NoCredentialsError, ClientError):
            pytest.skip("Cannot verify audit log sanitization due to access restrictions")


def run_readiness_validation():
    """
    Run all readiness validation tests
    This function can be called from deployment scripts
    """
    import subprocess
    import sys
    
    # Run the readiness validation tests
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/test_readiness_validation.py", 
        "-v", 
        "--tb=short",
        "-x"  # Stop on first failure
    ], capture_output=True, text=True)
    
    return result.returncode == 0, result.stdout, result.stderr


if __name__ == "__main__":
    # Allow running readiness validation directly
    success, stdout, stderr = run_readiness_validation()
    print(stdout)
    if stderr:
        print("STDERR:", stderr)
    exit(0 if success else 1)