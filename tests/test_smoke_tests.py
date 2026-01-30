"""
Smoke tests and readiness validation for OpsAgent Controller
Requirements: 11.6, 11.8, 11.10, 11.11, 11.14

This module provides comprehensive smoke tests to validate:
1. Infrastructure provisioning and accessibility
2. Diagnosis tool functionality
3. Approval gate and remediation workflows
4. Audit logging verification
"""
import json
import os
import time
import pytest
import boto3
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError

from src.main import lambda_handler, get_system_status
from src.models import ExecutionMode, ChannelType, InternalMessage, ToolCall
from src.audit_logger import AuditLogger
from src.approval_gate import ApprovalGate
from src.aws_diagnosis_tools import CloudWatchMetricsTool, EC2DescribeTool
from src.aws_remediation_tools import EC2RebootTool


class TestInfrastructureSmokeTests:
    """
    Infrastructure smoke tests to verify basic system functionality
    Requirements: 11.6, 11.8
    """
    
    def test_health_endpoint_accessibility(self):
        """Test that health endpoint returns HTTP 200 with proper structure"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "GET",
                "path": "/health",
                "headers": {}
            }
            
            response = lambda_handler(event, None)
            
            # Should return 200 OK
            assert response["statusCode"] == 200
            assert "application/json" in response["headers"]["Content-Type"]
            
            # Parse response body
            body = json.loads(response["body"])
            assert body["success"] is True
            assert "data" in body
            
            # Verify required health check fields
            data = body["data"]
            assert data["status"] == "healthy"
            assert "system" in data
            
            system = data["system"]
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
    
    def test_health_endpoint_execution_mode_reporting(self):
        """Test that health endpoint correctly reports execution mode"""
        test_modes = ["LOCAL_MOCK", "DRY_RUN", "SANDBOX_LIVE"]
        
        for mode in test_modes:
            with patch.dict(os.environ, {"EXECUTION_MODE": mode}):
                event = {
                    "httpMethod": "GET",
                    "path": "/health",
                    "headers": {}
                }
                
                response = lambda_handler(event, None)
                assert response["statusCode"] == 200
                
                body = json.loads(response["body"])
                system = body["data"]["system"]
                assert system["execution_mode"] == mode
    
    def test_health_endpoint_llm_provider_status(self):
        """Test that health endpoint reports LLM provider status"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "GET",
                "path": "/health",
                "headers": {}
            }
            
            response = lambda_handler(event, None)
            assert response["statusCode"] == 200
            
            body = json.loads(response["body"])
            system = body["data"]["system"]
            
            # Should have LLM provider status
            assert "llm_provider_status" in system
            assert system["llm_provider_status"] in ["configured", "not_configured", "error"]
            
            if system["llm_provider_status"] == "configured":
                assert "llm_provider_type" in system
    
    def test_health_endpoint_aws_tool_access_status(self):
        """Test that health endpoint reports AWS tool access status"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            # Mock successful AWS calls
            with patch('boto3.client') as mock_boto3:
                mock_sts = MagicMock()
                mock_sts.get_caller_identity.return_value = {
                    "Account": "123456789012",
                    "UserId": "test-user",
                    "Arn": "arn:aws:iam::123456789012:user/test"
                }
                mock_cloudwatch = MagicMock()
                mock_ec2 = MagicMock()
                mock_logs = MagicMock()
                
                def client_side_effect(service):
                    if service == 'sts':
                        return mock_sts
                    elif service == 'cloudwatch':
                        return mock_cloudwatch
                    elif service == 'ec2':
                        return mock_ec2
                    elif service == 'logs':
                        return mock_logs
                    return MagicMock()
                
                mock_boto3.side_effect = client_side_effect
                
                event = {
                    "httpMethod": "GET",
                    "path": "/health",
                    "headers": {}
                }
                
                response = lambda_handler(event, None)
                assert response["statusCode"] == 200
                
                body = json.loads(response["body"])
                system = body["data"]["system"]
                
                # Should report AWS tool access
                assert "aws_tool_access_status" in system
                assert system["aws_tool_access_status"] in ["configured", "error", "not_configured"]
                
                if system["aws_tool_access_status"] == "configured":
                    assert "cloudwatch_access" in system
                    assert "ec2_access" in system
                    assert system["cloudwatch_access"] == "available"
                    assert system["ec2_access"] == "available"
    
    def test_chat_endpoint_accessibility(self):
        """Test that chat endpoint is accessible and handles requests"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "userId": "smoke-test-user",
                    "messageText": "health check",
                    "channel": "web"
                })
            }
            
            response = lambda_handler(event, None)
            
            # Should return 200 OK (not authentication error)
            assert response["statusCode"] == 200
            
            body = json.loads(response["body"])
            assert body["success"] is True
            assert "correlationId" in body
    
    def test_cors_headers_present(self):
        """Test that CORS headers are properly configured"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "OPTIONS",
                "path": "/chat",
                "headers": {}
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 200
            headers = response["headers"]
            
            # Verify CORS headers
            assert headers["Access-Control-Allow-Origin"] == "*"
            assert "GET,POST,OPTIONS" in headers["Access-Control-Allow-Methods"]
            assert "Content-Type" in headers["Access-Control-Allow-Headers"]
    
    def test_rate_limiting_functionality(self):
        """Test that rate limiting is working"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            # Clear any existing rate limit state
            from src.main import _rate_limit_store
            _rate_limit_store.clear()
            
            base_event = {
                "httpMethod": "POST",
                "path": "/chat",
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "userId": "rate-limit-test-user",
                    "messageText": "test",
                    "channel": "web"
                }),
                "requestContext": {
                    "identity": {
                        "sourceIp": "192.168.1.200"
                    }
                }
            }
            
            # Make requests up to the limit (30 per minute)
            for i in range(30):
                response = lambda_handler(base_event, None)
                assert response["statusCode"] == 200, f"Request {i+1} failed"
            
            # Next request should be rate limited
            response = lambda_handler(base_event, None)
            assert response["statusCode"] == 429
            
            body = json.loads(response["body"])
            assert "Rate limit exceeded" in body["error"]
    
    def test_component_initialization_status(self):
        """Test that all system components are properly initialized"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "GET",
                "path": "/health",
                "headers": {}
            }
            
            response = lambda_handler(event, None)
            assert response["statusCode"] == 200
            
            body = json.loads(response["body"])
            system = body["data"]["system"]
            
            # Should have component status
            if "components" in system:
                components = system["components"]
                
                # Check that key components are initialized
                expected_components = [
                    "llm_provider",
                    "tool_execution_engine", 
                    "approval_gate",
                    "audit_logger"
                ]
                
                for component in expected_components:
                    if component in components:
                        assert components[component]["initialized"] is True


class TestDiagnosisToolValidation:
    """
    Diagnosis tool validation tests
    Requirements: 11.8, 11.10
    """
    
    def test_cloudwatch_metrics_tool_functionality(self):
        """Test CloudWatch metrics tool in different execution modes"""
        # Test LOCAL_MOCK mode (no AWS credentials needed)
        tool = CloudWatchMetricsTool(ExecutionMode.LOCAL_MOCK)
        
        # Create tool call for metric retrieval
        from src.models import ToolCall
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0",
                "time_window": "15m"
            }
        )
        
        # Test basic metric retrieval in LOCAL_MOCK mode
        result = tool.execute(tool_call, "test-correlation-id")
        
        # Should return a valid result
        assert result.success is True
        assert result.tool_name == "get_cloudwatch_metrics"
        assert result.execution_mode == ExecutionMode.LOCAL_MOCK
        assert result.correlation_id is not None
        
        # Should contain mock metric data
        assert result.data is not None
        assert result.data.get("mock") is True
        
        # Should not contain sensitive information
        assert "aws_access_key" not in str(result.data).lower()
        assert "secret" not in str(result.data).lower()
        
        # Test DRY_RUN mode with mocked AWS client
        with patch('boto3.client') as mock_boto3:
            mock_client = MagicMock()
            mock_client.get_metric_statistics.return_value = {
                'Datapoints': [
                    {
                        'Timestamp': datetime.utcnow(),
                        'Average': 50.0,
                        'Unit': 'Percent'
                    }
                ],
                'Label': 'CPUUtilization'
            }
            mock_boto3.return_value = mock_client
            
            tool_dry_run = CloudWatchMetricsTool(ExecutionMode.DRY_RUN)
            result_dry_run = tool_dry_run.execute(tool_call, "test-correlation-id")
            
            # Should return a valid result
            assert result_dry_run.success is True
            assert result_dry_run.tool_name == "get_cloudwatch_metrics"
            assert result_dry_run.execution_mode == ExecutionMode.DRY_RUN
            assert result_dry_run.correlation_id is not None
            
            # Should contain metric data
            assert result_dry_run.data is not None
            assert "metric_data" in result_dry_run.data or "summary" in result_dry_run.data
    
    def test_ec2_describe_tool_functionality(self):
        """Test EC2 describe tool in different execution modes"""
        # Test LOCAL_MOCK mode (no AWS credentials needed)
        tool = EC2DescribeTool(ExecutionMode.LOCAL_MOCK)
        
        # Create tool call for instance description
        from src.models import ToolCall
        tool_call = ToolCall(
            tool_name="describe_ec2_instances",
            args={
                "instance_ids": ["i-1234567890abcdef0"]
            }
        )
        
        # Test instance description in LOCAL_MOCK mode
        result = tool.execute(tool_call, "test-correlation-id")
        
        # Should return a valid result
        assert result.success is True
        assert result.tool_name == "describe_ec2_instances"
        assert result.execution_mode == ExecutionMode.LOCAL_MOCK
        assert result.correlation_id is not None
        
        # Should contain mock instance data
        assert result.data is not None
        assert result.data.get("mock") is True
        
        # Should not expose sensitive information
        assert "password" not in str(result.data).lower()
        assert "key" not in str(result.data).lower()
        
        # Test DRY_RUN mode with mocked AWS client
        with patch('boto3.client') as mock_boto3:
            mock_client = MagicMock()
            mock_client.describe_instances.return_value = {
                'Reservations': [
                    {
                        'Instances': [
                            {
                                'InstanceId': 'i-1234567890abcdef0',
                                'State': {'Name': 'running'},
                                'InstanceType': 't3.micro',
                                'LaunchTime': datetime.utcnow(),
                                'Tags': [
                                    {'Key': 'Name', 'Value': 'test-instance'}
                                ]
                            }
                        ]
                    }
                ]
            }
            mock_boto3.return_value = mock_client
            
            tool_dry_run = EC2DescribeTool(ExecutionMode.DRY_RUN)
            result_dry_run = tool_dry_run.execute(tool_call, "test-correlation-id")
            
            # Should return a valid result
            assert result_dry_run.success is True
            assert result_dry_run.tool_name == "describe_ec2_instances"
            assert result_dry_run.execution_mode == ExecutionMode.DRY_RUN
            assert result_dry_run.correlation_id is not None
            
            # Should contain instance data
            assert result_dry_run.data is not None
            assert "instances" in result_dry_run.data or "summary" in result_dry_run.data
    
    def test_diagnosis_tools_error_handling(self):
        """Test diagnosis tools handle AWS API errors gracefully"""
        # Test with DRY_RUN mode to potentially trigger real AWS errors
        with patch('boto3.client') as mock_boto3:
            # Mock AWS client to raise errors
            mock_client = MagicMock()
            mock_client.get_metric_statistics.side_effect = ClientError(
                {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
                'GetMetricStatistics'
            )
            mock_boto3.return_value = mock_client
            
            tool = CloudWatchMetricsTool(ExecutionMode.DRY_RUN)
            
            from src.models import ToolCall
            tool_call = ToolCall(
                tool_name="get_cloudwatch_metrics",
                args={
                    "namespace": "AWS/EC2",
                    "metric_name": "CPUUtilization",
                    "resource_id": "i-1234567890abcdef0",
                    "time_window": "15m"
                }
            )
            
            result = tool.execute(tool_call, "test-correlation-id")
            
            # Should handle error gracefully
            assert result.success is False
            assert result.error is not None
            assert ("access denied" in result.error.lower() or 
                    "insufficient permissions" in result.error.lower())
            
            # Should not expose internal details
            assert "boto3" not in result.error.lower()
            assert "traceback" not in result.error.lower()
    
    def test_diagnosis_tools_integration_with_chat(self):
        """Test diagnosis tools work through chat interface"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "userId": "diagnosis-test-user",
                    "messageText": "Check CPU metrics for instance i-1234567890abcdef0",
                    "channel": "web"
                })
            }
            
            response = lambda_handler(event, None)
            assert response["statusCode"] == 200
            
            body = json.loads(response["body"])
            assert body["success"] is True
            
            # Should contain tool execution results
            data = body["data"]
            assert "channel_data" in data
            
            channel_data = data["channel_data"]
            if "tool_results" in channel_data:
                tool_results = channel_data["tool_results"]
                assert len(tool_results) > 0
                
                # At least one tool should have executed successfully
                successful_tools = [tr for tr in tool_results if tr["success"]]
                assert len(successful_tools) > 0
    
    def test_diagnosis_tools_read_only_guarantee(self):
        """Test that diagnosis tools only perform read-only operations"""
        # This is a property test - diagnosis tools should never make write calls
        with patch('boto3.client') as mock_boto3:
            mock_client = MagicMock()
            mock_boto3.return_value = mock_client
            
            # Test CloudWatch tool
            cw_tool = CloudWatchMetricsTool(ExecutionMode.DRY_RUN)
            tool_call = ToolCall(
                tool_name="get_cloudwatch_metrics",
                args={
                    "namespace": "AWS/EC2",
                    "metric_name": "CPUUtilization",
                    "resource_id": "i-test"
                }
            )
            cw_tool.execute(tool_call, "test-correlation-id")
            
            # Should only call read methods
            called_methods = [call[0] for call in mock_client.method_calls]
            write_methods = [
                'put_metric_data', 'put_metric_alarm', 'delete_alarms',
                'put_dashboard', 'delete_dashboard'
            ]
            
            for write_method in write_methods:
                assert write_method not in called_methods, f"Diagnosis tool called write method: {write_method}"
            
            # Reset mock for EC2 tool
            mock_client.reset_mock()
            
            # Test EC2 tool
            ec2_tool = EC2DescribeTool(ExecutionMode.DRY_RUN)
            ec2_tool_call = ToolCall(
                tool_name="describe_ec2_instances",
                args={"instance_ids": ["i-test"]}
            )
            ec2_tool.execute(ec2_tool_call, "test-correlation-id")
            
            # Should only call describe methods
            called_methods = [call[0] for call in mock_client.method_calls]
            write_methods = [
                'run_instances', 'terminate_instances', 'stop_instances',
                'start_instances', 'reboot_instances', 'modify_instance_attribute'
            ]
            
            for write_method in write_methods:
                assert write_method not in called_methods, f"Diagnosis tool called write method: {write_method}"


class TestApprovalGateAndRemediationTesting:
    """
    Approval gate and remediation testing
    Requirements: 11.10, 11.11
    """
    
    def test_approval_gate_creation_and_validation(self):
        """Test approval gate creates and validates tokens correctly"""
        approval_gate = ApprovalGate(storage_backend="memory")
        
        from src.models import ToolCall
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"},
            requires_approval=True
        )
        
        # Create approval request
        approval_request = approval_gate.create_approval_request(
            tool_call=tool_call,
            requested_by="test-user",
            risk_level="medium"
        )
        
        # Should have valid token
        assert approval_request.token is not None
        assert len(approval_request.token) > 0
        assert approval_request.tool_call == tool_call
        assert approval_request.requested_by == "test-user"
        assert approval_request.risk_level == "medium"
        
        # Token should be valid initially
        is_valid, reason = approval_gate.validate_approval_token(
            approval_request.token,
            "test-user",
            tool_call
        )
        assert is_valid is True
        assert reason == "Token is valid"
        
        # Wrong user should be rejected
        is_valid, reason = approval_gate.validate_approval_token(
            approval_request.token,
            "wrong-user",
            tool_call
        )
        assert is_valid is False
        assert "user" in reason.lower() and ("mismatch" in reason.lower() or "authorized" in reason.lower())
    
    def test_approval_gate_token_expiry(self):
        """Test approval tokens expire correctly"""
        approval_gate = ApprovalGate(
            storage_backend="memory",
            default_expiry_minutes=0.01  # 0.6 seconds for testing
        )
        
        from src.models import ToolCall
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-test"},
            requires_approval=True
        )
        
        # Create approval request
        approval_request = approval_gate.create_approval_request(
            tool_call=tool_call,
            requested_by="test-user",
            risk_level="low"
        )
        
        # Should be valid initially
        is_valid, _ = approval_gate.validate_approval_token(
            approval_request.token,
            "test-user",
            tool_call
        )
        assert is_valid is True
        
        # Wait for expiry
        time.sleep(1)
        
        # Should be expired now
        is_valid, reason = approval_gate.validate_approval_token(
            approval_request.token,
            "test-user",
            tool_call
        )
        assert is_valid is False
        assert "expired" in reason.lower()
    
    def test_approval_gate_token_consumption(self):
        """Test approval tokens are consumed after use"""
        approval_gate = ApprovalGate(storage_backend="memory")
        
        from src.models import ToolCall
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-test"},
            requires_approval=True
        )
        
        # Create and approve request
        approval_request = approval_gate.create_approval_request(
            tool_call=tool_call,
            requested_by="test-user",
            risk_level="low"
        )
        
        # Approve the request
        decision = approval_gate.approve_request(
            approval_request.token,
            "test-user",
            True
        )
        assert decision.approved is True
        
        # Consume the token
        consumed = approval_gate.consume_approval_token(approval_request.token)
        assert consumed is True
        
        # Token should no longer be valid
        is_valid, reason = approval_gate.validate_approval_token(
            approval_request.token,
            "test-user",
            tool_call
        )
        assert is_valid is False
        assert ("not found" in reason.lower() or 
                "consumed" in reason.lower() or 
                "already been used" in reason.lower())
    
    def test_remediation_tool_dry_run_mode(self):
        """Test remediation tools in DRY_RUN mode"""
        # Mock boto3.client to prevent real AWS calls
        with patch('boto3.client') as mock_boto3:
            mock_ec2_client = MagicMock()
            mock_ec2_client.describe_instances.return_value = {
                'Reservations': [{
                    'Instances': [{
                        'InstanceId': 'i-1234567890abcdef0',
                        'State': {'Name': 'running'},
                        'Tags': [
                            {'Key': 'OpsAgentManaged', 'Value': 'true'},
                            {'Key': 'Environment', 'Value': 'test'}
                        ]
                    }]
                }]
            }
            mock_boto3.return_value = mock_ec2_client
            
            tool = EC2RebootTool(ExecutionMode.DRY_RUN)
            
            from src.models import ToolCall
            tool_call = ToolCall(
                tool_name="reboot_ec2_instance",
                args={"instance_id": "i-1234567890abcdef0"}
            )
            
            result = tool.execute(tool_call, "test-correlation-id")
            
            # Should succeed in dry-run mode
            assert result.success is True
            assert result.execution_mode == ExecutionMode.DRY_RUN
            
            # Should indicate simulation
            assert result.data is not None
            action = result.data.get("action", "")
            assert "WOULD_EXECUTE" in action or "would be executed" in str(result.data).lower()
    
    def test_remediation_tool_tag_validation(self):
        """Test remediation tools validate resource tags"""
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        
        # Test with missing tag
        with patch('src.tool_guardrails.boto3.client') as mock_boto:
            mock_ec2_client = MagicMock()
            mock_ec2_client.describe_tags.return_value = {
                'Tags': [
                    {'Key': 'Environment', 'Value': 'test'}
                    # Missing OpsAgentManaged tag
                ]
            }
            mock_boto.return_value = mock_ec2_client
            
            from src.models import ToolCall
            tool_call = ToolCall(
                tool_name="reboot_ec2_instance",
                args={"instance_id": "i-untagged"}
            )
            
            result = tool.execute(tool_call, "test-correlation-id")
            
            # Should fail due to missing tag
            assert result.success is False
            assert "tag" in result.error.lower() or "opsagentmanaged" in result.error.lower()
        
        # Test with wrong tag value
        with patch('src.tool_guardrails.boto3.client') as mock_boto:
            mock_ec2_client = MagicMock()
            mock_ec2_client.describe_tags.return_value = {
                'Tags': [
                    {'Key': 'OpsAgentManaged', 'Value': 'false'},
                    {'Key': 'Environment', 'Value': 'test'}
                ]
            }
            mock_boto.return_value = mock_ec2_client
            
            tool_call = ToolCall(
                tool_name="reboot_ec2_instance",
                args={"instance_id": "i-wrongtag"}
            )
            
            result = tool.execute(tool_call, "test-correlation-id")
            
            # Should fail due to wrong tag value
            assert result.success is False
            assert "tag" in result.error.lower() or "opsagentmanaged" in result.error.lower()
    
    def test_end_to_end_approval_workflow(self):
        """Test complete approval workflow through chat interface"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            # Step 1: Request remediation action
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "userId": "approval-test-user",
                    "messageText": "Reboot instance i-1234567890abcdef0",
                    "channel": "web"
                })
            }
            
            response = lambda_handler(event, None)
            assert response["statusCode"] == 200
            
            body = json.loads(response["body"])
            assert body["success"] is True
            
            # Should require approval
            data = body["data"]
            if data.get("approval_required"):
                assert "approval_data" in data
                approval_data = data["approval_data"]
                assert approval_data["type"] == "approval_card"
                assert "token" in approval_data
                
                approval_token = approval_data["token"]
                
                # Step 2: Approve the request
                approval_event = {
                    "httpMethod": "POST",
                    "path": "/chat",
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({
                        "userId": "approval-test-user",
                        "messageText": f"approve token:{approval_token}",
                        "channel": "web"
                    })
                }
                
                approval_response = lambda_handler(approval_event, None)
                assert approval_response["statusCode"] == 200
                
                approval_body = json.loads(approval_response["body"])
                assert approval_body["success"] is True
                
                # Should contain execution results
                approval_data = approval_body["data"]
                assert "Approval Granted" in approval_data["message"]
    
    def test_approval_denial_workflow(self):
        """Test approval denial workflow"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            # Request remediation
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "userId": "denial-test-user",
                    "messageText": "Reboot instance i-test",
                    "channel": "web"
                })
            }
            
            response = lambda_handler(event, None)
            assert response["statusCode"] == 200
            
            body = json.loads(response["body"])
            data = body["data"]
            
            if data.get("approval_required"):
                approval_token = data["approval_data"]["token"]
                
                # Deny the request
                denial_event = {
                    "httpMethod": "POST",
                    "path": "/chat",
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({
                        "userId": "denial-test-user",
                        "messageText": f"deny token:{approval_token}",
                        "channel": "web"
                    })
                }
                
                denial_response = lambda_handler(denial_event, None)
                assert denial_response["statusCode"] == 200
                
                denial_body = json.loads(denial_response["body"])
                assert denial_body["success"] is True
                
                # Should indicate denial
                denial_data = denial_body["data"]
                assert "denied" in denial_data["message"].lower() or "cancelled" in denial_data["message"].lower()


class TestAuditLoggingVerification:
    """
    Audit logging verification tests
    Requirements: 11.11, 11.14
    """
    
    def test_audit_logger_initialization(self):
        """Test audit logger initializes correctly"""
        audit_logger = AuditLogger(
            cloudwatch_log_group="/test/audit",
            execution_mode=ExecutionMode.LOCAL_MOCK
        )
        
        assert audit_logger.cloudwatch_log_group == "/test/audit"
        assert audit_logger.execution_mode == ExecutionMode.LOCAL_MOCK
        assert audit_logger.dynamodb_table_name is None  # Not required
    
    def test_audit_logging_request_received(self):
        """Test audit logging for incoming requests"""
        audit_logger = AuditLogger(
            cloudwatch_log_group="/test/audit",
            execution_mode=ExecutionMode.LOCAL_MOCK
        )
        
        internal_message = InternalMessage(
            user_id="audit-test-user",
            channel=ChannelType.WEB,
            message_text="Test audit message"
        )
        
        # Should not raise exception
        audit_logger.log_request_received(internal_message)
        
        # In LOCAL_MOCK mode, this should work without AWS credentials
        assert True  # If we get here, logging succeeded
    
    def test_audit_logging_tool_execution(self):
        """Test audit logging for tool execution"""
        audit_logger = AuditLogger(
            cloudwatch_log_group="/test/audit",
            execution_mode=ExecutionMode.LOCAL_MOCK
        )
        
        from src.models import ToolCall, ToolResult
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={"namespace": "AWS/EC2", "metric_name": "CPUUtilization"},
            requires_approval=False
        )
        
        tool_result = ToolResult(
            tool_name="get_cloudwatch_metrics",
            success=True,
            data={"metric_value": 50.0},
            execution_mode=ExecutionMode.LOCAL_MOCK,
            correlation_id=tool_call.correlation_id
        )
        
        # Should not raise exception
        audit_logger.log_tool_call_requested(tool_call, "audit-test-user", "web")
        audit_logger.log_tool_call_executed(tool_call, tool_result, "audit-test-user", "web")
        
        assert True  # If we get here, logging succeeded
    
    def test_audit_logging_approval_workflow(self):
        """Test audit logging for approval workflow"""
        audit_logger = AuditLogger(
            cloudwatch_log_group="/test/audit",
            execution_mode=ExecutionMode.LOCAL_MOCK
        )
        
        from src.models import ToolCall
        from src.approval_gate import ApprovalRequest
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-test"},
            requires_approval=True
        )
        
        approval_request = ApprovalRequest(
            token="test-token-123",
            tool_call=tool_call,
            requested_by="audit-test-user",
            risk_level="medium",
            expires_at=datetime.utcnow() + timedelta(minutes=15)
        )
        
        # Should not raise exception
        audit_logger.log_approval_requested(approval_request, "audit-test-user", "web")
        audit_logger.log_approval_decision(approval_request, "granted", "audit-test-user", "web")
        
        assert True  # If we get here, logging succeeded
    
    def test_audit_logging_error_handling(self):
        """Test audit logging for errors"""
        audit_logger = AuditLogger(
            cloudwatch_log_group="/test/audit",
            execution_mode=ExecutionMode.LOCAL_MOCK
        )
        
        test_error = ValueError("Test error for audit logging")
        
        # Should not raise exception
        audit_logger.log_error(
            test_error,
            "test-correlation-id",
            "audit-test-user",
            {"step": "test", "component": "audit_test"}
        )
        
        assert True  # If we get here, logging succeeded
    
    def test_audit_logging_secret_sanitization(self):
        """Test that audit logging sanitizes secrets"""
        audit_logger = AuditLogger(
            cloudwatch_log_group="/test/audit",
            execution_mode=ExecutionMode.LOCAL_MOCK
        )
        
        # Mock the actual logging to capture what would be logged
        logged_data = []
        
        def mock_write_audit_event(event):
            logged_data.append(event.to_dict())
        
        with patch.object(audit_logger, '_write_audit_event', side_effect=mock_write_audit_event):
            from src.models import ToolCall, ToolResult
            
            # Create tool call with sensitive data
            tool_call = ToolCall(
                tool_name="test_tool",
                args={
                    "api_key": "secret-key-123",
                    "password": "super-secret-password",
                    "token": "bearer-token-456",
                    "normal_param": "safe-value"
                }
            )
            
            tool_result = ToolResult(
                tool_name="test_tool",
                success=True,
                data={
                    "result": "success",
                    "aws_access_key_id": "AKIA123456789",
                    "secret_access_key": "secret123",
                    "session_token": "token456"
                },
                execution_mode=ExecutionMode.LOCAL_MOCK,
                correlation_id=tool_call.correlation_id
            )
            
            audit_logger.log_tool_call_executed(tool_call, tool_result, "test-user", "web")
            
            # Check that sensitive data was sanitized
            assert len(logged_data) > 0
            log_entry = logged_data[0]
            log_str = json.dumps(log_entry).lower()
            
            # Should not contain actual secrets
            assert "secret-key-123" not in log_str
            assert "super-secret-password" not in log_str
            assert "bearer-token-456" not in log_str
            assert "akia123456789" not in log_str
            assert "secret123" not in log_str
            assert "token456" not in log_str
            
            # Should contain sanitized indicators
            assert "[redacted]" in log_str or "***" in log_str
            
            # Should still contain non-sensitive data
            assert "safe-value" in log_str
            assert "success" in log_str
    
    def test_audit_logging_correlation_id_consistency(self):
        """Test that correlation IDs are consistent across audit logs"""
        audit_logger = AuditLogger(
            cloudwatch_log_group="/test/audit",
            execution_mode=ExecutionMode.LOCAL_MOCK
        )
        
        # Mock logging to capture correlation IDs
        logged_correlation_ids = []
        
        def mock_write_audit_event(event):
            event_dict = event.to_dict()
            if "correlation_id" in event_dict:
                logged_correlation_ids.append(event_dict["correlation_id"])
        
        with patch.object(audit_logger, '_write_audit_event', side_effect=mock_write_audit_event):
            internal_message = InternalMessage(
                user_id="correlation-test-user",
                channel=ChannelType.WEB,
                message_text="Test correlation"
            )
            
            correlation_id = internal_message.correlation_id
            
            # Log multiple events with same correlation ID
            audit_logger.log_request_received(internal_message)
            
            from src.models import ToolCall, ToolResult
            tool_call = ToolCall(
                tool_name="test_tool",
                args={},
                correlation_id=correlation_id
            )
            
            audit_logger.log_tool_call_requested(tool_call, "correlation-test-user", "web")
            
            # All logged correlation IDs should match
            assert len(logged_correlation_ids) >= 2
            for logged_id in logged_correlation_ids:
                assert logged_id == correlation_id
    
    def test_audit_logging_integration_with_chat(self):
        """Test audit logging works through chat interface"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            # Mock audit logger to capture logs
            logged_events = []
            
            def mock_log_method(*args, **kwargs):
                logged_events.append({"method": "log_called", "args": args, "kwargs": kwargs})
            
            with patch('src.audit_logger.AuditLogger._write_audit_event', side_effect=mock_log_method):
                event = {
                    "httpMethod": "POST",
                    "path": "/chat",
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({
                        "userId": "audit-integration-user",
                        "messageText": "Check system status",
                        "channel": "web"
                    })
                }
                
                response = lambda_handler(event, None)
                assert response["statusCode"] == 200
                
                # Should have generated audit logs
                assert len(logged_events) > 0
                
                # Should contain request received log
                # (In LOCAL_MOCK mode, some logging might be mocked)


def run_smoke_tests():
    """
    Run all smoke tests and return results
    This function can be called from deployment scripts
    """
    import subprocess
    import sys
    
    # Run the smoke tests
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/test_smoke_tests.py", 
        "-v", 
        "--tb=short",
        "-x"  # Stop on first failure
    ], capture_output=True, text=True)
    
    return result.returncode == 0, result.stdout, result.stderr


if __name__ == "__main__":
    # Allow running smoke tests directly
    success, stdout, stderr = run_smoke_tests()
    print(stdout)
    if stderr:
        print("STDERR:", stderr)
    exit(0 if success else 1)