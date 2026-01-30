"""
Integration tests for plugin workflow
Requirements: 13.1, 13.2

This test file covers end-to-end integration testing of the plugin workflow:
- Complete approval workflow from propose to execute
- Audit logging across all operations  
- Error scenarios and edge cases
- Amazon Q Business plugin call simulation
"""
import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

from src.models import (
    PluginRequest, PluginResponse, OperationResult, UserContext, 
    ExecutionMode, ToolCall, ToolResult, ApprovalRequest
)
from src.main import plugin_handler


def mock_integration_environment(execution_mode="DRY_RUN"):
    """Helper function to mock the integration test environment"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with patch.dict('os.environ', {'EXECUTION_MODE': execution_mode}):
                with patch('src.main.authenticate_and_authorize_request') as mock_auth:
                    with patch('boto3.client') as mock_boto3:
                        # Mock AWS clients
                        mock_boto3.return_value = Mock()
                        
                        from src.authentication import AuthenticationResult
                        from src.models import UserContext
                        user_context = UserContext(user_id="integration-test@company.com")
                        mock_auth.return_value = AuthenticationResult(
                            authenticated=True,
                            user_context=user_context,
                            correlation_id="integration-test-correlation-id"
                        )
                        return func(*args, **kwargs)
        return wrapper
    return decorator


class TestPluginWorkflowIntegration:
    """Test complete plugin workflow integration"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="integration-test@company.com")
    
    @mock_integration_environment("DRY_RUN")
    def test_complete_approval_workflow_reboot_ec2(self):
        """Test complete approval workflow for EC2 reboot from propose to execute"""
        
        # Step 1: Propose the action
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-1234567890abcdef0",
                "reason": "Integration test - high CPU utilization"
            },
            "user_context": self.user_context.to_dict()
        }
        
        propose_response = plugin_handler({"body": json.dumps(propose_request)})
        
        # Verify proposal response
        assert propose_response["statusCode"] == 200
        propose_body = json.loads(propose_response["body"])
        assert propose_body["success"] is True
        assert propose_body["data"]["approval_required"] is True
        assert "approval_token" in propose_body["data"]
        assert "expires_at" in propose_body["data"]
        
        approval_token = propose_body["data"]["approval_token"]
        
        # Step 2: Approve and execute the action
        approve_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": approval_token,
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        approve_response = plugin_handler({"body": json.dumps(approve_request)})
        
        # Verify approval and execution response
        assert approve_response["statusCode"] == 200
        approve_body = json.loads(approve_response["body"])
        assert approve_body["success"] is True
        assert approve_body["data"]["action"] == "WOULD_EXECUTE"  # DRY_RUN mode
        assert approve_body["data"]["instance_id"] == "i-1234567890abcdef0"
        
        # Verify correlation IDs are present for audit tracking
        assert "correlationId" in propose_body
        assert "correlationId" in approve_body
    
    @mock_integration_environment("DRY_RUN")
    def test_complete_approval_workflow_scale_ecs(self):
        """Test complete approval workflow for ECS scaling"""
        
        # Step 1: Propose ECS scaling action
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "scale_ecs_service",
                "cluster": "integration-test-cluster",
                "service": "integration-test-service",
                "desired_count": 3,
                "reason": "Integration test - scale up for load testing"
            },
            "user_context": self.user_context.to_dict()
        }
        
        propose_response = plugin_handler({"body": json.dumps(propose_request)})
        
        assert propose_response["statusCode"] == 200
        propose_body = json.loads(propose_response["body"])
        assert propose_body["success"] is True
        assert propose_body["data"]["approval_required"] is True
        
        approval_token = propose_body["data"]["approval_token"]
        
        # Step 2: Approve and execute
        approve_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": approval_token,
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        approve_response = plugin_handler({"body": json.dumps(approve_request)})
        
        assert approve_response["statusCode"] == 200
        approve_body = json.loads(approve_response["body"])
        assert approve_body["success"] is True
        assert approve_body["data"]["action"] == "WOULD_EXECUTE"
    
    @mock_integration_environment("DRY_RUN")
    def test_approval_workflow_denial(self):
        """Test approval workflow with denial"""
        
        # Step 1: Propose action
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-1234567890abcdef0",
                "reason": "Integration test - denial scenario"
            },
            "user_context": self.user_context.to_dict()
        }
        
        propose_response = plugin_handler({"body": json.dumps(propose_request)})
        propose_body = json.loads(propose_response["body"])
        approval_token = propose_body["data"]["approval_token"]
        
        # Step 2: Deny the action
        deny_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": approval_token,
                "approved": False
            },
            "user_context": self.user_context.to_dict()
        }
        
        deny_response = plugin_handler({"body": json.dumps(deny_request)})
        
        assert deny_response["statusCode"] == 200
        deny_body = json.loads(deny_response["body"])
        assert deny_body["success"] is True
        assert deny_body["data"]["approved"] is False
        assert "denied" in deny_body["data"]["message"].lower()
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_diagnostic_operations_integration(self):
        """Test integration of all diagnostic operations"""
        
        diagnostic_operations = [
            {
                "operation": "get_ec2_status",
                "parameters": {
                    "instance_id": "i-1234567890abcdef0",
                    "metrics": ["cpu", "memory", "network"],
                    "time_window": "15m"
                }
            },
            {
                "operation": "get_cloudwatch_metrics",
                "parameters": {
                    "namespace": "AWS/EC2",
                    "metric_name": "CPUUtilization",
                    "resource_id": "i-1234567890abcdef0",
                    "time_window": "30m"
                }
            },
            {
                "operation": "describe_alb_target_health",
                "parameters": {
                    "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/1234567890123456"
                }
            },
            {
                "operation": "search_cloudtrail_events",
                "parameters": {
                    "time_window": "2h",
                    "event_name": "RunInstances"
                }
            }
        ]
        
        for operation_data in diagnostic_operations:
            operation_data["user_context"] = self.user_context.to_dict()
            
            response = plugin_handler({"body": json.dumps(operation_data)})
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            assert body["data"]["execution_mode"] == "LOCAL_MOCK"
            assert "correlationId" in body  # Audit tracking
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_workflow_operations_integration(self):
        """Test integration of workflow operations"""
        
        # Test incident record creation
        incident_request = {
            "operation": "create_incident_record",
            "parameters": {
                "summary": "Integration test incident - high CPU utilization",
                "severity": "medium",
                "links": [
                    "https://console.aws.amazon.com/ec2/v2/home#Instances:instanceId=i-1234567890abcdef0",
                    "https://monitoring.company.com/dashboard/ec2"
                ],
                "description": "Integration test for incident creation workflow"
            },
            "user_context": self.user_context.to_dict()
        }
        
        incident_response = plugin_handler({"body": json.dumps(incident_request)})
        
        assert incident_response["statusCode"] == 200
        incident_body = json.loads(incident_response["body"])
        assert incident_body["success"] is True
        assert "incident_id" in incident_body["data"]["details"]
        
        # Test channel notification
        notification_request = {
            "operation": "post_summary_to_channel",
            "parameters": {
                "text": "🚨 **Integration Test**: Incident created and resolved successfully",
                "channel_id": "19:integration_test_channel@thread.tacv2",
                "message_type": "integration_test"
            },
            "user_context": self.user_context.to_dict()
        }
        
        notification_response = plugin_handler({"body": json.dumps(notification_request)})
        
        assert notification_response["statusCode"] == 200
        notification_body = json.loads(notification_response["body"])
        assert notification_body["success"] is True
        assert "message_id" in notification_body["data"]["details"]
    
    @mock_integration_environment("DRY_RUN")
    def test_mixed_operations_workflow(self):
        """Test workflow combining diagnostic, approval, and workflow operations"""
        
        # Step 1: Diagnose the issue
        diagnostic_request = {
            "operation": "get_ec2_status",
            "parameters": {
                "instance_id": "i-1234567890abcdef0",
                "metrics": ["cpu", "memory"],
                "time_window": "15m"
            },
            "user_context": self.user_context.to_dict()
        }
        
        diagnostic_response = plugin_handler({"body": json.dumps(diagnostic_request)})
        assert diagnostic_response["statusCode"] == 200
        
        # Step 2: Create incident record
        incident_request = {
            "operation": "create_incident_record",
            "parameters": {
                "summary": "Mixed workflow test - EC2 instance issues detected",
                "severity": "high",
                "links": ["https://console.aws.amazon.com/ec2/"]
            },
            "user_context": self.user_context.to_dict()
        }
        
        incident_response = plugin_handler({"body": json.dumps(incident_request)})
        assert incident_response["statusCode"] == 200
        
        # Step 3: Propose remediation action
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-1234567890abcdef0",
                "reason": "Mixed workflow test - remediate detected issues"
            },
            "user_context": self.user_context.to_dict()
        }
        
        propose_response = plugin_handler({"body": json.dumps(propose_request)})
        assert propose_response["statusCode"] == 200
        propose_body = json.loads(propose_response["body"])
        approval_token = propose_body["data"]["approval_token"]
        
        # Step 4: Execute remediation
        approve_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": approval_token,
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        approve_response = plugin_handler({"body": json.dumps(approve_request)})
        assert approve_response["statusCode"] == 200
        
        # Step 5: Post summary to channel
        summary_request = {
            "operation": "post_summary_to_channel",
            "parameters": {
                "text": "✅ **Mixed Workflow Complete**: Issue diagnosed, incident created, remediation executed",
                "channel_id": "19:mixed_workflow_test@thread.tacv2"
            },
            "user_context": self.user_context.to_dict()
        }
        
        summary_response = plugin_handler({"body": json.dumps(summary_request)})
        assert summary_response["statusCode"] == 200


class TestErrorScenariosIntegration:
    """Test error scenarios and edge cases in integration"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="integration-test@company.com")
    
    @mock_integration_environment("DRY_RUN")
    def test_invalid_approval_token_integration(self):
        """Test integration with invalid approval token"""
        
        approve_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": "invalid-token-12345",
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(approve_request)})
        
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["success"] is False
        assert "invalid" in body["error"].lower() or "token" in body["error"].lower()
    
    @mock_integration_environment("DRY_RUN")
    def test_expired_approval_token_integration(self):
        """Test integration with expired approval token scenario"""
        
        # This test simulates what would happen with an expired token
        # In a real scenario, the token would be expired by time
        approve_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": "expired-token-12345",
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(approve_request)})
        
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["success"] is False
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_invalid_operation_integration(self):
        """Test integration with invalid operation"""
        
        request_data = {
            "operation": "invalid_operation_name",
            "parameters": {},
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["success"] is False
        assert "invalid operation" in body["error"].lower()
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_malformed_request_integration(self):
        """Test integration with malformed JSON request"""
        
        malformed_json = '{"operation": "get_ec2_status", "parameters": {'
        
        response = plugin_handler({"body": malformed_json})
        
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["success"] is False
        assert "json" in body["error"].lower() or "parse" in body["error"].lower()
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_missing_required_parameters_integration(self):
        """Test integration with missing required parameters"""
        
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {},  # Missing required instance_id or tag_filter
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["success"] is False


class TestAuditLoggingIntegration:
    """Test audit logging across all operations"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="audit-test@company.com")
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_audit_logging_diagnostic_operations(self):
        """Test that diagnostic operations generate audit logs"""
        
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {
                "instance_id": "i-audit-test-instance",
                "metrics": ["cpu", "memory"]
            },
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        
        # Verify correlation ID is present for audit tracking
        assert "correlationId" in body
        assert body["correlationId"] is not None
        assert len(body["correlationId"]) > 0
    
    @mock_integration_environment("DRY_RUN")
    def test_audit_logging_approval_workflow(self):
        """Test that approval workflow generates comprehensive audit logs"""
        
        # Propose action
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-audit-test-instance",
                "reason": "Audit logging test"
            },
            "user_context": self.user_context.to_dict()
        }
        
        propose_response = plugin_handler({"body": json.dumps(propose_request)})
        propose_body = json.loads(propose_response["body"])
        approval_token = propose_body["data"]["approval_token"]
        
        # Verify proposal audit
        assert "correlationId" in propose_body
        propose_correlation_id = propose_body["correlationId"]
        
        # Approve action
        approve_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": approval_token,
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        approve_response = plugin_handler({"body": json.dumps(approve_request)})
        approve_body = json.loads(approve_response["body"])
        
        # Verify approval audit
        assert "correlationId" in approve_body
        approve_correlation_id = approve_body["correlationId"]
        
        # Correlation IDs should be different for different operations
        assert propose_correlation_id != approve_correlation_id
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_audit_logging_workflow_operations(self):
        """Test that workflow operations generate audit logs"""
        
        # Test incident creation audit
        incident_request = {
            "operation": "create_incident_record",
            "parameters": {
                "summary": "Audit test incident",
                "severity": "low"
            },
            "user_context": self.user_context.to_dict()
        }
        
        incident_response = plugin_handler({"body": json.dumps(incident_request)})
        incident_body = json.loads(incident_response["body"])
        
        assert "correlationId" in incident_body
        
        # Test notification audit
        notification_request = {
            "operation": "post_summary_to_channel",
            "parameters": {
                "text": "Audit test notification",
                "channel_id": "audit-test-channel"
            },
            "user_context": self.user_context.to_dict()
        }
        
        notification_response = plugin_handler({"body": json.dumps(notification_request)})
        notification_body = json.loads(notification_response["body"])
        
        assert "correlationId" in notification_body
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_audit_logging_error_scenarios(self):
        """Test that error scenarios also generate audit logs"""
        
        # Test with invalid operation
        request_data = {
            "operation": "invalid_operation",
            "parameters": {},
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(request_data)})
        body = json.loads(response["body"])
        
        # Even error responses should have correlation IDs for audit
        assert "correlationId" in body
        assert body["correlationId"] is not None


class TestExecutionModeIntegration:
    """Test execution mode behavior in integration scenarios"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="execution-mode-test@company.com")
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_local_mock_mode_integration(self):
        """Test LOCAL_MOCK mode integration behavior"""
        
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {
                "instance_id": "i-mock-test-instance"
            },
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(request_data)})
        body = json.loads(response["body"])
        
        assert body["data"]["execution_mode"] == "LOCAL_MOCK"
        assert body["data"]["details"]["mock"] is True
    
    @mock_integration_environment("DRY_RUN")
    def test_dry_run_mode_integration(self):
        """Test DRY_RUN mode integration behavior"""
        
        # Test write operation in DRY_RUN mode
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-dry-run-test"
            },
            "user_context": self.user_context.to_dict()
        }
        
        propose_response = plugin_handler({"body": json.dumps(propose_request)})
        propose_body = json.loads(propose_response["body"])
        approval_token = propose_body["data"]["approval_token"]
        
        approve_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": approval_token,
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        approve_response = plugin_handler({"body": json.dumps(approve_request)})
        approve_body = json.loads(approve_response["body"])
        
        assert approve_body["data"]["execution_mode"] == "DRY_RUN"
        assert approve_body["data"]["action"] == "WOULD_EXECUTE"
    
    @mock_integration_environment("SANDBOX_LIVE")
    def test_sandbox_live_mode_integration(self):
        """Test SANDBOX_LIVE mode integration behavior"""
        
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {
                "instance_id": "i-sandbox-test-instance"
            },
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(request_data)})
        body = json.loads(response["body"])
        
        assert body["data"]["execution_mode"] == "SANDBOX_LIVE"


class TestPluginResponseFormatIntegration:
    """Test plugin response format compliance in integration scenarios"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="response-format-test@company.com")
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_successful_response_format_compliance(self):
        """Test that all successful responses comply with plugin schema"""
        
        operations = [
            {
                "operation": "get_ec2_status",
                "parameters": {"instance_id": "i-format-test"}
            },
            {
                "operation": "get_cloudwatch_metrics",
                "parameters": {
                    "namespace": "AWS/EC2",
                    "metric_name": "CPUUtilization",
                    "resource_id": "i-format-test"
                }
            },
            {
                "operation": "create_incident_record",
                "parameters": {
                    "summary": "Format test incident",
                    "severity": "low"
                }
            }
        ]
        
        for operation_data in operations:
            operation_data["user_context"] = self.user_context.to_dict()
            
            response = plugin_handler({"body": json.dumps(operation_data)})
            
            # Verify HTTP response structure
            assert response["statusCode"] == 200
            assert "Content-Type" in response["headers"]
            assert response["headers"]["Content-Type"] == "application/json"
            assert "Access-Control-Allow-Origin" in response["headers"]
            
            # Verify JSON response structure
            body = json.loads(response["body"])
            required_fields = ["success", "data", "correlationId", "timestamp"]
            for field in required_fields:
                assert field in body, f"Missing field {field} in response for {operation_data['operation']}"
            
            assert body["success"] is True
            assert isinstance(body["correlationId"], str)
            assert len(body["correlationId"]) > 0
    
    @mock_integration_environment("LOCAL_MOCK")
    def test_error_response_format_compliance(self):
        """Test that error responses comply with plugin schema"""
        
        request_data = {
            "operation": "invalid_operation",
            "parameters": {},
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(request_data)})
        
        # Verify HTTP error response structure
        assert response["statusCode"] == 400
        assert "Content-Type" in response["headers"]
        assert "Access-Control-Allow-Origin" in response["headers"]
        
        # Verify JSON error response structure
        body = json.loads(response["body"])
        required_fields = ["success", "error", "correlationId", "timestamp"]
        for field in required_fields:
            assert field in body
        
        assert body["success"] is False
        assert isinstance(body["error"], str)
        assert len(body["error"]) > 0
        assert isinstance(body["correlationId"], str)
    
    @mock_integration_environment("DRY_RUN")
    def test_approval_response_format_compliance(self):
        """Test that approval workflow responses comply with plugin schema"""
        
        # Test proposal response format
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-format-test"
            },
            "user_context": self.user_context.to_dict()
        }
        
        propose_response = plugin_handler({"body": json.dumps(propose_request)})
        propose_body = json.loads(propose_response["body"])
        
        # Verify proposal response has required approval fields
        assert "approval_required" in propose_body["data"]
        assert "approval_token" in propose_body["data"]
        assert "expires_at" in propose_body["data"]
        assert "action_summary" in propose_body["data"]
        
        # Test approval response format
        approval_token = propose_body["data"]["approval_token"]
        approve_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": approval_token,
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        approve_response = plugin_handler({"body": json.dumps(approve_request)})
        approve_body = json.loads(approve_response["body"])
        
        # Verify approval response has execution details
        assert "action" in approve_body["data"]
        assert "execution_mode" in approve_body["data"]
        assert approve_body["data"]["action"] == "WOULD_EXECUTE"  # DRY_RUN mode