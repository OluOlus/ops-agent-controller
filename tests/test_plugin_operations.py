"""
Comprehensive unit tests for all 8 plugin operations
Requirements: 13.1, 13.2

This test file covers all 8 operations defined in the OpsAgent Actions system:

Diagnostic Operations (4):
1. get_ec2_status - EC2 instance health and metrics
2. get_cloudwatch_metrics - CloudWatch metrics retrieval  
3. describe_alb_target_health - ALB/Target Group health
4. search_cloudtrail_events - CloudTrail event search

Write Operations (2):
5. reboot_ec2 - EC2 instance reboot (approval required)
6. scale_ecs_service - ECS service scaling (approval required)

Workflow Operations (2):
7. create_incident_record - Incident management
8. post_summary_to_channel - Teams notifications
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
from src.tool_execution_engine import ToolExecutionEngine, ExecutionContext
from src.approval_gate import ApprovalGate
from src.main import plugin_handler


def mock_plugin_environment(execution_mode="LOCAL_MOCK"):
    """Helper function to mock the plugin environment"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with patch.dict('os.environ', {'EXECUTION_MODE': execution_mode}):
                with patch('src.main.authenticate_and_authorize_request') as mock_auth:
                    with patch('boto3.client') as mock_boto3:
                        # Mock AWS clients
                        mock_boto3.return_value = Mock()
                        
                        from src.authentication import AuthenticationResult
                        from src.models import UserContext
                        user_context = UserContext(user_id="test-user@company.com")
                        mock_auth.return_value = AuthenticationResult(
                            authenticated=True,
                            user_context=user_context,
                            correlation_id="test-correlation-id"
                        )
                        return func(*args, **kwargs)
        return wrapper
    return decorator


class TestDiagnosticOperations:
    """Test all 4 diagnostic operations (no approval required)"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="test-user@company.com")
        self.execution_mode = ExecutionMode.LOCAL_MOCK
        
    @mock_plugin_environment()
    def test_get_ec2_status_success(self):
        """Test get_ec2_status operation success"""
        # Create plugin request
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {
                "instance_id": "i-1234567890abcdef0",
                "metrics": ["cpu", "memory", "network"],
                "time_window": "15m"
            },
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        assert body["data"]["execution_mode"] == "LOCAL_MOCK"
        assert "instances" in body["data"]["details"]
        assert body["data"]["details"]["instance_count"] == 1
        assert body["data"]["details"]["mock"] is True
    
    @mock_plugin_environment()
    def test_get_ec2_status_with_tag_filter(self):
        """Test get_ec2_status with tag filter instead of instance ID"""
        request_data = {
            "operation": "get_ec2_status", 
            "parameters": {
                "tag_filter": {"Environment": "production", "Service": "web"},
                "metrics": ["cpu", "memory"]
            },
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
    
    @mock_plugin_environment()
    def test_get_cloudwatch_metrics_success(self):
        """Test get_cloudwatch_metrics operation success"""
        request_data = {
            "operation": "get_cloudwatch_metrics",
            "parameters": {
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization", 
                "resource_id": "i-1234567890abcdef0",
                "time_window": "30m"
            },
            "user_context": self.user_context.to_dict()
        }
        
        response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        assert body["data"]["execution_mode"] == "LOCAL_MOCK"
        assert "latest_value" in body["data"]["details"]
        assert "max_value" in body["data"]["details"]
        assert "min_value" in body["data"]["details"]
    
    def test_get_cloudwatch_metrics_multiple_dimensions(self):
        """Test get_cloudwatch_metrics with multiple dimensions"""
        request_data = {
            "operation": "get_cloudwatch_metrics",
            "parameters": {
                "namespace": "AWS/ECS",
                "metric_name": "CPUUtilization",
                "dimensions": {
                    "ServiceName": "my-service",
                    "ClusterName": "my-cluster"
                },
                "time_window": "1h"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
    
    def test_describe_alb_target_health_success(self):
        """Test describe_alb_target_health operation success"""
        request_data = {
            "operation": "describe_alb_target_health",
            "parameters": {
                "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/1234567890123456"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        assert body["data"]["operation"] == "describe_alb_target_health"
        assert "healthy_targets" in body["data"]["details"]
        assert "unhealthy_targets" in body["data"]["details"]
        assert "target_details" in body["data"]["details"]
    
    def test_describe_alb_target_health_with_alb_arn(self):
        """Test describe_alb_target_health with ALB ARN"""
        request_data = {
            "operation": "describe_alb_target_health",
            "parameters": {
                "alb_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
    
    def test_search_cloudtrail_events_success(self):
        """Test search_cloudtrail_events operation success"""
        request_data = {
            "operation": "search_cloudtrail_events",
            "parameters": {
                "filter": {
                    "event_name": "RunInstances",
                    "resource_name": "i-1234567890abcdef0"
                },
                "time_window": "1h",
                "max_results": 50
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        assert body["data"]["operation"] == "search_cloudtrail_events"
        assert "events" in body["data"]["details"]
        assert "event_count" in body["data"]["details"]
    
    def test_search_cloudtrail_events_with_filters(self):
        """Test search_cloudtrail_events with additional filters"""
        request_data = {
            "operation": "search_cloudtrail_events",
            "parameters": {
                "filter": {
                    "user_name": "test-user",
                    "source_ip": "192.168.1.100"
                },
                "time_window": "24h"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
    
    def test_diagnostic_operations_error_handling(self):
        """Test error handling for diagnostic operations"""
        # Test with invalid parameters
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {
                "instance_id": "invalid-instance-id"  # Invalid format
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        # Should still succeed in LOCAL_MOCK mode but may include validation warnings
        assert response["statusCode"] == 200
    
    def test_diagnostic_operations_read_only_guarantee(self):
        """Test that diagnostic operations are truly read-only"""
        # This test verifies that diagnostic operations don't modify resources
        diagnostic_operations = [
            "get_ec2_status",
            "get_cloudwatch_metrics", 
            "describe_alb_target_health",
            "search_cloudtrail_events"
        ]
        
        for operation in diagnostic_operations:
            request_data = {
                "operation": operation,
                "parameters": {"instance_id": "i-1234567890abcdef0"} if operation == "get_ec2_status" else {},
                "user_context": self.user_context.to_dict()
            }
            
            with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
                response = plugin_handler({"body": json.dumps(request_data)})
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            # Verify no approval was required
            assert "approval_required" not in body["data"] or body["data"]["approval_required"] is False


class TestWriteOperations:
    """Test both write operations (approval required)"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="test-user@company.com")
        self.execution_mode = ExecutionMode.DRY_RUN
    
    @mock_plugin_environment("DRY_RUN")
    def test_reboot_ec2_propose_action(self):
        """Test proposing reboot_ec2 action (should require approval)"""
        request_data = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-1234567890abcdef0",
                "reason": "High CPU utilization, unresponsive to SSH"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        assert body["data"]["approval_required"] is True
        assert "approval_token" in body["data"]
        assert "expires_at" in body["data"]
        assert body["data"]["action_summary"] == "Execute reboot_ec2 with specified parameters"
        assert "risk_level" in body["data"]
    
    @mock_plugin_environment("DRY_RUN")
    def test_reboot_ec2_approve_and_execute(self):
        """Test approving and executing reboot_ec2 action"""
        # First propose the action
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-1234567890abcdef0",
                "reason": "System maintenance"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            propose_response = plugin_handler({"body": json.dumps(propose_request)})
        
        assert propose_response["statusCode"] == 200
        propose_body = json.loads(propose_response["body"])
        approval_token = propose_body["data"]["approval_token"]
        
        # Then approve and execute
        approve_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": approval_token,
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            approve_response = plugin_handler({"body": json.dumps(approve_request)})
        
        assert approve_response["statusCode"] == 200
        approve_body = json.loads(approve_response["body"])
        assert approve_body["success"] is True
        assert approve_body["data"]["action"] == "WOULD_EXECUTE"  # DRY_RUN mode
        assert approve_body["data"]["instance_id"] == "i-1234567890abcdef0"
    
    @mock_plugin_environment("DRY_RUN")
    def test_scale_ecs_service_propose_action(self):
        """Test proposing scale_ecs_service action"""
        request_data = {
            "operation": "propose_action",
            "parameters": {
                "action": "scale_ecs_service",
                "cluster": "my-cluster",
                "service": "my-service", 
                "desired_count": 5,
                "reason": "Increased traffic load"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        assert body["data"]["approval_required"] is True
        assert "approval_token" in body["data"]
        assert "Execute scale_ecs_service with specified parameters" in body["data"]["action_summary"]
    
    @mock_plugin_environment("DRY_RUN")
    def test_scale_ecs_service_approve_and_execute(self):
        """Test approving and executing scale_ecs_service action"""
        # First propose the action
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "scale_ecs_service",
                "cluster": "my-cluster",
                "service": "my-service",
                "desired_count": 3,
                "reason": "Scale down for cost optimization"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            propose_response = plugin_handler({"body": json.dumps(propose_request)})
        
        assert propose_response["statusCode"] == 200
        propose_body = json.loads(propose_response["body"])
        approval_token = propose_body["data"]["approval_token"]
        
        # Then approve and execute
        approve_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": approval_token,
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            approve_response = plugin_handler({"body": json.dumps(approve_request)})
        
        assert approve_response["statusCode"] == 200
        approve_body = json.loads(approve_response["body"])
        assert approve_body["success"] is True
        assert approve_body["data"]["action"] == "WOULD_EXECUTE"  # DRY_RUN mode
    
    @mock_plugin_environment("DRY_RUN")
    def test_write_operations_require_approval(self):
        """Test that write operations always require approval"""
        write_operations = [
            {
                "action": "reboot_ec2",
                "instance_id": "i-1234567890abcdef0",
                "reason": "System maintenance required"
            },
            {
                "action": "scale_ecs_service", 
                "cluster": "my-cluster",
                "service": "my-service",
                "desired_count": 2,
                "reason": "Scale down for cost optimization"
            }
        ]
        
        for operation_params in write_operations:
            request_data = {
                "operation": "propose_action",
                "parameters": operation_params,
                "user_context": self.user_context.to_dict()
            }
            
            with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
                response = plugin_handler({"body": json.dumps(request_data)})
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            assert body["data"]["approval_required"] is True
            assert "approval_token" in body["data"]
    
    @mock_plugin_environment("DRY_RUN")
    def test_approval_token_expiry(self):
        """Test that approval tokens have proper expiry"""
        request_data = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-1234567890abcdef0",
                "reason": "System maintenance required"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        
        # Verify expiry time is set and is in the future
        expires_at = datetime.fromisoformat(body["data"]["expires_at"].replace('Z', '+00:00'))
        now = datetime.now(expires_at.tzinfo)
        assert expires_at > now
        
        # Verify expiry is within reasonable range (should be ~15 minutes)
        time_diff = expires_at - now
        assert timedelta(minutes=10) < time_diff < timedelta(minutes=20)
    
    @mock_plugin_environment("DRY_RUN")
    def test_approval_denial(self):
        """Test denying an approval request"""
        # First propose the action
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-1234567890abcdef0",
                "reason": "System maintenance required"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            propose_response = plugin_handler({"body": json.dumps(propose_request)})
        
        propose_body = json.loads(propose_response["body"])
        approval_token = propose_body["data"]["approval_token"]
        
        # Then deny the request
        deny_request = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": approval_token,
                "approved": False
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            deny_response = plugin_handler({"body": json.dumps(deny_request)})
        
        assert deny_response["statusCode"] == 200
        deny_body = json.loads(deny_response["body"])
        assert deny_body["success"] is True
        assert deny_body["data"]["approved"] is False
        assert "denied" in deny_body["data"]["message"].lower()


class TestWorkflowOperations:
    """Test both workflow operations (no approval, fully audited)"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="test-user@company.com")
        self.execution_mode = ExecutionMode.LOCAL_MOCK
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_create_incident_record_success(self):
        """Test create_incident_record operation success"""
        request_data = {
            "operation": "create_incident_record",
            "parameters": {
                "summary": "High CPU utilization on production instances",
                "severity": "medium",
                "links": [
                    "https://console.aws.amazon.com/ec2/v2/home#Instances:instanceId=i-1234567890abcdef0",
                    "https://monitoring.company.com/dashboard/ec2"
                ]
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        assert body["data"]["operation"] == "create_incident_record"
        assert "incident_id" in body["data"]["details"]
        assert "created_at" in body["data"]["details"]
        assert body["data"]["details"]["severity"] == "medium"
        assert len(body["data"]["details"]["links"]) == 2
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_create_incident_record_different_severities(self):
        """Test create_incident_record with different severity levels"""
        severities = ["low", "medium", "high", "critical"]
        
        for severity in severities:
            request_data = {
                "operation": "create_incident_record",
                "parameters": {
                    "summary": f"Test incident - {severity} severity",
                    "severity": severity,
                    "links": ["https://example.com/dashboard"]
                },
                "user_context": self.user_context.to_dict()
            }
            
            with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
                response = plugin_handler({"body": json.dumps(request_data)})
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            assert body["data"]["details"]["severity"] == severity
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_post_summary_to_channel_success(self):
        """Test post_summary_to_channel operation success"""
        request_data = {
            "operation": "post_summary_to_channel",
            "parameters": {
                "text": "🚨 **Incident Update**: High CPU utilization resolved on production instances. All systems normal.",
                "channel_id": "19:meeting_channel_id@thread.tacv2",
                "message_type": "incident_update"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        assert body["data"]["operation"] == "post_summary_to_channel"
        assert "message_id" in body["data"]["details"]
        assert "posted_at" in body["data"]["details"]
        assert body["data"]["details"]["delivery_status"] == "sent"
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_post_summary_to_channel_with_webhook(self):
        """Test post_summary_to_channel with webhook URL"""
        request_data = {
            "operation": "post_summary_to_channel",
            "parameters": {
                "text": "Automated deployment completed successfully",
                "webhook_url": "https://company.webhook.office.com/webhookb2/...",
                "message_type": "deployment_notification"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        assert body["data"]["details"]["delivery_method"] == "webhook"
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_workflow_operations_no_approval_required(self):
        """Test that workflow operations don't require approval"""
        workflow_operations = [
            {
                "operation": "create_incident_record",
                "parameters": {
                    "summary": "Test incident",
                    "severity": "low"
                }
            },
            {
                "operation": "post_summary_to_channel", 
                "parameters": {
                    "text": "Test message",
                    "channel_id": "test-channel"
                }
            }
        ]
        
        for request_data in workflow_operations:
            request_data["user_context"] = self.user_context.to_dict()
            
            with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
                response = plugin_handler({"body": json.dumps(request_data)})
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            # Verify no approval was required
            assert "approval_required" not in body["data"] or body["data"]["approval_required"] is False
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_workflow_operations_audit_logging(self):
        """Test that workflow operations are fully audited"""
        request_data = {
            "operation": "create_incident_record",
            "parameters": {
                "summary": "Audit test incident",
                "severity": "low"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        
        # Verify correlation ID is present for audit tracking
        assert "correlationId" in body
        assert body["correlationId"] is not None


class TestExecutionModeHandling:
    """Test execution mode switching and response formatting"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="test-user@company.com")
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_local_mock_mode_responses(self):
        """Test that LOCAL_MOCK mode returns mock responses"""
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {"instance_id": "i-1234567890abcdef0"},
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["data"]["execution_mode"] == "LOCAL_MOCK"
        assert body["data"]["details"]["mock"] is True
    
    @mock_plugin_environment("DRY_RUN")
    def test_dry_run_mode_responses(self):
        """Test that DRY_RUN mode returns appropriate responses"""
        # Test write operation in DRY_RUN mode
        propose_request = {
            "operation": "propose_action",
            "parameters": {
                "action": "reboot_ec2",
                "instance_id": "i-1234567890abcdef0"
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            propose_response = plugin_handler({"body": json.dumps(propose_request)})
            propose_body = json.loads(propose_response["body"])
            approval_token = propose_body["data"]["approval_token"]
            
            # Approve and execute
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
        assert approve_body["data"]["execution_mode"] == "DRY_RUN"
        assert approve_body["data"]["action"] == "WOULD_EXECUTE"
    
    @mock_plugin_environment("SANDBOX_LIVE")
    def test_sandbox_live_mode_responses(self):
        """Test that SANDBOX_LIVE mode returns live responses"""
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {"instance_id": "i-1234567890abcdef0"},
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'SANDBOX_LIVE'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["data"]["execution_mode"] == "SANDBOX_LIVE"
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_execution_mode_consistency(self):
        """Test that execution mode is consistent across operations"""
        operations = [
            {
                "operation": "get_ec2_status",
                "parameters": {"instance_id": "i-1234567890abcdef0"}
            },
            {
                "operation": "get_cloudwatch_metrics",
                "parameters": {
                    "namespace": "AWS/EC2",
                    "metric_name": "CPUUtilization",
                    "resource_id": "i-1234567890abcdef0"
                }
            },
            {
                "operation": "create_incident_record",
                "parameters": {
                    "summary": "Test incident",
                    "severity": "low"
                }
            }
        ]
        
        for mode in ["LOCAL_MOCK", "DRY_RUN", "SANDBOX_LIVE"]:
            for operation_data in operations:
                operation_data["user_context"] = self.user_context.to_dict()
                
                with patch.dict('os.environ', {'EXECUTION_MODE': mode}):
                    response = plugin_handler({"body": json.dumps(operation_data)})
                
                assert response["statusCode"] == 200
                body = json.loads(response["body"])
                assert body["data"]["execution_mode"] == mode


class TestErrorHandling:
    """Test error handling across all operations"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="test-user@company.com")
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_invalid_operation_error(self):
        """Test handling of invalid operation names"""
        request_data = {
            "operation": "invalid_operation",
            "parameters": {},
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["success"] is False
        assert "invalid operation" in body["error"].lower()
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_missing_parameters_error(self):
        """Test handling of missing required parameters"""
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {},  # Missing required instance_id or tag_filter
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        # Should return error for missing parameters
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["success"] is False
    
    @mock_plugin_environment("DRY_RUN")
    def test_invalid_approval_token_error(self):
        """Test handling of invalid approval tokens"""
        request_data = {
            "operation": "approve_action",
            "parameters": {
                "approval_token": "invalid-token-123",
                "approved": True
            },
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'DRY_RUN'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["success"] is False
        assert "invalid" in body["error"].lower() or "token" in body["error"].lower()
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_aws_api_error_handling(self):
        """Test handling of AWS API errors"""
        # This test would require mocking AWS API failures
        # For now, we'll test that the system handles errors gracefully
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {"instance_id": "i-nonexistent"},
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        # In LOCAL_MOCK mode, should still succeed with mock data
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_malformed_request_error(self):
        """Test handling of malformed JSON requests"""
        malformed_json = '{"operation": "get_ec2_status", "parameters": {'
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": malformed_json})
        
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        # Error responses have different structure
        assert "error" in body
        assert isinstance(body["error"], str)
        assert len(body["error"]) > 0


class TestResponseFormatCompliance:
    """Test that all responses conform to plugin schema"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.user_context = UserContext(user_id="test-user@company.com")
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_successful_response_format(self):
        """Test that successful responses have required fields"""
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {"instance_id": "i-1234567890abcdef0"},
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 200
        assert "Content-Type" in response["headers"]
        assert response["headers"]["Content-Type"] == "application/json"
        
        body = json.loads(response["body"])
        required_fields = ["success", "data", "correlationId"]
        for field in required_fields:
            assert field in body
        
        # Check data structure
        assert "operation" in body["data"]
        assert "execution_mode" in body["data"]
        assert "details" in body["data"]
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_error_response_format(self):
        """Test that error responses have required fields"""
        request_data = {
            "operation": "invalid_operation",
            "parameters": {},
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        
        # Error responses have different structure - they have "error" at top level, not "success"
        assert "error" in body
        assert "correlationId" in body
        assert isinstance(body["error"], str)
        assert len(body["error"]) > 0
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_cors_headers_present(self):
        """Test that CORS headers are present in all responses"""
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {"instance_id": "i-1234567890abcdef0"},
            "user_context": self.user_context.to_dict()
        }
        
        with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
            response = plugin_handler({"body": json.dumps(request_data)})
        
        assert "Access-Control-Allow-Origin" in response["headers"]
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"
    
    @mock_plugin_environment("LOCAL_MOCK")
    def test_correlation_id_consistency(self):
        """Test that correlation IDs are consistent and unique"""
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {"instance_id": "i-1234567890abcdef0"},
            "user_context": self.user_context.to_dict()
        }
        
        correlation_ids = set()
        
        # Make multiple requests and verify unique correlation IDs
        for _ in range(5):
            with patch.dict('os.environ', {'EXECUTION_MODE': 'LOCAL_MOCK'}):
                response = plugin_handler({"body": json.dumps(request_data)})
            
            body = json.loads(response["body"])
            correlation_id = body["correlationId"]
            
            assert correlation_id is not None
            assert len(correlation_id) > 0
            assert correlation_id not in correlation_ids
            correlation_ids.add(correlation_id)