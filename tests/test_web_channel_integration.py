"""
Integration tests for WebChannelAdapter with approval workflow
"""
import json
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from src.main import lambda_handler
from src.channel_adapters import WebChannelAdapter
from src.models import ToolCall, ApprovalRequest, ExecutionMode


class TestWebChannelIntegration:
    """Integration tests for Web channel adapter"""
    
    def test_web_chat_request_integration(self):
        """Test complete web chat request through Lambda handler"""
        # Simulate API Gateway event for web chat
        event = {
            "httpMethod": "POST",
            "path": "/chat",
            "body": json.dumps({
                "userId": "integration-test-user",
                "messageText": "Check system status",
                "channelConversationId": "web-conv-123",
                "executionMode": "DRY_RUN"
            }),
            "headers": {
                "Content-Type": "application/json"
            },
            "requestContext": {
                "identity": {
                    "sourceIp": "192.168.1.100"
                }
            }
        }
        
        # Mock environment for LOCAL_MOCK mode to bypass authentication
        with patch.dict('os.environ', {"EXECUTION_MODE": "LOCAL_MOCK"}):
            response = lambda_handler(event, None)
        
        # Verify response structure
        assert response["statusCode"] == 200
        assert "application/json" in response["headers"]["Content-Type"]
        
        # Parse response body
        body = json.loads(response["body"])
        assert body["success"] is True
        assert "data" in body
        assert "correlationId" in body
        
        # Verify channel adapter formatting
        data = body["data"]
        assert data["message"] is not None
        assert data["channel_data"]["format"] == "text"
        assert "integration-test-user" in data["message"]
        assert "DRY_RUN" in data["message"]
    
    def test_web_health_check_integration(self):
        """Test health check through web channel adapter"""
        event = {
            "httpMethod": "GET",
            "path": "/health",
            "headers": {},
            "requestContext": {
                "identity": {
                    "sourceIp": "192.168.1.100"
                }
            }
        }
        
        with patch('src.main.get_system_status') as mock_status:
            mock_status.return_value = {
                "execution_mode": "LOCAL_MOCK",
                "llm_provider_status": "configured",
                "aws_tool_access_status": "configured",
                "environment": "local",
                "version": "1.0.0"
            }
            
            response = lambda_handler(event, None)
        
        assert response["statusCode"] == 200
        
        body = json.loads(response["body"])
        assert body["success"] is True
        assert "system" in body["data"]
        assert "formatted" in body["data"]
        
        # Verify web channel formatting
        formatted = body["data"]["formatted"]
        assert formatted["channel_data"]["type"] == "system_status"
        assert formatted["channel_data"]["status"] == "healthy"
        assert "OpsAgent Controller Status" in formatted["message"]
    
    def test_approval_card_rendering_integration(self):
        """Test approval card rendering through web channel adapter"""
        adapter = WebChannelAdapter()
        
        # Create a realistic tool call requiring approval
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={
                "instance_id": "i-1234567890abcdef0",
                "force": False,
                "wait_for_running": True
            },
            requires_approval=True,
            correlation_id="approval-integration-test"
        )
        
        # Create approval request
        approval_request = ApprovalRequest(
            token="integration-approval-token-12345",
            expires_at=datetime.utcnow() + timedelta(minutes=15),
            requested_by="integration-test-user",
            tool_call=tool_call,
            risk_level="medium",
            correlation_id="approval-integration-test"
        )
        
        # Format approval card for different execution modes
        for mode in [ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE]:
            response = adapter.format_approval_card(approval_request, mode)
            
            # Verify response structure
            assert response.requires_approval is True
            assert response.approval_data is not None
            assert response.correlation_id == "approval-integration-test"
            
            # Verify approval card content
            card = response.approval_data
            assert card["type"] == "approval_card"
            assert card["token"] == "integration-approval-token-12345"
            assert card["tool"]["name"] == "reboot_ec2_instance"
            assert len(card["tool"]["arguments"]) == 3  # instance_id, force, wait_for_running
            
            # Verify execution mode specific content
            if mode == ExecutionMode.DRY_RUN:
                assert card["execution"]["description"] == "SIMULATE (dry-run)"
                assert card["execution"]["will_modify_infrastructure"] is False
                assert "SIMULATE (dry-run)" in card["actions"][0]["label"]
            else:  # SANDBOX_LIVE
                assert card["execution"]["description"] == "EXECUTE"
                assert card["execution"]["will_modify_infrastructure"] is True
                assert "EXECUTE" in card["actions"][0]["label"]
                assert card["actions"][0]["confirmation_required"] is True
            
            # Verify risk level formatting
            assert card["risk"]["level"] == "medium"
            assert card["risk"]["icon"] == "🟡"
            assert card["risk"]["color"] == "#ffc107"
            
            # Verify expiry information
            assert card["expiry"]["expires_in_minutes"] > 0
            assert card["expiry"]["is_expired"] is False
            
            # Verify actions
            assert len(card["actions"]) == 2
            approve_action = next(a for a in card["actions"] if a["type"] == "approve")
            deny_action = next(a for a in card["actions"] if a["type"] == "deny")
            
            assert approve_action["token"] == "integration-approval-token-12345"
            assert deny_action["token"] == "integration-approval-token-12345"
    
    def test_error_handling_integration(self):
        """Test error handling through web channel adapter"""
        adapter = WebChannelAdapter()
        
        # Test various error scenarios
        error_scenarios = [
            ("VALIDATION_ERROR", "Invalid input provided"),
            ("AUTH_ERROR", "Authentication failed"),
            ("SYSTEM_ERROR", "Internal system error")
        ]
        
        for error_code, error_message in error_scenarios:
            response = adapter.format_error_response(
                error_message,
                error_code,
                "error-test-correlation-123"
            )
            
            # Verify error response structure
            assert response.message == f"❌ Error: {error_message}"
            assert response.correlation_id == "error-test-correlation-123"
            assert response.channel_data["error"] is True
            assert response.channel_data["error_code"] == error_code
            assert response.channel_data["format"] == "error"
    
    def test_message_validation_integration(self):
        """Test message validation through web channel adapter"""
        adapter = WebChannelAdapter()
        
        # Test various invalid message scenarios
        invalid_requests = [
            # Missing body
            {},
            # Invalid JSON
            {"body": "invalid json"},
            # Missing required fields
            {"body": json.dumps({})},
            # Empty message text
            {"body": json.dumps({"userId": "test", "messageText": ""})},
            # Empty user ID
            {"body": json.dumps({"userId": "", "messageText": "Hello"})},
        ]
        
        for invalid_request in invalid_requests:
            with pytest.raises(ValueError):
                adapter.normalize_message(invalid_request)
    
    def test_channel_adapter_factory_integration(self):
        """Test channel adapter factory with web channel"""
        from src.channel_adapters import create_channel_adapter, ChannelType
        
        adapter = create_channel_adapter(ChannelType.WEB)
        
        assert isinstance(adapter, WebChannelAdapter)
        assert adapter.channel_type == ChannelType.WEB
        
        # Test that the adapter can handle a complete workflow
        raw_request = {
            "body": json.dumps({
                "userId": "factory-test-user",
                "messageText": "Test factory integration",
                "executionMode": "LOCAL_MOCK"
            })
        }
        
        # Normalize message
        message = adapter.normalize_message(raw_request)
        assert message.user_id == "factory-test-user"
        assert message.message_text == "Test factory integration"
        
        # Format response
        response = adapter.format_response(
            "Factory test successful",
            message.correlation_id
        )
        assert response.message == "Factory test successful"
        assert response.correlation_id == message.correlation_id
    
    def test_cors_and_headers_integration(self):
        """Test CORS headers in web channel responses"""
        event = {
            "httpMethod": "OPTIONS",
            "path": "/chat",
            "headers": {
                "Origin": "https://example.com"
            }
        }
        
        response = lambda_handler(event, None)
        
        assert response["statusCode"] == 200
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"
        assert "GET,POST,OPTIONS" in response["headers"]["Access-Control-Allow-Methods"]
        assert "Content-Type" in response["headers"]["Access-Control-Allow-Headers"]
    
    def test_rate_limiting_integration(self):
        """Test rate limiting with web channel adapter"""
        base_event = {
            "httpMethod": "POST",
            "path": "/chat",
            "body": json.dumps({
                "userId": "rate-limit-test-user",
                "messageText": "Rate limit test",
            }),
            "headers": {"Content-Type": "application/json"},
            "requestContext": {
                "identity": {"sourceIp": "192.168.1.200"}
            }
        }
        
        with patch.dict('os.environ', {"EXECUTION_MODE": "LOCAL_MOCK"}):
            # Make requests up to the limit (30 requests per minute)
            for i in range(30):
                response = lambda_handler(base_event, None)
                assert response["statusCode"] == 200
            
            # Next request should be rate limited
            response = lambda_handler(base_event, None)
            assert response["statusCode"] == 429
            
            body = json.loads(response["body"])
            assert "Rate limit exceeded" in body["error"]