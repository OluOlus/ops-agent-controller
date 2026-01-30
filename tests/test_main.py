"""
Tests for main Lambda handler
"""
import json
import os
import pytest
from unittest.mock import patch, MagicMock
from src.main import (
    lambda_handler, health_handler, get_execution_mode, get_system_status,
    check_rate_limit, validate_request_signature, parse_chat_request,
    format_response_for_channel, chat_handler, options_handler,
    create_error_response, create_success_response, extract_client_id
)
from src.models import ChannelType


class TestExecutionMode:
    """Test execution mode functionality"""
    
    def test_default_execution_mode(self):
        """Test default execution mode when not set"""
        with patch.dict(os.environ, {}, clear=True):
            mode = get_execution_mode()
            assert mode == "LOCAL_MOCK"
    
    def test_valid_execution_mode(self):
        """Test valid execution mode from environment"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "DRY_RUN"}):
            mode = get_execution_mode()
            assert mode == "DRY_RUN"
    
    def test_invalid_execution_mode_defaults(self):
        """Test invalid execution mode defaults to LOCAL_MOCK"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "INVALID_MODE"}):
            mode = get_execution_mode()
            assert mode == "LOCAL_MOCK"


class TestSystemStatus:
    """Test system status functionality"""
    
    def test_system_status_structure(self):
        """Test system status returns required fields"""
        with patch('boto3.client') as mock_boto3:
            # Mock successful AWS calls
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
            
            status = get_system_status()
            
            required_fields = [
                "execution_mode",
                "llm_provider_status", 
                "aws_tool_access_status",
                "timestamp",
                "environment",
                "version"
            ]
            
            for field in required_fields:
                assert field in status
    
    def test_system_status_lambda_environment(self):
        """Test system status detects Lambda environment"""
        with patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function"}):
            with patch('boto3.client'):
                status = get_system_status()
                assert status["environment"] == "lambda"
                assert status["function_name"] == "test-function"
    
    def test_system_status_local_environment(self):
        """Test system status detects local environment"""
        with patch.dict(os.environ, {}, clear=True):
            with patch('boto3.client'):
                status = get_system_status()
                assert status["environment"] == "local"
    
    def test_system_status_llm_provider_bedrock(self):
        """Test LLM provider status detection for Bedrock"""
        with patch.dict(os.environ, {"LLM_PROVIDER": "bedrock"}):
            with patch('boto3.client'):
                status = get_system_status()
                assert status["llm_provider_type"] == "bedrock"
    
    def test_system_status_aws_error_handling(self):
        """Test AWS error handling in system status"""
        with patch('boto3.client') as mock_boto3:
            mock_boto3.side_effect = Exception("AWS connection failed")
            
            status = get_system_status()
            assert status["aws_tool_access_status"] == "error"
            assert "aws_tool_error" in status


class TestHealthHandler:
    """Test health endpoint handler"""
    
    def test_health_handler_success(self):
        """Test successful health check"""
        with patch('src.main.get_system_status') as mock_status:
            mock_status.return_value = {
                "execution_mode": "LOCAL_MOCK",
                "llm_provider_status": "configured",
                "aws_tool_access_status": "configured",
                "timestamp": "2024-01-01T00:00:00Z",
                "environment": "local",
                "version": "1.0.0"
            }
            
            event = {}
            response = health_handler(event)
            
            assert response["statusCode"] == 200
            assert "application/json" in response["headers"]["Content-Type"]
            
            body = json.loads(response["body"])
            assert body["success"] is True
            assert "data" in body
            assert body["data"]["status"] == "healthy"
            assert "system" in body["data"]
            assert "execution_mode" in body["data"]["system"]
    
    def test_health_handler_cors_headers(self):
        """Test health handler includes CORS headers"""
        with patch('src.main.get_system_status') as mock_status:
            mock_status.return_value = {
                "execution_mode": "LOCAL_MOCK",
                "llm_provider_status": "configured",
                "aws_tool_access_status": "configured",
                "timestamp": "2024-01-01T00:00:00Z",
                "environment": "local",
                "version": "1.0.0"
            }
            
            event = {}
            response = health_handler(event)
            
            assert response["headers"]["Access-Control-Allow-Origin"] == "*"


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limit_allows_initial_requests(self):
        """Test rate limiting allows initial requests"""
        client_id = "test_client_1"
        assert check_rate_limit(client_id) is True
    
    def test_rate_limit_blocks_excessive_requests(self):
        """Test rate limiting blocks excessive requests"""
        client_id = "test_client_2"
        
        # Make requests up to the limit
        for _ in range(30):  # RATE_LIMIT_REQUESTS_PER_MINUTE
            assert check_rate_limit(client_id) is True
        
        # Next request should be blocked
        assert check_rate_limit(client_id) is False


class TestAuthentication:
    """Test request authentication"""
    
    def test_validate_request_signature_with_api_key(self):
        """Test API key authentication"""
        with patch.dict(os.environ, {"API_KEY": "test-key"}):
            event = {
                "headers": {
                    "x-api-key": "test-key"
                }
            }
            assert validate_request_signature(event) is True
    
    def test_validate_request_signature_invalid_api_key(self):
        """Test invalid API key authentication"""
        with patch.dict(os.environ, {"API_KEY": "test-key"}):
            event = {
                "headers": {
                    "x-api-key": "wrong-key"
                }
            }
            assert validate_request_signature(event) is False
    
    def test_validate_request_signature_local_mock_mode(self):
        """Test authentication bypass in LOCAL_MOCK mode"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {"headers": {}}
            assert validate_request_signature(event) is True


class TestChatRequest:
    """Test chat request parsing"""
    
    def test_parse_chat_request_valid(self):
        """Test parsing valid chat request"""
        event = {
            "body": json.dumps({
                "userId": "test-user",
                "messageText": "Hello, OpsAgent!",
                "channel": "web",
                "channelConversationId": "conv-123"
            })
        }
        
        message = parse_chat_request(event)
        assert message.user_id == "test-user"
        assert message.message_text == "Hello, OpsAgent!"
        assert message.channel == ChannelType.WEB
        assert message.channel_conversation_id == "conv-123"
    
    def test_parse_chat_request_missing_fields(self):
        """Test parsing chat request with missing fields"""
        event = {
            "body": json.dumps({})
        }
        
        with pytest.raises(ValueError, match="Message text is required"):
            parse_chat_request(event)
    
    def test_parse_chat_request_invalid_json(self):
        """Test parsing chat request with invalid JSON"""
        event = {
            "body": "invalid json"
        }
        
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_chat_request(event)


class TestResponseFormatting:
    """Test response formatting for different channels"""
    
    def test_format_response_web_channel(self):
        """Test response formatting for web channel"""
        response = format_response_for_channel("Test message", ChannelType.WEB)
        assert response["message"] == "Test message"
        assert "timestamp" in response
    
    def test_format_response_teams_channel(self):
        """Test response formatting for Teams channel"""
        response = format_response_for_channel("Test message", ChannelType.TEAMS)
        assert response["type"] == "message"
        assert response["text"] == "Test message"
    
    def test_format_response_slack_channel(self):
        """Test response formatting for Slack channel"""
        response = format_response_for_channel("Test message", ChannelType.SLACK)
        assert response["text"] == "Test message"
        assert "blocks" in response


class TestChatHandler:
    """Test chat message handler"""
    
    def test_chat_handler_success(self):
        """Test successful chat message handling"""
        event = {
            "body": json.dumps({
                "userId": "test-user",
                "messageText": "Hello, OpsAgent!",
                "channel": "web"
            })
        }
        
        response = chat_handler(event)
        assert response["statusCode"] == 200
        
        body = json.loads(response["body"])
        assert body["success"] is True
        assert "correlationId" in body
    
    def test_chat_handler_validation_error(self):
        """Test chat handler with validation error"""
        event = {
            "body": json.dumps({})
        }
        
        response = chat_handler(event)
        assert response["statusCode"] == 400
        
        body = json.loads(response["body"])
        assert "Bad Request" in body["error"]


class TestOptionsHandler:
    """Test CORS options handler"""
    
    def test_options_handler_cors_headers(self):
        """Test OPTIONS handler returns proper CORS headers"""
        event = {}
        response = options_handler(event)
        
        assert response["statusCode"] == 200
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"
        assert "GET,POST,OPTIONS" in response["headers"]["Access-Control-Allow-Methods"]


class TestLambdaHandler:
    """Test main Lambda handler"""
    
    def test_health_endpoint_routing(self):
        """Test routing to health endpoint"""
        with patch('src.main.get_system_status') as mock_status:
            mock_status.return_value = {
                "execution_mode": "LOCAL_MOCK",
                "llm_provider_status": "configured",
                "aws_tool_access_status": "configured",
                "timestamp": "2024-01-01T00:00:00Z",
                "environment": "local",
                "version": "1.0.0"
            }
            
            event = {
                "httpMethod": "GET",
                "path": "/health"
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            assert body["data"]["status"] == "healthy"
    
    def test_chat_endpoint_routing(self):
        """Test routing to chat endpoint"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "body": json.dumps({
                    "userId": "test-user",
                    "messageText": "Hello!",
                    "channel": "web"
                })
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
    
    def test_options_endpoint_routing(self):
        """Test routing to OPTIONS endpoint"""
        event = {
            "httpMethod": "OPTIONS",
            "path": "/chat"
        }
        
        response = lambda_handler(event, None)
        
        assert response["statusCode"] == 200
        assert response["headers"]["Access-Control-Allow-Origin"] == "*"
    
    def test_unknown_path_returns_404(self):
        """Test unknown paths return 404"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "GET",
                "path": "/unknown"
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 404
            body = json.loads(response["body"])
            assert "Not Found" in body["error"]
    
    def test_rate_limiting_integration(self):
        """Test rate limiting in Lambda handler"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "body": json.dumps({
                    "userId": "rate-limit-user",
                    "messageText": "Hello!",
                    "channel": "web"
                }),
                "requestContext": {
                    "identity": {
                        "sourceIp": "192.168.1.100"
                    }
                }
            }
            
            # Make requests up to the limit
            for _ in range(30):
                response = lambda_handler(event, None)
                assert response["statusCode"] == 200
            
            # Next request should be rate limited
            response = lambda_handler(event, None)
            assert response["statusCode"] == 429
            body = json.loads(response["body"])
            assert "Rate limit exceeded" in body["error"]
    
    def test_authentication_failure(self):
        """Test authentication failure"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "DRY_RUN", "API_KEY": "secret-key"}):
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "body": json.dumps({
                    "userId": "test-user",
                    "messageText": "Hello!",
                    "channel": "web"
                }),
                "headers": {}
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 401
            body = json.loads(response["body"])
            assert "Unauthorized" in body["error"]
    
    def test_lambda_handler_error_handling(self):
        """Test Lambda handler error handling"""
        # Malformed event that should cause an error
        event = None
        
        response = lambda_handler(event, None)
        
        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert "Internal Server Error" in body["error"]


class TestUtilityFunctions:
    """Test utility functions"""
    
    def test_extract_client_id_from_user(self):
        """Test extracting client ID from user ID"""
        event = {
            "body": json.dumps({"userId": "test-user"})
        }
        client_id = extract_client_id(event)
        assert client_id == "user:test-user"
    
    def test_extract_client_id_from_ip(self):
        """Test extracting client ID from IP address"""
        event = {
            "requestContext": {
                "identity": {
                    "sourceIp": "192.168.1.1"
                }
            }
        }
        client_id = extract_client_id(event)
        assert client_id == "ip:192.168.1.1"
    
    def test_create_error_response(self):
        """Test error response creation"""
        response = create_error_response(400, "Test error", "corr-123")
        
        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"] == "Test error"
        assert body["correlationId"] == "corr-123"
    
    def test_create_success_response(self):
        """Test success response creation"""
        data = {"message": "Success"}
        response = create_success_response(data, "corr-456")
        
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["success"] is True
        assert body["data"] == data
        assert body["correlationId"] == "corr-456"