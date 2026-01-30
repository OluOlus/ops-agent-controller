"""
Unit tests for internal message models
"""
import pytest
from datetime import datetime, timedelta
from src.models import (
    InternalMessage, ToolCall, ToolResult, ApprovalToken, ApprovalRequest,
    ExecutionMode, ChannelType, UserContext, PluginRequest, PluginResponse, OperationResult,
    generate_correlation_id, generate_approval_token, validate_plugin_request,
    sanitize_parameters, extract_user_context, validate_message_text, 
    validate_user_id, validate_channel_conversation_id
)


class TestInternalMessage:
    """Test InternalMessage model"""
    
    def test_default_creation(self):
        """Test creating InternalMessage with defaults"""
        msg = InternalMessage()
        
        assert msg.correlation_id is not None
        assert len(msg.correlation_id) > 0
        assert msg.user_id == ""
        assert msg.channel == ChannelType.WEB
        assert msg.channel_conversation_id == ""
        assert msg.message_text == ""
        assert isinstance(msg.timestamp, datetime)
        assert msg.execution_mode == ExecutionMode.SANDBOX_LIVE
    
    def test_creation_with_values(self):
        """Test creating InternalMessage with specific values"""
        timestamp = datetime.utcnow()
        msg = InternalMessage(
            user_id="test_user",
            channel=ChannelType.TEAMS,
            channel_conversation_id="conv_123",
            message_text="Hello world",
            timestamp=timestamp,
            execution_mode=ExecutionMode.DRY_RUN
        )
        
        assert msg.user_id == "test_user"
        assert msg.channel == ChannelType.TEAMS
        assert msg.channel_conversation_id == "conv_123"
        assert msg.message_text == "Hello world"
        assert msg.timestamp == timestamp
        assert msg.execution_mode == ExecutionMode.DRY_RUN
    
    def test_to_dict(self):
        """Test converting InternalMessage to dictionary"""
        msg = InternalMessage(
            user_id="test_user",
            channel=ChannelType.TEAMS,
            message_text="Hello"
        )
        
        data = msg.to_dict()
        
        assert data["user_id"] == "test_user"
        assert data["channel"] == "teams"
        assert data["message_text"] == "Hello"
        assert data["execution_mode"] == "SANDBOX_LIVE"
        assert "correlation_id" in data
        assert "timestamp" in data
    
    def test_from_dict(self):
        """Test creating InternalMessage from dictionary"""
        data = {
            "user_id": "test_user",
            "channel": "teams",
            "message_text": "Hello",
            "execution_mode": "DRY_RUN"
        }
        
        msg = InternalMessage.from_dict(data)
        
        assert msg.user_id == "test_user"
        assert msg.channel == ChannelType.TEAMS
        assert msg.message_text == "Hello"
        assert msg.execution_mode == ExecutionMode.DRY_RUN


class TestToolCall:
    """Test ToolCall model"""
    
    def test_default_creation(self):
        """Test creating ToolCall with defaults"""
        tool_call = ToolCall(tool_name="test_tool")
        
        assert tool_call.tool_name == "test_tool"
        assert tool_call.args == {}
        assert tool_call.requires_approval is False
        assert tool_call.correlation_id is not None
    
    def test_creation_with_values(self):
        """Test creating ToolCall with specific values"""
        args = {"param1": "value1", "param2": 42}
        tool_call = ToolCall(
            tool_name="ec2_reboot",
            args=args,
            requires_approval=True
        )
        
        assert tool_call.tool_name == "ec2_reboot"
        assert tool_call.args == args
        assert tool_call.requires_approval is True
    
    def test_to_dict(self):
        """Test converting ToolCall to dictionary"""
        tool_call = ToolCall(
            tool_name="test_tool",
            args={"key": "value"},
            requires_approval=True
        )
        
        data = tool_call.to_dict()
        
        assert data["tool_name"] == "test_tool"
        assert data["args"] == {"key": "value"}
        assert data["requires_approval"] is True
        assert "correlation_id" in data
    
    def test_from_dict(self):
        """Test creating ToolCall from dictionary"""
        data = {
            "tool_name": "test_tool",
            "args": {"key": "value"},
            "requires_approval": True
        }
        
        tool_call = ToolCall.from_dict(data)
        
        assert tool_call.tool_name == "test_tool"
        assert tool_call.args == {"key": "value"}
        assert tool_call.requires_approval is True


class TestToolResult:
    """Test ToolResult model"""
    
    def test_success_result(self):
        """Test creating successful ToolResult"""
        data = {"metric": "cpu_utilization", "value": 75.5}
        result = ToolResult(
            tool_name="get_metrics",
            success=True,
            data=data
        )
        
        assert result.tool_name == "get_metrics"
        assert result.success is True
        assert result.data == data
        assert result.error is None
        assert result.execution_mode == ExecutionMode.SANDBOX_LIVE
    
    def test_error_result(self):
        """Test creating error ToolResult"""
        result = ToolResult(
            tool_name="get_metrics",
            success=False,
            error="AWS API error: Access denied"
        )
        
        assert result.tool_name == "get_metrics"
        assert result.success is False
        assert result.data is None
        assert result.error == "AWS API error: Access denied"
    
    def test_to_dict(self):
        """Test converting ToolResult to dictionary"""
        result = ToolResult(
            tool_name="test_tool",
            success=True,
            data={"result": "success"},
            execution_mode=ExecutionMode.DRY_RUN
        )
        
        data = result.to_dict()
        
        assert data["tool_name"] == "test_tool"
        assert data["success"] is True
        assert data["data"] == {"result": "success"}
        assert data["execution_mode"] == "DRY_RUN"
        assert "timestamp" in data
        assert "correlation_id" in data


class TestApprovalRequest:
    """Test ApprovalRequest model (legacy alias for ApprovalToken)"""
    
    def test_default_creation(self):
        """Test creating ApprovalRequest with defaults"""
        approval = ApprovalRequest()
        
        assert approval.token is not None
        assert len(approval.token) > 0
        assert isinstance(approval.expires_at, datetime)
        assert approval.user_id == ""
        assert approval.tool_call is None
        assert approval.risk_level == "medium"
    
    def test_creation_with_tool_call(self):
        """Test creating ApprovalRequest with ToolCall"""
        tool_call = ToolCall(tool_name="ec2_reboot", requires_approval=True)
        approval = ApprovalRequest(
            user_id="user123",
            tool_call=tool_call,
            risk_level="high"
        )
        
        assert approval.user_id == "user123"
        assert approval.tool_call == tool_call
        assert approval.risk_level == "high"
    
    def test_to_dict_with_tool_call(self):
        """Test converting ApprovalRequest with ToolCall to dictionary"""
        tool_call = ToolCall(tool_name="test_tool")
        approval = ApprovalRequest(
            user_id="user123",
            tool_call=tool_call
        )
        
        data = approval.to_dict()
        
        assert data["user_id"] == "user123"
        assert data["tool_call"]["tool_name"] == "test_tool"
        assert "token" in data
        assert "expires_at" in data


class TestUtilityFunctions:
    """Test utility functions"""
    
    def test_generate_correlation_id(self):
        """Test correlation ID generation"""
        id1 = generate_correlation_id()
        id2 = generate_correlation_id()
        
        assert id1 != id2
        assert len(id1) > 0
        assert len(id2) > 0
    
    def test_validate_message_text_valid(self):
        """Test validating valid message text"""
        text = "Hello, how are you?"
        result = validate_message_text(text)
        assert result == text
    
    def test_validate_message_text_sanitization(self):
        """Test message text sanitization"""
        text = "Hello\x00world\r\n  "
        result = validate_message_text(text)
        assert result == "Helloworld"
    
    def test_validate_message_text_truncation(self):
        """Test message text truncation"""
        text = "a" * 5000  # Longer than max_length
        result = validate_message_text(text)
        assert len(result) <= 4020  # 4000 + "... [truncated]"
        assert result.endswith("... [truncated]")
    
    def test_validate_message_text_invalid_type(self):
        """Test validating invalid message text type"""
        with pytest.raises(ValueError, match="Message text must be a string"):
            validate_message_text(123)
    
    def test_validate_user_id_valid(self):
        """Test validating valid user ID"""
        user_id = "user123"
        result = validate_user_id(user_id)
        assert result == user_id
    
    def test_validate_user_id_empty(self):
        """Test validating empty user ID"""
        with pytest.raises(ValueError, match="User ID cannot be empty"):
            validate_user_id("")
        
        with pytest.raises(ValueError, match="User ID cannot be empty"):
            validate_user_id("   ")
    
    def test_validate_user_id_too_long(self):
        """Test validating too long user ID"""
        user_id = "a" * 300  # Longer than max_length
        with pytest.raises(ValueError, match="User ID too long"):
            validate_user_id(user_id)
    
    def test_validate_user_id_invalid_type(self):
        """Test validating invalid user ID type"""
        with pytest.raises(ValueError, match="User ID must be a string"):
            validate_user_id(123)
    
    def test_validate_channel_conversation_id_valid(self):
        """Test validating valid conversation ID"""
        conv_id = "conv_123"
        result = validate_channel_conversation_id(conv_id)
        assert result == conv_id
    
    def test_validate_channel_conversation_id_empty(self):
        """Test validating empty conversation ID (allowed)"""
        result = validate_channel_conversation_id("")
        assert result == ""
    
    def test_validate_channel_conversation_id_too_long(self):
        """Test validating too long conversation ID"""
        conv_id = "a" * 600  # Longer than max_length
        with pytest.raises(ValueError, match="Conversation ID too long"):
            validate_channel_conversation_id(conv_id)
    
    def test_validate_channel_conversation_id_invalid_type(self):
        """Test validating invalid conversation ID type"""
        with pytest.raises(ValueError, match="Conversation ID must be a string"):
            validate_channel_conversation_id(123)


class TestUserContext:
    """Test UserContext model"""
    
    def test_creation_with_required_fields(self):
        """Test creating UserContext with required fields"""
        context = UserContext(user_id="user@company.com")
        
        assert context.user_id == "user@company.com"
        assert context.teams_tenant is None
        assert context.session_id is None
    
    def test_creation_with_all_fields(self):
        """Test creating UserContext with all fields"""
        context = UserContext(
            user_id="user@company.com",
            teams_tenant="company.onmicrosoft.com",
            session_id="session-123"
        )
        
        assert context.user_id == "user@company.com"
        assert context.teams_tenant == "company.onmicrosoft.com"
        assert context.session_id == "session-123"
    
    def test_to_dict(self):
        """Test converting UserContext to dictionary"""
        context = UserContext(
            user_id="user@company.com",
            teams_tenant="company.onmicrosoft.com"
        )
        
        data = context.to_dict()
        
        assert data["user_id"] == "user@company.com"
        assert data["teams_tenant"] == "company.onmicrosoft.com"
        assert data["session_id"] is None
    
    def test_from_dict(self):
        """Test creating UserContext from dictionary"""
        data = {
            "user_id": "user@company.com",
            "teams_tenant": "company.onmicrosoft.com",
            "session_id": "session-123"
        }
        
        context = UserContext.from_dict(data)
        
        assert context.user_id == "user@company.com"
        assert context.teams_tenant == "company.onmicrosoft.com"
        assert context.session_id == "session-123"


class TestPluginRequest:
    """Test PluginRequest model"""
    
    def test_creation_with_required_fields(self):
        """Test creating PluginRequest with required fields"""
        user_context = UserContext(user_id="user@company.com")
        request = PluginRequest(
            operation="get_ec2_status",
            parameters={"instance_id": "i-123"},
            user_context=user_context
        )
        
        assert request.operation == "get_ec2_status"
        assert request.parameters == {"instance_id": "i-123"}
        assert request.user_context == user_context
        assert request.correlation_id is not None
        assert isinstance(request.timestamp, datetime)
    
    def test_to_dict(self):
        """Test converting PluginRequest to dictionary"""
        user_context = UserContext(user_id="user@company.com")
        request = PluginRequest(
            operation="get_ec2_status",
            parameters={"instance_id": "i-123"},
            user_context=user_context
        )
        
        data = request.to_dict()
        
        assert data["operation"] == "get_ec2_status"
        assert data["parameters"] == {"instance_id": "i-123"}
        assert data["user_context"]["user_id"] == "user@company.com"
        assert "correlation_id" in data
        assert "timestamp" in data
    
    def test_from_dict(self):
        """Test creating PluginRequest from dictionary"""
        data = {
            "operation": "get_ec2_status",
            "parameters": {"instance_id": "i-123"},
            "user_context": {"user_id": "user@company.com"}
        }
        
        request = PluginRequest.from_dict(data)
        
        assert request.operation == "get_ec2_status"
        assert request.parameters == {"instance_id": "i-123"}
        assert request.user_context.user_id == "user@company.com"


class TestPluginResponse:
    """Test PluginResponse model"""
    
    def test_success_response(self):
        """Test creating successful PluginResponse"""
        response = PluginResponse(
            success=True,
            correlation_id="test-123",
            summary="Operation completed successfully",
            details={"status": "running"}
        )
        
        assert response.success is True
        assert response.correlation_id == "test-123"
        assert response.summary == "Operation completed successfully"
        assert response.details == {"status": "running"}
        assert response.execution_mode == ExecutionMode.SANDBOX_LIVE
    
    def test_approval_response(self):
        """Test creating approval PluginResponse"""
        expires_at = datetime.utcnow() + timedelta(minutes=15)
        response = PluginResponse(
            success=True,
            correlation_id="test-123",
            approval_required=True,
            approval_token="approve-abc123",
            expires_at=expires_at,
            action_summary="Reboot EC2 instance",
            risk_level="medium",
            instructions="Use approve_action to proceed"
        )
        
        assert response.approval_required is True
        assert response.approval_token == "approve-abc123"
        assert response.expires_at == expires_at
        assert response.action_summary == "Reboot EC2 instance"
        assert response.risk_level == "medium"
        assert response.instructions == "Use approve_action to proceed"
    
    def test_to_dict_with_optional_fields(self):
        """Test converting PluginResponse with optional fields to dictionary"""
        response = PluginResponse(
            success=True,
            correlation_id="test-123",
            approval_required=True,
            approval_token="approve-abc123"
        )
        
        data = response.to_dict()
        
        assert data["success"] is True
        assert data["correlation_id"] == "test-123"
        assert data["approval_required"] is True
        assert data["approval_token"] == "approve-abc123"
        assert "summary" not in data  # Should not include None values


class TestOperationResult:
    """Test OperationResult model"""
    
    def test_success_result(self):
        """Test creating successful OperationResult"""
        result = OperationResult(
            operation="get_ec2_status",
            success=True,
            data={"instance_state": "running"},
            user_id="user@company.com"
        )
        
        assert result.operation == "get_ec2_status"
        assert result.success is True
        assert result.data == {"instance_state": "running"}
        assert result.user_id == "user@company.com"
        assert result.error_code is None
        assert result.error_message is None
    
    def test_error_result(self):
        """Test creating error OperationResult"""
        result = OperationResult(
            operation="get_ec2_status",
            success=False,
            error_code="AWS_API_ERROR",
            error_message="Access denied",
            user_id="user@company.com"
        )
        
        assert result.operation == "get_ec2_status"
        assert result.success is False
        assert result.error_code == "AWS_API_ERROR"
        assert result.error_message == "Access denied"
        assert result.data is None


class TestApprovalToken:
    """Test ApprovalToken model"""
    
    def test_default_creation(self):
        """Test creating ApprovalToken with defaults"""
        token = ApprovalToken()
        
        assert token.token.startswith("approve-")
        assert len(token.token) > 10
        assert isinstance(token.expires_at, datetime)
        assert token.expires_at > datetime.utcnow()
        assert token.user_id == ""
        assert token.tool_call is None
        assert token.risk_level == "medium"
        assert token.consumed is False
    
    def test_creation_with_tool_call(self):
        """Test creating ApprovalToken with ToolCall"""
        tool_call = ToolCall(tool_name="reboot_ec2", requires_approval=True)
        token = ApprovalToken(
            user_id="user@company.com",
            tool_call=tool_call,
            risk_level="high"
        )
        
        assert token.user_id == "user@company.com"
        assert token.tool_call == tool_call
        assert token.risk_level == "high"
    
    def test_is_valid(self):
        """Test token validity checking"""
        # Valid token
        token = ApprovalToken()
        assert token.is_valid() is True
        
        # Consumed token
        token.consume()
        assert token.is_valid() is False
        
        # Expired token
        token2 = ApprovalToken()
        token2.expires_at = datetime.utcnow() - timedelta(minutes=1)
        assert token2.is_valid() is False
    
    def test_consume(self):
        """Test token consumption"""
        token = ApprovalToken()
        assert token.consumed is False
        
        token.consume()
        assert token.consumed is True


class TestUtilityFunctions:
    """Test utility functions"""
    
    def test_generate_approval_token(self):
        """Test approval token generation"""
        token1 = generate_approval_token()
        token2 = generate_approval_token()
        
        assert token1 != token2
        assert token1.startswith("approve-")
        assert token2.startswith("approve-")
        assert len(token1) > 10
        assert len(token2) > 10
    
    def test_validate_plugin_request_valid(self):
        """Test validating valid plugin request"""
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {"instance_id": "i-123"},
            "user_context": {"user_id": "user@company.com"}
        }
        
        request = validate_plugin_request(request_data)
        
        assert request.operation == "get_ec2_status"
        assert request.parameters == {"instance_id": "i-123"}
        assert request.user_context.user_id == "user@company.com"
    
    def test_validate_plugin_request_missing_operation(self):
        """Test validating plugin request with missing operation"""
        request_data = {
            "parameters": {"instance_id": "i-123"},
            "user_context": {"user_id": "user@company.com"}
        }
        
        with pytest.raises(ValueError, match="Operation field is required"):
            validate_plugin_request(request_data)
    
    def test_validate_plugin_request_missing_user_id(self):
        """Test validating plugin request with missing user ID"""
        request_data = {
            "operation": "get_ec2_status",
            "parameters": {"instance_id": "i-123"},
            "user_context": {}
        }
        
        with pytest.raises(ValueError, match="User ID is required"):
            validate_plugin_request(request_data)
    
    def test_sanitize_parameters_basic(self):
        """Test basic parameter sanitization"""
        params = {
            "instance_id": "i-123",
            "count": 5,
            "enabled": True,
            "tags": ["prod", "web"]
        }
        
        sanitized = sanitize_parameters(params)
        
        assert sanitized == params
    
    def test_sanitize_parameters_malicious(self):
        """Test sanitizing malicious parameters"""
        params = {
            "instance_id": "i-123\x00\r",
            "script": "rm -rf /",
            "long_value": "a" * 2000,
            "nested": {"key": "value\x00"}
        }
        
        sanitized = sanitize_parameters(params)
        
        assert sanitized["instance_id"] == "i-123"
        assert sanitized["script"] == "rm -rf /"
        assert len(sanitized["long_value"]) <= 1020  # 1000 + "... [truncated]"
        assert sanitized["nested"]["key"] == "value"
    
    def test_extract_user_context_valid(self):
        """Test extracting valid user context"""
        request_data = {
            "user_context": {
                "user_id": "user@company.com",
                "teams_tenant": "company.onmicrosoft.com"
            }
        }
        
        context = extract_user_context(request_data)
        
        assert context.user_id == "user@company.com"
        assert context.teams_tenant == "company.onmicrosoft.com"
    
    def test_extract_user_context_missing(self):
        """Test extracting user context when missing"""
        request_data = {}
        
        with pytest.raises(ValueError, match="User ID is required"):
            extract_user_context(request_data)
    
    def test_validate_user_id_email_format(self):
        """Test validating user ID with email format"""
        # Valid email
        result = validate_user_id("user@company.com")
        assert result == "user@company.com"
        
        # Invalid email format
        with pytest.raises(ValueError, match="User ID must be a valid email format"):
            validate_user_id("invalid-email@")
        
        # Non-email format (should pass)
        result = validate_user_id("user123")
        assert result == "user123"