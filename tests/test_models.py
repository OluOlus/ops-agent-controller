"""
Unit tests for internal message models
"""
import pytest
from datetime import datetime, timedelta
from src.models import (
    InternalMessage, ToolCall, ToolResult, ApprovalRequest,
    ExecutionMode, ChannelType,
    generate_correlation_id, validate_message_text, 
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
        assert msg.execution_mode == ExecutionMode.LOCAL_MOCK
    
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
        assert data["execution_mode"] == "LOCAL_MOCK"
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
        assert result.execution_mode == ExecutionMode.LOCAL_MOCK
    
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
    """Test ApprovalRequest model"""
    
    def test_default_creation(self):
        """Test creating ApprovalRequest with defaults"""
        approval = ApprovalRequest()
        
        assert approval.token is not None
        assert len(approval.token) > 0
        assert isinstance(approval.expires_at, datetime)
        assert approval.requested_by == ""
        assert approval.tool_call is None
        assert approval.risk_level == "medium"
    
    def test_creation_with_tool_call(self):
        """Test creating ApprovalRequest with ToolCall"""
        tool_call = ToolCall(tool_name="ec2_reboot", requires_approval=True)
        approval = ApprovalRequest(
            requested_by="user123",
            tool_call=tool_call,
            risk_level="high"
        )
        
        assert approval.requested_by == "user123"
        assert approval.tool_call == tool_call
        assert approval.risk_level == "high"
    
    def test_to_dict_with_tool_call(self):
        """Test converting ApprovalRequest with ToolCall to dictionary"""
        tool_call = ToolCall(tool_name="test_tool")
        approval = ApprovalRequest(
            requested_by="user123",
            tool_call=tool_call
        )
        
        data = approval.to_dict()
        
        assert data["requested_by"] == "user123"
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