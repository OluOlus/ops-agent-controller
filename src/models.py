"""
Internal message models and data structures for OpsAgent Controller
Requirements: 1.1, 6.1
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional, Literal
from enum import Enum


class ExecutionMode(Enum):
    """Execution modes for the OpsAgent Controller"""
    LOCAL_MOCK = "LOCAL_MOCK"
    DRY_RUN = "DRY_RUN"
    SANDBOX_LIVE = "SANDBOX_LIVE"


class ChannelType(Enum):
    """Supported chat channel types"""
    TEAMS = "teams"
    SLACK = "slack"
    WEB = "web"


@dataclass
class InternalMessage:
    """
    Internal message format normalized from different chat channels
    Requirements: 1.1, 6.1
    """
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    channel: ChannelType = ChannelType.WEB
    channel_conversation_id: str = ""
    message_text: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    execution_mode: ExecutionMode = ExecutionMode.LOCAL_MOCK
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "correlation_id": self.correlation_id,
            "user_id": self.user_id,
            "channel": self.channel.value,
            "channel_conversation_id": self.channel_conversation_id,
            "message_text": self.message_text,
            "timestamp": self.timestamp.isoformat() + "Z",
            "execution_mode": self.execution_mode.value
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InternalMessage":
        """Create from dictionary"""
        return cls(
            correlation_id=data.get("correlation_id", str(uuid.uuid4())),
            user_id=data.get("user_id", ""),
            channel=ChannelType(data.get("channel", "web")),
            channel_conversation_id=data.get("channel_conversation_id", ""),
            message_text=data.get("message_text", ""),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat()).replace("Z", "")),
            execution_mode=ExecutionMode(data.get("execution_mode", "LOCAL_MOCK"))
        )


@dataclass
class ToolCall:
    """
    Represents a tool call request from the LLM
    Requirements: 4.1, 4.2
    """
    tool_name: str
    args: Dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "tool_name": self.tool_name,
            "args": self.args,
            "requires_approval": self.requires_approval,
            "correlation_id": self.correlation_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolCall":
        """Create from dictionary"""
        return cls(
            tool_name=data.get("tool_name", ""),
            args=data.get("args", {}),
            requires_approval=data.get("requires_approval", False),
            correlation_id=data.get("correlation_id", str(uuid.uuid4()))
        )


@dataclass
class ToolResult:
    """
    Represents the result of a tool execution
    Requirements: 4.4, 6.1
    """
    tool_name: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_mode: ExecutionMode = ExecutionMode.LOCAL_MOCK
    timestamp: datetime = field(default_factory=datetime.utcnow)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "execution_mode": self.execution_mode.value,
            "timestamp": self.timestamp.isoformat() + "Z",
            "correlation_id": self.correlation_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolResult":
        """Create from dictionary"""
        return cls(
            tool_name=data.get("tool_name", ""),
            success=data.get("success", False),
            data=data.get("data"),
            error=data.get("error"),
            execution_mode=ExecutionMode(data.get("execution_mode", "LOCAL_MOCK")),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat()).replace("Z", "")),
            correlation_id=data.get("correlation_id", str(uuid.uuid4()))
        )


@dataclass
class ApprovalRequest:
    """
    Represents an approval request for write operations
    Requirements: 3.1, 3.4
    """
    token: str = field(default_factory=lambda: str(uuid.uuid4()))
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow())
    requested_by: str = ""
    tool_call: Optional[ToolCall] = None
    risk_level: Literal["low", "medium", "high"] = "medium"
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "token": self.token,
            "expires_at": self.expires_at.isoformat() + "Z",
            "requested_by": self.requested_by,
            "tool_call": self.tool_call.to_dict() if self.tool_call else None,
            "risk_level": self.risk_level,
            "correlation_id": self.correlation_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalRequest":
        """Create from dictionary"""
        tool_call_data = data.get("tool_call")
        return cls(
            token=data.get("token", str(uuid.uuid4())),
            expires_at=datetime.fromisoformat(data.get("expires_at", datetime.utcnow().isoformat()).replace("Z", "")),
            requested_by=data.get("requested_by", ""),
            tool_call=ToolCall.from_dict(tool_call_data) if tool_call_data else None,
            risk_level=data.get("risk_level", "medium"),
            correlation_id=data.get("correlation_id", str(uuid.uuid4()))
        )


def generate_correlation_id() -> str:
    """
    Generate a unique correlation ID for request tracking
    Requirements: 6.1
    """
    return str(uuid.uuid4())


def validate_message_text(text: str) -> str:
    """
    Validate and sanitize message text
    Requirements: 1.1, 8.4
    """
    if not isinstance(text, str):
        raise ValueError("Message text must be a string")
    
    # Basic sanitization - remove null bytes and control characters
    sanitized = text.replace('\x00', '').replace('\r', '').strip()
    
    # Limit message length to prevent abuse
    max_length = 4000  # Reasonable limit for chat messages
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... [truncated]"
    
    return sanitized


def validate_user_id(user_id: str) -> str:
    """
    Validate and sanitize user ID
    Requirements: 1.4, 5.5
    """
    if not isinstance(user_id, str):
        raise ValueError("User ID must be a string")
    
    # Basic sanitization
    sanitized = user_id.strip()
    
    if not sanitized:
        raise ValueError("User ID cannot be empty")
    
    # Limit length
    max_length = 256
    if len(sanitized) > max_length:
        raise ValueError(f"User ID too long (max {max_length} characters)")
    
    return sanitized


def validate_channel_conversation_id(conversation_id: str) -> str:
    """
    Validate and sanitize channel conversation ID
    Requirements: 1.1
    """
    if not isinstance(conversation_id, str):
        raise ValueError("Conversation ID must be a string")
    
    # Basic sanitization
    sanitized = conversation_id.strip()
    
    # Limit length
    max_length = 512
    if len(sanitized) > max_length:
        raise ValueError(f"Conversation ID too long (max {max_length} characters)")
    
    return sanitized