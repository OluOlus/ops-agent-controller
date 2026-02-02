"""
Internal message models and data structures for OpsAgent Controller
Requirements: 1.1, 6.1, 8.2, 9.1
"""
import uuid
import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Literal, Union
from enum import Enum


class ExecutionMode(Enum):
    """Execution mode for the OpsAgent Controller"""
    LOCAL_MOCK = "LOCAL_MOCK"
    DRY_RUN = "DRY_RUN"
    SANDBOX_LIVE = "SANDBOX_LIVE"


class ChannelType(Enum):
    """Supported chat channel types"""
    TEAMS = "teams"
    SLACK = "slack"
    WEB = "web"


@dataclass
class UserContext:
    """
    User context extracted from Amazon Q Business requests
    Requirements: 8.2, 9.1
    """
    user_id: str
    teams_tenant: Optional[str] = None
    session_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "user_id": self.user_id,
            "teams_tenant": self.teams_tenant,
            "session_id": self.session_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserContext":
        """Create from dictionary"""
        return cls(
            user_id=data.get("user_id", ""),
            teams_tenant=data.get("teams_tenant"),
            session_id=data.get("session_id")
        )


@dataclass
class PluginRequest:
    """
    Plugin request from Amazon Q Business
    Requirements: 1.1, 8.2, 9.1
    """
    operation: str
    parameters: Dict[str, Any]
    user_context: UserContext
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "operation": self.operation,
            "parameters": self.parameters,
            "user_context": self.user_context.to_dict(),
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat() + "Z"
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginRequest":
        """Create from dictionary"""
        user_context_data = data.get("user_context", {})
        return cls(
            operation=data.get("operation", ""),
            parameters=data.get("parameters", {}),
            user_context=UserContext.from_dict(user_context_data),
            correlation_id=data.get("correlation_id", str(uuid.uuid4())),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat()).replace("Z", ""))
        )


@dataclass
class PluginResponse:
    """
    Plugin response to Amazon Q Business
    Requirements: 1.1, 9.1
    """
    success: bool
    correlation_id: str
    operation: Optional[str] = None  # Add operation field
    summary: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE
    error: Optional[Dict[str, Any]] = None
    
    # Approval-specific fields
    approval_required: Optional[bool] = None
    approval_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    action_summary: Optional[str] = None
    risk_level: Optional[Literal["low", "medium", "high"]] = None
    instructions: Optional[str] = None
    
    # Execution-specific fields
    action_executed: Optional[str] = None
    target_resource: Optional[str] = None
    execution_status: Optional[Literal["completed", "failed", "partial"]] = None
    execution_time: Optional[datetime] = None
    
    # Workflow-specific fields
    incident_id: Optional[str] = None
    message_id: Optional[str] = None
    created_at: Optional[datetime] = None
    posted_at: Optional[datetime] = None
    notification_sent: Optional[bool] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            "success": self.success,
            "correlation_id": self.correlation_id,
            "execution_mode": self.execution_mode.value
        }
        
        # Add optional fields if they exist
        if self.operation is not None:
            result["operation"] = self.operation
        if self.summary is not None:
            result["summary"] = self.summary
        if self.details is not None:
            result["details"] = self.details
        if self.error is not None:
            result["error"] = self.error
            
        # Approval fields
        if self.approval_required is not None:
            result["approval_required"] = self.approval_required
        if self.approval_token is not None:
            result["approval_token"] = self.approval_token
        if self.expires_at is not None:
            result["expires_at"] = self.expires_at.isoformat() + "Z"
        if self.action_summary is not None:
            result["action_summary"] = self.action_summary
        if self.risk_level is not None:
            result["risk_level"] = self.risk_level
        if self.instructions is not None:
            result["instructions"] = self.instructions
            
        # Execution fields
        if self.action_executed is not None:
            result["action_executed"] = self.action_executed
        if self.target_resource is not None:
            result["target_resource"] = self.target_resource
        if self.execution_status is not None:
            result["execution_status"] = self.execution_status
        if self.execution_time is not None:
            result["execution_time"] = self.execution_time.isoformat() + "Z"
            
        # Workflow fields
        if self.incident_id is not None:
            result["incident_id"] = self.incident_id
        if self.message_id is not None:
            result["message_id"] = self.message_id
        if self.created_at is not None:
            result["created_at"] = self.created_at.isoformat() + "Z"
        if self.posted_at is not None:
            result["posted_at"] = self.posted_at.isoformat() + "Z"
        if self.notification_sent is not None:
            result["notification_sent"] = self.notification_sent
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginResponse":
        """Create from dictionary"""
        return cls(
            success=data.get("success", False),
            correlation_id=data.get("correlation_id", str(uuid.uuid4())),
            operation=data.get("operation"),
            summary=data.get("summary"),
            details=data.get("details"),
            execution_mode=ExecutionMode(data.get("execution_mode", "SANDBOX_LIVE")),
            error=data.get("error"),
            approval_required=data.get("approval_required"),
            approval_token=data.get("approval_token"),
            expires_at=datetime.fromisoformat(data["expires_at"].replace("Z", "")) if data.get("expires_at") else None,
            action_summary=data.get("action_summary"),
            risk_level=data.get("risk_level"),
            instructions=data.get("instructions"),
            action_executed=data.get("action_executed"),
            target_resource=data.get("target_resource"),
            execution_status=data.get("execution_status"),
            execution_time=datetime.fromisoformat(data["execution_time"].replace("Z", "")) if data.get("execution_time") else None,
            incident_id=data.get("incident_id"),
            message_id=data.get("message_id"),
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "")) if data.get("created_at") else None,
            posted_at=datetime.fromisoformat(data["posted_at"].replace("Z", "")) if data.get("posted_at") else None,
            notification_sent=data.get("notification_sent")
        )


@dataclass
class OperationResult:
    """
    Internal operation result for tracking execution
    Requirements: 9.1
    """
    operation: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE
    timestamp: datetime = field(default_factory=datetime.utcnow)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "operation": self.operation,
            "success": self.success,
            "data": self.data,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "execution_mode": self.execution_mode.value,
            "timestamp": self.timestamp.isoformat() + "Z",
            "correlation_id": self.correlation_id,
            "user_id": self.user_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OperationResult":
        """Create from dictionary"""
        return cls(
            operation=data.get("operation", ""),
            success=data.get("success", False),
            data=data.get("data"),
            error_code=data.get("error_code"),
            error_message=data.get("error_message"),
            execution_mode=ExecutionMode(data.get("execution_mode", "SANDBOX_LIVE")),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat()).replace("Z", "")),
            correlation_id=data.get("correlation_id", str(uuid.uuid4())),
            user_id=data.get("user_id")
        )


@dataclass
class InternalMessage:
    """
    Internal message format normalized from different chat channels
    Requirements: 1.1, 6.1, 8.2, 9.1
    """
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    channel: ChannelType = ChannelType.WEB
    channel_conversation_id: str = ""
    message_text: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE
    user_context: Optional[UserContext] = None  # Added for authentication tracking
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            "correlation_id": self.correlation_id,
            "user_id": self.user_id,
            "channel": self.channel.value,
            "channel_conversation_id": self.channel_conversation_id,
            "message_text": self.message_text,
            "timestamp": self.timestamp.isoformat() + "Z",
            "execution_mode": self.execution_mode.value
        }
        
        if self.user_context:
            result["user_context"] = self.user_context.to_dict()
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InternalMessage":
        """Create from dictionary"""
        user_context_data = data.get("user_context")
        user_context = UserContext.from_dict(user_context_data) if user_context_data else None
        
        return cls(
            correlation_id=data.get("correlation_id", str(uuid.uuid4())),
            user_id=data.get("user_id", ""),
            channel=ChannelType(data.get("channel", "web")),
            channel_conversation_id=data.get("channel_conversation_id", ""),
            message_text=data.get("message_text", ""),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat()).replace("Z", "")),
            execution_mode=ExecutionMode(data.get("execution_mode", "SANDBOX_LIVE")),
            user_context=user_context
        )


@dataclass
class ToolCall:
    """
    Represents a tool call request from the LLM or plugin
    Requirements: 4.1, 4.2, 9.1
    """
    tool_name: str
    args: Dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "tool_name": self.tool_name,
            "args": self.args,
            "requires_approval": self.requires_approval,
            "correlation_id": self.correlation_id,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat() + "Z"
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolCall":
        """Create from dictionary"""
        return cls(
            tool_name=data.get("tool_name", ""),
            args=data.get("args", {}),
            requires_approval=data.get("requires_approval", False),
            correlation_id=data.get("correlation_id", str(uuid.uuid4())),
            user_id=data.get("user_id", ""),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat()).replace("Z", ""))
        )


@dataclass
class ToolResult:
    """
    Represents the result of a tool execution
    Requirements: 4.4, 6.1, 9.1
    """
    tool_name: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE
    timestamp: datetime = field(default_factory=datetime.utcnow)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "execution_mode": self.execution_mode.value,
            "timestamp": self.timestamp.isoformat() + "Z",
            "correlation_id": self.correlation_id,
            "user_id": self.user_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolResult":
        """Create from dictionary"""
        return cls(
            tool_name=data.get("tool_name", ""),
            success=data.get("success", False),
            data=data.get("data"),
            error=data.get("error"),
            execution_mode=ExecutionMode(data.get("execution_mode", "SANDBOX_LIVE")),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat()).replace("Z", "")),
            correlation_id=data.get("correlation_id", str(uuid.uuid4())),
            user_id=data.get("user_id", "")
        )


@dataclass
class ApprovalToken:
    """
    Approval token for write operations with enhanced security
    Requirements: 5.1, 5.2, 5.3, 5.4
    """
    token: str = field(default_factory=lambda: generate_approval_token())
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(minutes=15))
    user_id: str = ""
    tool_call: Optional[ToolCall] = None
    risk_level: Literal["low", "medium", "high"] = "medium"
    consumed: bool = False
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def is_valid(self) -> bool:
        """Check if token is valid (not expired and not consumed)"""
        return not self.consumed and datetime.utcnow() < self.expires_at
    
    def consume(self) -> None:
        """Mark token as consumed"""
        self.consumed = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "token": self.token,
            "expires_at": self.expires_at.isoformat() + "Z",
            "user_id": self.user_id,
            "tool_call": self.tool_call.to_dict() if self.tool_call else None,
            "risk_level": self.risk_level,
            "consumed": self.consumed,
            "correlation_id": self.correlation_id,
            "created_at": self.created_at.isoformat() + "Z"
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalToken":
        """Create from dictionary"""
        tool_call_data = data.get("tool_call")
        return cls(
            token=data.get("token", generate_approval_token()),
            expires_at=datetime.fromisoformat(data.get("expires_at", (datetime.utcnow() + timedelta(minutes=15)).isoformat()).replace("Z", "")),
            user_id=data.get("user_id", ""),
            tool_call=ToolCall.from_dict(tool_call_data) if tool_call_data else None,
            risk_level=data.get("risk_level", "medium"),
            consumed=data.get("consumed", False),
            correlation_id=data.get("correlation_id", str(uuid.uuid4())),
            created_at=datetime.fromisoformat(data.get("created_at", datetime.utcnow().isoformat()).replace("Z", ""))
        )


# Legacy ApprovalRequest for backward compatibility
ApprovalRequest = ApprovalToken


def generate_correlation_id() -> str:
    """
    Generate a unique correlation ID for request tracking
    Requirements: 9.1
    """
    return str(uuid.uuid4())


def generate_approval_token() -> str:
    """
    Generate a secure approval token with prefix
    Requirements: 5.1, 5.2
    """
    # Generate a cryptographically secure random string
    alphabet = string.ascii_letters + string.digits
    token_suffix = ''.join(secrets.choice(alphabet) for _ in range(16))
    return f"approve-{token_suffix}"


def validate_plugin_request(request_data: Dict[str, Any]) -> PluginRequest:
    """
    Validate and sanitize plugin request from Amazon Q Business
    Requirements: 1.1, 8.2, 9.1
    """
    if not isinstance(request_data, dict):
        raise ValueError("Request data must be a dictionary")
    
    # Validate required fields
    operation = request_data.get("operation")
    if not operation or not isinstance(operation, str):
        raise ValueError("Operation field is required and must be a string")
    
    parameters = request_data.get("parameters", {})
    if not isinstance(parameters, dict):
        raise ValueError("Parameters field must be a dictionary")
    
    user_context_data = request_data.get("user_context", {})
    if not isinstance(user_context_data, dict):
        raise ValueError("User context field must be a dictionary")
    
    # Validate user context
    user_id = user_context_data.get("user_id")
    if not user_id or not isinstance(user_id, str):
        raise ValueError("User ID is required in user context")
    
    # Sanitize parameters
    sanitized_parameters = sanitize_parameters(parameters)
    
    # Create user context
    user_context = UserContext(
        user_id=validate_user_id(user_id),
        teams_tenant=user_context_data.get("teams_tenant"),
        session_id=user_context_data.get("session_id")
    )
    
    # Create plugin request
    return PluginRequest(
        operation=operation.strip(),
        parameters=sanitized_parameters,
        user_context=user_context,
        correlation_id=request_data.get("correlation_id", generate_correlation_id())
    )


def sanitize_parameters(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize plugin parameters to prevent injection attacks
    Requirements: 8.2, 9.1
    """
    if not isinstance(parameters, dict):
        return {}
    
    sanitized = {}
    
    for key, value in parameters.items():
        # Sanitize key
        if not isinstance(key, str):
            continue
        
        clean_key = key.strip()
        if not clean_key or len(clean_key) > 100:  # Reasonable key length limit
            continue
        
        # Sanitize value based on type
        if isinstance(value, str):
            # Remove null bytes and control characters, limit length
            clean_value = value.replace('\x00', '').replace('\r', '').strip()
            if len(clean_value) > 1000:  # Reasonable value length limit
                clean_value = clean_value[:1000] + "... [truncated]"
            sanitized[clean_key] = clean_value
        elif isinstance(value, (int, float, bool)):
            sanitized[clean_key] = value
        elif isinstance(value, list):
            # Sanitize list elements (only allow simple types)
            clean_list = []
            for item in value[:50]:  # Limit list size
                if isinstance(item, str):
                    clean_item = item.replace('\x00', '').replace('\r', '').strip()
                    if len(clean_item) <= 500:  # Shorter limit for list items
                        clean_list.append(clean_item)
                elif isinstance(item, (int, float, bool)):
                    clean_list.append(item)
            sanitized[clean_key] = clean_list
        elif isinstance(value, dict):
            # Recursively sanitize nested dictionaries (limit depth)
            if len(str(value)) <= 2000:  # Limit nested object size
                sanitized[clean_key] = sanitize_parameters(value)
        # Skip other types (functions, objects, etc.)
    
    return sanitized


def extract_user_context(request_data: Dict[str, Any]) -> UserContext:
    """
    Extract user context from Amazon Q Business request
    Requirements: 8.2, 9.1
    """
    user_context_data = request_data.get("user_context", {})
    
    if not isinstance(user_context_data, dict):
        raise ValueError("User context must be a dictionary")
    
    user_id = user_context_data.get("user_id")
    if not user_id:
        raise ValueError("User ID is required in user context")
    
    return UserContext(
        user_id=validate_user_id(user_id),
        teams_tenant=user_context_data.get("teams_tenant"),
        session_id=user_context_data.get("session_id")
    )


def validate_message_text(text: str) -> str:
    """
    Validate and sanitize message text
    Requirements: 1.1, 8.2
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
    Requirements: 8.2, 9.1
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
    
    # Basic format validation for email-like user IDs
    if '@' in sanitized and not _is_valid_email_format(sanitized):
        raise ValueError("User ID must be a valid email format")
    
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


def _is_valid_email_format(email: str) -> bool:
    """
    Basic email format validation
    Requirements: 8.2
    """
    import re
    # Simple email regex - not comprehensive but good enough for basic validation
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None