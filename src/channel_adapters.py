"""
Channel adapters for different chat interfaces
Requirements: 1.1, 1.2, 1.5
"""
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from models import (
    InternalMessage,
    ChannelType,
    ExecutionMode,
    ApprovalRequest,
    validate_message_text,
    validate_user_id,
    validate_channel_conversation_id,
)

logger = logging.getLogger(__name__)


@dataclass
class ChannelResponse:
    """
    Standardized response format for channel adapters
    """
    message: str
    channel_data: Dict[str, Any]
    correlation_id: Optional[str] = None
    requires_approval: bool = False
    approval_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            "message": self.message,
            "channel_data": self.channel_data,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        if self.correlation_id:
            result["correlation_id"] = self.correlation_id
        
        if self.requires_approval and self.approval_data:
            result["approval_required"] = True
            result["approval_data"] = self.approval_data
        
        return result


class ChannelAdapter(ABC):
    """
    Abstract base class for chat channel adapters
    Requirements: 1.1, 1.2
    """
    
    def __init__(self, channel_type: ChannelType):
        """
        Initialize the channel adapter
        
        Args:
            channel_type: The type of channel this adapter handles
        """
        self.channel_type = channel_type
        logger.info(f"Initialized {channel_type.value} channel adapter")
    
    @abstractmethod
    def normalize_message(self, raw_request: Dict[str, Any]) -> InternalMessage:
        """
        Normalize incoming message to internal format
        
        Args:
            raw_request: Raw request data from the channel
            
        Returns:
            InternalMessage object
            
        Requirements: 1.1
        """
        pass
    
    @abstractmethod
    def format_response(
        self,
        message: str,
        correlation_id: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> ChannelResponse:
        """
        Format response for the specific channel
        
        Args:
            message: The response message
            correlation_id: Optional correlation ID
            additional_data: Additional channel-specific data
            
        Returns:
            ChannelResponse object
            
        Requirements: 1.2, 1.5
        """
        pass
    
    @abstractmethod
    def format_approval_card(
        self,
        approval_request: ApprovalRequest,
        execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE
    ) -> ChannelResponse:
        """
        Format approval request as interactive card/UI
        
        Args:
            approval_request: The approval request to format
            execution_mode: Current execution mode
            
        Returns:
            ChannelResponse with approval card data
            
        Requirements: 1.5, 3.1
        """
        pass
    
    def validate_request_authenticity(self, raw_request: Dict[str, Any]) -> bool:
        """
        Validate the authenticity of the incoming request
        
        Args:
            raw_request: Raw request data from the channel
            
        Returns:
            True if request is authentic, False otherwise
            
        Requirements: 1.4, 5.5
        """
        # Default implementation - subclasses should override for channel-specific validation
        return True


class TeamsChannelAdapter(ChannelAdapter):
    """
    Channel adapter for Microsoft Teams Bot Framework integration
    Requirements: 1.1, 1.2, 1.4, 1.5
    """
    
    def __init__(self):
        """Initialize the Teams channel adapter"""
        super().__init__(ChannelType.TEAMS)
    
    def normalize_message(self, raw_request: Dict[str, Any]) -> InternalMessage:
        """
        Normalize Teams Bot Framework Activity to internal message format
        
        Args:
            raw_request: Raw Teams Bot Framework Activity object
            
        Returns:
            InternalMessage object
            
        Requirements: 1.1
        """
        try:
            # Teams sends Activity objects directly in the request body
            if isinstance(raw_request.get("body"), str):
                activity = json.loads(raw_request["body"])
            else:
                activity = raw_request.get("body", raw_request)
            
            # Validate this is a message activity
            if activity.get("type") != "message":
                raise ValueError(f"Unsupported activity type: {activity.get('type')}")
            
            # Extract message text
            message_text = validate_message_text(activity.get("text", ""))
            if not message_text:
                raise ValueError("Message text is required")
            
            # Extract user information from 'from' field
            from_user = activity.get("from", {})
            user_id = validate_user_id(from_user.get("id", ""))
            if not user_id:
                raise ValueError("User ID is required")
            
            # Extract conversation information
            conversation = activity.get("conversation", {})
            channel_conversation_id = validate_channel_conversation_id(
                conversation.get("id", "")
            )
            
            # Teams always runs in live mode when deployed
            execution_mode = ExecutionMode.SANDBOX_LIVE
            
            # Create internal message
            internal_message = InternalMessage(
                user_id=user_id,
                channel=ChannelType.TEAMS,
                channel_conversation_id=channel_conversation_id,
                message_text=message_text,
                execution_mode=execution_mode
            )
            
            # Store Teams-specific data for response routing
            internal_message.channel_metadata = {
                "service_url": activity.get("serviceUrl"),
                "conversation_id": conversation.get("id"),
                "activity_id": activity.get("id"),
                "from_id": from_user.get("id"),
                "from_name": from_user.get("name"),
                "recipient": activity.get("recipient", {}),
                "channel_id": activity.get("channelId")
            }
            
            logger.info(
                f"Normalized Teams message: user={user_id}, "
                f"conversation={channel_conversation_id}, "
                f"correlation_id={internal_message.correlation_id}"
            )
            
            return internal_message
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in Teams activity: {str(e)}")
        except Exception as e:
            logger.error(f"Error normalizing Teams message: {str(e)}")
            raise ValueError(f"Failed to normalize Teams message: {str(e)}")
    
    def format_response(
        self,
        message: str,
        correlation_id: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> ChannelResponse:
        """
        Format response for Teams Bot Framework
        
        Args:
            message: The response message
            correlation_id: Optional correlation ID
            additional_data: Additional data to include
            
        Returns:
            ChannelResponse formatted for Teams
            
        Requirements: 1.2, 1.5
        """
        # Teams Bot Framework Activity format
        channel_data = {
            "type": "message",
            "text": message,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        # Add any additional data
        if additional_data:
            # Add metadata without overriding core fields
            for key, value in additional_data.items():
                if key not in ["type", "text", "timestamp"]:
                    channel_data[key] = value
        
        # Add correlation ID as metadata
        if correlation_id:
            channel_data["channelData"] = {
                "correlation_id": correlation_id
            }
        
        response = ChannelResponse(
            message=message,
            channel_data=channel_data,
            correlation_id=correlation_id
        )
        
        logger.debug(f"Formatted Teams response: correlation_id={correlation_id}")
        
        return response
    
    def format_approval_card(
        self,
        approval_request: ApprovalRequest,
        execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE
    ) -> ChannelResponse:
        """
        Format approval request as Teams Adaptive Card
        
        Args:
            approval_request: The approval request to format
            execution_mode: Current execution mode
            
        Returns:
            ChannelResponse with Teams Adaptive Card
            
        Requirements: 1.5, 3.1
        """
        if not approval_request.tool_call:
            raise ValueError("Approval request missing tool call")
        
        tool_call = approval_request.tool_call
        
        # Format tool arguments for display
        formatted_args = []
        for key, value in tool_call.args.items():
            formatted_args.append({
                "type": "TextBlock",
                "text": f"**{key}:** {str(value)}",
                "wrap": True,
                "size": "Small"
            })
        
        # Determine action description and styling based on execution mode
        mode_descriptions = {
            ExecutionMode.SANDBOX_LIVE: "EXECUTE"
        }
        mode_description = mode_descriptions.get(execution_mode, "EXECUTE")
        
        # Risk level styling
        risk_colors = {
            "low": "Good",
            "medium": "Warning", 
            "high": "Attention"
        }
        risk_color = risk_colors.get(approval_request.risk_level, "Warning")
        
        # Calculate expiry information
        expires_in_seconds = int((approval_request.expires_at - datetime.utcnow()).total_seconds())
        expires_in_minutes = max(0, expires_in_seconds // 60)
        
        # Create Teams Adaptive Card
        adaptive_card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.3",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": "Approval Required",
                                "weight": "Bolder",
                                "size": "Large",
                                "color": risk_color
                            },
                            {
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "auto",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": "**Operation:**",
                                                "weight": "Bolder"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "**Mode:**",
                                                "weight": "Bolder"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "**Risk Level:**",
                                                "weight": "Bolder"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "**Expires:**",
                                                "weight": "Bolder"
                                            }
                                        ]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": tool_call.tool_name,
                                                "wrap": True
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": mode_description,
                                                "wrap": True
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": approval_request.risk_level.upper(),
                                                "wrap": True,
                                                "color": risk_color
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": f"{expires_in_minutes} minutes",
                                                "wrap": True
                                            }
                                        ]
                                    }
                                ]
                            }
                        ] + ([
                            {
                                "type": "TextBlock",
                                "text": "**Parameters:**",
                                "weight": "Bolder",
                                "spacing": "Medium"
                            }
                        ] + formatted_args if formatted_args else []) + [
                            {
                                "type": "TextBlock",
                                "text": f"**Token:** `{approval_request.token}`",
                                "size": "Small",
                                "spacing": "Medium"
                            }
                        ],
                        "actions": [
                            {
                                "type": "Action.Submit",
                                "title": f"Approve {mode_description}",
                                "style": "positive",
                                "data": {
                                    "action": "approve",
                                    "token": approval_request.token,
                                    "correlation_id": approval_request.correlation_id
                                }
                            },
                            {
                                "type": "Action.Submit",
                                "title": "Deny Request",
                                "style": "destructive",
                                "data": {
                                    "action": "deny",
                                    "token": approval_request.token,
                                    "correlation_id": approval_request.correlation_id
                                }
                            }
                        ]
                    }
                }
            ]
        }
        
        # Create the response message
        message = (
            f"**Approval Required**\n\n"
            f"**Operation:** {tool_call.tool_name}\n"
            f"**Mode:** {mode_description}\n"
            f"**Risk Level:** {approval_request.risk_level.upper()}\n"
            f"**Expires:** {expires_in_minutes} minutes\n\n"
            f"Please review the details and approve or deny this request."
        )
        
        response = ChannelResponse(
            message=message,
            channel_data=adaptive_card,
            correlation_id=approval_request.correlation_id,
            requires_approval=True,
            approval_data=adaptive_card
        )
        
        logger.info(
            f"Formatted Teams approval card: tool={tool_call.tool_name}, "
            f"token={approval_request.token}, expires_in={expires_in_minutes}min"
        )
        
        return response
    
    def validate_request_authenticity(self, raw_request: Dict[str, Any]) -> bool:
        """
        Validate Teams Bot Framework request authenticity
        
        Args:
            raw_request: Raw Teams Bot Framework request
            
        Returns:
            True if request is authentic
            
        Requirements: 1.4, 5.5
        """
        # For Teams Bot Framework, we should validate JWT tokens
        # For MVP, we'll do basic validation and rely on Azure Bot Service security
        
        # Check for Teams-specific headers
        headers = raw_request.get("headers", {})
        
        # Teams Bot Framework sends Authorization header with JWT
        auth_header = headers.get("authorization") or headers.get("Authorization")
        if not auth_header:
            logger.warning("Missing Authorization header in Teams request")
            return False
        
        # Basic JWT format validation (Bearer token)
        if not auth_header.startswith("Bearer "):
            logger.warning("Invalid Authorization header format in Teams request")
            return False
        
        # Validate request has Teams Bot Framework structure
        try:
            if isinstance(raw_request.get("body"), str):
                activity = json.loads(raw_request["body"])
            else:
                activity = raw_request.get("body", raw_request)
            
            # Check for required Bot Framework Activity fields
            required_fields = ["type", "id", "from", "conversation"]
            for field in required_fields:
                if field not in activity:
                    logger.warning(f"Missing required field '{field}' in Teams activity")
                    return False
            
            # Validate it's from Teams channel
            channel_id = activity.get("channelId", "")
            if channel_id and channel_id != "msteams":
                logger.warning(f"Unexpected channelId: {channel_id}")
                return False
            
            return True
            
        except (json.JSONDecodeError, TypeError) as e:
            logger.warning(f"Invalid Teams activity format: {e}")
            return False
    
    def format_error_response(
        self,
        error_message: str,
        error_code: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> ChannelResponse:
        """
        Format error response for Teams display
        
        Args:
            error_message: The error message
            error_code: Optional error code
            correlation_id: Optional correlation ID
            
        Returns:
            ChannelResponse formatted for Teams error display
        """
        channel_data = {
            "type": "message",
            "text": f"**Error:** {error_message}",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        if correlation_id:
            channel_data["channelData"] = {
                "correlation_id": correlation_id,
                "error": True
            }
            if error_code:
                channel_data["channelData"]["error_code"] = error_code
        
        response = ChannelResponse(
            message=f"Error: {error_message}",
            channel_data=channel_data,
            correlation_id=correlation_id
        )
        
        logger.debug(f"Formatted Teams error response: {error_message}")
        
        return response


class WebChannelAdapter(ChannelAdapter):
    """
    Channel adapter for Web/CLI HTTP-based chat interface
    Requirements: 1.1, 1.2, 1.5
    """
    
    def __init__(self):
        """Initialize the Web channel adapter"""
        super().__init__(ChannelType.WEB)
    
    def normalize_message(self, raw_request: Dict[str, Any]) -> InternalMessage:
        """
        Normalize Web/CLI request to internal message format
        
        Args:
            raw_request: Raw HTTP request data
            
        Returns:
            InternalMessage object
            
        Requirements: 1.1
        """
        try:
            # Extract body from HTTP request
            if isinstance(raw_request.get("body"), str):
                body = json.loads(raw_request["body"])
            else:
                body = raw_request.get("body", {})
            
            # Validate and extract required fields
            message_text = validate_message_text(body.get("messageText", ""))
            if not message_text:
                raise ValueError("Message text is required")
            
            user_id = validate_user_id(body.get("userId", ""))
            if not user_id:
                raise ValueError("User ID is required")
            
            # Extract optional fields
            channel_conversation_id = validate_channel_conversation_id(
                body.get("channelConversationId", "")
            )
            
            # Determine execution mode from environment or request
            execution_mode_str = (
                body.get("executionMode") or
                raw_request.get("executionMode", "SANDBOX_LIVE")
            )
            
            try:
                execution_mode = ExecutionMode(execution_mode_str)
            except ValueError:
                logger.warning(f"Invalid execution mode {execution_mode_str}, defaulting to SANDBOX_LIVE")
                execution_mode = ExecutionMode.SANDBOX_LIVE
            
            # Create internal message
            internal_message = InternalMessage(
                user_id=user_id,
                channel=ChannelType.WEB,
                channel_conversation_id=channel_conversation_id,
                message_text=message_text,
                execution_mode=execution_mode
            )
            
            logger.info(
                f"Normalized web message: user={user_id}, "
                f"correlation_id={internal_message.correlation_id}, "
                f"mode={execution_mode.value}"
            )
            
            return internal_message
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in request body: {str(e)}")
        except Exception as e:
            logger.error(f"Error normalizing web message: {str(e)}")
            raise ValueError(f"Failed to normalize message: {str(e)}")
    
    def format_response(
        self,
        message: str,
        correlation_id: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> ChannelResponse:
        """
        Format response for Web/CLI display
        
        Args:
            message: The response message
            correlation_id: Optional correlation ID
            additional_data: Additional data to include
            
        Returns:
            ChannelResponse formatted for web display
            
        Requirements: 1.2, 1.5
        """
        # Web channel uses simple JSON format
        if additional_data and additional_data.get("user_id"):
            user_id = additional_data["user_id"]
            if user_id not in message:
                message = f"{message}\n\nUser: {user_id}"

        channel_data = {
            "message": message,
            "format": "text",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        # Add any additional data
        if additional_data:
            channel_data.update(additional_data)
        
        # Add metadata
        if correlation_id:
            channel_data["correlation_id"] = correlation_id
        
        response = ChannelResponse(
            message=message,
            channel_data=channel_data,
            correlation_id=correlation_id
        )
        
        logger.debug(f"Formatted web response: correlation_id={correlation_id}")
        
        return response
    
    def format_approval_card(
        self,
        approval_request: ApprovalRequest,
        execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE
    ) -> ChannelResponse:
        """
        Format approval request as interactive web card
        
        Args:
            approval_request: The approval request to format
            execution_mode: Current execution mode
            
        Returns:
            ChannelResponse with web approval card
            
        Requirements: 1.5, 3.1
        """
        if not approval_request.tool_call:
            raise ValueError("Approval request missing tool call")
        
        tool_call = approval_request.tool_call
        
        # Format tool arguments for display
        formatted_args = []
        for key, value in tool_call.args.items():
            formatted_args.append({
                "name": key,
                "value": str(value),
                "type": type(value).__name__
            })
        
        # Determine action description based on execution mode
        mode_descriptions = {
            ExecutionMode.SANDBOX_LIVE: "EXECUTE"
        }
        mode_description = mode_descriptions.get(execution_mode, "EXECUTE")
        
        # Risk level styling
        risk_styles = {
            "low": {"color": "#28a745", "icon": "🟢"},
            "medium": {"color": "#ffc107", "icon": "🟡"},
            "high": {"color": "#dc3545", "icon": "🔴"}
        }
        risk_style = risk_styles.get(approval_request.risk_level, risk_styles["medium"])
        
        # Calculate expiry information
        expires_in_seconds = int((approval_request.expires_at - datetime.utcnow()).total_seconds())
        expires_in_minutes = max(0, expires_in_seconds // 60)
        
        # Create approval card data
        approval_card = {
            "type": "approval_card",
            "title": f"Approval Required: {tool_call.tool_name}",
            "subtitle": f"{mode_description} operation requested",
            "token": approval_request.token,
            "correlation_id": approval_request.correlation_id,
            "tool": {
                "name": tool_call.tool_name,
                "description": f"Execute {tool_call.tool_name} with the specified parameters",
                "arguments": formatted_args
            },
            "risk": {
                "level": approval_request.risk_level,
                "color": risk_style["color"],
                "icon": risk_style["icon"],
                "description": f"{approval_request.risk_level.upper()} risk operation"
            },
            "expiry": {
                "expires_at": approval_request.expires_at.isoformat() + "Z",
                "expires_in_minutes": expires_in_minutes,
                "expires_in_seconds": expires_in_seconds,
                "is_expired": expires_in_seconds <= 0
            },
            "execution": {
                "mode": execution_mode.value,
                "description": mode_description,
                "will_modify_infrastructure": execution_mode == ExecutionMode.SANDBOX_LIVE
            },
            "actions": [
                {
                    "type": "approve",
                    "label": f"✅ Approve {mode_description}",
                    "style": "primary",
                    "token": approval_request.token,
                    "confirmation_required": execution_mode == ExecutionMode.SANDBOX_LIVE
                },
                {
                    "type": "deny",
                    "label": "❌ Deny Request",
                    "style": "secondary",
                    "token": approval_request.token,
                    "confirmation_required": False
                }
            ],
            "metadata": {
                "requested_by": approval_request.user_id,
                "created_at": datetime.utcnow().isoformat() + "Z",
                "format_version": "1.0"
            }
        }
        
        # Create the response message
        message = (
            f"**Approval Required**\n\n"
            f"**Operation:** {tool_call.tool_name}\n"
            f"**Mode:** {mode_description}\n"
            f"**Risk Level:** {risk_style['icon']} {approval_request.risk_level.upper()}\n"
            f"**Expires:** {expires_in_minutes} minutes\n\n"
            f"Please review the details and approve or deny this request."
        )
        
        response = ChannelResponse(
            message=message,
            channel_data=approval_card,
            correlation_id=approval_request.correlation_id,
            requires_approval=True,
            approval_data=approval_card
        )
        
        logger.info(
            f"Formatted web approval card: tool={tool_call.tool_name}, "
            f"token={approval_request.token}, expires_in={expires_in_minutes}min"
        )
        
        return response
    
    def validate_request_authenticity(self, raw_request: Dict[str, Any]) -> bool:
        """
        Validate Web/CLI request authenticity
        
        Args:
            raw_request: Raw HTTP request data
            
        Returns:
            True if request is authentic
            
        Requirements: 1.4, 5.5
        """
        # For Web/CLI, we rely on API key authentication handled in main.py
        # This method can be extended for additional validation if needed
        
        # Basic request structure validation
        if not isinstance(raw_request, dict):
            logger.warning("Invalid request structure - not a dictionary")
            return False
        
        # Check for required HTTP fields (when coming from API Gateway)
        if "body" not in raw_request and "messageText" not in raw_request:
            logger.warning("Invalid request structure - missing body or messageText")
            return False
        
        # Additional validation could include:
        # - Request signature validation
        # - Rate limiting checks (handled in main.py)
        # - Content-Type validation
        # - Request size limits
        
        return True
    
    def format_error_response(
        self,
        error_message: str,
        error_code: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> ChannelResponse:
        """
        Format error response for Web/CLI display
        
        Args:
            error_message: The error message
            error_code: Optional error code
            correlation_id: Optional correlation ID
            
        Returns:
            ChannelResponse formatted for web error display
        """
        channel_data = {
            "error": True,
            "message": error_message,
            "format": "error",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        if error_code:
            channel_data["error_code"] = error_code
        
        if correlation_id:
            channel_data["correlation_id"] = correlation_id
        
        response = ChannelResponse(
            message=f"Error: {error_message}",
            channel_data=channel_data,
            correlation_id=correlation_id
        )
        
        logger.debug(f"Formatted web error response: {error_message}")
        
        return response
    
    def format_system_status(self, status_data: Dict[str, Any]) -> ChannelResponse:
        """
        Format system status for Web/CLI display
        
        Args:
            status_data: System status information
            
        Returns:
            ChannelResponse formatted for web status display
        """
        # Create a user-friendly status message
        execution_mode = status_data.get("execution_mode", "UNKNOWN")
        llm_status = status_data.get("llm_provider_status", "unknown")
        aws_status = status_data.get("aws_tool_access_status", "unknown")
        
        status_emoji = {
            "configured": "OK",
            "not_configured": "WARNING",
            "error": "ERROR"
        }
        
        message = (
            f"**OpsAgent Controller Status**\n\n"
            f"**Execution Mode:** {execution_mode}\n"
            f"**LLM Provider:** {status_emoji.get(llm_status, 'UNKNOWN')} {llm_status}\n"
            f"**AWS Tools:** {status_emoji.get(aws_status, 'UNKNOWN')} {aws_status}\n"
            f"**Environment:** {status_data.get('environment', 'unknown')}\n"
            f"**Version:** {status_data.get('version', 'unknown')}"
        )
        
        # Add detailed status information for web display
        channel_data = {
            "type": "system_status",
            "status": "healthy" if llm_status == "configured" and aws_status == "configured" else "degraded",
            "details": status_data,
            "format": "status",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        response = ChannelResponse(
            message=message,
            channel_data=channel_data
        )
        
        logger.debug("Formatted web system status response")
        
        return response


# Factory function for creating channel adapters
def create_channel_adapter(channel_type: ChannelType) -> ChannelAdapter:
    """
    Factory function to create appropriate channel adapter
    
    Args:
        channel_type: The type of channel adapter to create
        
    Returns:
        ChannelAdapter instance
        
    Raises:
        ValueError: If channel type is not supported
    """
    if channel_type == ChannelType.WEB:
        return WebChannelAdapter()
    elif channel_type == ChannelType.TEAMS:
        return TeamsChannelAdapter()
    elif channel_type == ChannelType.SLACK:
        # TODO: Implement SlackChannelAdapter (future enhancement)
        raise NotImplementedError("Slack channel adapter not yet implemented")
    else:
        raise ValueError(f"Unsupported channel type: {channel_type}")


def detect_channel_type(raw_request: Dict[str, Any]) -> ChannelType:
    """
    Detect the channel type from the incoming request
    
    Args:
        raw_request: Raw request data
        
    Returns:
        ChannelType detected from the request
    """
    # Check for Teams Bot Framework Activity structure
    try:
        if isinstance(raw_request.get("body"), str):
            body = json.loads(raw_request["body"])
        else:
            body = raw_request.get("body", raw_request)
        
        # Teams Bot Framework Activity has specific structure
        if (body.get("type") == "message" and 
            "from" in body and 
            "conversation" in body and
            body.get("channelId") in ["msteams", None]):
            return ChannelType.TEAMS
    except (json.JSONDecodeError, TypeError):
        pass
    
    # Check for Teams-specific headers
    headers = raw_request.get("headers", {})
    auth_header = headers.get("authorization") or headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and "from" in raw_request.get("body", "{}"):
        return ChannelType.TEAMS
    
    # Default to Web for HTTP requests
    return ChannelType.WEB
