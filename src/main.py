"""
OpsAgent Controller - Main Lambda handler
"""
import json
import logging
import os
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import hashlib
import hmac
import base64

import requests

from src.models import InternalMessage, ChannelType, ExecutionMode, validate_message_text, validate_user_id, generate_correlation_id
from src.channel_adapters import WebChannelAdapter, create_channel_adapter, ChannelAdapter, detect_channel_type
from src.llm_provider import create_llm_provider, LLMProviderError
from src.tool_execution_engine import ToolExecutionEngine, ExecutionContext
from src.approval_gate import ApprovalGate
from src.audit_logger import AuditLogger
from src.authentication import authenticate_and_authorize_request, get_user_authenticator, get_signature_validator
# Teams authentication handled by Amazon Q Business natively

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate limiting storage (in-memory for MVP, should use Redis/DynamoDB in production)
_rate_limit_store = {}
_rate_limit_cleanup_time = time.time()
_last_pytest_test = None

# Execution modes (Requirement 10: LOCAL_MOCK, DRY_RUN, SANDBOX_LIVE)
EXECUTION_MODES = ["LOCAL_MOCK", "DRY_RUN", "SANDBOX_LIVE"]

# Rate limiting configuration
RATE_LIMIT_REQUESTS_PER_MINUTE = 30
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_CLEANUP_INTERVAL = 300  # Clean up old entries every 5 minutes

# Global components (initialized on first use)
_llm_provider = None
_tool_execution_engine = None
_approval_gate = None
_audit_logger = None
_llm_provider_execution_mode = None


def get_or_create_components(execution_mode: ExecutionMode):
    """
    Get or create global components based on execution mode
    Requirements: All requirements integration
    """
    global _llm_provider, _tool_execution_engine, _approval_gate, _audit_logger, _llm_provider_execution_mode
    
    # Initialize LLM provider if not exists or mode changed
    if _llm_provider is None or _llm_provider_execution_mode != execution_mode:
        # Get current AWS region from environment or boto3 session
        import boto3
        current_region = boto3.Session().region_name or os.environ.get('AWS_REGION', 'us-east-1')
        
        # Check for Amazon Q Business configuration
        amazon_q_config = {}
        if os.environ.get('AMAZON_Q_APP_ID'):
            amazon_q_config = {
                'amazon_q_app_id': os.environ.get('AMAZON_Q_APP_ID'),
                'amazon_q_user_id': os.environ.get('AMAZON_Q_USER_ID', 'opsagent-user'),
                'amazon_q_session_id': os.environ.get('AMAZON_Q_SESSION_ID'),
                'bedrock_model_id': os.environ.get('BEDROCK_MODEL_ID')
            }
        
        _llm_provider = create_llm_provider(
            execution_mode, 
            region_name=current_region,
            **amazon_q_config
        )
        _llm_provider_execution_mode = execution_mode
        
        provider_type = "Amazon Q Business Hybrid" if amazon_q_config else "Bedrock"
        logger.info(f"Initialized {provider_type} LLM provider for {execution_mode.value} mode in region {current_region}")
    
    # Initialize tool execution engine if not exists or mode changed
    if _tool_execution_engine is None:
        _tool_execution_engine = ToolExecutionEngine(execution_mode)
        logger.info(f"Initialized tool execution engine for {execution_mode.value} mode")
    
    # Initialize approval gate if not exists
    if _approval_gate is None:
        _approval_gate = ApprovalGate(storage_backend="memory", default_expiry_minutes=15)
        logger.info("Initialized approval gate")
    
    # Initialize audit logger if not exists or mode changed
    if _audit_logger is None:
        cloudwatch_log_group = os.environ.get("CLOUDWATCH_LOG_GROUP", "/aws/lambda/opsagent-controller")
        dynamodb_table = os.environ.get("AUDIT_TABLE_NAME")
        _audit_logger = AuditLogger(
            cloudwatch_log_group=cloudwatch_log_group,
            dynamodb_table_name=dynamodb_table,
            execution_mode=execution_mode
        )
        logger.info(f"Initialized audit logger for {execution_mode.value} mode")
    
    # Update execution modes if they've changed
    if hasattr(_tool_execution_engine, 'execution_mode') and _tool_execution_engine.execution_mode != execution_mode:
        _tool_execution_engine.set_execution_mode(execution_mode)
        logger.info(f"Updated tool execution engine to {execution_mode.value} mode")
    
    if hasattr(_audit_logger, 'execution_mode') and _audit_logger.execution_mode != execution_mode:
        _audit_logger.set_execution_mode(execution_mode)
        logger.info(f"Updated audit logger to {execution_mode.value} mode")
    
    return _llm_provider, _tool_execution_engine, _approval_gate, _audit_logger


def cleanup_rate_limit_store():
    """Clean up old rate limit entries"""
    global _rate_limit_cleanup_time
    current_time = time.time()
    
    if current_time - _rate_limit_cleanup_time > RATE_LIMIT_CLEANUP_INTERVAL:
        cutoff_time = current_time - RATE_LIMIT_WINDOW_SECONDS
        keys_to_remove = [
            key for key, timestamps in _rate_limit_store.items()
            if all(ts < cutoff_time for ts in timestamps)
        ]
        for key in keys_to_remove:
            del _rate_limit_store[key]
        _rate_limit_cleanup_time = current_time


def check_rate_limit(client_id: str) -> bool:
    """
    Check if client has exceeded rate limit
    Returns True if request is allowed, False if rate limited
    """
    cleanup_rate_limit_store()
    
    current_time = time.time()
    cutoff_time = current_time - RATE_LIMIT_WINDOW_SECONDS
    
    # Get existing timestamps for this client
    if client_id not in _rate_limit_store:
        _rate_limit_store[client_id] = []
    
    timestamps = _rate_limit_store[client_id]
    
    # Remove old timestamps
    timestamps[:] = [ts for ts in timestamps if ts > cutoff_time]
    
    # Check if under limit
    if len(timestamps) >= RATE_LIMIT_REQUESTS_PER_MINUTE:
        return False
    
    # Add current timestamp
    timestamps.append(current_time)
    return True


def validate_request_signature(event: Dict[str, Any]) -> bool:
    """
    Validate request signature for authentication
    Uses the new authentication system for comprehensive validation.
    Requirements: 8.1, 8.2, 9.1
    """
    try:
        # In LOCAL_MOCK mode, bypass authentication for testing purposes
        execution_mode = os.environ.get("EXECUTION_MODE", "SANDBOX_LIVE")
        if execution_mode == "LOCAL_MOCK":
            logger.info("Bypassing request signature validation in LOCAL_MOCK mode")
            return True
        
        # Use the new authentication system
        signature_validator = get_signature_validator()
        is_valid, error_message = signature_validator.validate_plugin_signature(event)
        
        if not is_valid:
            logger.warning(f"Request signature validation failed: {error_message}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Signature validation error: {e}")
        return False


def extract_client_id(event: Dict[str, Any]) -> str:
    """Extract client identifier for rate limiting"""
    # Try to get user ID from request
    try:
        if event.get("body"):
            body = json.loads(event["body"])
            if body.get("userId"):
                return f"user:{body['userId']}"
    except (json.JSONDecodeError, KeyError):
        pass
    
    # Fall back to source IP
    source_ip = (
        event.get("requestContext", {}).get("identity", {}).get("sourceIp") or
        event.get("headers", {}).get("x-forwarded-for", "").split(",")[0].strip() or
        "unknown"
    )
    return f"ip:{source_ip}"


def parse_chat_request(event: Dict[str, Any]) -> InternalMessage:
    """
    Parse incoming chat request and convert to internal message format
    Requirements: 1.1, 1.2
    """
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON in request body")
    
    # Extract and validate required fields
    message_text = validate_message_text(body.get("messageText", ""))
    if not message_text:
        raise ValueError("Message text is required")
    
    user_id = validate_user_id(body.get("userId", ""))
    if not user_id:
        raise ValueError("User ID is required")
    
    # Determine channel type
    channel_str = body.get("channel", "web").lower()
    try:
        channel = ChannelType(channel_str)
    except ValueError:
        channel = ChannelType.WEB
    
    # Get execution mode
    execution_mode_str = os.environ.get("EXECUTION_MODE", "SANDBOX_LIVE")
    try:
        execution_mode = ExecutionMode(execution_mode_str)
    except ValueError:
        execution_mode = ExecutionMode.SANDBOX_LIVE
    
    return InternalMessage(
        user_id=user_id,
        channel=channel,
        channel_conversation_id=body.get("channelConversationId", ""),
        message_text=message_text,
        execution_mode=execution_mode
    )


def format_response_for_channel(message: str, channel: ChannelType, additional_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Format response based on channel type
    Requirements: 1.5
    """
    base_response = {
        "message": message,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if additional_data:
        base_response.update(additional_data)
    
    if channel == ChannelType.TEAMS:
        # Teams-specific formatting with rich cards
        return {
            "type": "message",
            "text": message,
            "attachments": base_response.get("attachments", [])
        }
    elif channel == ChannelType.SLACK:
        # Slack-specific formatting
        return {
            "text": message,
            "blocks": base_response.get("blocks", [])
        }
    else:
        # Web/CLI - simple JSON response
        return base_response


def create_error_response(status_code: int, error_message: str, correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Create standardized error response
    Requirements: 10.3
    """
    error_body = {
        "error": error_message,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if correlation_id:
        error_body["correlationId"] = correlation_id
    
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        },
        "body": json.dumps(error_body)
    }


def create_success_response(data: Dict[str, Any], correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Create standardized success response
    Requirements: 10.3
    """
    response_body = {
        "success": True,
        "data": data,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    if correlation_id:
        response_body["correlationId"] = correlation_id

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        },
        "body": json.dumps(response_body)
    }


def get_bot_framework_token() -> Optional[str]:
    """Get Bot Framework access token for Bot Connector API"""
    bot_app_id = os.environ.get("TEAMS_BOT_APP_ID")
    
    if not bot_app_id:
        logger.warning("TEAMS_BOT_APP_ID not configured")
        return None

    # Get bot password from SSM Parameter Store
    try:
        import boto3
        ssm_client = boto3.client('ssm')
        response = ssm_client.get_parameter(
            Name='/opsagent/teams-bot-app-secret',
            WithDecryption=True
        )
        bot_app_password = response['Parameter']['Value']
    except Exception as e:
        logger.error(f"Failed to get bot password from SSM: {e}")
        logger.error("Ensure /opsagent/teams-bot-app-secret parameter exists in SSM Parameter Store")
        return None

    try:
        # Bot Framework always uses botframework.com for OAuth, regardless of bot configuration
        token_url = "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": bot_app_id,
            "client_secret": bot_app_password,
            "scope": "https://api.botframework.com/.default"
        }

        logger.info(f"Requesting Bot Framework token from {token_url}")
        response = requests.post(token_url, data=data, timeout=10)
        response.raise_for_status()

        token_data = response.json()
        logger.info("Successfully obtained Bot Framework access token")
        return token_data.get("access_token")
    except Exception as e:
        logger.error(f"Failed to get Bot Framework token: {e}")
        logger.error("Check that TEAMS_BOT_APP_ID and bot secret in SSM are correct")
        return None


def send_bot_framework_reply(
    text: str,
    incoming_activity: Dict[str, Any],
    bot_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    attachments: Optional[List[Dict[str, Any]]] = None
) -> bool:
    """Send reply via Bot Connector API"""
    if bot_id is None:
        bot_id = os.environ.get("TEAMS_BOT_APP_ID", "unknown")

    # Get access token
    access_token = get_bot_framework_token()
    if not access_token:
        logger.error("Failed to get Bot Framework access token")
        return False

    # Create reply Activity
    activity = {
        "type": "message",
        "text": text,
        "from": {
            "id": f"28:{bot_id}",
            "name": "OpsAgent AWS"
        },
        "conversation": incoming_activity.get("conversation", {}),
        "recipient": incoming_activity.get("from", {}),
        "replyToId": incoming_activity.get("id"),
        "channelId": incoming_activity.get("channelId", "msteams")
    }

    # Add attachments if provided
    if attachments:
        activity["attachments"] = attachments

    if correlation_id:
        if "channelData" not in activity:
            activity["channelData"] = {}
        activity["channelData"]["correlationId"] = correlation_id

    # Send to Bot Connector API
    service_url = incoming_activity.get("serviceUrl")
    if not service_url:
        logger.error("No serviceUrl in incoming activity")
        return False

    # Remove trailing slash from service_url to avoid double slashes
    service_url = service_url.rstrip("/")

    conversation_id = incoming_activity.get("conversation", {}).get("id")
    if not conversation_id:
        logger.error("No conversation ID in incoming activity")
        return False

    # POST to Bot Connector API
    connector_url = f"{service_url}/v3/conversations/{conversation_id}/activities"
    logger.info(f"Sending reply to Bot Connector API: {connector_url}")

    try:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        response = requests.post(connector_url, json=activity, headers=headers, timeout=10)
        response.raise_for_status()

        logger.info(f"Successfully sent reply via Bot Connector API: {response.status_code}")
        return True
    except Exception as e:
        logger.error(f"Failed to send reply via Bot Connector API: {e}")
        return False


def create_bot_framework_response(
    text: str,
    incoming_activity: Dict[str, Any],
    bot_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    attachments: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Create Bot Framework Activity response (returns Activity directly in HTTP response)

    Args:
        text: The message text to send
        incoming_activity: The original incoming Activity from Teams
        bot_id: Bot application ID
        correlation_id: Optional correlation ID for tracking
        attachments: Optional attachments (e.g., Adaptive Cards)

    Returns:
        Lambda response with Activity in body (200 OK)
    """
    if bot_id is None:
        bot_id = os.environ.get("TEAMS_BOT_APP_ID", "unknown")

    # Create reply Activity
    activity = {
        "type": "message",
        "text": text,
        "from": {
            "id": f"28:{bot_id}",
            "name": "OpsAgent AWS"
        },
        "conversation": incoming_activity.get("conversation", {}),
        "recipient": incoming_activity.get("from", {}),
        "replyToId": incoming_activity.get("id"),
        "channelId": incoming_activity.get("channelId", "msteams")
    }

    # Add attachments if provided (e.g., Adaptive Cards)
    if attachments:
        activity["attachments"] = attachments

    # Add correlation ID for tracking
    if correlation_id:
        if "channelData" not in activity:
            activity["channelData"] = {}
        activity["channelData"]["correlationId"] = correlation_id

    logger.info(f"Returning Bot Framework Activity response for conversation {activity.get('conversation', {}).get('id')}")

    # Return the Activity directly in the HTTP response
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(activity)
    }


def get_execution_mode() -> str:
    """Get current execution mode from environment variable"""
    mode = os.environ.get("EXECUTION_MODE", "SANDBOX_LIVE")
    if mode not in EXECUTION_MODES:
        logger.warning(f"Invalid execution mode {mode}, defaulting to SANDBOX_LIVE")
        return "SANDBOX_LIVE"
    return mode


def get_system_status() -> Dict[str, Any]:
    """
    Get system status including dependencies
    Requirements: 11.6, 11.7
    """
    status = {
        "execution_mode": get_execution_mode(),
        "llm_provider_status": "not_configured",
        "aws_tool_access_status": "not_configured",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "1.0.0",
        "uptime_seconds": 0  # Would be calculated from startup time in production
    }
    
    # Check if running in AWS Lambda environment
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        status["environment"] = "lambda"
        status["function_name"] = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        status["function_version"] = os.environ.get("AWS_LAMBDA_FUNCTION_VERSION", "$LATEST")
    else:
        status["environment"] = "local"
    
    # Check LLM provider configuration
    try:
        # Check for Amazon Q Business integration first
        amazon_q_app_id = os.environ.get("AMAZON_Q_APP_ID")
        if amazon_q_app_id:
            # Test Amazon Q Business access
            import boto3
            try:
                q_client = boto3.client('qbusiness')
                # Try to get application info to verify access
                q_client.get_application(applicationId=amazon_q_app_id)
                status["llm_provider_status"] = "configured"
                status["llm_provider_type"] = "amazon_q_business_hybrid"
                status["amazon_q_app_id"] = amazon_q_app_id
                status["amazon_q_user_id"] = os.environ.get("AMAZON_Q_USER_ID", "opsagent-user")
                status["hybrid_mode"] = "enabled"
            except Exception as q_error:
                logger.warning(f"Amazon Q Business access check failed: {q_error}")
                status["llm_provider_status"] = "error"
                status["llm_provider_type"] = "amazon_q_business_hybrid"
                status["amazon_q_error"] = str(q_error)
                status["hybrid_mode"] = "error"
        else:
            # Check traditional LLM providers
            llm_provider = os.environ.get("LLM_PROVIDER", "").lower()
            if llm_provider == "bedrock":
                # Check if Bedrock is accessible
                import boto3
                bedrock_client = boto3.client('bedrock-runtime')
                # Try to list models to verify access
                status["llm_provider_status"] = "configured"
                status["llm_provider_type"] = "bedrock"
            elif os.environ.get("OPENAI_API_KEY"):
                status["llm_provider_status"] = "configured"
                status["llm_provider_type"] = "openai"
            elif os.environ.get("AZURE_OPENAI_ENDPOINT"):
                status["llm_provider_status"] = "configured"
                status["llm_provider_type"] = "azure_openai"
            else:
                status["llm_provider_status"] = "not_configured"
                status["llm_provider_type"] = "none"
    except Exception as e:
        logger.warning(f"LLM provider check failed: {str(e)}")
        status["llm_provider_status"] = "error"
        status["llm_provider_error"] = str(e)
    
    # Check AWS tool access with detailed validation
    try:
        import boto3
        
        # Test STS access (basic AWS connectivity)
        sts_client = boto3.client('sts')
        identity = sts_client.get_caller_identity()
        status["aws_identity"] = {
            "account": identity.get("Account"),
            "user_id": identity.get("UserId"),
            "arn": identity.get("Arn")
        }
        
        # Test CloudWatch access (diagnosis tools)
        cloudwatch_client = boto3.client('cloudwatch')
        cloudwatch_client.list_metrics(Namespace='AWS/EC2')
        status["cloudwatch_access"] = "available"
        
        # Test EC2 access (diagnosis and remediation tools)
        ec2_client = boto3.client('ec2')
        ec2_client.describe_instances(MaxResults=5)
        status["ec2_access"] = "available"
        
        status["aws_tool_access_status"] = "configured"
        
    except Exception as e:
        logger.warning(f"AWS tool access check failed: {str(e)}")
        status["aws_tool_access_status"] = "error"
        status["aws_tool_error"] = str(e)
        status["cloudwatch_access"] = "unavailable"
        status["ec2_access"] = "unavailable"
    
    # Check audit logging capability
    try:
        # Test CloudWatch Logs access
        logs_client = boto3.client('logs')
        logs_client.describe_log_groups(limit=1)
        status["audit_logging_status"] = "configured"
    except Exception as e:
        logger.warning(f"Audit logging check failed: {str(e)}")
        status["audit_logging_status"] = "error"
        status["audit_logging_error"] = str(e)
    
    return status


def chat_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """
    Handle chat message requests using integrated OpsAgent system
    Requirements: 1.1, 1.2, 4.1, All requirements integration
    """
    correlation_id = None
    internal_message = None
    incoming_activity = None

    try:
        # Create appropriate channel adapter
        channel_type = detect_channel_type(event)
        channel_adapter = create_channel_adapter(channel_type)

        logger.info(f"Detected channel type: {channel_type.value}")

        # Extract Bot Framework Activity for Teams (needed for responses)
        if channel_type == ChannelType.TEAMS:
            try:
                if isinstance(event.get("body"), str):
                    incoming_activity = json.loads(event["body"])
                else:
                    incoming_activity = event.get("body", {})
            except (json.JSONDecodeError, TypeError):
                incoming_activity = {}

        # Normalize the incoming message first (needed for authentication)
        internal_message = channel_adapter.normalize_message(event)
        correlation_id = internal_message.correlation_id

        # Validate request authenticity and authenticate user
        # In LOCAL_MOCK mode, bypass authentication for testing purposes
        execution_mode_env = os.environ.get("EXECUTION_MODE", "SANDBOX_LIVE")

        if execution_mode_env == "LOCAL_MOCK":
            # Skip authentication in LOCAL_MOCK mode for testing
            logger.info("Bypassing authentication in LOCAL_MOCK mode")
        elif channel_type == ChannelType.TEAMS:
            # For Teams requests, validate using channel adapter and then authenticate user
            if not channel_adapter.validate_request_authenticity(event):
                logger.warning("Teams request authenticity validation failed")
                return create_error_response(401, "Request authentication failed")

            # Extract and validate user from Teams activity
            user_authenticator = get_user_authenticator()
            if isinstance(event.get("body"), str):
                activity = json.loads(event["body"])
            else:
                activity = event.get("body", {})

            user_context, error_msg = user_authenticator.extract_user_identity_from_teams(activity)
            if not user_context:
                logger.warning(f"Failed to extract Teams user identity: {error_msg}")
                return create_error_response(401, f"User authentication failed: {error_msg}")

            # Validate user authorization
            is_authorized, auth_error = user_authenticator.validate_user_authorization(user_context.user_id, correlation_id)
            if not is_authorized:
                logger.warning(f"Teams user not authorized: {user_context.user_id} - {auth_error}")
                return create_error_response(403, f"User not authorized: {auth_error}")

            # Update internal message with authenticated user context
            internal_message.user_id = user_context.user_id
            internal_message.user_context = user_context
        else:
            # For non-Teams requests, use comprehensive authentication
            auth_result = authenticate_and_authorize_request(event, correlation_id)

            if not auth_result.authenticated:
                logger.warning(f"Authentication failed: {auth_result.error_message}")
                return create_error_response(401, f"Authentication failed: {auth_result.error_message}", correlation_id)

            # Update internal message with authenticated user context
            if auth_result.user_context:
                internal_message.user_id = auth_result.user_context.user_id
                # Store additional user context for audit logging
                internal_message.user_context = auth_result.user_context

        logger.info(f"Processing chat message: {correlation_id}")
        
        # Determine effective execution mode (environment override for testing/safety)
        effective_execution_mode = internal_message.execution_mode
        env_execution_mode = os.environ.get("EXECUTION_MODE")
        if env_execution_mode:
            try:
                effective_execution_mode = ExecutionMode(env_execution_mode)
            except ValueError:
                logger.warning(
                    f"Invalid EXECUTION_MODE {env_execution_mode}, "
                    f"using requested mode {internal_message.execution_mode.value}"
                )

        # Get or create system components
        llm_provider, tool_execution_engine, approval_gate, audit_logger = get_or_create_components(
            effective_execution_mode
        )
        
        # Log the incoming request
        audit_logger.log_request_received(internal_message)
        
        # Check if this is an approval response
        approval_token = None
        approval_decision = None
        
        # Handle Teams Adaptive Card action submissions
        if channel_type == ChannelType.TEAMS:
            try:
                if isinstance(event.get("body"), str):
                    activity = json.loads(event["body"])
                else:
                    activity = event.get("body", event)
                
                # Check if this is an Adaptive Card action submission
                if activity.get("type") == "message" and activity.get("value"):
                    action_data = activity.get("value", {})
                    if action_data.get("action") in ["approve", "deny"]:
                        approval_token = action_data.get("token")
                        approval_decision = action_data.get("action")
                        logger.info(f"Teams approval action: {approval_decision} for token {approval_token}")
            except (json.JSONDecodeError, KeyError, TypeError):
                pass
        
        # Simple approval parsing for text-based approvals (fallback)
        if not approval_token:
            message_lower = internal_message.message_text.lower()
            if "approve" in message_lower and "token:" in message_lower:
                # Extract token from message like "approve token:abc123"
                try:
                    token_part = internal_message.message_text.split("token:")[1].strip().split()[0]
                    approval_token = token_part
                    approval_decision = "approve"
                except (IndexError, AttributeError):
                    pass
            elif "deny" in message_lower and "token:" in message_lower:
                try:
                    token_part = internal_message.message_text.split("token:")[1].strip().split()[0]
                    approval_token = token_part
                    approval_decision = "deny"
                except (IndexError, AttributeError):
                    pass
        
        # Handle approval responses
        if approval_token and approval_decision:
            return handle_approval_response(
                approval_token, approval_decision, internal_message, 
                channel_adapter, approval_gate, audit_logger
            )
        
        # Generate tool calls using LLM
        try:
            llm_response = llm_provider.generate_tool_calls(
                internal_message.message_text, 
                correlation_id
            )
            
            logger.info(f"LLM generated {len(llm_response.tool_calls)} tool calls")
            
            # Log tool calls requested
            for tool_call in llm_response.tool_calls:
                audit_logger.log_tool_call_requested(
                    tool_call, 
                    internal_message.user_id, 
                    internal_message.channel.value
                )
            
        except LLMProviderError as e:
            logger.error(f"LLM provider error: {e}")
            audit_logger.log_error(e, correlation_id, internal_message.user_id, {"step": "llm_generation"})

            error_message = "I'm having trouble understanding your request. Please try again."

            # Return Bot Framework format for Teams
            if channel_type == ChannelType.TEAMS and incoming_activity:
                return create_bot_framework_response(error_message, incoming_activity, correlation_id=correlation_id)

            error_response = channel_adapter.format_error_response(
                error_message,
                "LLM_ERROR",
                correlation_id
            )
            return create_success_response(error_response.to_dict(), correlation_id)
        except Exception as e:
            logger.error(f"LLM generation error: {e}")
            audit_logger.log_error(e, correlation_id, internal_message.user_id, {"step": "llm_generation"})

            error_message = "I'm having trouble understanding your request. Please try again."

            # Return Bot Framework format for Teams
            if channel_type == ChannelType.TEAMS and incoming_activity:
                return create_bot_framework_response(error_message, incoming_activity, correlation_id=correlation_id)

            error_response = channel_adapter.format_error_response(
                error_message,
                "LLM_ERROR",
                correlation_id
            )
            return create_success_response(error_response.to_dict(), correlation_id)
        
        # Check if any tools require approval
        approval_required_tools = [tc for tc in llm_response.tool_calls if tc.requires_approval]
        
        if approval_required_tools:
            # Create approval requests for write operations
            approval_requests = []
            
            for tool_call in approval_required_tools:
                try:
                    approval_request = approval_gate.create_approval_request(
                        tool_call=tool_call,
                        requested_by=internal_message.user_id,
                        risk_level="medium"  # Could be determined by tool type/args
                    )
                    approval_requests.append(approval_request)
                    
                    # Log approval request
                    audit_logger.log_approval_requested(
                        approval_request,
                        internal_message.user_id,
                        internal_message.channel.value
                    )
                    
                except Exception as e:
                    logger.error(f"Failed to create approval request: {e}")
                    audit_logger.log_error(e, correlation_id, internal_message.user_id, {"step": "approval_creation"})
            
            # Format approval cards for the user
            if approval_requests:
                # For simplicity, handle one approval at a time in MVP
                approval_request = approval_requests[0]
                approval_response = channel_adapter.format_approval_card(
                    approval_request,
                    effective_execution_mode
                )

                # Return Bot Framework format for Teams
                if channel_type == ChannelType.TEAMS and incoming_activity:
                    approval_text = approval_response.to_dict().get("message", "Approval required")
                    return create_bot_framework_response(approval_text, incoming_activity, correlation_id=correlation_id)

                return create_success_response(approval_response.to_dict(), correlation_id)
        
        # Execute tools (only read-only tools or approved write tools)
        execution_context = ExecutionContext(
            correlation_id=correlation_id,
            user_id=internal_message.user_id,
            execution_mode=effective_execution_mode,
            approval_tokens={}  # No pre-approved tokens in this flow
        )
        
        tool_results = tool_execution_engine.execute_tools(
            llm_response.tool_calls,
            execution_context
        )
        
        # Log tool execution results
        for i, result in enumerate(tool_results):
            if i < len(llm_response.tool_calls):
                audit_logger.log_tool_call_executed(
                    llm_response.tool_calls[i],
                    result,
                    internal_message.user_id,
                    internal_message.channel.value
                )
        
        # Generate summary using LLM
        try:
            summary = llm_provider.generate_summary(
                [result.to_dict() for result in tool_results],
                correlation_id
            )
        except LLMProviderError as e:
            logger.warning(f"Failed to generate summary: {e}")
            # Fallback to basic summary
            successful_tools = [r for r in tool_results if r.success]
            failed_tools = [r for r in tool_results if not r.success]
            
            summary_parts = []
            if successful_tools:
                summary_parts.append(f"Successfully executed {len(successful_tools)} operation(s)")
            if failed_tools:
                summary_parts.append(f"{len(failed_tools)} operation(s) failed")
            
            summary = "\n".join(summary_parts) if summary_parts else "Operations completed."
        
        # Add execution mode context to summary
        mode_context = {
            ExecutionMode.SANDBOX_LIVE: f" ({internal_message.execution_mode.value})"
        }.get(internal_message.execution_mode, f" ({internal_message.execution_mode.value})")
        
        final_message = f"{llm_response.assistant_message}\n\n{summary}{mode_context}"

        # Return Bot Framework format for Teams
        if channel_type == ChannelType.TEAMS and incoming_activity:
            # Try to send via Bot Connector API first
            success = send_bot_framework_reply(final_message, incoming_activity, correlation_id=correlation_id)
            
            if success:
                return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": ""}
            else:
                # Fallback to HTTP response
                return create_bot_framework_response(final_message, incoming_activity, correlation_id=correlation_id)

        # Format response using channel adapter
        channel_response = channel_adapter.format_response(
            final_message,
            correlation_id,
            {
                "user_id": internal_message.user_id,
                "execution_mode": internal_message.execution_mode.value,
                "tool_results": [{"tool_name": r.tool_name, "success": r.success} for r in tool_results],
                "llm_confidence": llm_response.confidence
            }
        )

        return create_success_response(channel_response.to_dict(), correlation_id)
        
    except ValueError as e:
        logger.warning(f"Validation error: {str(e)}")
        if internal_message and correlation_id:
            # Log error if we have context
            try:
                _, _, _, audit_logger, _ = get_or_create_components(effective_execution_mode)
                audit_logger.log_error(e, correlation_id, internal_message.user_id, {"step": "validation"})
            except:
                pass

        # Return Bot Framework format for Teams if available
        if 'channel_type' in locals() and channel_type == ChannelType.TEAMS and incoming_activity:
            error_message = f"Bad Request: {str(e)}"
            return create_bot_framework_response(error_message, incoming_activity, correlation_id=correlation_id)

        return create_error_response(400, f"Bad Request: {str(e)}", correlation_id)
    except Exception as e:
        logger.error(f"Chat handler error: {str(e)}")
        if internal_message and correlation_id:
            # Log error if we have context
            try:
                _, _, _, audit_logger, _ = get_or_create_components(effective_execution_mode)
                audit_logger.log_error(e, correlation_id, internal_message.user_id, {"step": "processing"})
            except:
                pass

        # Return Bot Framework format for Teams if available
        if 'channel_type' in locals() and channel_type == ChannelType.TEAMS and incoming_activity:
            return create_bot_framework_response("Internal server error", incoming_activity, correlation_id=correlation_id)

        return create_error_response(500, "Internal server error", correlation_id)


def handle_approval_response(
    approval_token: str,
    decision: str,
    internal_message: InternalMessage,
    channel_adapter: ChannelAdapter,
    approval_gate: ApprovalGate,
    audit_logger: AuditLogger
) -> Dict[str, Any]:
    """
    Handle approval response from user
    Requirements: 3.1, 3.4
    """
    correlation_id = internal_message.correlation_id
    effective_execution_mode = internal_message.execution_mode
    env_execution_mode = os.environ.get("EXECUTION_MODE")
    if env_execution_mode:
        try:
            effective_execution_mode = ExecutionMode(env_execution_mode)
        except ValueError:
            logger.warning(
                f"Invalid EXECUTION_MODE {env_execution_mode}, "
                f"using requested mode {internal_message.execution_mode.value}"
            )
    
    try:
        # Find the approval request
        pending_approvals = approval_gate.get_pending_approvals(internal_message.user_id)
        approval_request = None
        
        for req in pending_approvals:
            if req.token == approval_token:
                approval_request = req
                break
        
        if not approval_request:
            error_msg = "Invalid or expired approval token"
            channel_response = channel_adapter.format_error_response(error_msg, "INVALID_TOKEN", correlation_id)
            return create_success_response(channel_response.to_dict(), correlation_id)
        
        # Record the approval decision
        approved = decision.lower() == "approve"
        approval_decision_obj = approval_gate.approve_request(
            approval_token,
            internal_message.user_id,
            approved
        )
        
        # Log the approval decision
        audit_logger.log_approval_decision(
            approval_request,
            "granted" if approved else "denied",
            internal_message.user_id,
            internal_message.channel.value
        )
        
        if not approved:
            # User denied the request
            response_message = f"Request denied. Operation cancelled.\n\nCorrelation ID: {correlation_id}"
            channel_response = channel_adapter.format_response(response_message, correlation_id)
            return create_success_response(channel_response.to_dict(), correlation_id)
        
        # User approved - execute the tool
        if not approval_request.tool_call:
            error_msg = "Approval request missing tool call"
            channel_response = channel_adapter.format_error_response(error_msg, "INVALID_REQUEST", correlation_id)
            return create_success_response(channel_response.to_dict(), correlation_id)
        
        # Get system components
        llm_provider, tool_execution_engine, _, _, _ = get_or_create_components(effective_execution_mode)
        
        # Execute the approved tool
        execution_context = ExecutionContext(
            correlation_id=correlation_id,
            user_id=internal_message.user_id,
            execution_mode=effective_execution_mode,
            approval_tokens={approval_token: approval_request}
        )
        
        tool_results = tool_execution_engine.execute_tools(
            [approval_request.tool_call],
            execution_context
        )
        
        # Consume the approval token
        approval_gate.consume_approval_token(approval_token)
        
        # Log tool execution
        if tool_results:
            audit_logger.log_tool_call_executed(
                approval_request.tool_call,
                tool_results[0],
                internal_message.user_id,
                internal_message.channel.value
            )
        
        # Generate summary
        try:
            summary = llm_provider.generate_summary(
                [result.to_dict() for result in tool_results],
                correlation_id
            )
        except Exception as e:
            logger.warning(f"Failed to generate summary: {e}")
            if tool_results and tool_results[0].success:
                summary = f"Successfully executed {approval_request.tool_call.tool_name}"
            else:
                error_msg = tool_results[0].error if tool_results else "Unknown error"
                summary = f"Failed to execute {approval_request.tool_call.tool_name}: {error_msg}"
        
        # Add execution mode context
        mode_context = {
            ExecutionMode.SANDBOX_LIVE: f" ({internal_message.execution_mode.value})"
        }.get(internal_message.execution_mode, f" ({internal_message.execution_mode.value})")
        
        response_message = f"**Approval Granted & Executed**\n\n{summary}{mode_context}\n\nCorrelation ID: {correlation_id}"
        
        channel_response = channel_adapter.format_response(
            response_message,
            correlation_id,
            {
                "approval_token": approval_token,
                "tool_executed": approval_request.tool_call.tool_name,
                "execution_mode": internal_message.execution_mode.value,
                "success": tool_results[0].success if tool_results else False
            }
        )
        
        return create_success_response(channel_response.to_dict(), correlation_id)
        
    except Exception as e:
        logger.error(f"Approval response handling error: {e}")
        audit_logger.log_error(e, correlation_id, internal_message.user_id, {"step": "approval_response"})
        
        error_response = channel_adapter.format_error_response(
            "Failed to process approval response",
            "APPROVAL_ERROR",
            correlation_id
        )
        return create_success_response(error_response.to_dict(), correlation_id)


def plugin_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """
    Handle Amazon Q Business plugin requests
    Requirements: 8.1, 8.2, 9.1
    """
    correlation_id = None
    
    try:
        # Generate correlation ID for tracking
        correlation_id = generate_correlation_id()
        
        logger.info(f"Processing plugin request: {correlation_id}")
        
        # Authenticate and authorize the request
        auth_result = authenticate_and_authorize_request(event, correlation_id)
        
        if not auth_result.authenticated:
            logger.warning(f"Plugin authentication failed: {auth_result.error_message}")
            return create_error_response(401, f"Authentication failed: {auth_result.error_message}", correlation_id)
        
        # Parse plugin request
        try:
            if isinstance(event.get("body"), str):
                request_body = json.loads(event["body"])
            else:
                request_body = event.get("body", {})
            
            # Validate plugin request structure
            from src.models import validate_plugin_request
            plugin_request = validate_plugin_request(request_body)
            
        except ValueError as e:
            logger.warning(f"Invalid plugin request: {str(e)}")
            return create_error_response(400, f"Invalid request: {str(e)}", correlation_id)
        
        # Get execution mode
        execution_mode_str = os.environ.get("EXECUTION_MODE", "SANDBOX_LIVE")
        try:
            execution_mode = ExecutionMode(execution_mode_str)
        except ValueError:
            execution_mode = ExecutionMode.SANDBOX_LIVE
        
        # Get system components
        llm_provider, tool_execution_engine, approval_gate, audit_logger = get_or_create_components(execution_mode)
        
        # Log the plugin request
        audit_logger.log_plugin_request(plugin_request, auth_result.user_context)
        
        # Route to appropriate operation handler based on operation type
        operation = plugin_request.operation.lower()
        
        # Diagnostic operations (no approval required)
        diagnostic_operations = ["get_ec2_status", "get_cloudwatch_metrics", "describe_alb_target_health", "search_cloudtrail_events"]
        
        # Write operations (approval required)
        write_operations = ["reboot_ec2", "scale_ecs_service"]
        
        # Workflow operations (no approval, fully audited)
        workflow_operations = ["create_incident_record", "post_summary_to_channel"]
        
        if operation in diagnostic_operations:
            return handle_diagnostic_operation(plugin_request, execution_mode, tool_execution_engine, audit_logger, correlation_id)
        elif operation in write_operations:
            # Write operations cannot be called directly - must use propose_action → approve_action workflow
            return create_error_response(
                400,
                f"Write operation '{operation}' requires approval. Use 'propose_action' with action='{operation}' to initiate the approval workflow.",
                correlation_id
            )
        elif operation in workflow_operations:
            return handle_workflow_operation(plugin_request, execution_mode, tool_execution_engine, audit_logger, correlation_id)
        elif operation == "propose_action":
            return handle_propose_action(plugin_request, execution_mode, approval_gate, audit_logger, correlation_id)
        elif operation == "approve_action":
            return handle_approve_action(plugin_request, execution_mode, tool_execution_engine, approval_gate, audit_logger, correlation_id)
        else:
            logger.warning(f"Unknown plugin operation: {operation}")
            return create_error_response(400, f"Unknown operation: {operation}", correlation_id)
        
    except Exception as e:
        logger.error(f"Plugin handler error: {str(e)}")
        return create_error_response(500, "Internal server error", correlation_id)


def handle_diagnostic_operation(plugin_request, execution_mode, tool_execution_engine, audit_logger, correlation_id):
    """Handle diagnostic operations that require no approval"""
    try:
        # Create tool call from plugin request
        from src.models import ToolCall, PluginResponse
        tool_call = ToolCall(
            tool_name=plugin_request.operation,
            args=plugin_request.parameters,
            requires_approval=False,
            correlation_id=correlation_id,
            user_id=plugin_request.user_context.user_id
        )
        
        # Execute the tool
        execution_context = ExecutionContext(
            correlation_id=correlation_id,
            user_id=plugin_request.user_context.user_id,
            execution_mode=execution_mode,
            approval_tokens={}
        )
        
        tool_results = tool_execution_engine.execute_tools([tool_call], execution_context)
        
        # Log tool execution
        if tool_results:
            audit_logger.log_tool_call_executed(tool_call, tool_results[0], plugin_request.user_context.user_id, "plugin")
        
        # Format response
        if tool_results and tool_results[0].success:
            response = PluginResponse(
                success=True,
                correlation_id=correlation_id,
                operation=plugin_request.operation,
                summary=f"Successfully executed {plugin_request.operation}",
                details=tool_results[0].data,
                execution_mode=execution_mode
            )
        else:
            error_msg = tool_results[0].error if tool_results else "Unknown error"
            response = PluginResponse(
                success=False,
                correlation_id=correlation_id,
                operation=plugin_request.operation,
                error={"code": "EXECUTION_ERROR", "message": error_msg},
                execution_mode=execution_mode
            )
        
        return create_success_response(response.to_dict(), correlation_id)
        
    except Exception as e:
        logger.error(f"Diagnostic operation error: {str(e)}")
        audit_logger.log_error(e, correlation_id, plugin_request.user_context.user_id, {"step": "diagnostic_execution"})
        return create_error_response(500, f"Operation failed: {str(e)}", correlation_id)


def handle_propose_action(plugin_request, execution_mode, approval_gate, audit_logger, correlation_id):
    """Handle action proposal for write operations"""
    try:
        # Extract the actual action from parameters
        action = plugin_request.parameters.get("action")
        if not action:
            return create_error_response(400, "Missing 'action' parameter in propose_action request", correlation_id)
        
        # Validate that the action is a supported write operation
        supported_write_actions = ["reboot_ec2", "scale_ecs_service"]
        if action not in supported_write_actions:
            return create_error_response(400, f"Unsupported action: {action}. Supported actions: {', '.join(supported_write_actions)}", correlation_id)
        
        # Extract reason parameter (required for all write actions)
        reason = plugin_request.parameters.get("reason")
        if not reason or len(reason.strip()) < 10:
            return create_error_response(400, "Missing or insufficient 'reason' parameter (minimum 10 characters required)", correlation_id)
        
        # Create tool call for the proposed action
        from src.models import ToolCall
        tool_call = ToolCall(
            tool_name=action,
            args={k: v for k, v in plugin_request.parameters.items() if k not in ["action", "reason"]},
            requires_approval=True,
            correlation_id=correlation_id,
            user_id=plugin_request.user_context.user_id
        )

        # REQUIREMENT 7: Validate resource tags BEFORE approval token generation
        # This ensures users don't get approval tokens for resources they can't actually modify
        from src.tool_guardrails import ToolGuardrails, ResourceTagValidationError
        try:
            guardrails = ToolGuardrails(execution_mode=execution_mode)
            policy = guardrails.get_tool_policy(action)
            if policy and policy.requires_resource_tags:
                guardrails._validate_resource_tags(tool_call, policy)
                logger.info(f"Tag validation passed for proposed action: {action}")
        except ResourceTagValidationError as e:
            logger.warning(f"Tag validation failed for proposed action: {str(e)}")
            return create_error_response(
                403,
                f"Resource validation failed: {str(e)}. Only resources tagged with 'OpsAgentManaged=true' can be modified.",
                correlation_id
            )
        except Exception as e:
            logger.error(f"Tag validation error: {str(e)}")
            return create_error_response(500, f"Tag validation error: {str(e)}", correlation_id)

        # Determine risk level based on action type
        risk_level = "medium"  # Default
        if action == "reboot_ec2":
            risk_level = "high"  # Rebooting instances is high risk
        elif action == "scale_ecs_service":
            # Check if scaling up significantly
            desired_count = plugin_request.parameters.get("desired_count", 0)
            if desired_count > 10:
                risk_level = "high"
            else:
                risk_level = "medium"
        
        # Create approval request
        approval_request = approval_gate.create_approval_request(
            tool_call=tool_call,
            requested_by=plugin_request.user_context.user_id,
            risk_level=risk_level
        )
        
        # Log approval request
        audit_logger.log_approval_requested(approval_request, plugin_request.user_context.user_id, "plugin")
        
        # Generate detailed action plan for display
        action_plan = _generate_action_plan(action, plugin_request.parameters, reason)
        
        # Format response
        from src.models import PluginResponse
        response = PluginResponse(
            success=True,
            correlation_id=correlation_id,
            approval_required=True,
            approval_token=approval_request.token,
            expires_at=approval_request.expires_at,
            action_summary=f"Execute {action} with specified parameters",
            risk_level=approval_request.risk_level,
            instructions=f"To proceed, use approve_action with token '{approval_request.token}'",
            execution_mode=execution_mode
        )
        
        return create_success_response(response.to_dict(), correlation_id)
        
    except Exception as e:
        logger.error(f"Propose action error: {str(e)}")
        audit_logger.log_error(e, correlation_id, plugin_request.user_context.user_id, {"step": "propose_action"})
        return create_error_response(500, f"Failed to propose action: {str(e)}", correlation_id)


def _generate_action_plan(action: str, parameters: dict, reason: str) -> str:
    """Generate detailed action plan for approval display"""
    if action == "reboot_ec2":
        instance_id = parameters.get("instance_id", "unknown")
        return f"""**Action Plan: EC2 Instance Reboot**
        
**Target:** EC2 Instance {instance_id}
**Action:** Graceful reboot (stop and start)
**Reason:** {reason}
**Impact:** Instance will be temporarily unavailable during reboot
**Duration:** Typically 1-3 minutes
**Rollback:** None required (reboot is reversible)"""
    
    elif action == "scale_ecs_service":
        cluster = parameters.get("cluster", "unknown")
        service = parameters.get("service", "unknown") 
        desired_count = parameters.get("desired_count", 0)
        return f"""**Action Plan: ECS Service Scaling**
        
**Target:** ECS Service {service} in cluster {cluster}
**Action:** Scale to {desired_count} desired tasks
**Reason:** {reason}
**Impact:** Service capacity will change
**Duration:** 1-5 minutes depending on task startup time
**Rollback:** Can be scaled back to previous count if needed"""
    
    else:
        return f"""**Action Plan: {action}**
        
**Parameters:** {', '.join(f'{k}={v}' for k, v in parameters.items() if k not in ['action', 'reason'])}
**Reason:** {reason}
**Impact:** Will execute the specified operation
**Rollback:** Depends on operation type"""


def handle_approve_action(plugin_request, execution_mode, tool_execution_engine, approval_gate, audit_logger, correlation_id):
    """Handle action approval and execution"""
    try:
        from src.models import PluginResponse
        
        # Extract approval token
        approval_token = plugin_request.parameters.get("approval_token")
        if not approval_token:
            return create_error_response(400, "Missing 'approval_token' parameter in approve_action request", correlation_id)
        
        # Find and validate approval request
        pending_approvals = approval_gate.get_pending_approvals(plugin_request.user_context.user_id)
        approval_request = None
        
        for req in pending_approvals:
            if req.token == approval_token:
                approval_request = req
                break
        
        if not approval_request:
            return create_error_response(400, "Invalid or expired approval token", correlation_id)
        
        # Approve the request
        approval_decision = approval_gate.approve_request(
            approval_token,
            plugin_request.user_context.user_id,
            True  # approved
        )
        
        # Log approval decision
        audit_logger.log_approval_decision(approval_request, "granted", plugin_request.user_context.user_id, "plugin")
        
        # Execute the approved action
        if not approval_request.tool_call:
            return create_error_response(500, "Approval request missing tool call", correlation_id)
        
        from src.tool_execution_engine import ExecutionContext
        execution_context = ExecutionContext(
            correlation_id=correlation_id,
            user_id=plugin_request.user_context.user_id,
            execution_mode=execution_mode,
            approval_tokens={approval_token: approval_request}
        )
        
        tool_results = tool_execution_engine.execute_tools([approval_request.tool_call], execution_context)
        
        # Consume the approval token
        approval_gate.consume_approval_token(approval_token)
        
        # Log tool execution
        if tool_results:
            audit_logger.log_tool_call_executed(approval_request.tool_call, tool_results[0], plugin_request.user_context.user_id, "plugin")
        
        # Format response
        if tool_results and tool_results[0].success:
            response = PluginResponse(
                success=True,
                correlation_id=correlation_id,
                action_executed=approval_request.tool_call.tool_name,
                target_resource=str(approval_request.tool_call.args.get("instance_id") or approval_request.tool_call.args.get("service")),
                execution_status="completed",
                execution_time=datetime.utcnow(),
                summary=f"Successfully executed {approval_request.tool_call.tool_name}",
                details=tool_results[0].data,
                execution_mode=execution_mode
            )
        else:
            error_msg = tool_results[0].error if tool_results else "Unknown error"
            response = PluginResponse(
                success=False,
                correlation_id=correlation_id,
                action_executed=approval_request.tool_call.tool_name,
                execution_status="failed",
                execution_time=datetime.utcnow(),
                error={"code": "EXECUTION_ERROR", "message": error_msg},
                execution_mode=execution_mode
            )
        
        return create_success_response(response.to_dict(), correlation_id)
        
    except Exception as e:
        logger.error(f"Approve action error: {str(e)}")
        audit_logger.log_error(e, correlation_id, plugin_request.user_context.user_id, {"step": "approve_action"})
        return create_error_response(500, f"Failed to approve action: {str(e)}", correlation_id)


def handle_workflow_operation(plugin_request, execution_mode, tool_execution_engine, audit_logger, correlation_id):
    """Handle workflow operations (incident records, notifications)"""
    try:
        # Create tool call from plugin request
        from src.models import ToolCall, PluginResponse
        tool_call = ToolCall(
            tool_name=plugin_request.operation,
            args=plugin_request.parameters,
            requires_approval=False,
            correlation_id=correlation_id,
            user_id=plugin_request.user_context.user_id
        )
        
        # Execute the tool
        execution_context = ExecutionContext(
            correlation_id=correlation_id,
            user_id=plugin_request.user_context.user_id,
            execution_mode=execution_mode,
            approval_tokens={}
        )
        
        tool_results = tool_execution_engine.execute_tools([tool_call], execution_context)
        
        # Log tool execution
        if tool_results:
            audit_logger.log_tool_call_executed(tool_call, tool_results[0], plugin_request.user_context.user_id, "plugin")
        
        # Format response based on operation type
        if tool_results and tool_results[0].success:
            
            if plugin_request.operation == "create_incident_record":
                response = PluginResponse(
                    success=True,
                    correlation_id=correlation_id,
                    operation=plugin_request.operation,
                    incident_id=tool_results[0].data.get("incident_id"),
                    created_at=datetime.utcnow(),
                    notification_sent=tool_results[0].data.get("notification_sent", False),
                    summary=f"Successfully created incident record",
                    details=tool_results[0].data,
                    execution_mode=execution_mode
                )
            elif plugin_request.operation == "post_summary_to_channel":
                response = PluginResponse(
                    success=True,
                    correlation_id=correlation_id,
                    operation=plugin_request.operation,
                    message_id=tool_results[0].data.get("message_id"),
                    posted_at=datetime.utcnow(),
                    summary=f"Successfully posted summary to channel",
                    details=tool_results[0].data,
                    execution_mode=execution_mode
                )
            else:
                response = PluginResponse(
                    success=True,
                    correlation_id=correlation_id,
                    operation=plugin_request.operation,
                    summary=f"Successfully executed {plugin_request.operation}",
                    details=tool_results[0].data,
                    execution_mode=execution_mode
                )
        else:
            error_msg = tool_results[0].error if tool_results else "Unknown error"
            response = PluginResponse(
                success=False,
                correlation_id=correlation_id,
                operation=plugin_request.operation,
                error={"code": "EXECUTION_ERROR", "message": error_msg},
                execution_mode=execution_mode
            )
        
        return create_success_response(response.to_dict(), correlation_id)
        
    except Exception as e:
        logger.error(f"Workflow operation error: {str(e)}")
        audit_logger.log_error(e, correlation_id, plugin_request.user_context.user_id, {"step": "workflow_execution"})
        return create_error_response(500, f"Operation failed: {str(e)}", correlation_id)


def auth_callback_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """
    Handle authentication callback requests (placeholder for future OAuth flows)
    Requirements: 8.1, 8.2
    """
    try:
        # For Amazon Q Business integration, authentication is handled natively
        # This endpoint is reserved for future OAuth callback implementations
        
        return create_success_response({
            "message": "Authentication is handled natively by Amazon Q Business",
            "status": "not_implemented",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        
    except Exception as e:
        logger.error(f"Auth callback handler error: {str(e)}")
        return create_error_response(500, "Internal server error")


def options_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """
    Handle CORS preflight requests
    Requirements: 10.3
    """
    return {
        "statusCode": 200,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "Access-Control-Max-Age": "86400"
        },
        "body": ""
    }


def health_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """
    Health endpoint handler using integrated system components
    Returns execution mode and system status
    Requirements: 11.7
    """
    try:
        # Get current execution mode
        execution_mode_str = get_execution_mode()
        execution_mode = ExecutionMode(execution_mode_str)
        
        # Get system status
        system_status = get_system_status()
        
        # Initialize components to check their status
        try:
            llm_provider, tool_execution_engine, approval_gate, audit_logger = get_or_create_components(execution_mode)
            
            # Add component status to system status
            system_status["components"] = {
                "llm_provider": {
                    "initialized": llm_provider is not None,
                    "type": type(llm_provider).__name__
                },
                "tool_execution_engine": {
                    "initialized": tool_execution_engine is not None,
                    "status": tool_execution_engine.get_execution_status() if tool_execution_engine else None
                },
                "approval_gate": {
                    "initialized": approval_gate is not None,
                    "storage_backend": approval_gate.storage_backend if approval_gate else None
                },
                "audit_logger": {
                    "initialized": audit_logger is not None,
                    "cloudwatch_log_group": audit_logger.cloudwatch_log_group if audit_logger else None
                }
            }
            
            # Log the health check
            correlation_id = f"health-{int(datetime.utcnow().timestamp())}"
            audit_logger.log_system_status_check(correlation_id, system_status, "system")
            
        except Exception as e:
            logger.warning(f"Failed to initialize components for health check: {e}")
            system_status["component_initialization_error"] = str(e)
        
        # Use Web channel adapter for consistent formatting
        channel_adapter = WebChannelAdapter()
        channel_response = channel_adapter.format_system_status(system_status)
        
        response_data = {
            "status": "healthy",
            "system": system_status,
            "formatted": channel_response.to_dict()
        }
        
        logger.info(f"Health check successful: {system_status}")
        return create_success_response(response_data)
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return create_error_response(500, "Health check failed")


def request_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """
    Main Lambda handler for API Gateway requests
    Requirements: 10.1, 10.2, 10.5
    """
    try:
        # Extract HTTP method and path
        http_method = event.get("httpMethod", "GET")
        path = event.get("path", "/")
        if path in {"", "/"}:
            path = "/health"
        
        logger.info(f"Received {http_method} request to {path}")
        
        # Handle CORS preflight requests
        if http_method == "OPTIONS":
            return options_handler(event, context)
        
        # Reset rate limiting per test case when running under pytest
        global _last_pytest_test
        pytest_test = os.environ.get("PYTEST_CURRENT_TEST")
        if pytest_test and pytest_test != _last_pytest_test:
            _rate_limit_store.clear()
            _last_pytest_test = pytest_test

        # Extract client ID for rate limiting
        client_id = extract_client_id(event)
        
        # Check rate limiting (skip for health checks and unknown clients)
        if path != "/health" and client_id != "ip:unknown":
            if not check_rate_limit(client_id):
                logger.warning(f"Rate limit exceeded for client: {client_id}")
                return create_error_response(429, "Too Many Requests - Rate limit exceeded")
        
        # Validate request authentication (except for health endpoint and Teams requests)
        # In LOCAL_MOCK mode, bypass authentication for testing purposes
        execution_mode = os.environ.get("EXECUTION_MODE", "SANDBOX_LIVE")

        if path != "/health" and path != "/auth/callback" and execution_mode != "LOCAL_MOCK":
            # For Teams requests, skip authentication for now (we'll validate in chat_handler)
            body_raw = event.get("body", "")
            try:
                if isinstance(body_raw, str):
                    body = json.loads(body_raw) if body_raw else {}
                else:
                    body = body_raw or {}

                # Check if this looks like a Teams Bot Framework request
                # Bot Framework requests have type="message", from, and conversation fields
                is_teams_request = (
                    isinstance(body, dict) and
                    body.get("type") == "message" and
                    "from" in body and
                    "conversation" in body
                )

                # Allow Bot Framework requests through without our custom authentication
                # Bot Framework has its own JWT-based auth that we validate separately
                if not is_teams_request:
                    if not validate_request_signature(event):
                        logger.warning(f"Authentication failed for {http_method} {path}")
                        return create_error_response(401, "Unauthorized - Invalid authentication")
            except (json.JSONDecodeError, TypeError) as e:
                logger.error(f"JSON parsing error: {e}")
                # If we can't parse the body, fall back to normal authentication
                if not validate_request_signature(event):
                    logger.warning(f"Authentication failed for {http_method} {path}")
                    return create_error_response(401, "Unauthorized - Invalid authentication")
        
        # Route to appropriate handler
        if path == "/health" and http_method == "GET":
            return health_handler(event, context)
        elif path == "/chat" and http_method == "POST":
            return chat_handler(event, context)
        elif path == "/plugin" and http_method == "POST":
            return plugin_handler(event, context)
        elif path == "/auth/callback" and http_method == "GET":
            return auth_callback_handler(event, context)
        else:
            # Unknown route
            logger.warning(f"Unknown route: {http_method} {path}")
            return create_error_response(404, f"Not Found - Path {path} not found")
        
    except Exception as e:
        logger.error(f"Lambda handler error: {str(e)}")
        return create_error_response(500, "Internal Server Error")


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """
    Main Lambda entry point - routes to appropriate handler
    """
    return request_handler(event, context)
