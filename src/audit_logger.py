"""
Audit Logger for OpsAgent Controller
Provides comprehensive audit logging with CloudWatch and DynamoDB support
Requirements: 6.1, 6.2, 6.3, 6.5
"""
import json
import logging
import re
from datetime import datetime
from typing import Dict, Any, Optional, List, Union
from enum import Enum
from dataclasses import dataclass, asdict

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from .models import InternalMessage, ToolCall, ToolResult, ApprovalRequest, ExecutionMode


logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events"""
    REQUEST_RECEIVED = "request_received"
    TOOL_CALL_REQUESTED = "tool_call_requested"
    TOOL_CALL_EXECUTED = "tool_call_executed"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_EXPIRED = "approval_expired"
    ERROR_OCCURRED = "error_occurred"
    SYSTEM_STATUS_CHECK = "system_status_check"


@dataclass
class AuditEvent:
    """
    Represents an audit event to be logged
    Requirements: 6.1, 6.2
    """
    event_type: AuditEventType
    correlation_id: str
    user_id: str
    timestamp: datetime
    event_data: Dict[str, Any]
    execution_mode: ExecutionMode
    channel: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "event_type": self.event_type.value,
            "correlation_id": self.correlation_id,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat() + "Z",
            "event_data": self.event_data,
            "execution_mode": self.execution_mode.value,
            "channel": self.channel
        }


class AuditLogger:
    """
    Comprehensive audit logger with CloudWatch and DynamoDB support
    Requirements: 6.1, 6.2, 6.3, 6.5
    """
    
    def __init__(self, 
                 cloudwatch_log_group: str = "/aws/lambda/opsagent-controller",
                 dynamodb_table_name: Optional[str] = None,
                 execution_mode: ExecutionMode = ExecutionMode.LOCAL_MOCK):
        """
        Initialize audit logger
        
        Args:
            cloudwatch_log_group: CloudWatch log group name
            dynamodb_table_name: Optional DynamoDB table name for audit storage
            execution_mode: Current execution mode
        """
        self.cloudwatch_log_group = cloudwatch_log_group
        self.dynamodb_table_name = dynamodb_table_name
        self.execution_mode = execution_mode
        
        # Initialize AWS clients
        self.cloudwatch_logs_client = None
        self.dynamodb_client = None
        
        if execution_mode != ExecutionMode.LOCAL_MOCK:
            self._initialize_clients()
    
    def _initialize_clients(self) -> None:
        """Initialize AWS clients for CloudWatch and DynamoDB"""
        try:
            self.cloudwatch_logs_client = boto3.client('logs')
            logger.info("CloudWatch Logs client initialized successfully")
            
            if self.dynamodb_table_name:
                self.dynamodb_client = boto3.client('dynamodb')
                logger.info("DynamoDB client initialized successfully")
                
        except Exception as e:
            logger.error(f"Failed to initialize audit logger AWS clients: {e}")
            # Continue without clients - will use local logging only
    
    def log_request_received(self, message: InternalMessage) -> None:
        """
        Log incoming request
        Requirements: 6.1
        """
        event_data = {
            "message_text_length": len(message.message_text),
            "channel": message.channel.value,
            "channel_conversation_id": self._sanitize_sensitive_data(message.channel_conversation_id)
        }
        
        event = AuditEvent(
            event_type=AuditEventType.REQUEST_RECEIVED,
            correlation_id=message.correlation_id,
            user_id=message.user_id,
            timestamp=message.timestamp,
            event_data=event_data,
            execution_mode=message.execution_mode,
            channel=message.channel.value
        )
        
        self._write_audit_event(event)
    
    def log_tool_call_requested(self, tool_call: ToolCall, user_id: str, channel: Optional[str] = None) -> None:
        """
        Log tool call request
        Requirements: 6.2
        """
        event_data = {
            "tool_name": tool_call.tool_name,
            "args": self._sanitize_tool_args(tool_call.args),
            "requires_approval": tool_call.requires_approval
        }
        
        event = AuditEvent(
            event_type=AuditEventType.TOOL_CALL_REQUESTED,
            correlation_id=tool_call.correlation_id,
            user_id=user_id,
            timestamp=datetime.utcnow(),
            event_data=event_data,
            execution_mode=self.execution_mode,
            channel=channel
        )
        
        self._write_audit_event(event)
    
    def log_tool_call_executed(self, tool_call: ToolCall, result: ToolResult, user_id: str, channel: Optional[str] = None) -> None:
        """
        Log tool call execution result
        Requirements: 6.2
        """
        event_data = {
            "tool_name": tool_call.tool_name,
            "args": self._sanitize_tool_args(tool_call.args),
            "success": result.success,
            "execution_mode": result.execution_mode.value,
            "error": self._sanitize_sensitive_data(result.error) if result.error else None,
            "data_keys": list(result.data.keys()) if result.data else None
        }
        
        event = AuditEvent(
            event_type=AuditEventType.TOOL_CALL_EXECUTED,
            correlation_id=tool_call.correlation_id,
            user_id=user_id,
            timestamp=result.timestamp,
            event_data=event_data,
            execution_mode=result.execution_mode,
            channel=channel
        )
        
        self._write_audit_event(event)
    
    def log_approval_requested(self, approval_request: ApprovalRequest, user_id: str, channel: Optional[str] = None) -> None:
        """
        Log approval request
        Requirements: 6.3
        """
        event_data = {
            "approval_token": self._sanitize_token(approval_request.token),
            "expires_at": approval_request.expires_at.isoformat() + "Z",
            "requested_by": approval_request.requested_by,
            "risk_level": approval_request.risk_level,
            "tool_name": approval_request.tool_call.tool_name if approval_request.tool_call else None,
            "tool_args": self._sanitize_tool_args(approval_request.tool_call.args) if approval_request.tool_call else None
        }
        
        event = AuditEvent(
            event_type=AuditEventType.APPROVAL_REQUESTED,
            correlation_id=approval_request.correlation_id,
            user_id=user_id,
            timestamp=datetime.utcnow(),
            event_data=event_data,
            execution_mode=self.execution_mode,
            channel=channel
        )
        
        self._write_audit_event(event)
    
    def log_approval_decision(self, approval_request: ApprovalRequest, decision: str, user_id: str, channel: Optional[str] = None) -> None:
        """
        Log approval decision (granted/denied/expired)
        Requirements: 6.3
        """
        if decision.lower() == "granted":
            event_type = AuditEventType.APPROVAL_GRANTED
        elif decision.lower() == "denied":
            event_type = AuditEventType.APPROVAL_DENIED
        elif decision.lower() == "expired":
            event_type = AuditEventType.APPROVAL_EXPIRED
        else:
            logger.warning(f"Unknown approval decision: {decision}")
            event_type = AuditEventType.APPROVAL_DENIED
        
        event_data = {
            "approval_token": self._sanitize_token(approval_request.token),
            "decision": decision.lower(),
            "requested_by": approval_request.requested_by,
            "tool_name": approval_request.tool_call.tool_name if approval_request.tool_call else None
        }
        
        event = AuditEvent(
            event_type=event_type,
            correlation_id=approval_request.correlation_id,
            user_id=user_id,
            timestamp=datetime.utcnow(),
            event_data=event_data,
            execution_mode=self.execution_mode,
            channel=channel
        )
        
        self._write_audit_event(event)
    
    def log_error(self, error: Exception, correlation_id: str, user_id: str, context: Dict[str, Any], channel: Optional[str] = None) -> None:
        """
        Log error occurrence
        Requirements: 6.1, 6.2
        """
        event_data = {
            "error_type": type(error).__name__,
            "error_message": self._sanitize_sensitive_data(str(error)),
            "context": self._sanitize_context_data(context)
        }
        
        event = AuditEvent(
            event_type=AuditEventType.ERROR_OCCURRED,
            correlation_id=correlation_id,
            user_id=user_id,
            timestamp=datetime.utcnow(),
            event_data=event_data,
            execution_mode=self.execution_mode,
            channel=channel
        )
        
        self._write_audit_event(event)
    
    def log_system_status_check(self, correlation_id: str, status_data: Dict[str, Any], user_id: str = "system") -> None:
        """
        Log system status check
        Requirements: 6.1
        """
        event_data = {
            "status": self._sanitize_context_data(status_data)
        }
        
        event = AuditEvent(
            event_type=AuditEventType.SYSTEM_STATUS_CHECK,
            correlation_id=correlation_id,
            user_id=user_id,
            timestamp=datetime.utcnow(),
            event_data=event_data,
            execution_mode=self.execution_mode
        )
        
        self._write_audit_event(event)
    
    def _write_audit_event(self, event: AuditEvent) -> None:
        """
        Write audit event to configured storage backends
        Requirements: 6.4, 6.5
        """
        # Always log to standard logger first
        logger.info(f"AUDIT: {json.dumps(event.to_dict())}")
        
        # Write to CloudWatch Logs if available
        if self.cloudwatch_logs_client:
            try:
                self._write_to_cloudwatch(event)
            except Exception as e:
                logger.error(f"Failed to write audit event to CloudWatch: {e}")
                # Continue - don't fail the operation due to audit logging failure
        
        # Write to DynamoDB if configured and available
        if self.dynamodb_client and self.dynamodb_table_name:
            try:
                self._write_to_dynamodb(event)
            except Exception as e:
                logger.error(f"Failed to write audit event to DynamoDB: {e}")
                # Continue - don't fail the operation due to audit logging failure
    
    def _write_to_cloudwatch(self, event: AuditEvent) -> None:
        """Write audit event to CloudWatch Logs"""
        log_event = {
            'timestamp': int(event.timestamp.timestamp() * 1000),
            'message': json.dumps(event.to_dict())
        }
        
        try:
            # Create log stream if it doesn't exist
            stream_name = f"audit-{datetime.utcnow().strftime('%Y-%m-%d')}"
            
            try:
                self.cloudwatch_logs_client.create_log_stream(
                    logGroupName=self.cloudwatch_log_group,
                    logStreamName=stream_name
                )
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                    raise
            
            # Put log event
            self.cloudwatch_logs_client.put_log_events(
                logGroupName=self.cloudwatch_log_group,
                logStreamName=stream_name,
                logEvents=[log_event]
            )
            
        except Exception as e:
            logger.error(f"CloudWatch Logs write failed: {e}")
            raise
    
    def _write_to_dynamodb(self, event: AuditEvent) -> None:
        """Write audit event to DynamoDB"""
        item = {
            'correlation_id': {'S': event.correlation_id},
            'timestamp': {'S': event.timestamp.isoformat() + 'Z'},
            'event_type': {'S': event.event_type.value},
            'user_id': {'S': event.user_id},
            'execution_mode': {'S': event.execution_mode.value},
            'event_data': {'S': json.dumps(event.event_data)},
            'ttl': {'N': str(int((event.timestamp.timestamp() + 2592000)))}  # 30 days TTL
        }
        
        if event.channel:
            item['channel'] = {'S': event.channel}
        
        try:
            self.dynamodb_client.put_item(
                TableName=self.dynamodb_table_name,
                Item=item
            )
        except Exception as e:
            logger.error(f"DynamoDB write failed: {e}")
            raise
    
    def _sanitize_sensitive_data(self, data: Any) -> Any:
        """
        Sanitize sensitive data from logs
        Requirements: 8.4, 11.15
        """
        if data is None:
            return None
        
        if isinstance(data, str):
            # Remove potential secrets, tokens, passwords, keys
            sensitive_patterns = [
                r'(?i)(password|passwd|pwd|secret|key|token|auth|credential)["\s]*[:=]["\s]*[^\s"]+',
                r'(?i)(bearer|basic)\s+[a-zA-Z0-9+/=]+',
                r'(?i)aws[_-]?access[_-]?key[_-]?id["\s]*[:=]["\s]*[A-Z0-9]{20}',
                r'(?i)aws[_-]?secret[_-]?access[_-]?key["\s]*[:=]["\s]*[A-Za-z0-9+/]{40}',
                r'(?i)(api[_-]?key|apikey)["\s]*[:=]["\s]*[^\s"]+',
                r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64 encoded strings (potential tokens)
            ]
            
            sanitized = data
            for pattern in sensitive_patterns:
                sanitized = re.sub(pattern, '[REDACTED]', sanitized)
            
            return sanitized
        
        elif isinstance(data, dict):
            sanitized = {}
            for k, v in data.items():
                # Check if key name suggests sensitive data - be more specific
                sensitive_keys = ['password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 'auth_token', 'token', 'credential', 'credentials']
                if any(k.lower() == sensitive or k.lower().endswith('_' + sensitive) or k.lower().startswith(sensitive + '_') for sensitive in sensitive_keys):
                    sanitized[k] = '[REDACTED]'
                else:
                    sanitized[k] = self._sanitize_sensitive_data(v)
            return sanitized
        
        elif isinstance(data, list):
            return [self._sanitize_sensitive_data(item) for item in data]
        
        else:
            return data
    
    def _sanitize_token(self, token: str) -> str:
        """
        Sanitize approval tokens for logging
        Requirements: 8.4
        """
        if not token or len(token) < 8:
            return "[REDACTED]"
        
        # Show first 4 and last 4 characters, redact middle
        return f"{token[:4]}...{token[-4:]}"
    
    def _sanitize_tool_args(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize tool arguments for logging
        Requirements: 8.4
        """
        if not args:
            return {}
        
        sanitized = {}
        for key, value in args.items():
            # Sanitize known sensitive parameter names
            if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'key', 'token', 'auth']):
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = self._sanitize_sensitive_data(value)
        
        return sanitized
    
    def _sanitize_context_data(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize context data for logging
        Requirements: 8.4
        """
        if not context:
            return {}
        
        return {k: self._sanitize_sensitive_data(v) for k, v in context.items()}
    
    def get_audit_events(self, correlation_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve audit events for a correlation ID (for testing/debugging)
        Requirements: 6.4
        """
        events = []
        
        # Try DynamoDB first if available
        if self.dynamodb_client and self.dynamodb_table_name:
            try:
                response = self.dynamodb_client.query(
                    TableName=self.dynamodb_table_name,
                    KeyConditionExpression='correlation_id = :cid',
                    ExpressionAttributeValues={
                        ':cid': {'S': correlation_id}
                    },
                    Limit=limit,
                    ScanIndexForward=False  # Most recent first
                )
                
                for item in response.get('Items', []):
                    event_data = {
                        'correlation_id': item['correlation_id']['S'],
                        'timestamp': item['timestamp']['S'],
                        'event_type': item['event_type']['S'],
                        'user_id': item['user_id']['S'],
                        'execution_mode': item['execution_mode']['S'],
                        'event_data': json.loads(item['event_data']['S']),
                        'channel': item.get('channel', {}).get('S')
                    }
                    events.append(event_data)
                    
            except Exception as e:
                logger.error(f"Failed to retrieve audit events from DynamoDB: {e}")
        
        return events
    
    def set_execution_mode(self, execution_mode: ExecutionMode) -> None:
        """
        Update execution mode and reinitialize clients if needed
        Requirements: 7.2
        """
        logger.info(f"Changing audit logger execution mode from {self.execution_mode.value} to {execution_mode.value}")
        
        self.execution_mode = execution_mode
        
        # Reinitialize clients if switching to/from LOCAL_MOCK
        if execution_mode != ExecutionMode.LOCAL_MOCK and (not self.cloudwatch_logs_client):
            self._initialize_clients()
        elif execution_mode == ExecutionMode.LOCAL_MOCK:
            # Clear clients in LOCAL_MOCK mode
            self.cloudwatch_logs_client = None
            self.dynamodb_client = None
