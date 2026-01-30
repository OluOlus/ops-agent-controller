"""
Workflow tools for incident management and channel notifications
Requirements: 6.1, 6.2, 6.3
"""
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

from src.models import ToolCall, ToolResult, ExecutionMode

logger = logging.getLogger(__name__)


class WorkflowToolError(Exception):
    """Base exception for workflow tool errors"""
    pass


class IncidentRecordTool:
    """
    Incident record creation tool for workflow management
    Requirements: 6.1, 6.2, 6.3
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.LOCAL_MOCK):
        self.execution_mode = execution_mode
        self.dynamodb = None
        self.sns_client = None
        
        if execution_mode != ExecutionMode.LOCAL_MOCK:
            try:
                self.dynamodb = boto3.resource('dynamodb')
                self.sns_client = boto3.client('sns')
            except Exception as e:
                logger.warning(f"Failed to initialize AWS clients for incident tool: {e}")
    
    def execute(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute incident record creation
        
        Args:
            tool_call: Tool call with incident parameters
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with incident creation status
        """
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_incident_response(tool_call, correlation_id)
        
        try:
            summary = tool_call.args.get("summary")
            severity = tool_call.args.get("severity", "medium")
            links = tool_call.args.get("links", [])
            
            if not summary:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="summary is required for incident creation",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            # Validate severity
            valid_severities = ["low", "medium", "high", "critical"]
            if severity not in valid_severities:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=f"severity must be one of: {', '.join(valid_severities)}",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            # Generate incident ID
            incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
            created_at = datetime.utcnow()
            
            # Create incident record
            incident_record = {
                'incident_id': incident_id,
                'summary': summary,
                'severity': severity,
                'links': links if isinstance(links, list) else [],
                'created_by': tool_call.user_id,
                'created_at': created_at.isoformat() + 'Z',
                'status': 'open',
                'correlation_id': correlation_id,
                'ttl': int((created_at.timestamp() + (90 * 24 * 3600)))  # 90 days TTL
            }
            
            # Store in DynamoDB
            if self.dynamodb:
                table_name = 'OpsAgent-Incidents'  # This should be configurable
                try:
                    table = self.dynamodb.Table(table_name)
                    table.put_item(Item=incident_record)
                    logger.info(f"Incident {incident_id} stored in DynamoDB")
                except Exception as e:
                    logger.warning(f"Failed to store incident in DynamoDB: {e}")
                    # Continue without failing - we'll still send notification
            
            # Send notification
            notification_sent = False
            if self.sns_client:
                try:
                    topic_arn = 'arn:aws:sns:us-east-1:123456789012:OpsAgent-Incidents'  # Should be configurable
                    message = {
                        'incident_id': incident_id,
                        'summary': summary,
                        'severity': severity,
                        'created_by': tool_call.user_id,
                        'created_at': created_at.isoformat() + 'Z',
                        'links': links
                    }
                    
                    self.sns_client.publish(
                        TopicArn=topic_arn,
                        Message=json.dumps(message),
                        Subject=f"New Incident: {incident_id} ({severity.upper()})"
                    )
                    notification_sent = True
                    logger.info(f"Incident notification sent for {incident_id}")
                except Exception as e:
                    logger.warning(f"Failed to send incident notification: {e}")
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={
                    'incident_id': incident_id,
                    'summary': summary,
                    'severity': severity,
                    'links': links,
                    'created_by': tool_call.user_id,
                    'created_at': created_at.isoformat() + 'Z',
                    'status': 'open',
                    'notification_sent': notification_sent,
                    'message': f"Incident {incident_id} created successfully"
                },
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except Exception as e:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Unexpected error creating incident: {str(e)}",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
    
    def _mock_incident_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """Generate mock response for incident creation"""
        summary = tool_call.args.get("summary", "Mock incident summary")
        severity = tool_call.args.get("severity", "medium")
        links = tool_call.args.get("links", [])
        
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-MOCK{str(uuid.uuid4())[:4].upper()}"
        created_at = datetime.utcnow()
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'incident_id': incident_id,
                'summary': summary,
                'severity': severity,
                'links': links,
                'created_by': tool_call.user_id or 'mock-user@company.com',
                'created_at': created_at.isoformat() + 'Z',
                'status': 'open',
                'notification_sent': True,
                'message': f"MOCK: Incident {incident_id} created successfully",
                'mock': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )


class ChannelNotificationTool:
    """
    Channel posting tool for operational summaries and notifications
    Requirements: 6.1, 6.2, 6.3
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.LOCAL_MOCK):
        self.execution_mode = execution_mode
        self.sns_client = None
        
        if execution_mode != ExecutionMode.LOCAL_MOCK:
            try:
                self.sns_client = boto3.client('sns')
            except Exception as e:
                logger.warning(f"Failed to initialize SNS client for channel tool: {e}")
    
    def execute(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute channel notification posting
        
        Args:
            tool_call: Tool call with message parameters
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with posting status
        """
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_channel_response(tool_call, correlation_id)
        
        try:
            text = tool_call.args.get("text")
            channel_id = tool_call.args.get("channel_id")
            webhook_url = tool_call.args.get("webhook_url")
            
            if not text:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="text is required for channel posting",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            if not channel_id and not webhook_url:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="Either channel_id or webhook_url is required",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            # Generate message ID
            message_id = f"MSG-{str(uuid.uuid4())[:8].upper()}"
            posted_at = datetime.utcnow()
            
            # Send via SNS (which can route to Teams webhook, Slack, etc.)
            delivery_status = False
            if self.sns_client:
                try:
                    topic_arn = 'arn:aws:sns:us-east-1:123456789012:OpsAgent-Notifications'  # Should be configurable
                    message = {
                        'message_id': message_id,
                        'text': text,
                        'channel_id': channel_id,
                        'webhook_url': webhook_url,
                        'posted_by': tool_call.user_id,
                        'posted_at': posted_at.isoformat() + 'Z',
                        'correlation_id': correlation_id
                    }
                    
                    self.sns_client.publish(
                        TopicArn=topic_arn,
                        Message=json.dumps(message),
                        Subject=f"OpsAgent Channel Notification: {message_id}"
                    )
                    delivery_status = True
                    logger.info(f"Channel notification sent: {message_id}")
                except Exception as e:
                    logger.warning(f"Failed to send channel notification: {e}")
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={
                    'message_id': message_id,
                    'text': text,
                    'channel_id': channel_id,
                    'webhook_url': webhook_url,
                    'posted_by': tool_call.user_id,
                    'posted_at': posted_at.isoformat() + 'Z',
                    'delivery_status': 'sent' if delivery_status else 'failed',
                    'message': f"Channel notification {message_id} {'sent successfully' if delivery_status else 'failed to send'}"
                },
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except Exception as e:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Unexpected error posting to channel: {str(e)}",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
    
    def _mock_channel_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """Generate mock response for channel posting"""
        text = tool_call.args.get("text", "Mock notification message")
        channel_id = tool_call.args.get("channel_id")
        webhook_url = tool_call.args.get("webhook_url")
        
        message_id = f"MSG-MOCK{str(uuid.uuid4())[:4].upper()}"
        posted_at = datetime.utcnow()
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'message_id': message_id,
                'text': text,
                'channel_id': channel_id,
                'webhook_url': webhook_url,
                'posted_by': tool_call.user_id or 'mock-user@company.com',
                'posted_at': posted_at.isoformat() + 'Z',
                'delivery_status': 'sent',
                'message': f"MOCK: Channel notification {message_id} sent successfully",
                'mock': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )