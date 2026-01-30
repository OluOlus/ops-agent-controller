"""
Unit tests for audit logger
Requirements: 6.1, 6.2, 6.3, 6.5
"""
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError

from src.audit_logger import AuditLogger, AuditEvent, AuditEventType
from src.models import (
    InternalMessage, ToolCall, ToolResult, ApprovalRequest,
    ExecutionMode, ChannelType
)


class TestAuditEvent:
    """Test AuditEvent model"""
    
    def test_audit_event_creation(self):
        """Test creating AuditEvent"""
        timestamp = datetime.utcnow()
        event = AuditEvent(
            event_type=AuditEventType.REQUEST_RECEIVED,
            correlation_id="test-123",
            user_id="user123",
            timestamp=timestamp,
            event_data={"test": "data"},
            execution_mode=ExecutionMode.DRY_RUN,
            channel="teams"
        )
        
        assert event.event_type == AuditEventType.REQUEST_RECEIVED
        assert event.correlation_id == "test-123"
        assert event.user_id == "user123"
        assert event.timestamp == timestamp
        assert event.event_data == {"test": "data"}
        assert event.execution_mode == ExecutionMode.DRY_RUN
        assert event.channel == "teams"
    
    def test_audit_event_to_dict(self):
        """Test converting AuditEvent to dictionary"""
        timestamp = datetime.utcnow()
        event = AuditEvent(
            event_type=AuditEventType.TOOL_CALL_EXECUTED,
            correlation_id="test-456",
            user_id="user456",
            timestamp=timestamp,
            event_data={"tool": "test_tool"},
            execution_mode=ExecutionMode.SANDBOX_LIVE
        )
        
        data = event.to_dict()
        
        assert data["event_type"] == "tool_call_executed"
        assert data["correlation_id"] == "test-456"
        assert data["user_id"] == "user456"
        assert data["timestamp"] == timestamp.isoformat() + "Z"
        assert data["event_data"] == {"tool": "test_tool"}
        assert data["execution_mode"] == "SANDBOX_LIVE"
        assert data["channel"] is None


class TestAuditLogger:
    """Test AuditLogger class"""
    
    def test_audit_logger_initialization_local_mock(self):
        """Test AuditLogger initialization in LOCAL_MOCK mode"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        assert logger.execution_mode == ExecutionMode.LOCAL_MOCK
        assert logger.cloudwatch_logs_client is None
        assert logger.dynamodb_client is None
        assert logger.cloudwatch_log_group == "/aws/lambda/opsagent-controller"
        assert logger.dynamodb_table_name is None
    
    @patch('boto3.client')
    def test_audit_logger_initialization_dry_run(self, mock_boto_client):
        """Test AuditLogger initialization in DRY_RUN mode"""
        mock_cloudwatch_client = Mock()
        mock_boto_client.return_value = mock_cloudwatch_client
        
        logger = AuditLogger(
            cloudwatch_log_group="/test/log/group",
            execution_mode=ExecutionMode.DRY_RUN
        )
        
        assert logger.execution_mode == ExecutionMode.DRY_RUN
        assert logger.cloudwatch_logs_client == mock_cloudwatch_client
        assert logger.dynamodb_client is None
        assert logger.cloudwatch_log_group == "/test/log/group"
        mock_boto_client.assert_called_once_with('logs')
    
    @patch('boto3.client')
    def test_audit_logger_initialization_with_dynamodb(self, mock_boto_client):
        """Test AuditLogger initialization with DynamoDB"""
        mock_clients = {
            'logs': Mock(),
            'dynamodb': Mock()
        }
        mock_boto_client.side_effect = lambda service: mock_clients[service]
        
        logger = AuditLogger(
            dynamodb_table_name="audit-table",
            execution_mode=ExecutionMode.SANDBOX_LIVE
        )
        
        assert logger.dynamodb_client == mock_clients['dynamodb']
        assert logger.dynamodb_table_name == "audit-table"
        assert mock_boto_client.call_count == 2
    
    @patch('boto3.client')
    def test_audit_logger_initialization_client_failure(self, mock_boto_client):
        """Test AuditLogger handles client initialization failure gracefully"""
        mock_boto_client.side_effect = Exception("AWS credentials not found")
        
        # Should not raise exception, just log error
        logger = AuditLogger(execution_mode=ExecutionMode.DRY_RUN)
        assert logger.cloudwatch_logs_client is None
        assert logger.dynamodb_client is None
    
    def test_log_request_received(self):
        """Test logging request received event"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        message = InternalMessage(
            correlation_id="test-123",
            user_id="user123",
            channel=ChannelType.TEAMS,
            channel_conversation_id="conv_456",
            message_text="Hello world",
            timestamp=datetime.utcnow()
        )
        
        with patch.object(logger, '_write_audit_event') as mock_write:
            logger.log_request_received(message)
            
            mock_write.assert_called_once()
            event = mock_write.call_args[0][0]
            
            assert event.event_type == AuditEventType.REQUEST_RECEIVED
            assert event.correlation_id == "test-123"
            assert event.user_id == "user123"
            assert event.channel == "teams"
            assert event.event_data["message_text_length"] == 11
            assert event.event_data["channel"] == "teams"
    
    def test_log_tool_call_requested(self):
        """Test logging tool call requested event"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="get_metrics",
            args={"instance_id": "i-123", "metric": "cpu"},
            requires_approval=False,
            correlation_id="test-456"
        )
        
        with patch.object(logger, '_write_audit_event') as mock_write:
            logger.log_tool_call_requested(tool_call, "user123", "teams")
            
            mock_write.assert_called_once()
            event = mock_write.call_args[0][0]
            
            assert event.event_type == AuditEventType.TOOL_CALL_REQUESTED
            assert event.correlation_id == "test-456"
            assert event.user_id == "user123"
            assert event.channel == "teams"
            assert event.event_data["tool_name"] == "get_metrics"
            assert event.event_data["requires_approval"] is False
    
    def test_log_tool_call_executed(self):
        """Test logging tool call executed event"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="get_metrics",
            args={"instance_id": "i-123"},
            correlation_id="test-789"
        )
        
        result = ToolResult(
            tool_name="get_metrics",
            success=True,
            data={"cpu_utilization": 75.5},
            execution_mode=ExecutionMode.DRY_RUN,
            timestamp=datetime.utcnow()
        )
        
        with patch.object(logger, '_write_audit_event') as mock_write:
            logger.log_tool_call_executed(tool_call, result, "user123")
            
            mock_write.assert_called_once()
            event = mock_write.call_args[0][0]
            
            assert event.event_type == AuditEventType.TOOL_CALL_EXECUTED
            assert event.correlation_id == "test-789"
            assert event.user_id == "user123"
            assert event.event_data["tool_name"] == "get_metrics"
            assert event.event_data["success"] is True
            assert event.event_data["data_keys"] == ["cpu_utilization"]
    
    def test_log_approval_requested(self):
        """Test logging approval requested event"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="ec2_reboot",
            args={"instance_id": "i-123"},
            requires_approval=True
        )
        
        approval_request = ApprovalRequest(
            token="approval-token-123",
            expires_at=datetime.utcnow() + timedelta(minutes=5),
            requested_by="user123",
            tool_call=tool_call,
            risk_level="medium",
            correlation_id="test-approval"
        )
        
        with patch.object(logger, '_write_audit_event') as mock_write:
            logger.log_approval_requested(approval_request, "user123", "web")
            
            mock_write.assert_called_once()
            event = mock_write.call_args[0][0]
            
            assert event.event_type == AuditEventType.APPROVAL_REQUESTED
            assert event.correlation_id == "test-approval"
            assert event.user_id == "user123"
            assert event.channel == "web"
            assert event.event_data["risk_level"] == "medium"
            assert event.event_data["tool_name"] == "ec2_reboot"
    
    def test_log_approval_decision_granted(self):
        """Test logging approval granted decision"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        approval_request = ApprovalRequest(
            token="approval-token-456",
            requested_by="user123",
            correlation_id="test-approval-decision"
        )
        
        with patch.object(logger, '_write_audit_event') as mock_write:
            logger.log_approval_decision(approval_request, "granted", "user123")
            
            mock_write.assert_called_once()
            event = mock_write.call_args[0][0]
            
            assert event.event_type == AuditEventType.APPROVAL_GRANTED
            assert event.correlation_id == "test-approval-decision"
            assert event.event_data["decision"] == "granted"
    
    def test_log_approval_decision_denied(self):
        """Test logging approval denied decision"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        approval_request = ApprovalRequest(
            token="approval-token-789",
            correlation_id="test-denial"
        )
        
        with patch.object(logger, '_write_audit_event') as mock_write:
            logger.log_approval_decision(approval_request, "denied", "user456")
            
            mock_write.assert_called_once()
            event = mock_write.call_args[0][0]
            
            assert event.event_type == AuditEventType.APPROVAL_DENIED
            assert event.event_data["decision"] == "denied"
    
    def test_log_approval_decision_expired(self):
        """Test logging approval expired decision"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        approval_request = ApprovalRequest(
            token="approval-token-expired",
            correlation_id="test-expired"
        )
        
        with patch.object(logger, '_write_audit_event') as mock_write:
            logger.log_approval_decision(approval_request, "expired", "system")
            
            mock_write.assert_called_once()
            event = mock_write.call_args[0][0]
            
            assert event.event_type == AuditEventType.APPROVAL_EXPIRED
            assert event.event_data["decision"] == "expired"
    
    def test_log_error(self):
        """Test logging error event"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        error = ValueError("Invalid parameter")
        context = {"tool_name": "test_tool", "args": {"param": "value"}}
        
        with patch.object(logger, '_write_audit_event') as mock_write:
            logger.log_error(error, "test-error", "user123", context, "slack")
            
            mock_write.assert_called_once()
            event = mock_write.call_args[0][0]
            
            assert event.event_type == AuditEventType.ERROR_OCCURRED
            assert event.correlation_id == "test-error"
            assert event.user_id == "user123"
            assert event.channel == "slack"
            assert event.event_data["error_type"] == "ValueError"
            assert "Invalid parameter" in event.event_data["error_message"]
    
    def test_log_system_status_check(self):
        """Test logging system status check event"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        status_data = {
            "execution_mode": "DRY_RUN",
            "llm_provider_status": "configured",
            "aws_tool_access_status": "available"
        }
        
        with patch.object(logger, '_write_audit_event') as mock_write:
            logger.log_system_status_check("test-status", status_data)
            
            mock_write.assert_called_once()
            event = mock_write.call_args[0][0]
            
            assert event.event_type == AuditEventType.SYSTEM_STATUS_CHECK
            assert event.correlation_id == "test-status"
            assert event.user_id == "system"
            assert event.event_data["status"]["execution_mode"] == "DRY_RUN"
    
    @patch('src.audit_logger.logger')
    def test_write_audit_event_local_mock(self, mock_logger):
        """Test writing audit event in LOCAL_MOCK mode"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        event = AuditEvent(
            event_type=AuditEventType.REQUEST_RECEIVED,
            correlation_id="test-123",
            user_id="user123",
            timestamp=datetime.utcnow(),
            event_data={"test": "data"},
            execution_mode=ExecutionMode.LOCAL_MOCK
        )
        
        logger._write_audit_event(event)
        
        # Should log to standard logger
        mock_logger.info.assert_called_once()
        log_call = mock_logger.info.call_args[0][0]
        assert "AUDIT:" in log_call
        assert "test-123" in log_call
    
    @patch('boto3.client')
    def test_write_to_cloudwatch_success(self, mock_boto_client):
        """Test successful CloudWatch Logs write"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        logger = AuditLogger(execution_mode=ExecutionMode.DRY_RUN)
        
        event = AuditEvent(
            event_type=AuditEventType.TOOL_CALL_EXECUTED,
            correlation_id="test-cloudwatch",
            user_id="user123",
            timestamp=datetime.utcnow(),
            event_data={"tool": "test"},
            execution_mode=ExecutionMode.DRY_RUN
        )
        
        logger._write_to_cloudwatch(event)
        
        # Should create log stream and put log event
        mock_client.create_log_stream.assert_called_once()
        mock_client.put_log_events.assert_called_once()
    
    @patch('boto3.client')
    def test_write_to_cloudwatch_stream_exists(self, mock_boto_client):
        """Test CloudWatch Logs write when stream already exists"""
        mock_client = Mock()
        mock_client.create_log_stream.side_effect = ClientError(
            {'Error': {'Code': 'ResourceAlreadyExistsException'}}, 'CreateLogStream'
        )
        mock_boto_client.return_value = mock_client
        
        logger = AuditLogger(execution_mode=ExecutionMode.DRY_RUN)
        
        event = AuditEvent(
            event_type=AuditEventType.REQUEST_RECEIVED,
            correlation_id="test-existing-stream",
            user_id="user123",
            timestamp=datetime.utcnow(),
            event_data={},
            execution_mode=ExecutionMode.DRY_RUN
        )
        
        # Should not raise exception
        logger._write_to_cloudwatch(event)
        
        mock_client.put_log_events.assert_called_once()
    
    @patch('boto3.client')
    def test_write_to_dynamodb_success(self, mock_boto_client):
        """Test successful DynamoDB write"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        logger = AuditLogger(
            dynamodb_table_name="audit-table",
            execution_mode=ExecutionMode.SANDBOX_LIVE
        )
        
        event = AuditEvent(
            event_type=AuditEventType.APPROVAL_GRANTED,
            correlation_id="test-dynamodb",
            user_id="user123",
            timestamp=datetime.utcnow(),
            event_data={"decision": "granted"},
            execution_mode=ExecutionMode.SANDBOX_LIVE,
            channel="teams"
        )
        
        logger._write_to_dynamodb(event)
        
        mock_client.put_item.assert_called_once()
        call_args = mock_client.put_item.call_args[1]
        
        assert call_args["TableName"] == "audit-table"
        assert call_args["Item"]["correlation_id"]["S"] == "test-dynamodb"
        assert call_args["Item"]["user_id"]["S"] == "user123"
        assert call_args["Item"]["channel"]["S"] == "teams"
    
    def test_sanitize_sensitive_data_string(self):
        """Test sanitizing sensitive data in strings"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        # Test password sanitization
        text = "password=secret123 and token=abc123def"
        result = logger._sanitize_sensitive_data(text)
        assert "secret123" not in result
        assert "abc123def" not in result
        assert "[REDACTED]" in result
        
        # Test AWS key sanitization
        text = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        result = logger._sanitize_sensitive_data(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED]" in result
    
    def test_sanitize_sensitive_data_dict(self):
        """Test sanitizing sensitive data in dictionaries"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        data = {
            "username": "testuser",
            "password": "secret123",
            "api_key": "abc123def",
            "normal_field": "normal_value"
        }
        
        result = logger._sanitize_sensitive_data(data)
        
        assert result["username"] == "testuser"
        assert result["password"] == "[REDACTED]"
        assert result["api_key"] == "[REDACTED]"
        assert result["normal_field"] == "normal_value"
    
    def test_sanitize_sensitive_data_list(self):
        """Test sanitizing sensitive data in lists"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        data = ["normal", "password=secret", {"key": "value", "token": "abc123"}]
        result = logger._sanitize_sensitive_data(data)
        
        assert result[0] == "normal"
        assert "secret" not in result[1]
        assert result[2]["key"] == "value"
        assert result[2]["token"] == "[REDACTED]"
    
    def test_sanitize_token(self):
        """Test token sanitization"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        # Normal token
        token = "abcd1234efgh5678ijkl"
        result = logger._sanitize_token(token)
        assert result == "abcd...ijkl"
        
        # Short token
        short_token = "abc"
        result = logger._sanitize_token(short_token)
        assert result == "[REDACTED]"
        
        # Empty token
        result = logger._sanitize_token("")
        assert result == "[REDACTED]"
    
    def test_sanitize_tool_args(self):
        """Test tool arguments sanitization"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        args = {
            "instance_id": "i-123456789",
            "password": "secret123",
            "auth_token": "bearer_token_123",
            "normal_param": "normal_value"
        }
        
        result = logger._sanitize_tool_args(args)
        
        assert result["instance_id"] == "i-123456789"
        assert result["password"] == "[REDACTED]"
        assert result["auth_token"] == "[REDACTED]"
        assert result["normal_param"] == "normal_value"
    
    @patch('boto3.client')
    def test_get_audit_events_from_dynamodb(self, mock_boto_client):
        """Test retrieving audit events from DynamoDB"""
        mock_client = Mock()
        mock_client.query.return_value = {
            'Items': [
                {
                    'correlation_id': {'S': 'test-123'},
                    'timestamp': {'S': '2023-01-01T12:00:00Z'},
                    'event_type': {'S': 'request_received'},
                    'user_id': {'S': 'user123'},
                    'execution_mode': {'S': 'DRY_RUN'},
                    'event_data': {'S': '{"test": "data"}'},
                    'channel': {'S': 'teams'}
                }
            ]
        }
        mock_boto_client.return_value = mock_client
        
        logger = AuditLogger(
            dynamodb_table_name="audit-table",
            execution_mode=ExecutionMode.SANDBOX_LIVE
        )
        
        events = logger.get_audit_events("test-123")
        
        assert len(events) == 1
        assert events[0]["correlation_id"] == "test-123"
        assert events[0]["event_type"] == "request_received"
        assert events[0]["user_id"] == "user123"
        assert events[0]["channel"] == "teams"
        
        mock_client.query.assert_called_once()
    
    def test_set_execution_mode(self):
        """Test setting execution mode"""
        logger = AuditLogger(execution_mode=ExecutionMode.LOCAL_MOCK)
        
        assert logger.execution_mode == ExecutionMode.LOCAL_MOCK
        
        with patch.object(logger, '_initialize_clients') as mock_init:
            logger.set_execution_mode(ExecutionMode.DRY_RUN)
            
            assert logger.execution_mode == ExecutionMode.DRY_RUN
            mock_init.assert_called_once()
    
    def test_set_execution_mode_to_local_mock(self):
        """Test setting execution mode to LOCAL_MOCK clears clients"""
        logger = AuditLogger(execution_mode=ExecutionMode.DRY_RUN)
        logger.cloudwatch_logs_client = Mock()
        logger.dynamodb_client = Mock()
        
        logger.set_execution_mode(ExecutionMode.LOCAL_MOCK)
        
        assert logger.execution_mode == ExecutionMode.LOCAL_MOCK
        assert logger.cloudwatch_logs_client is None
        assert logger.dynamodb_client is None


class TestAuditLoggerIntegration:
    """Integration tests for audit logger"""
    
    @patch('boto3.client')
    def test_full_audit_flow(self, mock_boto_client):
        """Test complete audit logging flow"""
        mock_logs_client = Mock()
        mock_dynamodb_client = Mock()
        mock_boto_client.side_effect = lambda service: {
            'logs': mock_logs_client,
            'dynamodb': mock_dynamodb_client
        }[service]
        
        logger = AuditLogger(
            cloudwatch_log_group="/test/audit",
            dynamodb_table_name="test-audit-table",
            execution_mode=ExecutionMode.SANDBOX_LIVE
        )
        
        # Log a complete flow: request -> tool call -> execution -> result
        message = InternalMessage(
            correlation_id="integration-test",
            user_id="test_user",
            message_text="Reboot instance i-123"
        )
        
        tool_call = ToolCall(
            tool_name="ec2_reboot",
            args={"instance_id": "i-123"},
            requires_approval=True,
            correlation_id="integration-test"
        )
        
        result = ToolResult(
            tool_name="ec2_reboot",
            success=True,
            data={"status": "rebooting"},
            correlation_id="integration-test"
        )
        
        # Log all events
        logger.log_request_received(message)
        logger.log_tool_call_requested(tool_call, "test_user")
        logger.log_tool_call_executed(tool_call, result, "test_user")
        
        # Verify CloudWatch calls
        assert mock_logs_client.create_log_stream.call_count == 3
        assert mock_logs_client.put_log_events.call_count == 3
        
        # Verify DynamoDB calls
        assert mock_dynamodb_client.put_item.call_count == 3
        
        # Verify all events have same correlation ID
        for call in mock_dynamodb_client.put_item.call_args_list:
            item = call[1]["Item"]
            assert item["correlation_id"]["S"] == "integration-test"