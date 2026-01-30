"""
Integration tests for the complete OpsAgent Controller system
Tests the wiring of all components together
Requirements: All requirements integration
"""
import json
import os
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from src.main import lambda_handler, chat_handler, get_or_create_components
from src.models import ExecutionMode, ChannelType


class TestSystemIntegration:
    """Test complete system integration"""
    
    def test_complete_chat_flow_local_mock(self):
        """Test complete chat flow in LOCAL_MOCK mode"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "body": json.dumps({
                    "userId": "test-user",
                    "messageText": "Check CPU metrics for instance i-123",
                    "channel": "web"
                })
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            assert "correlationId" in body
            
            # Check that response contains expected elements
            data = body["data"]
            assert "message" in data
            assert "channel_data" in data
            
            # Should contain tool execution results
            channel_data = data["channel_data"]
            assert "tool_results" in channel_data
    
    def test_approval_workflow_local_mock(self):
        """Test approval workflow in LOCAL_MOCK mode"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            # First request that requires approval
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "body": json.dumps({
                    "userId": "test-user",
                    "messageText": "Reboot instance i-123",
                    "channel": "web"
                })
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            
            # Should return approval request
            data = body["data"]
            assert data.get("approval_required") is True
            assert "approval_data" in data
            
            approval_data = data["approval_data"]
            assert approval_data["type"] == "approval_card"
            assert "token" in approval_data
            
            # Extract approval token
            approval_token = approval_data["token"]
            
            # Second request to approve
            approval_event = {
                "httpMethod": "POST",
                "path": "/chat",
                "body": json.dumps({
                    "userId": "test-user",
                    "messageText": f"approve token:{approval_token}",
                    "channel": "web"
                })
            }
            
            approval_response = lambda_handler(approval_event, None)
            
            assert approval_response["statusCode"] == 200
            approval_body = json.loads(approval_response["body"])
            assert approval_body["success"] is True
            
            # Should contain execution results
            approval_data = approval_body["data"]
            assert "Approval Granted" in approval_data["message"]
    
    def test_component_initialization(self):
        """Test that all components are properly initialized"""
        execution_mode = ExecutionMode.LOCAL_MOCK
        
        llm_provider, tool_execution_engine, approval_gate, audit_logger = get_or_create_components(execution_mode)
        
        # Check LLM provider
        assert llm_provider is not None
        assert hasattr(llm_provider, 'generate_tool_calls')
        assert hasattr(llm_provider, 'generate_summary')
        
        # Check tool execution engine
        assert tool_execution_engine is not None
        assert hasattr(tool_execution_engine, 'execute_tools')
        assert tool_execution_engine.execution_mode == execution_mode
        
        # Check approval gate
        assert approval_gate is not None
        assert hasattr(approval_gate, 'create_approval_request')
        assert hasattr(approval_gate, 'validate_approval_token')
        
        # Check audit logger
        assert audit_logger is not None
        assert hasattr(audit_logger, 'log_request_received')
        assert hasattr(audit_logger, 'log_tool_call_executed')
        assert audit_logger.execution_mode == execution_mode
    
    def test_health_endpoint_with_components(self):
        """Test health endpoint includes component status"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            event = {
                "httpMethod": "GET",
                "path": "/health"
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            
            system_data = body["data"]["system"]
            assert "components" in system_data
            
            components = system_data["components"]
            assert "llm_provider" in components
            assert "tool_execution_engine" in components
            assert "approval_gate" in components
            assert "audit_logger" in components
            
            # All components should be initialized
            assert components["llm_provider"]["initialized"] is True
            assert components["tool_execution_engine"]["initialized"] is True
            assert components["approval_gate"]["initialized"] is True
            assert components["audit_logger"]["initialized"] is True
    
    def test_error_handling_with_audit_logging(self):
        """Test error handling includes audit logging"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            # Send invalid request to trigger error
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "body": json.dumps({
                    "userId": "",  # Invalid empty user ID
                    "messageText": "Test message",
                    "channel": "web"
                })
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 400
            body = json.loads(response["body"])
            assert "Bad Request" in body["error"]
    
    def test_execution_mode_switching(self):
        """Test that components properly switch execution modes"""
        # Start with LOCAL_MOCK
        execution_mode1 = ExecutionMode.LOCAL_MOCK
        llm_provider1, tool_engine1, approval_gate1, audit_logger1 = get_or_create_components(execution_mode1)
        
        assert tool_engine1.execution_mode == execution_mode1
        assert audit_logger1.execution_mode == execution_mode1
        
        # Switch to DRY_RUN (simulate environment change)
        execution_mode2 = ExecutionMode.DRY_RUN
        
        # Components should update their execution mode
        tool_engine1.set_execution_mode(execution_mode2)
        audit_logger1.set_execution_mode(execution_mode2)
        
        assert tool_engine1.execution_mode == execution_mode2
        assert audit_logger1.execution_mode == execution_mode2
    
    def test_llm_tool_execution_integration(self):
        """Test LLM provider and tool execution engine integration"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            llm_provider, tool_execution_engine, _, _ = get_or_create_components(ExecutionMode.LOCAL_MOCK)
            
            # Generate tool calls
            llm_response = llm_provider.generate_tool_calls(
                "Check CPU metrics for instance i-123",
                "test-correlation-id"
            )
            
            assert len(llm_response.tool_calls) > 0
            assert llm_response.assistant_message is not None
            
            # Execute the tools
            from src.tool_execution_engine import ExecutionContext
            context = ExecutionContext(
                correlation_id="test-correlation-id",
                user_id="test-user",
                execution_mode=ExecutionMode.LOCAL_MOCK
            )
            
            results = tool_execution_engine.execute_tools(llm_response.tool_calls, context)
            
            assert len(results) == len(llm_response.tool_calls)
            
            # Generate summary
            summary = llm_provider.generate_summary(
                [result.to_dict() for result in results],
                "test-correlation-id"
            )
            
            assert isinstance(summary, str)
            assert len(summary) > 0
    
    def test_approval_gate_integration(self):
        """Test approval gate integration with tool execution"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            llm_provider, tool_execution_engine, approval_gate, _ = get_or_create_components(ExecutionMode.LOCAL_MOCK)
            
            # Generate tool calls that require approval
            llm_response = llm_provider.generate_tool_calls(
                "Reboot instance i-123",
                "test-correlation-id"
            )
            
            # Find approval-required tools
            approval_tools = [tc for tc in llm_response.tool_calls if tc.requires_approval]
            assert len(approval_tools) > 0
            
            # Create approval request
            approval_request = approval_gate.create_approval_request(
                tool_call=approval_tools[0],
                requested_by="test-user",
                risk_level="medium"
            )
            
            assert approval_request.token is not None
            assert approval_request.tool_call == approval_tools[0]
            
            # Validate token
            is_valid, reason = approval_gate.validate_approval_token(
                approval_request.token,
                "test-user",
                approval_tools[0]
            )
            
            assert is_valid is True
            assert reason == "Token is valid"
    
    def test_audit_logging_integration(self):
        """Test audit logging throughout the system"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            from src.models import InternalMessage
            
            _, _, _, audit_logger = get_or_create_components(ExecutionMode.LOCAL_MOCK)
            
            # Create test message
            internal_message = InternalMessage(
                user_id="test-user",
                channel=ChannelType.WEB,
                channel_conversation_id="test-conv",
                message_text="Test message",
                execution_mode=ExecutionMode.LOCAL_MOCK
            )
            
            # Test request logging
            audit_logger.log_request_received(internal_message)
            
            # Test tool call logging
            from src.models import ToolCall, ToolResult
            
            tool_call = ToolCall(
                tool_name="get_cloudwatch_metrics",
                args={"namespace": "AWS/EC2", "metric_name": "CPUUtilization"},
                requires_approval=False,
                correlation_id=internal_message.correlation_id
            )
            
            audit_logger.log_tool_call_requested(tool_call, "test-user", "web")
            
            # Test tool result logging
            tool_result = ToolResult(
                tool_name="get_cloudwatch_metrics",
                success=True,
                data={"metric_value": 50.0},
                execution_mode=ExecutionMode.LOCAL_MOCK,
                correlation_id=internal_message.correlation_id
            )
            
            audit_logger.log_tool_call_executed(tool_call, tool_result, "test-user", "web")
            
            # Test error logging
            test_error = ValueError("Test error")
            audit_logger.log_error(test_error, internal_message.correlation_id, "test-user", {"step": "test"})
    
    def test_channel_adapter_integration(self):
        """Test channel adapter integration with the system"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            from src.channel_adapters import WebChannelAdapter
            
            channel_adapter = WebChannelAdapter()
            
            # Test message normalization
            raw_request = {
                "body": json.dumps({
                    "userId": "test-user",
                    "messageText": "Test message",
                    "channel": "web"
                })
            }
            
            internal_message = channel_adapter.normalize_message(raw_request)
            
            assert internal_message.user_id == "test-user"
            assert internal_message.message_text == "Test message"
            assert internal_message.channel == ChannelType.WEB
            
            # Test response formatting
            response = channel_adapter.format_response(
                "Test response",
                internal_message.correlation_id,
                {"test": "data"}
            )
            
            assert response.message == "Test response"
            assert response.correlation_id == internal_message.correlation_id
            assert "test" in response.channel_data
    
    def test_end_to_end_diagnosis_flow(self):
        """Test complete end-to-end diagnosis flow"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            # Simulate a diagnosis request
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "body": json.dumps({
                    "userId": "ops-engineer",
                    "messageText": "Show me CPU metrics for instance i-1234567890abcdef0",
                    "channel": "web"
                })
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            
            data = body["data"]
            assert "message" in data
            assert "channel_data" in data
            
            # Should contain tool execution results
            channel_data = data["channel_data"]
            assert "tool_results" in channel_data
            
            # Should have executed diagnosis tools
            tool_results = channel_data["tool_results"]
            assert len(tool_results) > 0
            
            # At least one tool should be successful
            successful_tools = [tr for tr in tool_results if tr["success"]]
            assert len(successful_tools) > 0
    
    def test_end_to_end_remediation_flow(self):
        """Test complete end-to-end remediation flow with approval"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            # Step 1: Request remediation
            event = {
                "httpMethod": "POST",
                "path": "/chat",
                "body": json.dumps({
                    "userId": "ops-engineer",
                    "messageText": "Reboot instance i-1234567890abcdef0",
                    "channel": "web"
                })
            }
            
            response = lambda_handler(event, None)
            
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["success"] is True
            
            # Should require approval
            data = body["data"]
            assert data.get("approval_required") is True
            assert "approval_data" in data
            
            approval_data = data["approval_data"]
            assert approval_data["type"] == "approval_card"
            approval_token = approval_data["token"]
            
            # Step 2: Approve the request
            approval_event = {
                "httpMethod": "POST",
                "path": "/chat",
                "body": json.dumps({
                    "userId": "ops-engineer",
                    "messageText": f"approve token:{approval_token}",
                    "channel": "web"
                })
            }
            
            approval_response = lambda_handler(approval_event, None)
            
            assert approval_response["statusCode"] == 200
            approval_body = json.loads(approval_response["body"])
            assert approval_body["success"] is True
            
            # Should contain execution results
            approval_data = approval_body["data"]
            assert "Approval Granted" in approval_data["message"]
            assert "tool_executed" in approval_data["channel_data"]
            assert approval_data["channel_data"]["tool_executed"] == "reboot_ec2_instance"


class TestErrorScenarios:
    """Test error scenarios in the integrated system"""
    
    def test_llm_provider_error_handling(self):
        """Test handling of LLM provider errors"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            with patch('src.main.get_or_create_components') as mock_components:
                # Mock LLM provider to raise error
                mock_llm = MagicMock()
                mock_llm.generate_tool_calls.side_effect = Exception("LLM error")
                
                # Mock audit logger to avoid issues
                mock_audit = MagicMock()
                
                mock_components.return_value = (
                    mock_llm,
                    MagicMock(),
                    MagicMock(),
                    mock_audit
                )
                
                event = {
                    "httpMethod": "POST",
                    "path": "/chat",
                    "body": json.dumps({
                        "userId": "test-user",
                        "messageText": "Test message",
                        "channel": "web"
                    })
                }
                
                response = lambda_handler(event, None)
                
                assert response["statusCode"] == 200  # Should handle gracefully
                body = json.loads(response["body"])
                assert body["success"] is True
                
                # Should contain error message
                data = body["data"]
                assert "trouble understanding" in data["message"].lower()
    
    def test_tool_execution_error_handling(self):
        """Test handling of tool execution errors"""
        with patch.dict(os.environ, {"EXECUTION_MODE": "LOCAL_MOCK"}):
            with patch('src.main.get_or_create_components') as mock_components:
                # Mock tool execution engine to return failed results
                mock_engine = MagicMock()
                from src.models import ToolResult
                
                failed_result = ToolResult(
                    tool_name="test_tool",
                    success=False,
                    error="Tool execution failed",
                    execution_mode=ExecutionMode.LOCAL_MOCK,
                    correlation_id="test-id"
                )
                mock_engine.execute_tools.return_value = [failed_result]
                
                mock_llm = MagicMock()
                from src.llm_provider import LLMResponse
                from src.models import ToolCall
                
                mock_llm.generate_tool_calls.return_value = LLMResponse(
                    tool_calls=[ToolCall(
                        tool_name="test_tool",
                        args={},
                        requires_approval=False,
                        correlation_id="test-id"
                    )],
                    assistant_message="I'll help you with that.",
                    confidence=0.8
                )
                mock_llm.generate_summary.return_value = "Tool execution failed"
                
                mock_components.return_value = (
                    mock_llm,
                    mock_engine,
                    MagicMock(),
                    MagicMock()
                )
                
                event = {
                    "httpMethod": "POST",
                    "path": "/chat",
                    "body": json.dumps({
                        "userId": "test-user",
                        "messageText": "Test message",
                        "channel": "web"
                    })
                }
                
                response = lambda_handler(event, None)
                
                assert response["statusCode"] == 200
                body = json.loads(response["body"])
                assert body["success"] is True
                
                # Should contain failure information
                data = body["data"]
                channel_data = data["channel_data"]
                assert "tool_results" in channel_data
                assert not channel_data["tool_results"][0]["success"]