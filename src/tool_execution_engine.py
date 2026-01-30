"""
Tool execution engine for OpsAgent Controller
Requirements: 4.4, 7.4, 7.5
"""
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import asyncio
from dataclasses import dataclass
from enum import Enum
import boto3
from botocore.exceptions import ClientError

from models import ToolCall, ToolResult, ExecutionMode, ApprovalRequest
from tool_guardrails import ToolGuardrails, GuardrailViolation, ResourceTagValidationError
from aws_diagnosis_tools import CloudWatchMetricsTool, EC2DescribeTool
from aws_remediation_tools import EC2RebootTool

logger = logging.getLogger(__name__)


class ToolExecutionError(Exception):
    """Exception raised during tool execution"""
    pass


class ApprovalRequiredError(Exception):
    """Exception raised when approval is required but not provided"""
    pass


@dataclass
class ExecutionContext:
    """Context for tool execution"""
    correlation_id: str
    user_id: str
    execution_mode: ExecutionMode
    approval_tokens: Dict[str, ApprovalRequest] = None
    
    def __post_init__(self):
        if self.approval_tokens is None:
            self.approval_tokens = {}


class ToolExecutionEngine:
    """
    Tool execution engine with security controls and dependency management
    Requirements: 4.4, 7.4, 7.5
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.LOCAL_MOCK):
        self.execution_mode = execution_mode
        self.guardrails = ToolGuardrails(execution_mode)
        
        # Initialize AWS clients based on execution mode
        self.aws_clients = {}
        if execution_mode != ExecutionMode.LOCAL_MOCK:
            self._initialize_aws_clients()
        
        # Initialize AWS diagnosis tools
        self.cloudwatch_tool = CloudWatchMetricsTool(execution_mode)
        self.ec2_tool = EC2DescribeTool(execution_mode)
        
        # Initialize AWS remediation tools
        self.ec2_reboot_tool = EC2RebootTool(execution_mode)
        
        # Tool implementations
        self.tool_implementations = {
            "get_cloudwatch_metrics": self._execute_cloudwatch_metrics,
            "describe_ec2_instances": self._execute_describe_ec2_instances,
            "reboot_ec2_instance": self._execute_reboot_ec2_instance
        }
    
    def _initialize_aws_clients(self) -> None:
        """Initialize AWS service clients"""
        try:
            self.aws_clients['cloudwatch'] = boto3.client('cloudwatch')
            self.aws_clients['ec2'] = boto3.client('ec2')
            logger.info("AWS clients initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            # Continue without clients - tools will handle gracefully
    
    def execute_tools(
        self,
        tool_calls: List[ToolCall],
        context: ExecutionContext
    ) -> List[ToolResult]:
        """
        Execute a list of tool calls with dependency management
        Requirements: 4.4, 7.4
        
        Args:
            tool_calls: List of tool calls to execute
            context: Execution context with correlation ID and user info
            
        Returns:
            List of tool results
        """
        logger.info(f"Executing {len(tool_calls)} tool calls for correlation_id: {context.correlation_id}")
        
        results = []
        
        # Validate all tool calls first
        try:
            self._validate_all_tool_calls(tool_calls)
        except (GuardrailViolation, ResourceTagValidationError) as e:
            # If validation fails, return error result for all tools
            error_result = ToolResult(
                tool_name="validation",
                success=False,
                error=f"Tool validation failed: {str(e)}",
                execution_mode=self.execution_mode,
                correlation_id=context.correlation_id
            )
            return [error_result]
        
        # Execute tools in sequence (for MVP, no parallel execution)
        for tool_call in tool_calls:
            try:
                result = self._execute_single_tool(tool_call, context)
                results.append(result)
                
                # If a tool fails and it's critical, we might want to stop
                # For now, continue with remaining tools
                if not result.success:
                    logger.warning(f"Tool {tool_call.tool_name} failed: {result.error}")
                
            except Exception as e:
                logger.error(f"Unexpected error executing tool {tool_call.tool_name}: {e}")
                error_result = ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=f"Unexpected execution error: {str(e)}",
                    execution_mode=self.execution_mode,
                    correlation_id=context.correlation_id
                )
                results.append(error_result)
        
        logger.info(f"Completed execution of {len(tool_calls)} tool calls")
        return results
    
    def _validate_all_tool_calls(self, tool_calls: List[ToolCall]) -> None:
        """
        Validate all tool calls before execution
        
        Args:
            tool_calls: List of tool calls to validate
            
        Raises:
            GuardrailViolation: If any tool call violates guardrails
        """
        violations = self.guardrails.validate_multiple_tool_calls(tool_calls)
        if violations:
            raise GuardrailViolation(f"Tool validation failed: {'; '.join(violations)}")
    
    def _execute_single_tool(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute a single tool call
        
        Args:
            tool_call: The tool call to execute
            context: Execution context
            
        Returns:
            ToolResult with execution outcome
        """
        logger.info(f"Executing tool: {tool_call.tool_name}")
        
        # Check if tool requires approval
        if self.guardrails.requires_approval(tool_call.tool_name):
            if not self._check_approval(tool_call, context):
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="Approval required but not provided",
                    execution_mode=self.execution_mode,
                    correlation_id=context.correlation_id
                )
        
        # Get tool implementation
        tool_impl = self.tool_implementations.get(tool_call.tool_name)
        if not tool_impl:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Tool implementation not found: {tool_call.tool_name}",
                execution_mode=self.execution_mode,
                correlation_id=context.correlation_id
            )
        
        # Execute the tool
        try:
            return tool_impl(tool_call, context)
        except Exception as e:
            logger.error(f"Tool execution failed for {tool_call.tool_name}: {e}")
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=str(e),
                execution_mode=self.execution_mode,
                correlation_id=context.correlation_id
            )
    
    def _check_approval(self, tool_call: ToolCall, context: ExecutionContext) -> bool:
        """
        Check if tool call has valid approval
        
        Args:
            tool_call: The tool call requiring approval
            context: Execution context with approval tokens
            
        Returns:
            True if approval is valid, False otherwise
        """
        # In LOCAL_MOCK mode, assume approval is granted
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return True
        
        # Check if we have an approval token for this tool call
        # This is a simplified implementation - in production, you'd have
        # a more sophisticated approval token matching system
        for token, approval_request in context.approval_tokens.items():
            if (approval_request.tool_call and 
                approval_request.tool_call.tool_name == tool_call.tool_name and
                approval_request.expires_at > datetime.utcnow()):
                return True
        
        return False
    
    def _execute_cloudwatch_metrics(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute CloudWatch metrics retrieval using dedicated tool
        Requirements: 2.1, 2.4, 2.5
        """
        return self.cloudwatch_tool.execute(tool_call, context.correlation_id)
    
    def _execute_describe_ec2_instances(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute EC2 instance description using dedicated tool
        Requirements: 2.2, 2.4, 2.5
        """
        return self.ec2_tool.execute(tool_call, context.correlation_id)
    
    def _execute_reboot_ec2_instance(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute EC2 instance reboot using the dedicated EC2RebootTool
        Requirements: 3.2, 3.4, 3.5, 11.12, 11.13
        """
        return self.ec2_reboot_tool.execute(tool_call, context.correlation_id)

    
    def set_execution_mode(self, execution_mode: ExecutionMode) -> None:
        """
        Update execution mode and reinitialize components
        Requirements: 7.4, 7.5
        """
        logger.info(f"Changing execution mode from {self.execution_mode.value} to {execution_mode.value}")
        self.execution_mode = execution_mode
        self.guardrails.set_execution_mode(execution_mode)
        
        # Update AWS diagnosis tools execution mode
        self.cloudwatch_tool.execution_mode = execution_mode
        self.ec2_tool.execution_mode = execution_mode
        
        # Update AWS remediation tools execution mode
        self.ec2_reboot_tool.execution_mode = execution_mode
        
        # Reinitialize AWS clients if needed
        if execution_mode != ExecutionMode.LOCAL_MOCK and not self.aws_clients:
            self._initialize_aws_clients()
            # Reinitialize tool clients as well
            if execution_mode != ExecutionMode.LOCAL_MOCK:
                try:
                    self.cloudwatch_tool._initialize_client()
                    self.ec2_tool._initialize_client()
                    self.ec2_reboot_tool._initialize_client()
                except Exception as e:
                    logger.warning(f"Failed to reinitialize tool clients: {e}")
    
    def get_execution_status(self) -> Dict[str, Any]:
        """
        Get current execution engine status
        
        Returns:
            Dictionary with status information
        """
        return {
            'execution_mode': self.execution_mode.value,
            'aws_clients_initialized': bool(self.aws_clients),
            'available_tools': self.guardrails.get_allowed_tools_list(),
            'guardrails_active': True
        }