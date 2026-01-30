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
from types import SimpleNamespace
import boto3 as _boto3
from botocore.exceptions import ClientError

from src.models import ToolCall, ToolResult, ExecutionMode, ApprovalRequest
from src.tool_guardrails import ToolGuardrails, GuardrailViolation, ResourceTagValidationError
from src.aws_diagnosis_tools import CloudWatchMetricsTool, EC2DescribeTool, EC2StatusTool, ALBTargetHealthTool, CloudTrailSearchTool
from src.aws_remediation_tools import EC2RebootTool, ECSScalingTool
from src.workflow_tools import IncidentRecordTool, ChannelNotificationTool

boto3 = SimpleNamespace(client=_boto3.client)

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
        execution_mode_value = (
            execution_mode.value if isinstance(execution_mode, ExecutionMode) else str(execution_mode)
        )
        if execution_mode_value != ExecutionMode.LOCAL_MOCK.value:
            self._initialize_aws_clients()
        
        # Initialize AWS diagnosis tools without eager client setup
        self.cloudwatch_tool = CloudWatchMetricsTool(ExecutionMode.LOCAL_MOCK)
        self.ec2_tool = EC2DescribeTool(ExecutionMode.LOCAL_MOCK)
        self.ec2_status_tool = EC2StatusTool(ExecutionMode.LOCAL_MOCK)  # New dedicated tool for get_ec2_status
        self.alb_tool = ALBTargetHealthTool(ExecutionMode.SANDBOX_LIVE)
        self.cloudtrail_tool = CloudTrailSearchTool(ExecutionMode.LOCAL_MOCK)
        
        # Initialize AWS remediation tools without eager client setup
        self.ec2_reboot_tool = EC2RebootTool(ExecutionMode.LOCAL_MOCK)
        self.ecs_scaling_tool = ECSScalingTool(ExecutionMode.LOCAL_MOCK)
        
        # Initialize workflow tools
        self.incident_tool = IncidentRecordTool(ExecutionMode.LOCAL_MOCK)
        self.channel_tool = ChannelNotificationTool(ExecutionMode.LOCAL_MOCK)

        self.cloudwatch_tool.execution_mode = execution_mode
        self.ec2_tool.execution_mode = execution_mode
        self.ec2_status_tool.execution_mode = execution_mode  # Update execution mode for EC2 status tool
        self.alb_tool.execution_mode = execution_mode
        self.cloudtrail_tool.execution_mode = execution_mode
        self.ec2_reboot_tool.execution_mode = execution_mode
        self.ecs_scaling_tool.execution_mode = execution_mode
        self.incident_tool.execution_mode = execution_mode
        self.channel_tool.execution_mode = execution_mode

        self._sync_tool_clients()
        
        # Tool implementations
        self.tool_implementations = {
            # Diagnostic operations (no approval required)
            "get_cloudwatch_metrics": self._execute_cloudwatch_metrics,
            "get_ec2_status": self._execute_get_ec2_status,
            "describe_ec2_instances": self._execute_describe_ec2_instances,
            "describe_alb_target_health": self._execute_alb_target_health,
            "search_cloudtrail_events": self._execute_cloudtrail_search,
            
            # Write operations (approval required)
            "reboot_ec2_instance": self._execute_reboot_ec2_instance,
            "reboot_ec2": self._execute_reboot_ec2_instance,  # Alias for consistency
            "scale_ecs_service": self._execute_scale_ecs_service,
            
            # Workflow operations (no approval, fully audited)
            "create_incident_record": self._execute_create_incident,
            "post_summary_to_channel": self._execute_post_to_channel
        }

    def _sync_tool_clients(self) -> None:
        """Ensure tool instances share initialized AWS clients."""
        cloudwatch_client = self.aws_clients.get('cloudwatch')
        ec2_client = self.aws_clients.get('ec2')
        elbv2_client = self.aws_clients.get('elbv2')
        cloudtrail_client = self.aws_clients.get('cloudtrail')
        ecs_client = self.aws_clients.get('ecs')

        if cloudwatch_client:
            self.cloudwatch_tool.cloudwatch_client = cloudwatch_client
            self.ec2_status_tool.cloudwatch_client = cloudwatch_client  # Share CloudWatch client with EC2 status tool
        if ec2_client:
            self.ec2_tool.ec2_client = ec2_client
            self.ec2_status_tool.ec2_client = ec2_client  # Share EC2 client with EC2 status tool
            self.ec2_reboot_tool.ec2_client = ec2_client
        if elbv2_client:
            self.alb_tool.elbv2_client = elbv2_client
        if cloudtrail_client:
            self.cloudtrail_tool.cloudtrail_client = cloudtrail_client
        if ecs_client:
            self.ecs_scaling_tool.ecs_client = ecs_client
    
    def _initialize_aws_clients(self) -> None:
        """Initialize AWS service clients"""
        try:
            self.aws_clients['cloudwatch'] = boto3.client('cloudwatch')
            self.aws_clients['ec2'] = boto3.client('ec2')
            self.aws_clients['elbv2'] = boto3.client('elbv2')
            self.aws_clients['cloudtrail'] = boto3.client('cloudtrail')
            self.aws_clients['ecs'] = boto3.client('ecs')
            logger.info("AWS clients initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            # Continue without clients - tools will handle gracefully
    
    def executeOperation(
        self,
        operation: str,
        parameters: Dict[str, Any],
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute a single operation with proper routing
        Requirements: 2.2, 3.1, 10.1, 11.1
        
        Args:
            operation: Operation name to execute
            parameters: Operation parameters
            context: Execution context with correlation ID and user info
            
        Returns:
            ToolResult with execution outcome
        """
        logger.info(f"Executing operation: {operation} for correlation_id: {context.correlation_id}")
        
        # Create tool call from operation and parameters
        tool_call = ToolCall(
            tool_name=operation,
            args=parameters,
            correlation_id=context.correlation_id,
            user_id=context.user_id
        )
        
        # Execute single tool call
        results = self.execute_tools([tool_call], context)
        
        # Return the first (and only) result
        return results[0] if results else ToolResult(
            tool_name=operation,
            success=False,
            error="No result returned from tool execution",
            execution_mode=self.execution_mode,
            correlation_id=context.correlation_id
        )
    
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
    
    def _execute_get_ec2_status(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute EC2 status retrieval with CloudWatch metrics integration
        Requirements: 4.1, 4.2
        """
        return self.ec2_status_tool.execute(tool_call, context.correlation_id)
    
    def _execute_alb_target_health(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute ALB target health check using dedicated tool
        Requirements: 4.1, 4.2, 4.3
        """
        return self.alb_tool.execute(tool_call, context.correlation_id)
    
    def _execute_cloudtrail_search(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute CloudTrail event search using dedicated tool
        Requirements: 4.1, 4.2, 4.3
        """
        return self.cloudtrail_tool.execute(tool_call, context.correlation_id)
    
    def _execute_scale_ecs_service(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute ECS service scaling using dedicated tool
        Requirements: 5.4, 7.1, 7.2
        """
        return self.ecs_scaling_tool.execute(tool_call, context.correlation_id)
    
    def _execute_create_incident(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute incident record creation using dedicated tool
        Requirements: 6.1, 6.2, 6.3
        """
        return self.incident_tool.execute(tool_call, context.correlation_id)
    
    def _execute_post_to_channel(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute channel notification posting using dedicated tool
        Requirements: 6.1, 6.2, 6.3
        """
        return self.channel_tool.execute(tool_call, context.correlation_id)

    def _execute_cloudwatch_metrics(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Execute CloudWatch metrics retrieval using dedicated tool
        Requirements: 2.1, 2.4, 2.5
        """
        result = self.cloudwatch_tool.execute(tool_call, context.correlation_id)
        if not result.success and result.error and "AWS CloudWatch API error" not in result.error:
            if result.error == "Insufficient permissions to access CloudWatch metrics":
                result.error = f"{result.error}: Access denied"
            result.error = f"AWS CloudWatch API error: {result.error}"
        return result

    def _mock_cloudwatch_metrics(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Mock CloudWatch metrics retrieval for local testing
        Requirements: 2.1, 2.4, 2.5
        """
        return self.cloudwatch_tool._mock_metrics_response(tool_call, context.correlation_id)

    def _parse_time_window(self, time_window: str) -> timedelta:
        """Parse a time window string using CloudWatch tool logic."""
        try:
            return self.cloudwatch_tool._parse_time_window(time_window)
        except ValueError:
            return timedelta(minutes=15)

    def _get_metric_dimensions(self, namespace: str, resource_id: str) -> List[Dict[str, str]]:
        """Get CloudWatch metric dimensions using CloudWatch tool logic."""
        return self.cloudwatch_tool._get_metric_dimensions(namespace, resource_id)
    
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

    def _mock_describe_ec2_instances(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Mock EC2 describe instances for local testing
        Requirements: 2.2, 2.4, 2.5
        """
        return self.ec2_tool._mock_describe_response(tool_call, context.correlation_id)
    
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

    def _mock_reboot_ec2_instance(
        self,
        tool_call: ToolCall,
        context: ExecutionContext
    ) -> ToolResult:
        """
        Mock EC2 reboot for local testing
        Requirements: 3.2, 3.4, 3.5, 11.12, 11.13
        """
        return self.ec2_reboot_tool._mock_reboot_response(tool_call, context.correlation_id)

    
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
        self.ec2_status_tool.execution_mode = execution_mode  # Update execution mode for EC2 status tool
        self.alb_tool.execution_mode = execution_mode
        self.cloudtrail_tool.execution_mode = execution_mode
        
        # Update AWS remediation tools execution mode
        self.ec2_reboot_tool.execution_mode = execution_mode
        self.ecs_scaling_tool.execution_mode = execution_mode
        
        # Update workflow tools execution mode
        self.incident_tool.execution_mode = execution_mode
        self.channel_tool.execution_mode = execution_mode
        
        # Reinitialize AWS clients if needed
        execution_mode_value = (
            execution_mode.value if isinstance(execution_mode, ExecutionMode) else str(execution_mode)
        )
        if execution_mode_value != ExecutionMode.LOCAL_MOCK.value and not self.aws_clients:
            self._initialize_aws_clients()
            self._sync_tool_clients()
    
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
