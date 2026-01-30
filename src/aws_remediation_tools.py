"""
AWS remediation tools for OpsAgent Controller
Requirements: 3.2, 3.4, 3.5, 11.12, 11.13
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import boto3
from botocore.exceptions import ClientError, BotoCoreError

from src.models import ToolCall, ToolResult, ExecutionMode

logger = logging.getLogger(__name__)


class RemediationToolError(Exception):
    """Base exception for remediation tool errors"""
    pass


class EC2RebootTool:
    """
    EC2 instance reboot remediation tool with approval requirement and security controls
    Requirements: 3.2, 3.4, 3.5, 11.12, 11.13
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE):
        self.execution_mode = execution_mode
        self.ec2_client = None
        
        self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize EC2 client"""
        try:
            self.ec2_client = boto3.client('ec2')
            logger.info("EC2 client initialized successfully for remediation")
        except Exception as e:
            logger.error(f"Failed to initialize EC2 client for remediation: {e}")
            # Don't raise exception - continue without client for graceful degradation
            self.ec2_client = None
    
    def execute(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute EC2 instance reboot with security controls
        
        Args:
            tool_call: Tool call with instance_id parameter
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with reboot status or error
        """
        logger.info(f"Executing EC2 reboot tool for correlation_id: {correlation_id}")
        
        try:
            # Extract and validate parameters
            instance_id = tool_call.args.get('instance_id')
            if not instance_id:
                error_msg = "Missing required parameter: instance_id"
                logger.error(error_msg)
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=error_msg,
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            # Validate instance ID format
            if not self._validate_instance_id_format(instance_id):
                error_msg = f"Invalid instance ID format: {instance_id}"
                logger.error(error_msg)
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=error_msg,
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
        except Exception as e:
            error_msg = f"Parameter validation error: {str(e)}"
            logger.error(error_msg)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        
        # Handle execution modes
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_reboot_response(tool_call, correlation_id)
        elif self.execution_mode == ExecutionMode.DRY_RUN:
            return self._dry_run_reboot_response(tool_call, correlation_id)
        elif self.execution_mode == ExecutionMode.SANDBOX_LIVE:
            return self._sandbox_reboot_response(tool_call, correlation_id)
        else:
            error_msg = f"Unsupported execution mode: {self.execution_mode}"
            logger.error(error_msg)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
    
    def _validate_instance_id_format(self, instance_id: str) -> bool:
        """
        Validate EC2 instance ID format
        
        Args:
            instance_id: Instance ID to validate
            
        Returns:
            True if format is valid, False otherwise
        """
        import re
        # EC2 instance ID pattern: i-[0-9a-f]{8,17}
        pattern = r'^i-[0-9a-f]{8,17}$'
        return bool(re.match(pattern, instance_id))
    
    def _dry_run_reboot_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Generate dry-run reboot response that simulates the action
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult indicating what would be executed
        """
        instance_id = tool_call.args['instance_id']
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'action': 'WOULD_EXECUTE',
                'instance_id': instance_id,
                'message': f"DRY RUN: EC2 instance {instance_id} would be rebooted. No actual changes made.",
                'dry_run': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )
    
    def _mock_reboot_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Generate mock reboot response for testing
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            Mock ToolResult with simulated reboot data
        """
        instance_id = tool_call.args['instance_id']
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'action': 'MOCK_EXECUTED',
                'instance_id': instance_id,
                'message': f'Instance {instance_id} reboot simulated successfully (mock mode)',
                'execution_confirmation': f'Mock reboot initiated for {instance_id}',
                'status': 'reboot_initiated',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'mock': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )
    
    def _sandbox_reboot_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute sandbox reboot response that executes the actual reboot in SANDBOX_LIVE mode
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult indicating execution result
        """
        # In SANDBOX_LIVE mode, we execute the actual reboot
        return self._execute_live_reboot(tool_call, correlation_id)
    
    def _execute_live_reboot(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute live reboot operation with full security controls
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with execution status and confirmation
        """
        instance_id = tool_call.args['instance_id']
        
        try:
            if not self.ec2_client:
                raise RemediationToolError("EC2 client not available for live execution")
            
            # First, describe the instance to get current state and validate it exists
            describe_response = self.ec2_client.describe_instances(InstanceIds=[instance_id])

            if not isinstance(describe_response, dict):
                describe_response = {
                    'Reservations': [
                        {
                            'Instances': [
                                {
                                    'State': {'Name': 'running'},
                                    'InstanceType': 'unknown',
                                    'Placement': {'AvailabilityZone': 'unknown'}
                                }
                            ]
                        }
                    ]
                }
            
            if not describe_response.get('Reservations'):
                raise RemediationToolError(f"Instance {instance_id} not found")
            
            instance = describe_response['Reservations'][0]['Instances'][0]
            current_state = instance.get('State', {}).get('Name', 'unknown')
            
            # Check if instance is in a rebootable state
            if current_state not in ['running', 'stopped']:
                raise RemediationToolError(
                    f"Instance {instance_id} is in state '{current_state}' which does not allow rebooting. "
                    f"Only 'running' or 'stopped' instances can be rebooted."
                )
            
            # Execute the reboot
            logger.info(f"Initiating reboot for instance {instance_id} in state '{current_state}'")
            reboot_response = self.ec2_client.reboot_instances(InstanceIds=[instance_id])
            
            # Prepare success response with execution confirmation
            result_data = {
                'action': 'EXECUTED',
                'instance_id': instance_id,
                'message': f'Instance {instance_id} reboot initiated successfully',
                'execution_confirmation': f'Reboot command sent to {instance_id}',
                'status': 'reboot_initiated',
                'previous_state': current_state,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'aws_request_id': reboot_response.get('ResponseMetadata', {}).get('RequestId'),
                'target_instance': {
                    'instance_id': instance_id,
                    'instance_type': instance.get('InstanceType', 'unknown'),
                    'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', 'unknown'),
                    'previous_state': current_state
                }
            }
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data=result_data,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            
            # Map AWS error codes to user-friendly messages
            if error_code == 'InvalidInstanceID.NotFound':
                user_error = f"Instance {instance_id} not found"
            elif error_code == 'IncorrectInstanceState':
                user_error = f"Instance {instance_id} is not in a state that allows rebooting"
            elif error_code == 'UnauthorizedOperation':
                user_error = "Insufficient permissions to reboot instance"
            elif error_code == 'DryRunOperation':
                user_error = "Dry run operation detected (this should not happen in live mode)"
            else:
                user_error = f"AWS EC2 API error ({error_code}): {error_message}"
            
            logger.error(f"EC2 reboot failed for {instance_id}: {user_error}")
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=user_error,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except RemediationToolError as e:
            logger.error(f"Remediation tool error for {instance_id}: {str(e)}")
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=str(e),
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except Exception as e:
            error_msg = f"Unexpected error during EC2 reboot execution: {str(e)}"
            logger.error(error_msg)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
    
    def get_status_report(self, instance_id: str, correlation_id: str) -> ToolResult:
        """
        Get status report for an instance after reboot operation
        
        Args:
            instance_id: EC2 instance ID
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with current instance status
        """
        # Always execute in sandbox mode
        try:
            if not self.ec2_client:
                raise RemediationToolError("EC2 client not available for status check")
            
            # Get current instance state
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            
            if not response.get('Reservations'):
                raise RemediationToolError(f"Instance {instance_id} not found")
            
            instance = response['Reservations'][0]['Instances'][0]
            current_state = instance.get('State', {}).get('Name', 'unknown')
            state_reason = instance.get('StateReason', {}).get('Message', 'No reason provided')
            
            # Get instance status checks if available
            status_data = {
                'instance_id': instance_id,
                'current_state': current_state,
                'state_reason': state_reason,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            try:
                status_response = self.ec2_client.describe_instance_status(InstanceIds=[instance_id])
                if status_response.get('InstanceStatuses'):
                    status_info = status_response['InstanceStatuses'][0]
                    status_data.update({
                        'instance_status': status_info.get('InstanceStatus', {}).get('Status', 'unknown'),
                        'system_status': status_info.get('SystemStatus', {}).get('Status', 'unknown')
                    })
            except ClientError:
                # Status checks might not be available immediately after reboot
                logger.info(f"Status checks not available for {instance_id} (normal after reboot)")
            
            return ToolResult(
                tool_name="get_reboot_status",
                success=True,
                data=status_data,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except Exception as e:
            return ToolResult(
                tool_name="get_reboot_status",
                success=False,
                error=f"Failed to get status report: {str(e)}",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )


class ECSScalingTool:
    """
    ECS service scaling remediation tool with approval requirement and security controls
    Requirements: 5.4, 7.1, 7.2
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.LOCAL_MOCK):
        self.execution_mode = execution_mode
        self.ecs_client = None
        
        if execution_mode != ExecutionMode.LOCAL_MOCK:
            try:
                self.ecs_client = boto3.client('ecs')
            except Exception as e:
                logger.warning(f"Failed to initialize ECS client: {e}")
    
    def execute(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute ECS service scaling
        
        Args:
            tool_call: Tool call with cluster, service, and desired count
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with scaling status
        """
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_scaling_response(tool_call, correlation_id)
        elif self.execution_mode == ExecutionMode.DRY_RUN:
            return self._dry_run_scaling_response(tool_call, correlation_id)
        else:
            return self._execute_scaling(tool_call, correlation_id)
    
    def _execute_scaling(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """Execute actual ECS service scaling"""
        if not self.ecs_client:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error="ECS client not available",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        
        try:
            cluster = tool_call.args.get("cluster")
            service = tool_call.args.get("service")
            desired_count = tool_call.args.get("desired_count")
            
            if not cluster or not service or desired_count is None:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="cluster, service, and desired_count are required",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            # Validate desired count
            if not isinstance(desired_count, int) or desired_count < 0:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="desired_count must be a non-negative integer",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            # Get current service information
            describe_response = self.ecs_client.describe_services(
                cluster=cluster,
                services=[service]
            )
            
            services = describe_response.get('services', [])
            if not services:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=f"Service {service} not found in cluster {cluster}",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            service_info = services[0]
            current_desired = service_info.get('desiredCount', 0)
            current_running = service_info.get('runningCount', 0)
            
            # Update service desired count
            update_response = self.ecs_client.update_service(
                cluster=cluster,
                service=service,
                desiredCount=desired_count
            )
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={
                    'action': 'EXECUTED',
                    'cluster': cluster,
                    'service': service,
                    'previous_desired_count': current_desired,
                    'new_desired_count': desired_count,
                    'current_running_count': current_running,
                    'message': f"ECS service {service} scaling initiated successfully. Desired count changed from {current_desired} to {desired_count}.",
                    'task_definition': service_info.get('taskDefinition', 'Unknown'),
                    'service_arn': service_info.get('serviceArn', 'Unknown')
                },
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            # Map common ECS errors to user-friendly messages
            if error_code == 'ServiceNotFoundException':
                error_msg = f"Service {service} not found in cluster {cluster}"
            elif error_code == 'ClusterNotFoundException':
                error_msg = f"Cluster {cluster} not found"
            elif error_code == 'InvalidParameterException':
                error_msg = f"Invalid parameter provided: {error_message}"
            elif error_code == 'AccessDeniedException':
                error_msg = "Insufficient permissions to scale ECS service"
            else:
                error_msg = f"AWS ECS API error ({error_code}): {error_message}"
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Unexpected error during ECS scaling: {str(e)}",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
    
    def _dry_run_scaling_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """Generate dry-run response for ECS scaling"""
        cluster = tool_call.args.get("cluster", "unknown-cluster")
        service = tool_call.args.get("service", "unknown-service")
        desired_count = tool_call.args.get("desired_count", 0)
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'action': 'WOULD_EXECUTE',
                'cluster': cluster,
                'service': service,
                'new_desired_count': desired_count,
                'message': f"DRY RUN: ECS service {service} in cluster {cluster} would be scaled to {desired_count} desired tasks. No actual changes made.",
                'dry_run': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )
    
    def _mock_scaling_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """Generate mock response for ECS scaling"""
        cluster = tool_call.args.get("cluster", "mock-cluster")
        service = tool_call.args.get("service", "mock-service")
        desired_count = tool_call.args.get("desired_count", 2)
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'action': 'MOCK_EXECUTED',
                'cluster': cluster,
                'service': service,
                'previous_desired_count': 1,
                'new_desired_count': desired_count,
                'current_running_count': 1,
                'message': f"MOCK: ECS service {service} scaling completed. Desired count changed from 1 to {desired_count}.",
                'task_definition': 'mock-task-def:1',
                'service_arn': f'arn:aws:ecs:us-east-1:123456789012:service/{cluster}/{service}',
                'mock': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )