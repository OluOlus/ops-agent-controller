"""
Tool guardrails and policy engine for OpsAgent Controller
Requirements: 4.2, 5.3, 7.1, 7.2, 7.3
"""
import json
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
try:
    from jsonschema import validate, ValidationError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    # Fallback validation function
    def validate(instance, schema):
        pass
    class ValidationError(Exception):
        pass
import boto3
from botocore.exceptions import ClientError

from .models import ToolCall, ExecutionMode

logger = logging.getLogger(__name__)


class GuardrailViolation(Exception):
    """Exception raised when tool guardrails are violated"""
    pass


class ResourceTagValidationError(Exception):
    """Exception raised when resource tag validation fails"""
    pass


@dataclass
class ToolPolicy:
    """Policy definition for a tool"""
    tool_name: str
    allowed: bool = True
    requires_approval: bool = False
    allowed_execution_modes: Set[ExecutionMode] = None
    schema: Optional[Dict[str, Any]] = None
    requires_resource_tags: bool = False
    required_tags: Dict[str, str] = None
    
    def __post_init__(self):
        if self.allowed_execution_modes is None:
            self.allowed_execution_modes = {ExecutionMode.LOCAL_MOCK, ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE}
        if self.required_tags is None:
            self.required_tags = {}


class ToolGuardrails:
    """
    Tool guardrails and policy engine for security controls
    Requirements: 4.2, 5.3, 7.1, 7.2, 7.3
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.LOCAL_MOCK):
        self.execution_mode = execution_mode
        self.tool_policies = self._initialize_tool_policies()
        self.allowed_tools = self._get_allowed_tools()
        
        # Initialize AWS clients for tag validation (only in non-mock modes)
        self.ec2_client = None
        if execution_mode != ExecutionMode.LOCAL_MOCK:
            try:
                self.ec2_client = boto3.client('ec2')
            except Exception as e:
                logger.warning(f"Failed to initialize EC2 client: {e}")
    
    def _initialize_tool_policies(self) -> Dict[str, ToolPolicy]:
        """Initialize tool policies with schemas and requirements"""
        policies = {}
        
        # CloudWatch metrics tool (read-only)
        policies["get_cloudwatch_metrics"] = ToolPolicy(
            tool_name="get_cloudwatch_metrics",
            allowed=True,
            requires_approval=False,
            allowed_execution_modes={ExecutionMode.LOCAL_MOCK, ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE},
            requires_resource_tags=False,
            schema={
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "enum": ["AWS/EC2", "AWS/ECS", "AWS/ApplicationELB", "AWS/NetworkELB", "AWS/Lambda"]
                    },
                    "metric_name": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 255
                    },
                    "resource_id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 255
                    },
                    "time_window": {
                        "type": "string",
                        "enum": ["5m", "15m", "30m", "1h", "6h", "12h", "24h"],
                        "default": "15m"
                    }
                },
                "required": ["namespace", "metric_name", "resource_id"],
                "additionalProperties": False
            }
        )
        
        # EC2 describe tool (read-only)
        policies["describe_ec2_instances"] = ToolPolicy(
            tool_name="describe_ec2_instances",
            allowed=True,
            requires_approval=False,
            allowed_execution_modes={ExecutionMode.LOCAL_MOCK, ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE},
            requires_resource_tags=False,
            schema={
                "type": "object",
                "properties": {
                    "instance_ids": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "pattern": "^i-[0-9a-f]{8,17}$"
                        },
                        "maxItems": 50
                    },
                    "filters": {
                        "type": "object",
                        "properties": {
                            "state": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "enum": ["pending", "running", "shutting-down", "terminated", "stopping", "stopped"]
                                }
                            },
                            "tags": {
                                "type": "object",
                                "additionalProperties": {"type": "string"}
                            }
                        },
                        "additionalProperties": False
                    }
                },
                "additionalProperties": False
            }
        )
        
        # EC2 reboot tool (write operation, requires approval and tags)
        policies["reboot_ec2_instance"] = ToolPolicy(
            tool_name="reboot_ec2_instance",
            allowed=True,
            requires_approval=True,
            allowed_execution_modes={ExecutionMode.LOCAL_MOCK, ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE},
            requires_resource_tags=True,
            required_tags={"OpsAgentManaged": "true"},
            schema={
                "type": "object",
                "properties": {
                    "instance_id": {
                        "type": "string",
                        "pattern": "^i-[0-9a-f]{8,17}$"
                    }
                },
                "required": ["instance_id"],
                "additionalProperties": False
            }
        )
        
        return policies
    
    def _get_allowed_tools(self) -> Set[str]:
        """Get set of allowed tool names"""
        return {name for name, policy in self.tool_policies.items() if policy.allowed}
    
    def validate_tool_call(self, tool_call: ToolCall) -> None:
        """
        Validate a tool call against guardrails
        Requirements: 4.2, 4.3
        
        Args:
            tool_call: The tool call to validate
            
        Raises:
            GuardrailViolation: If the tool call violates any guardrails
        """
        logger.info(f"Validating tool call: {tool_call.tool_name}")
        
        # Check if tool is in allow-list
        if tool_call.tool_name not in self.allowed_tools:
            raise GuardrailViolation(f"Tool '{tool_call.tool_name}' is not in the allow-list")
        
        policy = self.tool_policies[tool_call.tool_name]
        
        # Check execution mode compatibility
        if self.execution_mode not in policy.allowed_execution_modes:
            raise GuardrailViolation(
                f"Tool '{tool_call.tool_name}' is not allowed in execution mode '{self.execution_mode.value}'"
            )
        
        # Validate tool arguments against schema
        if policy.schema:
            try:
                validate(instance=tool_call.args, schema=policy.schema)
            except ValidationError as e:
                raise GuardrailViolation(f"Tool arguments validation failed: {e.message}")
        
        # Validate resource tags if required
        if policy.requires_resource_tags:
            self._validate_resource_tags(tool_call, policy)
        
        logger.info(f"Tool call validation passed: {tool_call.tool_name}")
    
    def _validate_resource_tags(self, tool_call: ToolCall, policy: ToolPolicy) -> None:
        """
        Validate that target resources have required tags
        Requirements: 3.2, 5.3
        
        Args:
            tool_call: The tool call to validate
            policy: The tool policy with tag requirements
            
        Raises:
            ResourceTagValidationError: If resource tag validation fails
        """
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            # In mock mode, assume tags are valid
            logger.info("Skipping tag validation in LOCAL_MOCK mode")
            return
        
        if not self.ec2_client:
            raise ResourceTagValidationError("EC2 client not available for tag validation")
        
        # Extract resource ID based on tool type
        resource_id = None
        if tool_call.tool_name == "reboot_ec2_instance":
            resource_id = tool_call.args.get("instance_id")
        
        if not resource_id:
            raise ResourceTagValidationError(f"Could not extract resource ID from tool call: {tool_call.tool_name}")
        
        try:
            # Get resource tags
            response = self.ec2_client.describe_tags(
                Filters=[
                    {
                        'Name': 'resource-id',
                        'Values': [resource_id]
                    }
                ]
            )
            
            # Convert tags to dictionary
            resource_tags = {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
            
            # Check required tags
            for required_key, required_value in policy.required_tags.items():
                if required_key not in resource_tags:
                    raise ResourceTagValidationError(
                        f"Resource {resource_id} is missing required tag: {required_key}"
                    )
                
                if resource_tags[required_key] != required_value:
                    raise ResourceTagValidationError(
                        f"Resource {resource_id} has incorrect tag value for {required_key}: "
                        f"expected '{required_value}', got '{resource_tags[required_key]}'"
                    )
            
            logger.info(f"Resource tag validation passed for {resource_id}")
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == 'InvalidInstanceID.NotFound':
                raise ResourceTagValidationError(f"Resource {resource_id} not found")
            elif error_code == 'UnauthorizedOperation':
                raise ResourceTagValidationError(f"Insufficient permissions to validate tags for {resource_id}")
            else:
                raise ResourceTagValidationError(f"AWS API error during tag validation: {e}")
        except Exception as e:
            raise ResourceTagValidationError(f"Unexpected error during tag validation: {e}")
    
    def enforce_execution_mode(self, tool_call: ToolCall) -> None:
        """
        Enforce execution mode restrictions
        Requirements: 7.1, 7.2, 7.3
        
        Args:
            tool_call: The tool call to check
            
        Raises:
            GuardrailViolation: If execution mode restrictions are violated
        """
        policy = self.tool_policies.get(tool_call.tool_name)
        if not policy:
            raise GuardrailViolation(f"No policy found for tool: {tool_call.tool_name}")
        
        # Check if tool is allowed in current execution mode
        if self.execution_mode not in policy.allowed_execution_modes:
            raise GuardrailViolation(
                f"Tool '{tool_call.tool_name}' is not permitted in execution mode '{self.execution_mode.value}'"
            )
        
        # Additional mode-specific checks
        if self.execution_mode == ExecutionMode.DRY_RUN:
            # In dry-run mode, write operations should be simulated
            if policy.requires_approval:
                logger.info(f"Tool '{tool_call.tool_name}' will be simulated in DRY_RUN mode")
        
        elif self.execution_mode == ExecutionMode.SANDBOX_LIVE:
            # In sandbox live mode, ensure all safety checks are in place
            if policy.requires_approval and policy.requires_resource_tags:
                logger.info(f"Tool '{tool_call.tool_name}' requires approval and tag validation in SANDBOX_LIVE mode")
    
    def get_tool_policy(self, tool_name: str) -> Optional[ToolPolicy]:
        """
        Get policy for a specific tool
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            ToolPolicy if found, None otherwise
        """
        return self.tool_policies.get(tool_name)
    
    def is_tool_allowed(self, tool_name: str) -> bool:
        """
        Check if a tool is allowed
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool is allowed, False otherwise
        """
        return tool_name in self.allowed_tools
    
    def requires_approval(self, tool_name: str) -> bool:
        """
        Check if a tool requires approval
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool requires approval, False otherwise
        """
        policy = self.tool_policies.get(tool_name)
        return policy.requires_approval if policy else False
    
    def get_allowed_tools_list(self) -> List[str]:
        """
        Get list of all allowed tools
        
        Returns:
            List of allowed tool names
        """
        return list(self.allowed_tools)
    
    def validate_multiple_tool_calls(self, tool_calls: List[ToolCall]) -> List[str]:
        """
        Validate multiple tool calls and return any violations
        
        Args:
            tool_calls: List of tool calls to validate
            
        Returns:
            List of violation messages (empty if all valid)
        """
        violations = []
        
        for i, tool_call in enumerate(tool_calls):
            try:
                self.validate_tool_call(tool_call)
            except (GuardrailViolation, ResourceTagValidationError) as e:
                violations.append(f"Tool call {i+1} ({tool_call.tool_name}): {str(e)}")
        
        return violations
    
    def set_execution_mode(self, execution_mode: ExecutionMode) -> None:
        """
        Update the execution mode
        
        Args:
            execution_mode: New execution mode to set
        """
        logger.info(f"Changing execution mode from {self.execution_mode.value} to {execution_mode.value}")
        self.execution_mode = execution_mode
        
        # Reinitialize AWS clients if needed
        if execution_mode != ExecutionMode.LOCAL_MOCK and not self.ec2_client:
            try:
                self.ec2_client = boto3.client('ec2')
            except Exception as e:
                logger.warning(f"Failed to initialize EC2 client: {e}")
