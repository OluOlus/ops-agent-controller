"""
Unit tests for tool guardrails and policy engine
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError

from src.tool_guardrails import (
    ToolGuardrails, ToolPolicy, GuardrailViolation, ResourceTagValidationError
)
from src.models import ToolCall, ExecutionMode


class TestToolPolicy:
    """Test ToolPolicy dataclass"""
    
    def test_default_creation(self):
        """Test creating ToolPolicy with defaults"""
        policy = ToolPolicy(tool_name="test_tool")
        
        assert policy.tool_name == "test_tool"
        assert policy.allowed is True
        assert policy.requires_approval is False
        assert ExecutionMode.LOCAL_MOCK in policy.allowed_execution_modes
        assert ExecutionMode.DRY_RUN in policy.allowed_execution_modes
        assert ExecutionMode.SANDBOX_LIVE in policy.allowed_execution_modes
        assert policy.schema is None
        assert policy.requires_resource_tags is False
        assert policy.required_tags == {}
    
    def test_creation_with_values(self):
        """Test creating ToolPolicy with specific values"""
        schema = {"type": "object", "properties": {"param": {"type": "string"}}}
        required_tags = {"Environment": "test"}
        allowed_modes = {ExecutionMode.LOCAL_MOCK, ExecutionMode.DRY_RUN}
        
        policy = ToolPolicy(
            tool_name="test_tool",
            allowed=False,
            requires_approval=True,
            allowed_execution_modes=allowed_modes,
            schema=schema,
            requires_resource_tags=True,
            required_tags=required_tags
        )
        
        assert policy.tool_name == "test_tool"
        assert policy.allowed is False
        assert policy.requires_approval is True
        assert policy.allowed_execution_modes == allowed_modes
        assert policy.schema == schema
        assert policy.requires_resource_tags is True
        assert policy.required_tags == required_tags


class TestToolGuardrails:
    """Test ToolGuardrails class"""
    
    def test_initialization_local_mock(self):
        """Test ToolGuardrails initialization in LOCAL_MOCK mode"""
        guardrails = ToolGuardrails(ExecutionMode.LOCAL_MOCK)
        
        assert guardrails.execution_mode == ExecutionMode.LOCAL_MOCK
        assert len(guardrails.tool_policies) == 3  # get_cloudwatch_metrics, describe_ec2_instances, reboot_ec2_instance
        assert len(guardrails.allowed_tools) == 3
        assert guardrails.ec2_client is None
    
    @patch('boto3.client')
    def test_initialization_dry_run(self, mock_boto_client):
        """Test ToolGuardrails initialization in DRY_RUN mode"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        guardrails = ToolGuardrails(ExecutionMode.DRY_RUN)
        
        assert guardrails.execution_mode == ExecutionMode.DRY_RUN
        assert guardrails.ec2_client == mock_client
        mock_boto_client.assert_called_once_with('ec2')
    
    @patch('boto3.client')
    def test_initialization_aws_client_failure(self, mock_boto_client):
        """Test ToolGuardrails initialization with AWS client failure"""
        mock_boto_client.side_effect = Exception("AWS credentials not found")
        
        # Should not raise exception, just log warning
        guardrails = ToolGuardrails(ExecutionMode.DRY_RUN)
        assert guardrails.ec2_client is None
    
    def test_get_allowed_tools(self):
        """Test getting allowed tools list"""
        guardrails = ToolGuardrails()
        allowed_tools = guardrails.get_allowed_tools_list()
        
        assert "get_cloudwatch_metrics" in allowed_tools
        assert "describe_ec2_instances" in allowed_tools
        assert "reboot_ec2_instance" in allowed_tools
        assert len(allowed_tools) == 3
    
    def test_is_tool_allowed(self):
        """Test checking if tool is allowed"""
        guardrails = ToolGuardrails()
        
        assert guardrails.is_tool_allowed("get_cloudwatch_metrics") is True
        assert guardrails.is_tool_allowed("describe_ec2_instances") is True
        assert guardrails.is_tool_allowed("reboot_ec2_instance") is True
        assert guardrails.is_tool_allowed("unknown_tool") is False
    
    def test_requires_approval(self):
        """Test checking if tool requires approval"""
        guardrails = ToolGuardrails()
        
        assert guardrails.requires_approval("get_cloudwatch_metrics") is False
        assert guardrails.requires_approval("describe_ec2_instances") is False
        assert guardrails.requires_approval("reboot_ec2_instance") is True
        assert guardrails.requires_approval("unknown_tool") is False
    
    def test_get_tool_policy(self):
        """Test getting tool policy"""
        guardrails = ToolGuardrails()
        
        policy = guardrails.get_tool_policy("get_cloudwatch_metrics")
        assert policy is not None
        assert policy.tool_name == "get_cloudwatch_metrics"
        assert policy.requires_approval is False
        
        policy = guardrails.get_tool_policy("reboot_ec2_instance")
        assert policy is not None
        assert policy.requires_approval is True
        assert policy.requires_resource_tags is True
        
        policy = guardrails.get_tool_policy("unknown_tool")
        assert policy is None
    
    def test_validate_tool_call_unknown_tool(self):
        """Test validating unknown tool call"""
        guardrails = ToolGuardrails()
        tool_call = ToolCall(tool_name="unknown_tool")
        
        with pytest.raises(GuardrailViolation, match="not in the allow-list"):
            guardrails.validate_tool_call(tool_call)
    
    def test_validate_tool_call_execution_mode_restriction(self):
        """Test validating tool call with execution mode restriction"""
        # Create a custom policy that doesn't allow LOCAL_MOCK
        guardrails = ToolGuardrails(ExecutionMode.LOCAL_MOCK)
        guardrails.tool_policies["test_tool"] = ToolPolicy(
            tool_name="test_tool",
            allowed_execution_modes={ExecutionMode.DRY_RUN}
        )
        guardrails.allowed_tools.add("test_tool")
        
        tool_call = ToolCall(tool_name="test_tool")
        
        with pytest.raises(GuardrailViolation, match="not allowed in execution mode"):
            guardrails.validate_tool_call(tool_call)
    
    def test_validate_tool_call_schema_validation_success(self):
        """Test successful schema validation"""
        guardrails = ToolGuardrails()
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0",
                "time_window": "15m"
            }
        )
        
        # Should not raise exception
        guardrails.validate_tool_call(tool_call)
    
    def test_validate_tool_call_schema_validation_failure(self):
        """Test schema validation failure"""
        guardrails = ToolGuardrails()
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "INVALID_NAMESPACE",  # Not in enum
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0"
            }
        )
        
        with pytest.raises(GuardrailViolation, match="Tool arguments validation failed"):
            guardrails.validate_tool_call(tool_call)
    
    def test_validate_tool_call_missing_required_args(self):
        """Test validation with missing required arguments"""
        guardrails = ToolGuardrails()
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2"
                # Missing required metric_name and resource_id
            }
        )
        
        with pytest.raises(GuardrailViolation, match="Tool arguments validation failed"):
            guardrails.validate_tool_call(tool_call)
    
    def test_validate_tool_call_with_resource_tags_local_mock(self):
        """Test resource tag validation in LOCAL_MOCK mode (should skip)"""
        guardrails = ToolGuardrails(ExecutionMode.LOCAL_MOCK)
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        # Should not raise exception in LOCAL_MOCK mode
        guardrails.validate_tool_call(tool_call)
    
    @patch('boto3.client')
    def test_validate_resource_tags_success(self, mock_boto_client):
        """Test successful resource tag validation"""
        mock_ec2_client = Mock()
        mock_boto_client.return_value = mock_ec2_client
        
        # Mock successful tag response
        mock_ec2_client.describe_tags.return_value = {
            'Tags': [
                {'Key': 'OpsAgentManaged', 'Value': 'true'},
                {'Key': 'Environment', 'Value': 'test'}
            ]
        }
        
        guardrails = ToolGuardrails(ExecutionMode.DRY_RUN)
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        # Should not raise exception
        guardrails.validate_tool_call(tool_call)
        
        # Verify API call
        mock_ec2_client.describe_tags.assert_called_once_with(
            Filters=[{'Name': 'resource-id', 'Values': ['i-1234567890abcdef0']}]
        )
    
    @patch('boto3.client')
    def test_validate_resource_tags_missing_tag(self, mock_boto_client):
        """Test resource tag validation with missing required tag"""
        mock_ec2_client = Mock()
        mock_boto_client.return_value = mock_ec2_client
        
        # Mock response without required tag
        mock_ec2_client.describe_tags.return_value = {
            'Tags': [
                {'Key': 'Environment', 'Value': 'test'}
                # Missing OpsAgentManaged tag
            ]
        }
        
        guardrails = ToolGuardrails(ExecutionMode.DRY_RUN)
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        with pytest.raises(ResourceTagValidationError, match="missing required tag"):
            guardrails.validate_tool_call(tool_call)
    
    @patch('boto3.client')
    def test_validate_resource_tags_incorrect_value(self, mock_boto_client):
        """Test resource tag validation with incorrect tag value"""
        mock_ec2_client = Mock()
        mock_boto_client.return_value = mock_ec2_client
        
        # Mock response with incorrect tag value
        mock_ec2_client.describe_tags.return_value = {
            'Tags': [
                {'Key': 'OpsAgentManaged', 'Value': 'false'},  # Should be 'true'
                {'Key': 'Environment', 'Value': 'test'}
            ]
        }
        
        guardrails = ToolGuardrails(ExecutionMode.DRY_RUN)
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        with pytest.raises(ResourceTagValidationError, match="incorrect tag value"):
            guardrails.validate_tool_call(tool_call)
    
    @patch('boto3.client')
    def test_validate_resource_tags_instance_not_found(self, mock_boto_client):
        """Test resource tag validation with instance not found"""
        mock_ec2_client = Mock()
        mock_boto_client.return_value = mock_ec2_client
        
        # Mock ClientError for instance not found
        mock_ec2_client.describe_tags.side_effect = ClientError(
            {'Error': {'Code': 'InvalidInstanceID.NotFound', 'Message': 'Instance not found'}},
            'describe_tags'
        )
        
        guardrails = ToolGuardrails(ExecutionMode.DRY_RUN)
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}  # Valid format but non-existent
        )
        
        with pytest.raises(ResourceTagValidationError, match="not found"):
            guardrails.validate_tool_call(tool_call)
    
    @patch('boto3.client')
    def test_validate_resource_tags_unauthorized(self, mock_boto_client):
        """Test resource tag validation with unauthorized access"""
        mock_ec2_client = Mock()
        mock_boto_client.return_value = mock_ec2_client
        
        # Mock ClientError for unauthorized operation
        mock_ec2_client.describe_tags.side_effect = ClientError(
            {'Error': {'Code': 'UnauthorizedOperation', 'Message': 'Access denied'}},
            'describe_tags'
        )
        
        guardrails = ToolGuardrails(ExecutionMode.DRY_RUN)
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        with pytest.raises(ResourceTagValidationError, match="Insufficient permissions"):
            guardrails.validate_tool_call(tool_call)
    
    def test_validate_resource_tags_no_ec2_client(self):
        """Test resource tag validation without EC2 client"""
        guardrails = ToolGuardrails(ExecutionMode.DRY_RUN)
        guardrails.ec2_client = None  # Simulate client initialization failure
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        with pytest.raises(ResourceTagValidationError, match="EC2 client not available"):
            guardrails.validate_tool_call(tool_call)
    
    def test_enforce_execution_mode_success(self):
        """Test successful execution mode enforcement"""
        guardrails = ToolGuardrails(ExecutionMode.DRY_RUN)
        tool_call = ToolCall(tool_name="get_cloudwatch_metrics")
        
        # Should not raise exception
        guardrails.enforce_execution_mode(tool_call)
    
    def test_enforce_execution_mode_no_policy(self):
        """Test execution mode enforcement with no policy"""
        guardrails = ToolGuardrails()
        tool_call = ToolCall(tool_name="unknown_tool")
        
        with pytest.raises(GuardrailViolation, match="No policy found"):
            guardrails.enforce_execution_mode(tool_call)
    
    def test_validate_multiple_tool_calls_success(self):
        """Test validating multiple tool calls successfully"""
        guardrails = ToolGuardrails()
        tool_calls = [
            ToolCall(
                tool_name="get_cloudwatch_metrics",
                args={
                    "namespace": "AWS/EC2",
                    "metric_name": "CPUUtilization",
                    "resource_id": "i-1234567890abcdef0"
                }
            ),
            ToolCall(
                tool_name="describe_ec2_instances",
                args={"instance_ids": ["i-1234567890abcdef0"]}
            )
        ]
        
        violations = guardrails.validate_multiple_tool_calls(tool_calls)
        assert violations == []
    
    def test_validate_multiple_tool_calls_with_violations(self):
        """Test validating multiple tool calls with violations"""
        guardrails = ToolGuardrails()
        tool_calls = [
            ToolCall(tool_name="unknown_tool"),  # Violation: not in allow-list
            ToolCall(
                tool_name="get_cloudwatch_metrics",
                args={"namespace": "INVALID"}  # Violation: invalid schema
            )
        ]
        
        violations = guardrails.validate_multiple_tool_calls(tool_calls)
        assert len(violations) == 2
        assert "not in the allow-list" in violations[0]
        assert "validation failed" in violations[1]
    
    def test_set_execution_mode(self):
        """Test setting execution mode"""
        guardrails = ToolGuardrails(ExecutionMode.LOCAL_MOCK)
        assert guardrails.execution_mode == ExecutionMode.LOCAL_MOCK
        
        guardrails.set_execution_mode(ExecutionMode.DRY_RUN)
        assert guardrails.execution_mode == ExecutionMode.DRY_RUN
    
    @patch('boto3.client')
    def test_set_execution_mode_with_client_init(self, mock_boto_client):
        """Test setting execution mode with AWS client initialization"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        guardrails = ToolGuardrails(ExecutionMode.LOCAL_MOCK)
        assert guardrails.ec2_client is None
        
        guardrails.set_execution_mode(ExecutionMode.DRY_RUN)
        assert guardrails.ec2_client == mock_client