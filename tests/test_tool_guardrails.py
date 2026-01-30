"""
Unit tests for tool guardrails and policy engine
Focus on SANDBOX_LIVE execution mode only as per task requirements
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
    
    def test_creation_with_sandbox_live_only(self):
        """Test creating ToolPolicy with SANDBOX_LIVE mode only"""
        schema = {"type": "object", "properties": {"param": {"type": "string"}}}
        required_tags = {"OpsAgentManaged": "true"}
        allowed_modes = {ExecutionMode.SANDBOX_LIVE}
        
        policy = ToolPolicy(
            tool_name="test_tool",
            allowed=True,
            requires_approval=True,
            allowed_execution_modes=allowed_modes,
            schema=schema,
            requires_resource_tags=True,
            required_tags=required_tags
        )
        
        assert policy.tool_name == "test_tool"
        assert policy.allowed is True
        assert policy.requires_approval is True
        assert policy.allowed_execution_modes == allowed_modes
        assert ExecutionMode.SANDBOX_LIVE in policy.allowed_execution_modes
        assert policy.schema == schema
        assert policy.requires_resource_tags is True
        assert policy.required_tags == required_tags


class TestToolGuardrails:
    """Test ToolGuardrails class - focusing on SANDBOX_LIVE mode"""
    
    @patch('boto3.client')
    def test_initialization_sandbox_live(self, mock_boto_client):
        """Test ToolGuardrails initialization in SANDBOX_LIVE mode"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        assert guardrails.execution_mode == ExecutionMode.SANDBOX_LIVE
        assert len(guardrails.tool_policies) == 9  # All 8 operations plus describe_ec2_instances
        assert len(guardrails.allowed_tools) == 9
        assert guardrails.ec2_client == mock_client
        mock_boto_client.assert_called_once_with('ec2')
    
    @patch('boto3.client')
    def test_initialization_aws_client_failure(self, mock_boto_client):
        """Test ToolGuardrails initialization with AWS client failure"""
        mock_boto_client.side_effect = Exception("AWS credentials not found")
        
        # Should not raise exception, just log warning
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        assert guardrails.ec2_client is None
    
    def test_get_allowed_tools(self):
        """Test getting allowed tools list"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        allowed_tools = guardrails.get_allowed_tools_list()
        
        # Check that all 8 operations from requirements are present
        expected_tools = [
            "get_cloudwatch_metrics",
            "get_ec2_status", 
            "describe_ec2_instances",
            "describe_alb_target_health",
            "search_cloudtrail_events",
            "reboot_ec2_instance",
            "scale_ecs_service",
            "create_incident_record",
            "post_summary_to_channel"
        ]
        
        for tool in expected_tools:
            assert tool in allowed_tools, f"Tool {tool} should be in allowed tools list"
        
        assert len(allowed_tools) == 9  # All 8 operations plus describe_ec2_instances
    
    def test_is_tool_allowed(self):
        """Test checking if tool is allowed"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        # Test read-only diagnostic tools
        assert guardrails.is_tool_allowed("get_cloudwatch_metrics") is True
        assert guardrails.is_tool_allowed("get_ec2_status") is True
        assert guardrails.is_tool_allowed("describe_ec2_instances") is True
        assert guardrails.is_tool_allowed("describe_alb_target_health") is True
        assert guardrails.is_tool_allowed("search_cloudtrail_events") is True
        
        # Test write operations
        assert guardrails.is_tool_allowed("reboot_ec2_instance") is True
        assert guardrails.is_tool_allowed("scale_ecs_service") is True
        
        # Test workflow operations
        assert guardrails.is_tool_allowed("create_incident_record") is True
        assert guardrails.is_tool_allowed("post_summary_to_channel") is True
        
        # Test unknown tool
        assert guardrails.is_tool_allowed("unknown_tool") is False
    
    def test_requires_approval(self):
        """Test checking if tool requires approval"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        # Read-only diagnostic tools should not require approval
        assert guardrails.requires_approval("get_cloudwatch_metrics") is False
        assert guardrails.requires_approval("get_ec2_status") is False
        assert guardrails.requires_approval("describe_ec2_instances") is False
        assert guardrails.requires_approval("describe_alb_target_health") is False
        assert guardrails.requires_approval("search_cloudtrail_events") is False
        
        # Write operations should require approval
        assert guardrails.requires_approval("reboot_ec2_instance") is True
        assert guardrails.requires_approval("scale_ecs_service") is True
        
        # Workflow operations should not require approval
        assert guardrails.requires_approval("create_incident_record") is False
        assert guardrails.requires_approval("post_summary_to_channel") is False
        
        # Unknown tool
        assert guardrails.requires_approval("unknown_tool") is False
    
    def test_get_tool_policy(self):
        """Test getting tool policy"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        # Test read-only diagnostic tool
        policy = guardrails.get_tool_policy("get_cloudwatch_metrics")
        assert policy is not None
        assert policy.tool_name == "get_cloudwatch_metrics"
        assert policy.requires_approval is False
        assert policy.requires_resource_tags is False
        
        # Test write operation
        policy = guardrails.get_tool_policy("reboot_ec2_instance")
        assert policy is not None
        assert policy.requires_approval is True
        assert policy.requires_resource_tags is True
        assert policy.required_tags == {"OpsAgentManaged": "true"}
        
        # Test ECS scaling operation
        policy = guardrails.get_tool_policy("scale_ecs_service")
        assert policy is not None
        assert policy.requires_approval is True
        assert policy.requires_resource_tags is True
        assert policy.required_tags == {"OpsAgentManaged": "true"}
        
        # Test workflow operation
        policy = guardrails.get_tool_policy("create_incident_record")
        assert policy is not None
        assert policy.requires_approval is False
        assert policy.requires_resource_tags is False
        
        # Test unknown tool
        policy = guardrails.get_tool_policy("unknown_tool")
        assert policy is None
    
    def test_validate_tool_call_unknown_tool(self):
        """Test validating unknown tool call"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        tool_call = ToolCall(tool_name="unknown_tool")
        
        with pytest.raises(GuardrailViolation, match="not in the allow-list"):
            guardrails.validate_tool_call(tool_call)
    
    def test_validate_tool_call_execution_mode_restriction(self):
        """Test validating tool call with execution mode restriction"""
        # Create a custom policy that doesn't allow SANDBOX_LIVE
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        guardrails.tool_policies["test_tool"] = ToolPolicy(
            tool_name="test_tool",
            allowed_execution_modes={ExecutionMode.DRY_RUN}  # Only DRY_RUN allowed
        )
        guardrails.allowed_tools.add("test_tool")
        
        tool_call = ToolCall(tool_name="test_tool")
        
        with pytest.raises(GuardrailViolation, match="not allowed in execution mode"):
            guardrails.validate_tool_call(tool_call)
    
    def test_validate_tool_call_schema_validation_success(self):
        """Test successful schema validation"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
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
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
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
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2"
                # Missing required metric_name and resource_id
            }
        )
        
        with pytest.raises(GuardrailViolation, match="Tool arguments validation failed"):
            guardrails.validate_tool_call(tool_call)
    
    @patch('boto3.client')
    def test_validate_resource_tags_success(self, mock_boto_client):
        """Test successful resource tag validation in SANDBOX_LIVE mode"""
        mock_ec2_client = Mock()
        mock_boto_client.return_value = mock_ec2_client
        
        # Mock successful tag response
        mock_ec2_client.describe_tags.return_value = {
            'Tags': [
                {'Key': 'OpsAgentManaged', 'Value': 'true'},
                {'Key': 'Environment', 'Value': 'test'}
            ]
        }
        
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
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
        
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
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
        
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
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
        
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
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
        
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        with pytest.raises(ResourceTagValidationError, match="Insufficient permissions"):
            guardrails.validate_tool_call(tool_call)
    
    def test_validate_resource_tags_no_ec2_client(self):
        """Test resource tag validation without EC2 client"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        guardrails.ec2_client = None  # Simulate client initialization failure
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        with pytest.raises(ResourceTagValidationError, match="EC2 client not available"):
            guardrails.validate_tool_call(tool_call)
    
    def test_enforce_execution_mode_success(self):
        """Test successful execution mode enforcement in SANDBOX_LIVE"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        tool_call = ToolCall(tool_name="get_cloudwatch_metrics")
        
        # Should not raise exception
        guardrails.enforce_execution_mode(tool_call)
    
    def test_enforce_execution_mode_no_policy(self):
        """Test execution mode enforcement with no policy"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        tool_call = ToolCall(tool_name="unknown_tool")
        
        with pytest.raises(GuardrailViolation, match="No policy found"):
            guardrails.enforce_execution_mode(tool_call)
    
    def test_validate_multiple_tool_calls_success(self):
        """Test validating multiple tool calls successfully"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
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
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
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
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        assert guardrails.execution_mode == ExecutionMode.SANDBOX_LIVE
        
        # Test changing to another mode (though task focuses on SANDBOX_LIVE)
        guardrails.set_execution_mode(ExecutionMode.DRY_RUN)
        assert guardrails.execution_mode == ExecutionMode.DRY_RUN
    
    @patch('boto3.client')
    def test_set_execution_mode_with_client_init(self, mock_boto_client):
        """Test setting execution mode with AWS client initialization"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Start without client
        guardrails = ToolGuardrails(ExecutionMode.LOCAL_MOCK)
        guardrails.ec2_client = None
        
        # Change to SANDBOX_LIVE should initialize client
        guardrails.set_execution_mode(ExecutionMode.SANDBOX_LIVE)
        assert guardrails.ec2_client == mock_client
    
    def test_sandbox_live_mode_enforcement(self):
        """Test that SANDBOX_LIVE mode enforces all security controls"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        # Test that write operations require approval
        assert guardrails.requires_approval("reboot_ec2_instance") is True
        assert guardrails.requires_approval("scale_ecs_service") is True
        
        # Test that read operations don't require approval
        assert guardrails.requires_approval("get_cloudwatch_metrics") is False
        assert guardrails.requires_approval("get_ec2_status") is False
        assert guardrails.requires_approval("describe_ec2_instances") is False
        assert guardrails.requires_approval("describe_alb_target_health") is False
        assert guardrails.requires_approval("search_cloudtrail_events") is False
        
        # Test that workflow operations don't require approval
        assert guardrails.requires_approval("create_incident_record") is False
        assert guardrails.requires_approval("post_summary_to_channel") is False
        
        # Test that all tools are allowed in SANDBOX_LIVE mode
        all_tools = [
            "get_cloudwatch_metrics", "get_ec2_status", "describe_ec2_instances",
            "describe_alb_target_health", "search_cloudtrail_events", 
            "reboot_ec2_instance", "scale_ecs_service",
            "create_incident_record", "post_summary_to_channel"
        ]
        
        for tool_name in all_tools:
            policy = guardrails.get_tool_policy(tool_name)
            assert ExecutionMode.SANDBOX_LIVE in policy.allowed_execution_modes
    
    def test_parameter_schema_validation_comprehensive(self):
        """Test comprehensive parameter schema validation for all tools"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        # Test valid CloudWatch metrics call
        valid_cw_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0",
                "time_window": "1h"
            }
        )
        guardrails.validate_tool_call(valid_cw_call)  # Should not raise
        
        # Test valid EC2 status call
        valid_ec2_status_call = ToolCall(
            tool_name="get_ec2_status",
            args={
                "instance_id": "i-1234567890abcdef0",
                "metrics": ["cpu", "memory"],
                "time_window": "15m"
            }
        )
        guardrails.validate_tool_call(valid_ec2_status_call)  # Should not raise
        
        # Test valid ALB target health call
        valid_alb_call = ToolCall(
            tool_name="describe_alb_target_health",
            args={
                "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/1234567890123456"
            }
        )
        guardrails.validate_tool_call(valid_alb_call)  # Should not raise
        
        # Test valid CloudTrail search call
        valid_ct_call = ToolCall(
            tool_name="search_cloudtrail_events",
            args={
                "filter": {
                    "event_name": "RunInstances",
                    "user_name": "admin"
                },
                "time_window": "24h",
                "max_results": 10
            }
        )
        guardrails.validate_tool_call(valid_ct_call)  # Should not raise
        
        # Test valid ECS scaling call (schema validation only)
        valid_ecs_call = ToolCall(
            tool_name="scale_ecs_service",
            args={
                "cluster": "my-cluster",
                "service": "my-service",
                "desired_count": 3
            }
        )
        # This will fail on tag validation, but schema should pass
        try:
            guardrails.validate_tool_call(valid_ecs_call)
        except ResourceTagValidationError:
            pass  # Expected due to no ECS client
        except GuardrailViolation as e:
            if "validation failed" in str(e):
                pytest.fail("Schema validation should have passed")
        
        # Test valid incident record call
        valid_incident_call = ToolCall(
            tool_name="create_incident_record",
            args={
                "summary": "High CPU utilization detected",
                "severity": "medium",
                "links": ["https://console.aws.amazon.com/ec2"]
            }
        )
        guardrails.validate_tool_call(valid_incident_call)  # Should not raise
        
        # Test valid channel posting call
        valid_post_call = ToolCall(
            tool_name="post_summary_to_channel",
            args={
                "text": "System status update",
                "channel_id": "general"
            }
        )
        guardrails.validate_tool_call(valid_post_call)  # Should not raise
    
    def test_resource_tagging_validation_requirement(self):
        """Test that resource tagging validation is properly enforced"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        # Get the write operation policies
        reboot_policy = guardrails.get_tool_policy("reboot_ec2_instance")
        assert reboot_policy.requires_resource_tags is True
        assert reboot_policy.required_tags == {"OpsAgentManaged": "true"}
        
        ecs_policy = guardrails.get_tool_policy("scale_ecs_service")
        assert ecs_policy.requires_resource_tags is True
        assert ecs_policy.required_tags == {"OpsAgentManaged": "true"}
        
        # Get read-only policies
        cw_policy = guardrails.get_tool_policy("get_cloudwatch_metrics")
        assert cw_policy.requires_resource_tags is False
        
        ec2_policy = guardrails.get_tool_policy("describe_ec2_instances")
        assert ec2_policy.requires_resource_tags is False
        
        alb_policy = guardrails.get_tool_policy("describe_alb_target_health")
        assert alb_policy.requires_resource_tags is False
        
        ct_policy = guardrails.get_tool_policy("search_cloudtrail_events")
        assert ct_policy.requires_resource_tags is False
        
        # Get workflow policies
        incident_policy = guardrails.get_tool_policy("create_incident_record")
        assert incident_policy.requires_resource_tags is False
        
        post_policy = guardrails.get_tool_policy("post_summary_to_channel")
        assert post_policy.requires_resource_tags is False
    
    @patch('boto3.client')
    def test_ecs_service_tag_validation(self, mock_boto_client):
        """Test ECS service tag validation"""
        mock_ec2_client = Mock()
        mock_boto_client.return_value = mock_ec2_client
        
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        tool_call = ToolCall(
            tool_name="scale_ecs_service",
            args={
                "cluster": "my-cluster",
                "service": "my-service", 
                "desired_count": 3
            }
        )
        
        # Should not raise exception (ECS validation is simulated)
        guardrails.validate_tool_call(tool_call)
    
    def test_validate_execution_context(self):
        """Test execution context validation"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        # Test valid read-only tool
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0"
            }
        )
        
        result = guardrails.validate_execution_context(tool_call, "test@example.com")
        
        assert result["allowed"] is True
        assert result["requires_approval"] is False
        assert result["requires_tags"] is False
        assert result["execution_mode"] == "SANDBOX_LIVE"
        assert len(result["violations"]) == 0
        assert len(result["recommendations"]) > 0
    
    def test_validate_execution_context_write_operation(self):
        """Test execution context validation for write operation"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        # Test write operation requiring approval
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        result = guardrails.validate_execution_context(tool_call, "test@example.com")
        
        # Will have violations due to tag validation failure, but should show requirements
        assert result["requires_approval"] is True
        assert result["requires_tags"] is True
        assert "approval" in str(result["recommendations"]).lower()
    
    def test_get_execution_summary(self):
        """Test getting execution summary"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        summary = guardrails.get_execution_summary()
        
        assert summary["execution_mode"] == "SANDBOX_LIVE"
        assert summary["total_tools"] == 9
        assert summary["allowed_tools"] == 9
        assert summary["tools_requiring_approval"] == 2  # reboot_ec2_instance, scale_ecs_service
        assert summary["tools_requiring_tags"] == 2  # reboot_ec2_instance, scale_ecs_service
        assert "diagnostic" in summary["tool_categories"]
        assert "write_operations" in summary["tool_categories"]
        assert "workflow" in summary["tool_categories"]
    
    def test_validate_batch_operations(self):
        """Test batch operation validation"""
        guardrails = ToolGuardrails(ExecutionMode.SANDBOX_LIVE)
        
        tool_calls = [
            ToolCall(
                tool_name="get_cloudwatch_metrics",
                args={
                    "namespace": "AWS/EC2",
                    "metric_name": "CPUUtilization",
                    "resource_id": "i-1234567890abcdef0"
                }
            ),
            ToolCall(tool_name="unknown_tool"),  # Invalid
            ToolCall(
                tool_name="create_incident_record",
                args={
                    "summary": "Test incident",
                    "severity": "low"
                }
            )
        ]
        
        results = guardrails.validate_batch_operations(tool_calls)
        
        assert results["total_calls"] == 3
        assert results["valid_calls"] == 2
        assert results["invalid_calls"] == 1
        assert results["approval_required_calls"] == 0
        assert len(results["violations"]) == 1
        assert len(results["call_results"]) == 3