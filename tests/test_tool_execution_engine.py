"""
Unit tests for tool execution engine
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

from src.tool_execution_engine import (
    ToolExecutionEngine, ExecutionContext, ToolExecutionError, ApprovalRequiredError
)
from src.models import ToolCall, ToolResult, ExecutionMode, ApprovalRequest
from src.tool_guardrails import GuardrailViolation


class TestExecutionContext:
    """Test ExecutionContext dataclass"""
    
    def test_default_creation(self):
        """Test creating ExecutionContext with defaults"""
        context = ExecutionContext(
            correlation_id="test-correlation-id",
            user_id="test-user",
            execution_mode=ExecutionMode.LOCAL_MOCK
        )
        
        assert context.correlation_id == "test-correlation-id"
        assert context.user_id == "test-user"
        assert context.execution_mode == ExecutionMode.LOCAL_MOCK
        assert context.approval_tokens == {}
    
    def test_creation_with_approval_tokens(self):
        """Test creating ExecutionContext with approval tokens"""
        approval_request = ApprovalRequest(
            user_id="test-user",
            tool_call=ToolCall(tool_name="reboot_ec2_instance")
        )
        approval_tokens = {"token123": approval_request}
        
        context = ExecutionContext(
            correlation_id="test-correlation-id",
            user_id="test-user",
            execution_mode=ExecutionMode.DRY_RUN,
            approval_tokens=approval_tokens
        )
        
        assert context.approval_tokens == approval_tokens


class TestToolExecutionEngine:
    """Test ToolExecutionEngine class"""
    
    def test_initialization_local_mock(self):
        """Test ToolExecutionEngine initialization in LOCAL_MOCK mode"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        
        assert engine.execution_mode == ExecutionMode.LOCAL_MOCK
        assert engine.guardrails is not None
        assert engine.aws_clients == {}
        assert len(engine.tool_implementations) == 10
    
    @patch('src.tool_guardrails.boto3.client')
    @patch('src.tool_execution_engine.boto3.client')
    def test_initialization_with_aws_clients(self, mock_execution_boto, mock_guardrails_boto):
        """Test ToolExecutionEngine initialization with AWS clients"""
        mock_cloudwatch = Mock()
        mock_ec2 = Mock()
        mock_elbv2 = Mock()
        mock_cloudtrail = Mock()
        mock_ecs = Mock()
        mock_execution_boto.side_effect = [mock_cloudwatch, mock_ec2, mock_elbv2, mock_cloudtrail, mock_ecs]
        mock_guardrails_boto.return_value = Mock()  # For guardrails EC2 client
        
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        
        # Just verify that clients were created and stored
        assert 'cloudwatch' in engine.aws_clients
        assert 'ec2' in engine.aws_clients
        assert engine.aws_clients['cloudwatch'] is not None
        assert engine.aws_clients['ec2'] is not None
        assert mock_execution_boto.call_count == 5
    
    @patch('src.tool_execution_engine.boto3.client')
    def test_initialization_aws_client_failure(self, mock_boto_client):
        """Test ToolExecutionEngine initialization with AWS client failure"""
        mock_boto_client.side_effect = Exception("AWS credentials not found")
        
        # Should not raise exception, just log error
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        assert engine.aws_clients == {}
    
    def test_execute_tools_validation_failure(self):
        """Test executing tools with validation failure"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.LOCAL_MOCK)
        
        # Create invalid tool call
        tool_calls = [ToolCall(tool_name="unknown_tool")]
        
        results = engine.execute_tools(tool_calls, context)
        
        assert len(results) == 1
        assert results[0].tool_name == "validation"
        assert results[0].success is False
        assert "Tool validation failed" in results[0].error
    
    def test_execute_tools_success(self):
        """Test successful tool execution"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.LOCAL_MOCK)
        
        tool_calls = [
            ToolCall(
                tool_name="get_cloudwatch_metrics",
                args={
                    "namespace": "AWS/EC2",
                    "metric_name": "CPUUtilization",
                    "resource_id": "i-1234567890abcdef0"
                }
            )
        ]
        
        results = engine.execute_tools(tool_calls, context)
        
        assert len(results) == 1
        assert results[0].tool_name == "get_cloudwatch_metrics"
        assert results[0].success is True
        assert results[0].data is not None
        assert results[0].data['mock'] is True
    
    def test_execute_tools_multiple_success(self):
        """Test executing multiple tools successfully"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.LOCAL_MOCK)
        
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
        
        results = engine.execute_tools(tool_calls, context)
        
        assert len(results) == 2
        assert all(result.success for result in results)
        assert results[0].tool_name == "get_cloudwatch_metrics"
        assert results[1].tool_name == "describe_ec2_instances"
    
    def test_execute_tools_with_failure(self):
        """Test executing tools with one failure"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.LOCAL_MOCK)
        
        # Mock a tool implementation to fail
        def failing_tool(tool_call, context):
            raise Exception("Simulated tool failure")
        
        engine.tool_implementations["get_cloudwatch_metrics"] = failing_tool
        
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
        
        results = engine.execute_tools(tool_calls, context)
        
        assert len(results) == 2
        assert results[0].success is False
        assert "Simulated tool failure" in results[0].error
        assert results[1].success is True  # Second tool should still execute
    
    def test_execute_single_tool_approval_required_no_approval(self):
        """Test executing tool requiring approval without approval"""
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        result = engine._execute_single_tool(tool_call, context)
        
        assert result.success is False
        assert "Approval required but not provided" in result.error
    
    def test_execute_single_tool_approval_required_with_approval(self):
        """Test executing tool requiring approval with valid approval"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        
        # Create approval request
        approval_request = ApprovalRequest(
            user_id="test-user",
            tool_call=ToolCall(tool_name="reboot_ec2_instance"),
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        
        context = ExecutionContext(
            "test-id", 
            "test-user", 
            ExecutionMode.LOCAL_MOCK,
            approval_tokens={"token123": approval_request}
        )
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        result = engine._execute_single_tool(tool_call, context)
        
        assert result.success is True
        assert result.data['action'] == 'MOCK_EXECUTED'
    
    def test_execute_single_tool_unknown_implementation(self):
        """Test executing tool with unknown implementation"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.LOCAL_MOCK)
        
        # Remove tool implementation
        del engine.tool_implementations["get_cloudwatch_metrics"]
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0"
            }
        )
        
        result = engine._execute_single_tool(tool_call, context)
        
        assert result.success is False
        assert "Tool implementation not found" in result.error
    
    def test_check_approval_local_mock(self):
        """Test approval check in LOCAL_MOCK mode"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(tool_name="reboot_ec2_instance")
        
        # Should always return True in LOCAL_MOCK mode
        assert engine._check_approval(tool_call, context) is True
    
    def test_check_approval_with_valid_token(self):
        """Test approval check with valid token"""
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        
        approval_request = ApprovalRequest(
            user_id="test-user",
            tool_call=ToolCall(tool_name="reboot_ec2_instance"),
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        
        context = ExecutionContext(
            "test-id",
            "test-user",
            ExecutionMode.DRY_RUN,
            approval_tokens={"token123": approval_request}
        )
        
        tool_call = ToolCall(tool_name="reboot_ec2_instance")
        
        assert engine._check_approval(tool_call, context) is True
    
    def test_check_approval_with_expired_token(self):
        """Test approval check with expired token"""
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        
        approval_request = ApprovalRequest(
            user_id="test-user",
            tool_call=ToolCall(tool_name="reboot_ec2_instance"),
            expires_at=datetime.utcnow() - timedelta(minutes=5)  # Expired
        )
        
        context = ExecutionContext(
            "test-id",
            "test-user",
            ExecutionMode.DRY_RUN,
            approval_tokens={"token123": approval_request}
        )
        
        tool_call = ToolCall(tool_name="reboot_ec2_instance")
        
        assert engine._check_approval(tool_call, context) is False
    
    def test_check_approval_no_matching_token(self):
        """Test approval check with no matching token"""
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(tool_name="reboot_ec2_instance")
        
        assert engine._check_approval(tool_call, context) is False
    
    def test_mock_cloudwatch_metrics(self):
        """Test mock CloudWatch metrics execution"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0",
                "time_window": "30m"
            }
        )
        
        result = engine._mock_cloudwatch_metrics(tool_call, context)
        
        assert result.success is True
        assert result.data['metric_name'] == "CPUUtilization"
        assert result.data['namespace'] == "AWS/EC2"
        assert result.data['resource_id'] == "i-1234567890abcdef0"
        assert result.data['time_window'] == "30m"
        assert result.data['mock'] is True
        assert 'latest_value' in result.data
        assert 'max_value' in result.data
        assert 'min_value' in result.data
    
    def test_mock_describe_ec2_instances(self):
        """Test mock EC2 describe execution"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="describe_ec2_instances",
            args={"instance_ids": ["i-1234567890abcdef0"]}
        )
        
        result = engine._mock_describe_ec2_instances(tool_call, context)
        
        assert result.success is True
        assert result.data['instance_count'] == 1
        assert len(result.data['instances']) == 1
        assert result.data['instances'][0]['instance_id'] == 'i-1234567890abcdef0'
        assert result.data['instances'][0]['tags']['OpsAgentManaged'] == 'true'
        assert result.data['mock'] is True
    
    def test_mock_reboot_ec2_instance(self):
        """Test mock EC2 reboot execution"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        result = engine._mock_reboot_ec2_instance(tool_call, context)
        
        assert result.success is True
        assert result.data['action'] == 'MOCK_EXECUTED'
        assert result.data['instance_id'] == 'i-1234567890abcdef0'
        assert result.data['mock'] is True
    
    @patch('src.tool_guardrails.boto3.client')
    @patch('src.tool_execution_engine.boto3.client')
    def test_execute_cloudwatch_metrics_real(self, mock_execution_boto, mock_guardrails_boto):
        """Test real CloudWatch metrics execution"""
        mock_cloudwatch = Mock()
        mock_ec2 = Mock()
        mock_execution_boto.side_effect = [mock_cloudwatch, mock_ec2]
        mock_guardrails_boto.return_value = Mock()  # For guardrails EC2 client
        
        # Mock CloudWatch response
        mock_cloudwatch.get_metric_statistics.return_value = {
            'Datapoints': [
                {
                    'Timestamp': datetime.utcnow(),
                    'Average': 45.2,
                    'Maximum': 78.5,
                    'Minimum': 12.1
                }
            ],
            'Label': 'Percent'
        }
        
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0",
                "time_window": "15m"
            }
        )
        
        result = engine._execute_cloudwatch_metrics(tool_call, context)
        
        assert result.success is True
        assert result.data['latest_value'] == 45.2
        assert result.data['max_value'] == 78.5
        assert result.data['min_value'] == 12.1
        assert result.data['datapoint_count'] == 1
        
        # Verify API call
        mock_cloudwatch.get_metric_statistics.assert_called_once()
        call_args = mock_cloudwatch.get_metric_statistics.call_args[1]
        assert call_args['Namespace'] == 'AWS/EC2'
        assert call_args['MetricName'] == 'CPUUtilization'
        assert len(call_args['Dimensions']) == 1
        assert call_args['Dimensions'][0]['Name'] == 'InstanceId'
        assert call_args['Dimensions'][0]['Value'] == 'i-1234567890abcdef0'
    
    @patch('src.tool_guardrails.boto3.client')
    @patch('src.tool_execution_engine.boto3.client')
    def test_execute_cloudwatch_metrics_no_data(self, mock_execution_boto, mock_guardrails_boto):
        """Test CloudWatch metrics execution with no data"""
        mock_cloudwatch = Mock()
        mock_ec2 = Mock()
        mock_execution_boto.side_effect = [mock_cloudwatch, mock_ec2]
        mock_guardrails_boto.return_value = Mock()
        
        # Mock empty CloudWatch response
        mock_cloudwatch.get_metric_statistics.return_value = {
            'Datapoints': [],
            'Label': 'Percent'
        }
        
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0"
            }
        )
        
        result = engine._execute_cloudwatch_metrics(tool_call, context)
        
        assert result.success is True
        assert 'No data points found' in result.data['message']
    
    @patch('src.tool_guardrails.boto3.client')
    @patch('src.tool_execution_engine.boto3.client')
    def test_execute_cloudwatch_metrics_api_error(self, mock_execution_boto, mock_guardrails_boto):
        """Test CloudWatch metrics execution with API error"""
        mock_cloudwatch = Mock()
        mock_ec2 = Mock()
        mock_execution_boto.side_effect = [mock_cloudwatch, mock_ec2]
        mock_guardrails_boto.return_value = Mock()
        
        # Mock CloudWatch API error
        mock_cloudwatch.get_metric_statistics.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'get_metric_statistics'
        )
        
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0"
            }
        )
        
        result = engine._execute_cloudwatch_metrics(tool_call, context)
        
        assert result.success is False
        assert "AWS CloudWatch API error" in result.error
        assert "Access denied" in result.error
    
    def test_execute_cloudwatch_metrics_no_client(self):
        """Test CloudWatch metrics execution without client"""
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        engine.aws_clients = {}  # No clients available
        engine.cloudwatch_tool.cloudwatch_client = None  # Also clear the tool's client
        context = ExecutionContext("test-id", "test-user", ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "resource_id": "i-1234567890abcdef0"
            }
        )
        
        result = engine._execute_cloudwatch_metrics(tool_call, context)
        
        assert result.success is False
        assert "CloudWatch client not available" in result.error
    
    @patch('src.tool_guardrails.boto3.client')
    @patch('src.tool_execution_engine.boto3.client')
    def test_execute_describe_ec2_instances_real(self, mock_execution_boto, mock_guardrails_boto):
        """Test real EC2 describe execution"""
        mock_cloudwatch = Mock()
        mock_ec2 = Mock()
        mock_execution_boto.side_effect = [mock_cloudwatch, mock_ec2]
        mock_guardrails_boto.return_value = Mock()
        
        # Mock EC2 response
        mock_ec2.describe_instances.return_value = {
            'Reservations': [
                {
                    'Instances': [
                        {
                            'InstanceId': 'i-1234567890abcdef0',
                            'InstanceType': 't3.medium',
                            'State': {'Name': 'running'},
                            'LaunchTime': datetime.utcnow(),
                            'Placement': {'AvailabilityZone': 'us-east-1a'},
                            'VpcId': 'vpc-12345678',
                            'SubnetId': 'subnet-12345678',
                            'PrivateIpAddress': '10.0.1.100',
                            'PublicIpAddress': '54.123.45.67',
                            'Tags': [
                                {'Key': 'Name', 'Value': 'test-instance'},
                                {'Key': 'OpsAgentManaged', 'Value': 'true'}
                            ]
                        }
                    ]
                }
            ]
        }
        
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="describe_ec2_instances",
            args={"instance_ids": ["i-1234567890abcdef0"]}
        )
        
        result = engine._execute_describe_ec2_instances(tool_call, context)
        
        assert result.success is True
        assert result.data['instance_count'] == 1
        assert len(result.data['instances']) == 1
        
        instance = result.data['instances'][0]
        assert instance['instance_id'] == 'i-1234567890abcdef0'
        assert instance['instance_type'] == 't3.medium'
        assert instance['state'] == 'running'
        assert instance['tags']['OpsAgentManaged'] == 'true'
        
        # Verify API call
        mock_ec2.describe_instances.assert_called_once_with(
            InstanceIds=['i-1234567890abcdef0']
        )
    
    def test_execute_reboot_ec2_instance_dry_run(self):
        """Test EC2 reboot in DRY_RUN mode"""
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        result = engine._execute_reboot_ec2_instance(tool_call, context)
        
        assert result.success is True
        assert result.data['action'] == 'WOULD_EXECUTE'
        assert result.data['instance_id'] == 'i-1234567890abcdef0'
        assert 'would be rebooted' in result.data['message']
    
    @patch('src.tool_guardrails.boto3.client')
    @patch('src.tool_execution_engine.boto3.client')
    def test_execute_reboot_ec2_instance_real(self, mock_execution_boto, mock_guardrails_boto):
        """Test real EC2 reboot execution"""
        mock_cloudwatch = Mock()
        mock_ec2 = Mock()
        mock_elbv2 = Mock()
        mock_cloudtrail = Mock()
        mock_ecs = Mock()
        mock_execution_boto.side_effect = [mock_cloudwatch, mock_ec2, mock_elbv2, mock_cloudtrail, mock_ecs]
        mock_guardrails_boto.return_value = Mock()
        
        # Mock EC2 describe_instances response (for validation)
        mock_ec2.describe_instances.return_value = {
            'Reservations': [
                {
                    'Instances': [
                        {
                            'InstanceId': 'i-1234567890abcdef0',
                            'State': {'Name': 'running'},
                            'InstanceType': 't3.medium',
                            'Placement': {'AvailabilityZone': 'us-east-1a'}
                        }
                    ]
                }
            ]
        }
        
        # Mock EC2 reboot response
        mock_ec2.reboot_instances.return_value = {
            'ResponseMetadata': {'RequestId': 'req-12345'}
        }
        
        engine = ToolExecutionEngine(ExecutionMode.SANDBOX_LIVE)
        context = ExecutionContext("test-id", "test-user", ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={"instance_id": "i-1234567890abcdef0"}
        )
        
        result = engine._execute_reboot_ec2_instance(tool_call, context)
        
        assert result.success is True
        assert result.data['action'] == 'WOULD_EXECUTE'  # Sandbox mode returns WOULD_EXECUTE
        assert result.data['instance_id'] == 'i-1234567890abcdef0'
        assert 'would be executed' in result.data['message']
        
        # Verify API call
        mock_ec2.describe_instances.assert_called_once_with(
            InstanceIds=['i-1234567890abcdef0']
        )
    
    def test_parse_time_window(self):
        """Test time window parsing"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        
        assert engine._parse_time_window('5m') == timedelta(minutes=5)
        assert engine._parse_time_window('15m') == timedelta(minutes=15)
        assert engine._parse_time_window('30m') == timedelta(minutes=30)
        assert engine._parse_time_window('1h') == timedelta(hours=1)
        assert engine._parse_time_window('6h') == timedelta(hours=6)
        assert engine._parse_time_window('12h') == timedelta(hours=12)
        assert engine._parse_time_window('24h') == timedelta(hours=24)
        assert engine._parse_time_window('invalid') == timedelta(minutes=15)  # Default
    
    def test_get_metric_dimensions(self):
        """Test metric dimensions generation"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        
        # Test EC2 dimensions
        dims = engine._get_metric_dimensions('AWS/EC2', 'i-1234567890abcdef0')
        assert dims == [{'Name': 'InstanceId', 'Value': 'i-1234567890abcdef0'}]
        
        # Test ECS dimensions
        dims = engine._get_metric_dimensions('AWS/ECS', 'my-service')
        assert dims == [{'Name': 'ServiceName', 'Value': 'my-service'}]
        
        # Test ALB dimensions
        dims = engine._get_metric_dimensions('AWS/ApplicationELB', 'my-alb')
        assert dims == [{'Name': 'LoadBalancer', 'Value': 'my-alb'}]
        
        # Test Lambda dimensions
        dims = engine._get_metric_dimensions('AWS/Lambda', 'my-function')
        assert dims == [{'Name': 'FunctionName', 'Value': 'my-function'}]
        
        # Test unknown namespace
        dims = engine._get_metric_dimensions('AWS/Unknown', 'resource-id')
        assert dims == [{'Name': 'ResourceId', 'Value': 'resource-id'}]
    
    def test_set_execution_mode(self):
        """Test setting execution mode"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        assert engine.execution_mode == ExecutionMode.LOCAL_MOCK
        
        engine.set_execution_mode(ExecutionMode.DRY_RUN)
        assert engine.execution_mode == ExecutionMode.DRY_RUN
        assert engine.guardrails.execution_mode == ExecutionMode.DRY_RUN
    
    @patch('src.tool_guardrails.boto3.client')
    @patch('src.tool_execution_engine.boto3.client')
    def test_set_execution_mode_with_client_init(self, mock_execution_boto, mock_guardrails_boto):
        """Test setting execution mode with AWS client initialization"""
        mock_cloudwatch = Mock()
        mock_ec2 = Mock()
        mock_execution_boto.side_effect = [mock_cloudwatch, mock_ec2]
        mock_guardrails_boto.return_value = Mock()
        
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        assert engine.aws_clients == {}
        
        engine.set_execution_mode(ExecutionMode.DRY_RUN)
        # Just verify that clients were created
        assert 'cloudwatch' in engine.aws_clients
        assert 'ec2' in engine.aws_clients
    
    def test_get_execution_status(self):
        """Test getting execution status"""
        engine = ToolExecutionEngine(ExecutionMode.LOCAL_MOCK)
        status = engine.get_execution_status()
        
        assert status['execution_mode'] == 'LOCAL_MOCK'
        assert status['aws_clients_initialized'] is False
        assert 'get_cloudwatch_metrics' in status['available_tools']
        assert 'describe_ec2_instances' in status['available_tools']
        assert 'reboot_ec2_instance' in status['available_tools']
        assert status['guardrails_active'] is True
    
    @patch('src.tool_execution_engine.boto3.client')
    def test_get_execution_status_with_clients(self, mock_boto_client):
        """Test getting execution status with AWS clients"""
        mock_cloudwatch = Mock()
        mock_ec2 = Mock()
        mock_boto_client.side_effect = [mock_cloudwatch, mock_ec2]
        
        engine = ToolExecutionEngine(ExecutionMode.DRY_RUN)
        status = engine.get_execution_status()
        
        assert status['execution_mode'] == 'DRY_RUN'
        assert status['aws_clients_initialized'] is True