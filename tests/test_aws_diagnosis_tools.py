"""
Unit tests for AWS diagnosis tools
Requirements: 2.1, 2.2, 2.4, 2.5
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

from src.aws_diagnosis_tools import CloudWatchMetricsTool, EC2DescribeTool, EC2StatusTool, AWSToolError
from src.models import ToolCall, ToolResult, ExecutionMode


class TestCloudWatchMetricsTool:
    """Test CloudWatch metrics tool functionality"""
    
    def test_init_local_mock_mode(self):
        """Test initialization in LOCAL_MOCK mode"""
        tool = CloudWatchMetricsTool(ExecutionMode.LOCAL_MOCK)
        assert tool.execution_mode == ExecutionMode.LOCAL_MOCK
        assert tool.cloudwatch_client is None
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_init_dry_run_mode(self, mock_boto_client):
        """Test initialization in DRY_RUN mode"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        tool = CloudWatchMetricsTool(ExecutionMode.DRY_RUN)
        assert tool.execution_mode == ExecutionMode.DRY_RUN
        assert tool.cloudwatch_client == mock_client
        mock_boto_client.assert_called_once_with('cloudwatch')
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_init_client_failure(self, mock_boto_client):
        """Test client initialization failure"""
        mock_boto_client.side_effect = Exception("AWS credentials not found")
        
        # Should not raise exception, just log error and continue with None client
        tool = CloudWatchMetricsTool(ExecutionMode.DRY_RUN)
        assert tool.cloudwatch_client is None
    
    def test_parse_time_window_valid(self):
        """Test parsing valid time window strings"""
        tool = CloudWatchMetricsTool()
        
        assert tool._parse_time_window('5m') == timedelta(minutes=5)
        assert tool._parse_time_window('15m') == timedelta(minutes=15)
        assert tool._parse_time_window('1h') == timedelta(hours=1)
        assert tool._parse_time_window('24h') == timedelta(hours=24)
    
    def test_parse_time_window_invalid(self):
        """Test parsing invalid time window strings"""
        tool = CloudWatchMetricsTool()
        
        with pytest.raises(ValueError, match="Invalid time window"):
            tool._parse_time_window('invalid')
    
    def test_get_metric_dimensions(self):
        """Test metric dimensions generation for different namespaces"""
        tool = CloudWatchMetricsTool()
        
        # EC2 dimensions
        dims = tool._get_metric_dimensions('AWS/EC2', 'i-1234567890abcdef0')
        assert dims == [{'Name': 'InstanceId', 'Value': 'i-1234567890abcdef0'}]
        
        # ECS dimensions
        dims = tool._get_metric_dimensions('AWS/ECS', 'my-service')
        assert dims == [{'Name': 'ServiceName', 'Value': 'my-service'}]
        
        # Lambda dimensions
        dims = tool._get_metric_dimensions('AWS/Lambda', 'my-function')
        assert dims == [{'Name': 'FunctionName', 'Value': 'my-function'}]
        
        # Unknown namespace
        dims = tool._get_metric_dimensions('AWS/Unknown', 'resource-123')
        assert dims == [{'Name': 'ResourceId', 'Value': 'resource-123'}]
    
    def test_execute_mock_mode(self):
        """Test execution in LOCAL_MOCK mode"""
        tool = CloudWatchMetricsTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                'namespace': 'AWS/EC2',
                'metric_name': 'CPUUtilization',
                'resource_id': 'i-1234567890abcdef0',
                'time_window': '15m'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.tool_name == "get_cloudwatch_metrics"
        assert result.execution_mode == ExecutionMode.LOCAL_MOCK
        assert result.correlation_id == 'test-correlation-id'
        assert result.data['mock'] is True
        assert result.data['metric_name'] == 'CPUUtilization'
        assert result.data['namespace'] == 'AWS/EC2'
        assert result.data['resource_id'] == 'i-1234567890abcdef0'
        assert 'summary' in result.data
    
    def test_execute_missing_parameters(self):
        """Test execution with missing required parameters"""
        tool = CloudWatchMetricsTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={'namespace': 'AWS/EC2'}  # Missing metric_name and resource_id
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Missing required parameter" in result.error
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_with_real_api_success(self, mock_boto_client):
        """Test execution with successful CloudWatch API call"""
        # Mock CloudWatch client and response
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        mock_response = {
            'Datapoints': [
                {
                    'Timestamp': datetime.utcnow() - timedelta(minutes=10),
                    'Average': 45.2,
                    'Maximum': 78.5,
                    'Minimum': 12.1,
                    'Sum': 452.0,
                    'SampleCount': 10
                },
                {
                    'Timestamp': datetime.utcnow() - timedelta(minutes=5),
                    'Average': 52.1,
                    'Maximum': 85.0,
                    'Minimum': 15.3,
                    'Sum': 521.0,
                    'SampleCount': 10
                }
            ],
            'Label': 'Percent'
        }
        mock_client.get_metric_statistics.return_value = mock_response
        
        tool = CloudWatchMetricsTool(ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                'namespace': 'AWS/EC2',
                'metric_name': 'CPUUtilization',
                'resource_id': 'i-1234567890abcdef0',
                'time_window': '15m'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['status'] == 'success'
        assert result.data['latest_value'] == 52.1
        assert result.data['max_value'] == 85.0
        assert result.data['min_value'] == 12.1
        assert result.data['datapoint_count'] == 2
        assert result.data['unit'] == 'Percent'
        assert 'summary' in result.data
        
        # Verify API call
        mock_client.get_metric_statistics.assert_called_once()
        call_args = mock_client.get_metric_statistics.call_args[1]
        assert call_args['Namespace'] == 'AWS/EC2'
        assert call_args['MetricName'] == 'CPUUtilization'
        assert call_args['Dimensions'] == [{'Name': 'InstanceId', 'Value': 'i-1234567890abcdef0'}]
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_no_data_points(self, mock_boto_client):
        """Test execution when no data points are returned"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        mock_client.get_metric_statistics.return_value = {'Datapoints': []}
        
        tool = CloudWatchMetricsTool(ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                'namespace': 'AWS/EC2',
                'metric_name': 'CPUUtilization',
                'resource_id': 'i-1234567890abcdef0'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['status'] == 'no_data'
        assert 'No data points found' in result.data['message']
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_aws_api_error(self, mock_boto_client):
        """Test execution with AWS API error"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock ClientError
        error_response = {
            'Error': {
                'Code': 'AccessDenied',
                'Message': 'User is not authorized to perform cloudwatch:GetMetricStatistics'
            }
        }
        mock_client.get_metric_statistics.side_effect = ClientError(error_response, 'GetMetricStatistics')
        
        tool = CloudWatchMetricsTool(ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="get_cloudwatch_metrics",
            args={
                'namespace': 'AWS/EC2',
                'metric_name': 'CPUUtilization',
                'resource_id': 'i-1234567890abcdef0'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Insufficient permissions to access CloudWatch metrics" in result.error
    
    def test_generate_metrics_summary_cpu(self):
        """Test metrics summary generation for CPU metrics"""
        tool = CloudWatchMetricsTool()
        
        summary = tool._generate_metrics_summary(
            'CPUUtilization', 'AWS/EC2', 'i-123', 85.5, [90.0], [10.0], '15m'
        )
        
        assert 'EC2 CPUUtilization for i-123' in summary
        assert 'Current: 85.5% (HIGH)' in summary
        assert 'Peak: 90.0%' in summary
        assert 'Low: 10.0%' in summary
    
    def test_generate_metrics_summary_errors(self):
        """Test metrics summary generation for error metrics"""
        tool = CloudWatchMetricsTool()
        
        summary = tool._generate_metrics_summary(
            'Errors', 'AWS/Lambda', 'my-function', 5.0, [10.0], [0.0], '1h'
        )
        
        assert 'Lambda Errors for my-function' in summary
        assert 'Current: 5 (ERRORS DETECTED)' in summary
        assert 'Peak: 10' in summary
    
    def test_generate_metrics_summary_latency(self):
        """Test metrics summary generation for latency metrics"""
        tool = CloudWatchMetricsTool()
        
        summary = tool._generate_metrics_summary(
            'Duration', 'AWS/Lambda', 'my-function', 1500.0, [2000.0], [500.0], '30m'
        )
        
        assert 'Lambda Duration for my-function' in summary
        assert 'Current: 1500ms (HIGH LATENCY)' in summary
        assert 'Peak: 2000ms' in summary
    
    def test_format_aws_error(self):
        """Test AWS error formatting"""
        tool = CloudWatchMetricsTool()
        
        # Test known error code
        error = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'GetMetricStatistics'
        )
        formatted = tool._format_aws_error(error, 'CloudWatch')
        assert formatted == "Insufficient permissions to access CloudWatch metrics"
        
        # Test credential-related error (should be sanitized)
        error = ClientError(
            {'Error': {'Code': 'InvalidCredentials', 'Message': 'Invalid AWS credentials provided'}},
            'GetMetricStatistics'
        )
        formatted = tool._format_aws_error(error, 'CloudWatch')
        assert formatted == "Authentication error accessing CloudWatch service"


class TestEC2StatusTool:
    """Test EC2 status tool functionality with CloudWatch metrics integration"""
    
    def test_init_local_mock_mode(self):
        """Test initialization in LOCAL_MOCK mode"""
        tool = EC2StatusTool(ExecutionMode.LOCAL_MOCK)
        assert tool.execution_mode == ExecutionMode.LOCAL_MOCK
        assert tool.ec2_client is None
        assert tool.cloudwatch_client is None
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_init_sandbox_live_mode(self, mock_boto_client):
        """Test initialization in SANDBOX_LIVE mode"""
        mock_ec2_client = Mock()
        mock_cw_client = Mock()
        mock_boto_client.side_effect = [mock_ec2_client, mock_cw_client]
        
        tool = EC2StatusTool(ExecutionMode.SANDBOX_LIVE)
        assert tool.execution_mode == ExecutionMode.SANDBOX_LIVE
        assert tool.ec2_client == mock_ec2_client
        assert tool.cloudwatch_client == mock_cw_client
        
        # Verify both clients were created
        assert mock_boto_client.call_count == 2
        mock_boto_client.assert_any_call('ec2')
        mock_boto_client.assert_any_call('cloudwatch')
    
    def test_execute_mock_mode_single_instance(self):
        """Test execution in LOCAL_MOCK mode with single instance ID"""
        tool = EC2StatusTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="get_ec2_status",
            args={
                'instance_id': 'i-1234567890abcdef0',
                'metrics': ['cpu', 'network'],
                'time_window': '15m'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.tool_name == "get_ec2_status"
        assert result.execution_mode == ExecutionMode.LOCAL_MOCK
        assert result.correlation_id == 'test-correlation-id'
        assert result.data['mock'] is True
        assert result.data['instance_count'] == 1
        assert result.data['metrics_requested'] == ['cpu', 'network']
        assert result.data['time_window'] == '15m'
        
        # Check instance data
        instance = result.data['instances'][0]
        assert instance['instance_id'] == 'i-1234567890abcdef0'
        assert instance['state'] == 'running'
        assert 'metrics' in instance
        assert instance['metrics']['status'] == 'success'
        assert 'cpuutilization' in instance['metrics']['metrics']
        assert 'networkin' in instance['metrics']['metrics']
        
        # Check summary
        assert 'Found 1 EC2 instance(s)' in result.data['summary']
        assert 'CPU levels normal' in result.data['summary'] or 'High CPU' in result.data['summary']
    
    def test_execute_mock_mode_tag_filter(self):
        """Test execution in LOCAL_MOCK mode with tag filter"""
        tool = EC2StatusTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="get_ec2_status",
            args={
                'tag_filter': {'Environment': 'sandbox', 'OpsAgentManaged': 'true'},
                'metrics': ['cpu', 'memory'],
                'time_window': '30m'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['instance_count'] == 2  # Both mock instances match the filter
        assert result.data['metrics_requested'] == ['cpu', 'memory']
        assert result.data['time_window'] == '30m'
        
        # Check that all instances have the expected tags
        for instance in result.data['instances']:
            assert instance['tags']['Environment'] == 'sandbox'
            assert instance['tags']['OpsAgentManaged'] == 'true'
    
    def test_execute_missing_parameters(self):
        """Test execution with missing required parameters"""
        tool = EC2StatusTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="get_ec2_status",
            args={}  # Missing both instance_id and tag_filter
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Either instance_id or tag_filter is required" in result.error
    
    def test_parse_time_window(self):
        """Test time window parsing"""
        tool = EC2StatusTool()
        
        assert tool._parse_time_window('5m') == timedelta(minutes=5)
        assert tool._parse_time_window('15m') == timedelta(minutes=15)
        assert tool._parse_time_window('1h') == timedelta(hours=1)
        assert tool._parse_time_window('24h') == timedelta(hours=24)
        
        # Test invalid time window (should default to 15m)
        assert tool._parse_time_window('invalid') == timedelta(minutes=15)
    
    def test_get_metric_unit(self):
        """Test metric unit mapping"""
        tool = EC2StatusTool()
        
        assert tool._get_metric_unit('CPUUtilization') == 'Percent'
        assert tool._get_metric_unit('MemoryUtilization') == 'Percent'
        assert tool._get_metric_unit('NetworkIn') == 'Bytes'
        assert tool._get_metric_unit('NetworkOut') == 'Bytes'
        assert tool._get_metric_unit('UnknownMetric') == 'Unknown'
    
    def test_assess_metric_status(self):
        """Test metric status assessment"""
        tool = EC2StatusTool()
        
        # CPU metrics
        assert tool._assess_metric_status('CPUUtilization', 25.0) == 'NORMAL'
        assert tool._assess_metric_status('CPUUtilization', 65.0) == 'MODERATE'
        assert tool._assess_metric_status('CPUUtilization', 85.0) == 'HIGH'
        
        # Memory metrics
        assert tool._assess_metric_status('MemoryUtilization', 30.0) == 'NORMAL'
        assert tool._assess_metric_status('MemoryUtilization', 75.0) == 'MODERATE'
        assert tool._assess_metric_status('MemoryUtilization', 90.0) == 'HIGH'
        
        # Network metrics (always normal without context)
        assert tool._assess_metric_status('NetworkIn', 1000000) == 'NORMAL'
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_with_real_api_success(self, mock_boto_client):
        """Test execution with successful AWS API calls"""
        # Mock EC2 client
        mock_ec2_client = Mock()
        mock_cw_client = Mock()
        mock_boto_client.side_effect = [mock_ec2_client, mock_cw_client]
        
        # Mock EC2 response
        mock_ec2_response = {
            'Reservations': [
                {
                    'Instances': [
                        {
                            'InstanceId': 'i-1234567890abcdef0',
                            'InstanceType': 't3.medium',
                            'State': {'Name': 'running'},
                            'StateReason': {'Message': 'running'},
                            'LaunchTime': datetime(2024, 1, 15, 10, 30, 0),
                            'Placement': {'AvailabilityZone': 'us-east-1a'},
                            'VpcId': 'vpc-12345678',
                            'SubnetId': 'subnet-12345678',
                            'PrivateIpAddress': '10.0.1.100',
                            'PublicIpAddress': '54.123.45.67',
                            'SecurityGroups': [
                                {'GroupId': 'sg-12345678', 'GroupName': 'default'}
                            ],
                            'Tags': [
                                {'Key': 'Name', 'Value': 'test-instance'},
                                {'Key': 'Environment', 'Value': 'sandbox'},
                                {'Key': 'OpsAgentManaged', 'Value': 'true'}
                            ],
                            'Monitoring': {'State': 'enabled'},
                            'Architecture': 'x86_64',
                            'VirtualizationType': 'hvm',
                            'RootDeviceType': 'ebs'
                        }
                    ]
                }
            ]
        }
        mock_ec2_client.describe_instances.return_value = mock_ec2_response
        
        # Mock CloudWatch response
        mock_cw_response = {
            'Datapoints': [
                {
                    'Timestamp': datetime.utcnow() - timedelta(minutes=5),
                    'Average': 45.2,
                    'Maximum': 78.5,
                    'Minimum': 12.1
                }
            ]
        }
        mock_cw_client.get_metric_statistics.return_value = mock_cw_response
        
        tool = EC2StatusTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="get_ec2_status",
            args={
                'instance_id': 'i-1234567890abcdef0',
                'metrics': ['cpu'],
                'time_window': '15m'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['instance_count'] == 1
        
        instance = result.data['instances'][0]
        assert instance['instance_id'] == 'i-1234567890abcdef0'
        assert instance['state'] == 'running'
        assert instance['metrics']['status'] == 'success'
        assert 'cpuutilization' in instance['metrics']['metrics']
        
        cpu_metrics = instance['metrics']['metrics']['cpuutilization']
        assert cpu_metrics['latest_value'] == 45.2
        assert cpu_metrics['max_value'] == 78.5
        assert cpu_metrics['min_value'] == 12.1
        assert cpu_metrics['unit'] == 'Percent'
        assert cpu_metrics['status'] == 'NORMAL'
        
        # Verify API calls
        mock_ec2_client.describe_instances.assert_called_once_with(
            InstanceIds=['i-1234567890abcdef0']
        )
        mock_cw_client.get_metric_statistics.assert_called_once()
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_stopped_instance(self, mock_boto_client):
        """Test execution with stopped instance (no metrics)"""
        mock_ec2_client = Mock()
        mock_cw_client = Mock()
        mock_boto_client.side_effect = [mock_ec2_client, mock_cw_client]
        
        # Mock EC2 response with stopped instance
        mock_ec2_response = {
            'Reservations': [
                {
                    'Instances': [
                        {
                            'InstanceId': 'i-1234567890abcdef0',
                            'InstanceType': 't3.medium',
                            'State': {'Name': 'stopped'},
                            'StateReason': {'Message': 'User initiated'},
                            'LaunchTime': datetime(2024, 1, 15, 10, 30, 0),
                            'Placement': {'AvailabilityZone': 'us-east-1a'},
                            'VpcId': 'vpc-12345678',
                            'SubnetId': 'subnet-12345678',
                            'PrivateIpAddress': '10.0.1.100',
                            'Tags': [
                                {'Key': 'Name', 'Value': 'test-instance'},
                                {'Key': 'Environment', 'Value': 'sandbox'}
                            ],
                            'Monitoring': {'State': 'disabled'},
                            'Architecture': 'x86_64',
                            'VirtualizationType': 'hvm',
                            'RootDeviceType': 'ebs'
                        }
                    ]
                }
            ]
        }
        mock_ec2_client.describe_instances.return_value = mock_ec2_response
        
        tool = EC2StatusTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="get_ec2_status",
            args={
                'instance_id': 'i-1234567890abcdef0',
                'metrics': ['cpu'],
                'time_window': '15m'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['instance_count'] == 1
        
        instance = result.data['instances'][0]
        assert instance['instance_id'] == 'i-1234567890abcdef0'
        assert instance['state'] == 'stopped'
        assert instance['metrics']['status'] == 'instance_not_running'
        assert 'Metrics not available for stopped instance' in instance['metrics']['message']
        
        # CloudWatch should not be called for stopped instances
        mock_cw_client.get_metric_statistics.assert_not_called()
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_ec2_api_error(self, mock_boto_client):
        """Test execution with EC2 API error"""
        mock_ec2_client = Mock()
        mock_cw_client = Mock()
        mock_boto_client.side_effect = [mock_ec2_client, mock_cw_client]
        
        error_response = {
            'Error': {
                'Code': 'InvalidInstanceID.NotFound',
                'Message': 'The instance ID i-invalid does not exist'
            }
        }
        mock_ec2_client.describe_instances.side_effect = ClientError(error_response, 'DescribeInstances')
        
        tool = EC2StatusTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="get_ec2_status",
            args={'instance_id': 'i-invalid'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "One or more specified instance IDs do not exist" in result.error
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_cloudwatch_api_error(self, mock_boto_client):
        """Test execution with CloudWatch API error (should still return EC2 data)"""
        mock_ec2_client = Mock()
        mock_cw_client = Mock()
        mock_boto_client.side_effect = [mock_ec2_client, mock_cw_client]
        
        # Mock successful EC2 response
        mock_ec2_response = {
            'Reservations': [
                {
                    'Instances': [
                        {
                            'InstanceId': 'i-1234567890abcdef0',
                            'InstanceType': 't3.medium',
                            'State': {'Name': 'running'},
                            'StateReason': {'Message': 'running'},
                            'LaunchTime': datetime(2024, 1, 15, 10, 30, 0),
                            'Placement': {'AvailabilityZone': 'us-east-1a'},
                            'VpcId': 'vpc-12345678',
                            'Tags': [
                                {'Key': 'Name', 'Value': 'test-instance'}
                            ],
                            'Monitoring': {'State': 'enabled'},
                            'Architecture': 'x86_64',
                            'VirtualizationType': 'hvm',
                            'RootDeviceType': 'ebs'
                        }
                    ]
                }
            ]
        }
        mock_ec2_client.describe_instances.return_value = mock_ec2_response
        
        # Mock CloudWatch error
        error_response = {
            'Error': {
                'Code': 'AccessDenied',
                'Message': 'User is not authorized to perform cloudwatch:GetMetricStatistics'
            }
        }
        mock_cw_client.get_metric_statistics.side_effect = ClientError(error_response, 'GetMetricStatistics')
        
        tool = EC2StatusTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="get_ec2_status",
            args={
                'instance_id': 'i-1234567890abcdef0',
                'metrics': ['cpu']
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True  # Should still succeed with EC2 data
        assert result.data['instance_count'] == 1
        
        instance = result.data['instances'][0]
        assert instance['instance_id'] == 'i-1234567890abcdef0'
        assert instance['state'] == 'running'
        
        # Metrics should show error
        assert instance['metrics']['status'] == 'success'  # Overall status is success
        cpu_metrics = instance['metrics']['metrics']['cpuutilization']
        assert cpu_metrics['status'] == 'error'
        assert 'AccessDenied' in cpu_metrics['message']
    
    def test_generate_ec2_status_summary(self):
        """Test EC2 status summary generation"""
        tool = EC2StatusTool()
        
        instances = [
            {
                'instance_id': 'i-123',
                'state': 'running',
                'tags': {'OpsAgentManaged': 'true'},
                'metrics': {
                    'metrics': {
                        'cpuutilization': {
                            'latest_value': 85.3,
                            'status': 'HIGH'
                        }
                    }
                }
            },
            {
                'instance_id': 'i-456',
                'state': 'running',
                'tags': {'OpsAgentManaged': 'false'},
                'metrics': {
                    'metrics': {
                        'cpuutilization': {
                            'latest_value': 25.1,
                            'status': 'NORMAL'
                        }
                    }
                }
            },
            {
                'instance_id': 'i-789',
                'state': 'stopped',
                'tags': {'OpsAgentManaged': 'true'},
                'metrics': {
                    'status': 'instance_not_running'
                }
            }
        ]
        
        summary = tool._generate_ec2_status_summary(instances, ['cpu'], '15m')
        
        assert 'Found 3 EC2 instance(s)' in summary
        assert 'States: 2 running, 1 stopped' in summary
        assert 'High CPU: i-123 (85.3%)' in summary
        assert '2 OpsAgent-managed' in summary
        assert 'Metrics: cpu over 15m' in summary
    
    def test_generate_ec2_status_summary_empty(self):
        """Test EC2 status summary generation with no instances"""
        tool = EC2StatusTool()
        
        summary = tool._generate_ec2_status_summary([], ['cpu'], '15m')
        
        assert summary == "No EC2 instances found matching the specified criteria"
    
    def test_format_aws_error(self):
        """Test AWS error formatting"""
        tool = EC2StatusTool()
        
        # Test known error code
        error = ClientError(
            {'Error': {'Code': 'InvalidInstanceID.NotFound', 'Message': 'Instance not found'}},
            'DescribeInstances'
        )
        formatted = tool._format_aws_error(error, 'EC2')
        assert formatted == "One or more specified instance IDs do not exist"
        
        # Test credential-related error (should be sanitized)
        error = ClientError(
            {'Error': {'Code': 'InvalidCredentials', 'Message': 'Invalid AWS credentials provided'}},
            'DescribeInstances'
        )
        formatted = tool._format_aws_error(error, 'EC2')
        assert formatted == "Authentication error accessing EC2 service"


class TestEC2DescribeTool:
    """Test EC2 describe tool functionality"""
    
    def test_init_local_mock_mode(self):
        """Test initialization in LOCAL_MOCK mode"""
        tool = EC2DescribeTool(ExecutionMode.LOCAL_MOCK)
        assert tool.execution_mode == ExecutionMode.LOCAL_MOCK
        assert tool.ec2_client is None
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_init_dry_run_mode(self, mock_boto_client):
        """Test initialization in DRY_RUN mode"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        tool = EC2DescribeTool(ExecutionMode.DRY_RUN)
        assert tool.execution_mode == ExecutionMode.DRY_RUN
        assert tool.ec2_client == mock_client
        mock_boto_client.assert_called_once_with('ec2')
    
    def test_execute_mock_mode(self):
        """Test execution in LOCAL_MOCK mode"""
        tool = EC2DescribeTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="describe_ec2_instances",
            args={}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.tool_name == "describe_ec2_instances"
        assert result.execution_mode == ExecutionMode.LOCAL_MOCK
        assert result.correlation_id == 'test-correlation-id'
        assert result.data['mock'] is True
        assert result.data['instance_count'] == 2
        assert len(result.data['instances']) == 2
        assert 'summary' in result.data
    
    def test_execute_mock_mode_with_filters(self):
        """Test execution in mock mode with filters"""
        tool = EC2DescribeTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="describe_ec2_instances",
            args={
                'filters': {
                    'state': ['running'],
                    'tags': {'OpsAgentManaged': 'true'}
                }
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['instance_count'] == 1  # Only one running instance with OpsAgentManaged=true
        assert result.data['instances'][0]['state'] == 'running'
        assert result.data['instances'][0]['tags']['OpsAgentManaged'] == 'true'
    
    def test_build_filters(self):
        """Test filter building from tool arguments"""
        tool = EC2DescribeTool()
        
        filter_args = {
            'state': ['running', 'stopped'],
            'tags': {
                'Environment': 'production',
                'OpsAgentManaged': 'true'
            }
        }
        
        filters = tool._build_filters(filter_args)
        
        expected_filters = [
            {'Name': 'instance-state-name', 'Values': ['running', 'stopped']},
            {'Name': 'tag:Environment', 'Values': ['production']},
            {'Name': 'tag:OpsAgentManaged', 'Values': ['true']}
        ]
        
        assert len(filters) == 3
        assert {'Name': 'instance-state-name', 'Values': ['running', 'stopped']} in filters
        assert {'Name': 'tag:Environment', 'Values': ['production']} in filters
        assert {'Name': 'tag:OpsAgentManaged', 'Values': ['true']} in filters
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_with_real_api_success(self, mock_boto_client):
        """Test execution with successful EC2 API call"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        mock_response = {
            'Reservations': [
                {
                    'Instances': [
                        {
                            'InstanceId': 'i-1234567890abcdef0',
                            'InstanceType': 't3.medium',
                            'State': {'Name': 'running'},
                            'StateReason': {'Message': 'running'},
                            'LaunchTime': datetime(2024, 1, 15, 10, 30, 0),
                            'Placement': {'AvailabilityZone': 'us-east-1a'},
                            'VpcId': 'vpc-12345678',
                            'SubnetId': 'subnet-12345678',
                            'PrivateIpAddress': '10.0.1.100',
                            'PublicIpAddress': '54.123.45.67',
                            'SecurityGroups': [
                                {'GroupId': 'sg-12345678', 'GroupName': 'default'}
                            ],
                            'Tags': [
                                {'Key': 'Name', 'Value': 'test-instance'},
                                {'Key': 'Environment', 'Value': 'sandbox'},
                                {'Key': 'OpsAgentManaged', 'Value': 'true'}
                            ],
                            'Monitoring': {'State': 'enabled'},
                            'Architecture': 'x86_64',
                            'VirtualizationType': 'hvm',
                            'RootDeviceType': 'ebs'
                        }
                    ]
                }
            ]
        }
        mock_client.describe_instances.return_value = mock_response
        
        tool = EC2DescribeTool(ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="describe_ec2_instances",
            args={'instance_ids': ['i-1234567890abcdef0']}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['instance_count'] == 1
        
        instance = result.data['instances'][0]
        assert instance['instance_id'] == 'i-1234567890abcdef0'
        assert instance['instance_type'] == 't3.medium'
        assert instance['state'] == 'running'
        assert instance['tags']['OpsAgentManaged'] == 'true'
        assert 'summary' in result.data
        
        # Verify API call
        mock_client.describe_instances.assert_called_once_with(
            InstanceIds=['i-1234567890abcdef0']
        )
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_aws_api_error(self, mock_boto_client):
        """Test execution with AWS API error"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        error_response = {
            'Error': {
                'Code': 'InvalidInstanceID.NotFound',
                'Message': 'The instance ID i-invalid does not exist'
            }
        }
        mock_client.describe_instances.side_effect = ClientError(error_response, 'DescribeInstances')
        
        tool = EC2DescribeTool(ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="describe_ec2_instances",
            args={'instance_ids': ['i-invalid']}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "One or more specified instance IDs do not exist" in result.error
    
    def test_generate_instances_summary(self):
        """Test instance summary generation"""
        tool = EC2DescribeTool()
        
        instances = [
            {
                'instance_id': 'i-123',
                'instance_type': 't3.medium',
                'state': 'running',
                'tags': {'OpsAgentManaged': 'true'}
            },
            {
                'instance_id': 'i-456',
                'instance_type': 't3.small',
                'state': 'stopped',
                'tags': {'OpsAgentManaged': 'false'}
            }
        ]
        
        summary = tool._generate_instances_summary(instances)
        
        assert 'Found 2 EC2 instance(s)' in summary
        assert 'States: 1 running, 1 stopped' in summary
        assert 'Types: t3.medium, t3.small' in summary
        assert '1 OpsAgent-managed' in summary
    
    def test_generate_instances_summary_empty(self):
        """Test instance summary generation with no instances"""
        tool = EC2DescribeTool()
        
        summary = tool._generate_instances_summary([])
        
        assert summary == "No EC2 instances found matching the specified criteria"
    
    def test_apply_mock_filters(self):
        """Test applying filters to mock instances"""
        tool = EC2DescribeTool()
        
        instances = [
            {'instance_id': 'i-123', 'state': 'running', 'tags': {'Env': 'prod'}},
            {'instance_id': 'i-456', 'state': 'stopped', 'tags': {'Env': 'dev'}},
            {'instance_id': 'i-789', 'state': 'running', 'tags': {'Env': 'prod'}}
        ]
        
        # Test state filter
        args = {'filters': {'state': ['running']}}
        filtered = tool._apply_mock_filters(instances, args)
        assert len(filtered) == 2
        assert all(inst['state'] == 'running' for inst in filtered)
        
        # Test tag filter
        args = {'filters': {'tags': {'Env': 'prod'}}}
        filtered = tool._apply_mock_filters(instances, args)
        assert len(filtered) == 2
        assert all(inst['tags']['Env'] == 'prod' for inst in filtered)
        
        # Test instance ID filter
        args = {'instance_ids': ['i-123', 'i-456']}
        filtered = tool._apply_mock_filters(instances, args)
        assert len(filtered) == 2
        assert filtered[0]['instance_id'] == 'i-123'
        assert filtered[1]['instance_id'] == 'i-456'


class TestALBTargetHealthTool:
    """Test ALB target health tool functionality"""
    
    def test_init_local_mock_mode(self):
        """Test initialization in LOCAL_MOCK mode"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool(ExecutionMode.LOCAL_MOCK)
        assert tool.execution_mode == ExecutionMode.LOCAL_MOCK
        assert tool.elbv2_client is None
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_init_sandbox_live_mode(self, mock_boto_client):
        """Test initialization in SANDBOX_LIVE mode"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        tool = ALBTargetHealthTool(ExecutionMode.SANDBOX_LIVE)
        assert tool.execution_mode == ExecutionMode.SANDBOX_LIVE
        assert tool.elbv2_client == mock_client
        mock_boto_client.assert_called_once_with('elbv2')
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_init_client_failure(self, mock_boto_client):
        """Test client initialization failure"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        mock_boto_client.side_effect = Exception("AWS credentials not found")
        
        # Should not raise exception, just log error and continue with None client
        tool = ALBTargetHealthTool(ExecutionMode.SANDBOX_LIVE)
        assert tool.elbv2_client is None
    
    def test_execute_mock_mode_target_group(self):
        """Test execution in LOCAL_MOCK mode with target group ARN"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="describe_alb_target_health",
            args={
                'target_group_arn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890123456'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.tool_name == "describe_alb_target_health"
        assert result.execution_mode == ExecutionMode.LOCAL_MOCK
        assert result.correlation_id == 'test-correlation-id'
        assert result.data['mock'] is True
        assert result.data['target_group_name'] == 'mock-target-group'
        assert result.data['total_targets'] == 3
        assert result.data['healthy_targets'] == 2
        assert result.data['unhealthy_targets'] == 1
        assert result.data['overall_health'] == 'partial'
        assert len(result.data['unhealthy_details']) == 1
        assert len(result.data['health_issues']) == 1
        assert 'summary' in result.data
    
    def test_execute_mock_mode_alb(self):
        """Test execution in LOCAL_MOCK mode with ALB ARN"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="describe_alb_target_health",
            args={
                'alb_arn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890123456'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['mock'] is True
        assert result.data['alb_name'] == 'mock-alb'
        assert result.data['alb_state'] == 'active'
        assert result.data['target_group_count'] == 2
        assert result.data['total_targets'] == 5
        assert result.data['total_healthy'] == 4
        assert result.data['overall_health'] == 'partial'
        assert len(result.data['target_groups']) == 2
        assert 'summary' in result.data
        
        # Check target group details
        web_tg = next(tg for tg in result.data['target_groups'] if tg['target_group_name'] == 'web-servers')
        assert web_tg['health_status'] == 'partial'
        assert len(web_tg['health_issues']) == 1
        
        api_tg = next(tg for tg in result.data['target_groups'] if tg['target_group_name'] == 'api-servers')
        assert api_tg['health_status'] == 'healthy'
        assert len(api_tg['health_issues']) == 0
    
    def test_execute_missing_parameters(self):
        """Test execution with missing required parameters"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="describe_alb_target_health",
            args={}  # Missing both alb_arn and target_group_arn
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Either alb_arn or target_group_arn is required" in result.error
    
    def test_analyze_target_health_all_healthy(self):
        """Test target health analysis with all healthy targets"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool()
        
        targets = [
            {
                'Target': {'Id': 'i-123', 'Port': 80},
                'TargetHealth': {
                    'State': 'healthy',
                    'Reason': 'Target.HealthCheckSuccess',
                    'Description': 'Health checks succeeded'
                }
            },
            {
                'Target': {'Id': 'i-456', 'Port': 80},
                'TargetHealth': {
                    'State': 'healthy',
                    'Reason': 'Target.HealthCheckSuccess',
                    'Description': 'Health checks succeeded'
                }
            }
        ]
        
        analysis = tool._analyze_target_health(targets)
        
        assert analysis['total_targets'] == 2
        assert analysis['healthy_count'] == 2
        assert analysis['unhealthy_count'] == 0
        assert analysis['draining_count'] == 0
        assert analysis['unavailable_count'] == 0
        assert analysis['overall_health'] == 'healthy'
        assert len(analysis['health_issues']) == 0
        assert len(analysis['unhealthy_details']) == 0
        assert len(analysis['target_details']) == 2
    
    def test_analyze_target_health_mixed_states(self):
        """Test target health analysis with mixed target states"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool()
        
        targets = [
            {
                'Target': {'Id': 'i-123', 'Port': 80},
                'TargetHealth': {
                    'State': 'healthy',
                    'Reason': 'Target.HealthCheckSuccess',
                    'Description': 'Health checks succeeded'
                }
            },
            {
                'Target': {'Id': 'i-456', 'Port': 80},
                'TargetHealth': {
                    'State': 'unhealthy',
                    'Reason': 'Target.FailedHealthChecks',
                    'Description': 'Health check failed'
                }
            },
            {
                'Target': {'Id': 'i-789', 'Port': 80},
                'TargetHealth': {
                    'State': 'draining',
                    'Reason': 'Target.Draining',
                    'Description': 'Target is draining'
                }
            },
            {
                'Target': {'Id': 'i-abc', 'Port': 80},
                'TargetHealth': {
                    'State': 'unavailable',
                    'Reason': 'Target.NotRegistered',
                    'Description': 'Target is not registered'
                }
            }
        ]
        
        analysis = tool._analyze_target_health(targets)
        
        assert analysis['total_targets'] == 4
        assert analysis['healthy_count'] == 1
        assert analysis['unhealthy_count'] == 1
        assert analysis['draining_count'] == 1
        assert analysis['unavailable_count'] == 1
        assert analysis['overall_health'] == 'degraded'  # Only 1/4 healthy (25% < 50%)
        assert len(analysis['health_issues']) == 1
        assert 'Target i-456 failing health checks' in analysis['health_issues']
        assert len(analysis['unhealthy_details']) == 1
        assert analysis['unhealthy_details'][0]['target_id'] == 'i-456'
    
    def test_analyze_target_health_no_targets(self):
        """Test target health analysis with no targets"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool()
        
        analysis = tool._analyze_target_health([])
        
        assert analysis['total_targets'] == 0
        assert analysis['healthy_count'] == 0
        assert analysis['unhealthy_count'] == 0
        assert analysis['overall_health'] == 'no_targets'
        assert len(analysis['health_issues']) == 0
    
    def test_determine_overall_alb_health(self):
        """Test overall ALB health determination"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool()
        
        # ALB not active
        assert tool._determine_overall_alb_health('provisioning', 5, 5, []) == 'alb_provisioning'
        
        # No targets
        assert tool._determine_overall_alb_health('active', 0, 0, []) == 'no_targets'
        
        # All healthy
        assert tool._determine_overall_alb_health('active', 5, 5, []) == 'healthy'
        
        # No healthy targets
        assert tool._determine_overall_alb_health('active', 0, 5, ['issues']) == 'critical'
        
        # Less than 50% healthy
        assert tool._determine_overall_alb_health('active', 2, 5, ['issues']) == 'degraded'
        
        # More than 50% healthy
        assert tool._determine_overall_alb_health('active', 4, 5, ['issues']) == 'partial'
    
    def test_generate_target_group_summary(self):
        """Test target group summary generation"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool()
        
        # All healthy
        analysis = {
            'total_targets': 3,
            'healthy_count': 3,
            'unhealthy_count': 0,
            'draining_count': 0,
            'overall_health': 'healthy',
            'health_issues': []
        }
        summary = tool._generate_target_group_summary('web-servers', analysis)
        assert 'web-servers: 3/3 healthy' in summary
        assert '✓ All targets healthy' in summary
        
        # Mixed health
        analysis = {
            'total_targets': 4,
            'healthy_count': 2,
            'unhealthy_count': 1,
            'draining_count': 1,
            'overall_health': 'partial',
            'health_issues': ['Target i-123 failing health checks']
        }
        summary = tool._generate_target_group_summary('api-servers', analysis)
        assert 'api-servers: 2/4 healthy' in summary
        assert '1 unhealthy' in summary
        assert '1 draining' in summary
        assert '⚠ Some targets unhealthy' in summary
        assert 'Issues: Target i-123 failing health checks' in summary
    
    def test_generate_alb_summary(self):
        """Test ALB summary generation"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool()
        
        target_groups = [
            {
                'target_group_name': 'web-servers',
                'health_status': 'healthy',
                'total_targets': 3,
                'healthy_targets': 3
            },
            {
                'target_group_name': 'api-servers',
                'health_status': 'partial',
                'total_targets': 2,
                'healthy_targets': 1
            }
        ]
        
        summary = tool._generate_alb_summary('my-alb', 'active', target_groups, 5, 4, 'partial')
        
        assert 'ALB my-alb' in summary
        assert '2 target groups' in summary
        assert '4/5 targets healthy' in summary
        assert '⚠ Some targets unhealthy' in summary
        assert 'Issues in: api-servers' in summary
    
    def test_format_aws_error(self):
        """Test AWS error formatting"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        tool = ALBTargetHealthTool()
        
        # Test known error code
        error = ClientError(
            {'Error': {'Code': 'LoadBalancerNotFound', 'Message': 'Load balancer not found'}},
            'DescribeLoadBalancers'
        )
        formatted = tool._format_aws_error(error, 'ELBv2')
        assert formatted == "The specified load balancer does not exist"
        
        # Test target group not found
        error = ClientError(
            {'Error': {'Code': 'TargetGroupNotFound', 'Message': 'Target group not found'}},
            'DescribeTargetGroups'
        )
        formatted = tool._format_aws_error(error, 'ELBv2')
        assert formatted == "The specified target group does not exist"
        
        # Test credential-related error (should be sanitized)
        error = ClientError(
            {'Error': {'Code': 'InvalidCredentials', 'Message': 'Invalid AWS credentials provided'}},
            'DescribeTargetHealth'
        )
        formatted = tool._format_aws_error(error, 'ELBv2')
        assert formatted == "Authentication error accessing ELBv2 service"
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_with_real_api_target_group_success(self, mock_boto_client):
        """Test execution with successful ELBv2 API call for target group"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock target group details
        mock_tg_response = {
            'TargetGroups': [
                {
                    'TargetGroupName': 'test-targets',
                    'TargetType': 'instance',
                    'Protocol': 'HTTP',
                    'Port': 80,
                    'HealthCheckPath': '/health',
                    'HealthCheckIntervalSeconds': 30,
                    'HealthyThresholdCount': 5,
                    'UnhealthyThresholdCount': 2
                }
            ]
        }
        
        # Mock target health response
        mock_health_response = {
            'TargetHealthDescriptions': [
                {
                    'Target': {'Id': 'i-1234567890abcdef0', 'Port': 80},
                    'TargetHealth': {
                        'State': 'healthy',
                        'Reason': 'Target.HealthCheckSuccess',
                        'Description': 'Health checks succeeded'
                    }
                },
                {
                    'Target': {'Id': 'i-0987654321fedcba0', 'Port': 80},
                    'TargetHealth': {
                        'State': 'unhealthy',
                        'Reason': 'Target.FailedHealthChecks',
                        'Description': 'Health check failed'
                    }
                }
            ]
        }
        
        mock_client.describe_target_groups.return_value = mock_tg_response
        mock_client.describe_target_health.return_value = mock_health_response
        
        tool = ALBTargetHealthTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="describe_alb_target_health",
            args={
                'target_group_arn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-targets/1234567890123456'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['target_group_name'] == 'test-targets'
        assert result.data['total_targets'] == 2
        assert result.data['healthy_targets'] == 1
        assert result.data['unhealthy_targets'] == 1
        assert result.data['overall_health'] == 'partial'
        assert len(result.data['unhealthy_details']) == 1
        assert result.data['unhealthy_details'][0]['target_id'] == 'i-0987654321fedcba0'
        assert len(result.data['health_issues']) == 1
        assert 'Target i-0987654321fedcba0 failing health checks' in result.data['health_issues']
        
        # Verify API calls
        mock_client.describe_target_groups.assert_called_once()
        mock_client.describe_target_health.assert_called_once()
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_with_real_api_alb_success(self, mock_boto_client):
        """Test execution with successful ELBv2 API call for ALB"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock ALB details
        mock_alb_response = {
            'LoadBalancers': [
                {
                    'LoadBalancerName': 'test-alb',
                    'State': {'Code': 'active'},
                    'Scheme': 'internet-facing',
                    'Type': 'application',
                    'DNSName': 'test-alb-123456789.us-east-1.elb.amazonaws.com',
                    'AvailabilityZones': [
                        {'ZoneName': 'us-east-1a'},
                        {'ZoneName': 'us-east-1b'}
                    ]
                }
            ]
        }
        
        # Mock target groups
        mock_tg_response = {
            'TargetGroups': [
                {
                    'TargetGroupName': 'web-servers',
                    'TargetGroupArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web-servers/1234567890123456',
                    'TargetType': 'instance',
                    'Protocol': 'HTTP',
                    'Port': 80,
                    'HealthCheckPath': '/health'
                }
            ]
        }
        
        # Mock target health
        mock_health_response = {
            'TargetHealthDescriptions': [
                {
                    'Target': {'Id': 'i-1234567890abcdef0', 'Port': 80},
                    'TargetHealth': {
                        'State': 'healthy',
                        'Reason': 'Target.HealthCheckSuccess',
                        'Description': 'Health checks succeeded'
                    }
                }
            ]
        }
        
        mock_client.describe_load_balancers.return_value = mock_alb_response
        mock_client.describe_target_groups.return_value = mock_tg_response
        mock_client.describe_target_health.return_value = mock_health_response
        
        tool = ALBTargetHealthTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="describe_alb_target_health",
            args={
                'alb_arn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-alb/1234567890123456'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['alb_name'] == 'test-alb'
        assert result.data['alb_state'] == 'active'
        assert result.data['target_group_count'] == 1
        assert result.data['total_targets'] == 1
        assert result.data['total_healthy'] == 1
        assert result.data['overall_health'] == 'healthy'
        assert len(result.data['target_groups']) == 1
        assert result.data['target_groups'][0]['target_group_name'] == 'web-servers'
        assert result.data['target_groups'][0]['health_status'] == 'healthy'
        
        # Verify API calls
        mock_client.describe_load_balancers.assert_called_once()
        mock_client.describe_target_groups.assert_called_once()
        mock_client.describe_target_health.assert_called_once()
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_load_balancer_not_found(self, mock_boto_client):
        """Test execution with load balancer not found error"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        error_response = {
            'Error': {
                'Code': 'LoadBalancerNotFound',
                'Message': 'One or more load balancers not found'
            }
        }
        mock_client.describe_load_balancers.side_effect = ClientError(error_response, 'DescribeLoadBalancers')
        
        tool = ALBTargetHealthTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="describe_alb_target_health",
            args={'alb_arn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/invalid/1234567890123456'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "The specified load balancer does not exist" in result.error
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_target_group_not_found(self, mock_boto_client):
        """Test execution with target group not found error"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        error_response = {
            'Error': {
                'Code': 'TargetGroupNotFound',
                'Message': 'One or more target groups not found'
            }
        }
        mock_client.describe_target_groups.side_effect = ClientError(error_response, 'DescribeTargetGroups')
        
        tool = ALBTargetHealthTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="describe_alb_target_health",
            args={'target_group_arn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/invalid/1234567890123456'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "The specified target group does not exist" in result.error
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_no_client_available(self, mock_boto_client):
        """Test execution when ELBv2 client is not available"""
        from src.aws_diagnosis_tools import ALBTargetHealthTool
        mock_boto_client.side_effect = Exception("Client initialization failed")
        
        tool = ALBTargetHealthTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="describe_alb_target_health",
            args={'alb_arn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/1234567890123456'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "ELBv2 client not available" in result.error


class TestCloudTrailSearchTool:
    """Test CloudTrail search tool functionality with enhanced filtering and pagination"""
    
    def test_init_local_mock_mode(self):
        """Test initialization in LOCAL_MOCK mode"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool(ExecutionMode.LOCAL_MOCK)
        assert tool.execution_mode == ExecutionMode.LOCAL_MOCK
        assert tool.cloudtrail_client is None
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_init_sandbox_live_mode(self, mock_boto_client):
        """Test initialization in SANDBOX_LIVE mode"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        tool = CloudTrailSearchTool(ExecutionMode.SANDBOX_LIVE)
        assert tool.execution_mode == ExecutionMode.SANDBOX_LIVE
        assert tool.cloudtrail_client == mock_client
        mock_boto_client.assert_called_once_with('cloudtrail')
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_init_client_failure(self, mock_boto_client):
        """Test client initialization failure"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        mock_boto_client.side_effect = Exception("AWS credentials not found")
        
        # Should not raise exception, just log error and continue with None client
        tool = CloudTrailSearchTool(ExecutionMode.SANDBOX_LIVE)
        assert tool.cloudtrail_client is None
    
    def test_execute_mock_mode_basic(self):
        """Test execution in LOCAL_MOCK mode with basic parameters"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="search_cloudtrail_events",
            args={
                'time_window': '1h',
                'event_name': 'RunInstances',
                'resource_name': 'i-1234567890abcdef0'
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.tool_name == "search_cloudtrail_events"
        assert result.execution_mode == ExecutionMode.LOCAL_MOCK
        assert result.correlation_id == 'test-correlation-id'
        assert result.data['mock'] is True
        assert result.data['event_count'] == 3  # Updated mock returns 3 events
        assert result.data['time_range']['window'] == '1h'
        assert 'summary' in result.data
        assert 'mock data' in result.data['summary']
        
        # Check event formatting
        events = result.data['events']
        assert len(events) == 3
        for event in events:
            assert 'event_time' in event
            assert 'event_name' in event
            assert 'event_category' in event
            assert 'user_name' in event
            assert 'description' in event
            assert 'security_relevant' in event
            assert 'read_only' in event
    
    def test_execute_mock_mode_with_filters(self):
        """Test execution in LOCAL_MOCK mode with multiple filters"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="search_cloudtrail_events",
            args={
                'time_window': '6h',
                'event_name': 'ConsoleLogin',
                'user_name': 'admin@company.com',
                'source_ip': '203.0.113.1',
                'max_results': 25
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['time_range']['window'] == '6h'
        assert result.data['search_criteria']['event_name'] == 'ConsoleLogin'
        assert result.data['search_criteria']['user_name'] == 'admin@company.com'
        assert result.data['search_criteria']['source_ip'] == '203.0.113.1'
        assert result.data['pagination_info']['max_results_limit'] == 50  # Default in mock
    
    def test_parse_time_window_valid(self):
        """Test parsing valid time window strings"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool()
        
        assert tool._parse_time_window('5m') == timedelta(minutes=5)
        assert tool._parse_time_window('2h') == timedelta(hours=2)
        assert tool._parse_time_window('7d') == timedelta(days=7)
        assert tool._parse_time_window('invalid') == timedelta(hours=1)  # Default
    
    def test_categorize_event(self):
        """Test event categorization"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool()
        
        assert tool._categorize_event('RunInstances') == 'create'
        assert tool._categorize_event('CreateBucket') == 'create'
        assert tool._categorize_event('TerminateInstances') == 'delete'
        assert tool._categorize_event('DeleteBucket') == 'delete'
        assert tool._categorize_event('ModifyDBInstance') == 'modify'
        assert tool._categorize_event('UpdateStack') == 'modify'
        assert tool._categorize_event('DescribeInstances') == 'read'
        assert tool._categorize_event('ListBuckets') == 'read'
        assert tool._categorize_event('AssumeRole') == 'auth'
        assert tool._categorize_event('ConsoleLogin') == 'auth'
        assert tool._categorize_event('UnknownAction') == 'other'
    
    def test_is_security_relevant_event(self):
        """Test security relevance detection"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool()
        
        # Security-relevant events
        assert tool._is_security_relevant_event('AssumeRole') is True
        assert tool._is_security_relevant_event('CreateUser') is True
        assert tool._is_security_relevant_event('DeleteUser') is True
        assert tool._is_security_relevant_event('AttachUserPolicy') is True
        assert tool._is_security_relevant_event('ConsoleLogin') is True
        assert tool._is_security_relevant_event('AuthorizeSecurityGroupIngress') is True
        
        # Non-security events
        assert tool._is_security_relevant_event('RunInstances') is False
        assert tool._is_security_relevant_event('DescribeInstances') is False
        assert tool._is_security_relevant_event('CreateBucket') is False
    
    def test_is_read_only_event(self):
        """Test read-only event detection"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool()
        
        # Read-only events
        assert tool._is_read_only_event('DescribeInstances') is True
        assert tool._is_read_only_event('ListBuckets') is True
        assert tool._is_read_only_event('GetObject') is True
        assert tool._is_read_only_event('HeadObject') is True
        
        # Write events
        assert tool._is_read_only_event('RunInstances') is False
        assert tool._is_read_only_event('CreateBucket') is False
        assert tool._is_read_only_event('PutObject') is False
    
    def test_generate_event_description(self):
        """Test event description generation"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool()
        
        resources = [{'resource_type': 'AWS::EC2::Instance', 'resource_name': 'i-123456789'}]
        
        # Successful event
        desc = tool._generate_event_description('RunInstances', 'user@company.com', resources, None)
        assert 'user@company.com successfully launched EC2 instance' in desc
        assert 'AWS::EC2::Instance i-123456789' in desc
        
        # Failed event
        desc = tool._generate_event_description('RunInstances', 'user@company.com', resources, 'AccessDenied')
        assert 'user@company.com attempted to launched EC2 instance' in desc
        assert 'failed with error: AccessDenied' in desc
        
        # Multiple resources
        multi_resources = [
            {'resource_type': 'AWS::EC2::Instance', 'resource_name': 'i-123'},
            {'resource_type': 'AWS::EC2::Instance', 'resource_name': 'i-456'}
        ]
        desc = tool._generate_event_description('RunInstances', 'user@company.com', multi_resources, None)
        assert '2 resources' in desc
    
    def test_generate_cloudtrail_summary_empty(self):
        """Test summary generation with no events"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool()
        
        summary = tool._generate_cloudtrail_summary([], '1h', 'RunInstances', 'i-123', 'user@company.com')
        assert 'No CloudTrail events found in the last 1h' in summary
        assert "event 'RunInstances'" in summary
        assert "resource 'i-123'" in summary
        assert "user 'user@company.com'" in summary
    
    def test_generate_cloudtrail_summary_with_events(self):
        """Test summary generation with events"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool()
        
        events = [
            {
                'event_time': '2024-01-15T10:30:00Z',
                'event_category': 'create',
                'user_name': 'user1@company.com',
                'success': True,
                'security_relevant': False
            },
            {
                'event_time': '2024-01-15T10:25:00Z',
                'event_category': 'delete',
                'user_name': 'user2@company.com',
                'success': False,
                'security_relevant': True
            },
            {
                'event_time': '2024-01-15T10:20:00Z',
                'event_category': 'auth',
                'user_name': 'user1@company.com',
                'success': True,
                'security_relevant': True
            }
        ]
        
        summary = tool._generate_cloudtrail_summary(events, '1h', None, None, None)
        assert 'Found 3 CloudTrail event(s) in the last 1h' in summary
        assert 'Categories:' in summary
        assert 'Top users:' in summary
        assert '⚠ 1 failed event(s)' in summary
        assert '🔒 2 security-relevant event(s)' in summary
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_with_real_api_success(self, mock_boto_client):
        """Test execution with successful CloudTrail API call"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock CloudTrail response
        mock_response = {
            'Events': [
                {
                    'EventTime': datetime.utcnow() - timedelta(minutes=30),
                    'EventName': 'RunInstances',
                    'Username': 'test-user@company.com',
                    'SourceIPAddress': '203.0.113.1',
                    'UserAgent': 'aws-cli/2.0.0',
                    'AwsRegion': 'us-east-1',
                    'Resources': [
                        {
                            'ResourceType': 'AWS::EC2::Instance',
                            'ResourceName': 'i-1234567890abcdef0'
                        }
                    ]
                }
            ],
            'NextToken': None
        }
        mock_client.lookup_events.return_value = mock_response
        
        tool = CloudTrailSearchTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="search_cloudtrail_events",
            args={
                'time_window': '1h',
                'event_name': 'RunInstances',
                'max_results': 50
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['event_count'] == 1
        assert result.data['pagination_info']['pages_fetched'] == 1
        assert result.data['pagination_info']['has_more_results'] is False
        
        # Check event formatting
        event = result.data['events'][0]
        assert event['event_name'] == 'RunInstances'
        assert event['event_category'] == 'create'
        assert event['user_name'] == 'test-user@company.com'
        assert event['success'] is True
        assert event['security_relevant'] is False
        assert event['read_only'] is False
        assert 'description' in event
        
        # Verify API call
        mock_client.lookup_events.assert_called_once()
        call_args = mock_client.lookup_events.call_args[1]
        assert 'StartTime' in call_args
        assert 'EndTime' in call_args
        assert call_args['MaxItems'] == 50
        assert len(call_args['LookupAttributes']) == 1
        assert call_args['LookupAttributes'][0]['AttributeKey'] == 'EventName'
        assert call_args['LookupAttributes'][0]['AttributeValue'] == 'RunInstances'
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_with_pagination(self, mock_boto_client):
        """Test execution with pagination handling"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock paginated responses
        first_response = {
            'Events': [
                {
                    'EventTime': datetime.utcnow() - timedelta(minutes=30),
                    'EventName': 'RunInstances',
                    'Username': 'user1@company.com',
                    'SourceIPAddress': '203.0.113.1',
                    'UserAgent': 'aws-cli/2.0.0',
                    'AwsRegion': 'us-east-1',
                    'Resources': []
                }
            ],
            'NextToken': 'next-page-token'
        }
        
        second_response = {
            'Events': [
                {
                    'EventTime': datetime.utcnow() - timedelta(minutes=15),
                    'EventName': 'StopInstances',
                    'Username': 'user2@company.com',
                    'SourceIPAddress': '203.0.113.2',
                    'UserAgent': 'console.aws.amazon.com',
                    'AwsRegion': 'us-east-1',
                    'Resources': []
                }
            ],
            'NextToken': None
        }
        
        mock_client.lookup_events.side_effect = [first_response, second_response]
        
        tool = CloudTrailSearchTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="search_cloudtrail_events",
            args={'time_window': '2h', 'max_results': 100}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['event_count'] == 2
        assert result.data['pagination_info']['pages_fetched'] == 2
        assert result.data['pagination_info']['has_more_results'] is False
        
        # Verify both API calls were made
        assert mock_client.lookup_events.call_count == 2
        
        # Check second call had NextToken
        second_call_args = mock_client.lookup_events.call_args_list[1][1]
        assert second_call_args['NextToken'] == 'next-page-token'
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_time_range_validation(self, mock_boto_client):
        """Test time range validation (90-day limit)"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        tool = CloudTrailSearchTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="search_cloudtrail_events",
            args={'time_window': '100d'}  # Exceeds 90-day limit
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Time window cannot exceed 90 days" in result.error
        
        # API should not be called
        mock_client.lookup_events.assert_not_called()
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_source_ip_filtering(self, mock_boto_client):
        """Test source IP filtering (post-API filtering)"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock response with multiple events from different IPs
        mock_response = {
            'Events': [
                {
                    'EventTime': datetime.utcnow() - timedelta(minutes=30),
                    'EventName': 'RunInstances',
                    'Username': 'user@company.com',
                    'SourceIPAddress': '203.0.113.1',  # Matches filter
                    'UserAgent': 'aws-cli/2.0.0',
                    'AwsRegion': 'us-east-1',
                    'Resources': []
                },
                {
                    'EventTime': datetime.utcnow() - timedelta(minutes=15),
                    'EventName': 'StopInstances',
                    'Username': 'user@company.com',
                    'SourceIPAddress': '203.0.113.2',  # Does not match filter
                    'UserAgent': 'console.aws.amazon.com',
                    'AwsRegion': 'us-east-1',
                    'Resources': []
                }
            ],
            'NextToken': None
        }
        mock_client.lookup_events.return_value = mock_response
        
        tool = CloudTrailSearchTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="search_cloudtrail_events",
            args={
                'time_window': '1h',
                'source_ip': '203.0.113.1'  # Filter for specific IP
            }
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.data['event_count'] == 1  # Only one event should match
        assert result.data['events'][0]['source_ip'] == '203.0.113.1'
    
    @patch('src.aws_diagnosis_tools.boto3.client')
    def test_execute_cloudtrail_api_error(self, mock_boto_client):
        """Test execution with CloudTrail API error"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        error_response = {
            'Error': {
                'Code': 'AccessDenied',
                'Message': 'User is not authorized to perform cloudtrail:LookupEvents'
            }
        }
        mock_client.lookup_events.side_effect = ClientError(error_response, 'LookupEvents')
        
        tool = CloudTrailSearchTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="search_cloudtrail_events",
            args={'time_window': '1h'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Insufficient permissions to access CloudTrail service" in result.error
    
    def test_execute_no_client_available(self):
        """Test execution when CloudTrail client is not available"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool(ExecutionMode.SANDBOX_LIVE)
        tool.cloudtrail_client = None  # Simulate client initialization failure
        
        tool_call = ToolCall(
            tool_name="search_cloudtrail_events",
            args={'time_window': '1h'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "CloudTrail client not available" in result.error
    
    def test_format_aws_error(self):
        """Test AWS error formatting"""
        from src.aws_diagnosis_tools import CloudTrailSearchTool
        tool = CloudTrailSearchTool()
        
        # Test known error code
        error = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'LookupEvents'
        )
        formatted = tool._format_aws_error(error, 'CloudTrail')
        assert formatted == "Insufficient permissions to access CloudTrail service"
        
        # Test credential-related error (should be sanitized)
        error = ClientError(
            {'Error': {'Code': 'InvalidCredentials', 'Message': 'Invalid AWS credentials provided'}},
            'LookupEvents'
        )
        formatted = tool._format_aws_error(error, 'CloudTrail')
        assert formatted == "Authentication error accessing CloudTrail service"
        
        # Test CloudTrail-specific error
        error = ClientError(
            {'Error': {'Code': 'InvalidTimeRange', 'Message': 'Time range is invalid'}},
            'LookupEvents'
        )
        formatted = tool._format_aws_error(error, 'CloudTrail')
        assert formatted == "The specified time range is invalid or too large"