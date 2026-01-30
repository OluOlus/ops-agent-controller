"""
Unit tests for AWS diagnosis tools
Requirements: 2.1, 2.2, 2.4, 2.5
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

from src.aws_diagnosis_tools import CloudWatchMetricsTool, EC2DescribeTool, AWSToolError
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