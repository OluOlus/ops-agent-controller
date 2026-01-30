"""
AWS diagnosis tools for OpsAgent Controller
Requirements: 2.1, 2.2, 2.4, 2.5
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
import boto3
from botocore.exceptions import ClientError, BotoCoreError

from .models import ToolCall, ToolResult, ExecutionMode

logger = logging.getLogger(__name__)


class AWSToolError(Exception):
    """Base exception for AWS tool errors"""
    pass


class CloudWatchMetricsTool:
    """
    CloudWatch metrics retrieval tool with AWS SDK integration
    Requirements: 2.1, 2.4, 2.5
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.LOCAL_MOCK):
        self.execution_mode = execution_mode
        self.cloudwatch_client = None
        
        if execution_mode != ExecutionMode.LOCAL_MOCK:
            self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize CloudWatch client"""
        try:
            self.cloudwatch_client = boto3.client('cloudwatch')
            logger.info("CloudWatch client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize CloudWatch client: {e}")
            # Don't raise exception - continue without client for graceful degradation
            self.cloudwatch_client = None
    
    def execute(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute CloudWatch metrics retrieval
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with metrics data or error
        """
        logger.info(f"Executing CloudWatch metrics tool for correlation_id: {correlation_id}")
        
        try:
            # Extract and validate parameters (even in mock mode)
            namespace = tool_call.args['namespace']
            metric_name = tool_call.args['metric_name']
            resource_id = tool_call.args['resource_id']
            time_window = tool_call.args.get('time_window', '15m')
        except KeyError as e:
            error_msg = f"Missing required parameter: {e}"
            logger.error(error_msg)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_metrics_response(tool_call, correlation_id)
        
        try:
            if not self.cloudwatch_client:
                raise AWSToolError("CloudWatch client not available")
            
            # Parse time window and calculate time range
            time_delta = self._parse_time_window(time_window)
            end_time = datetime.utcnow()
            start_time = end_time - time_delta
            
            # Get metric dimensions based on namespace
            dimensions = self._get_metric_dimensions(namespace, resource_id)
            
            # Retrieve metric statistics from CloudWatch
            response = self.cloudwatch_client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start_time,
                EndTime=end_time,
                Period=300,  # 5-minute periods
                Statistics=['Average', 'Maximum', 'Minimum', 'Sum', 'SampleCount']
            )
            
            # Process and format the response
            result_data = self._format_metrics_response(
                response, namespace, metric_name, resource_id, time_window
            )
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data=result_data,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except ClientError as e:
            error_msg = self._format_aws_error(e, "CloudWatch")
            logger.error(f"CloudWatch API error: {error_msg}")
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        except KeyError as e:
            error_msg = f"Missing required parameter: {e}"
            logger.error(error_msg)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        except Exception as e:
            error_msg = f"Unexpected error retrieving CloudWatch metrics: {str(e)}"
            logger.error(error_msg)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
    
    def _parse_time_window(self, time_window: str) -> timedelta:
        """
        Parse time window string to timedelta
        
        Args:
            time_window: Time window string (e.g., '15m', '1h', '24h')
            
        Returns:
            timedelta object
            
        Raises:
            ValueError: If time window format is invalid
        """
        time_map = {
            '5m': timedelta(minutes=5),
            '15m': timedelta(minutes=15),
            '30m': timedelta(minutes=30),
            '1h': timedelta(hours=1),
            '6h': timedelta(hours=6),
            '12h': timedelta(hours=12),
            '24h': timedelta(hours=24)
        }
        
        if time_window not in time_map:
            raise ValueError(f"Invalid time window: {time_window}. Supported values: {list(time_map.keys())}")
        
        return time_map[time_window]
    
    def _get_metric_dimensions(self, namespace: str, resource_id: str) -> List[Dict[str, str]]:
        """
        Get CloudWatch metric dimensions based on namespace
        
        Args:
            namespace: AWS service namespace
            resource_id: Resource identifier
            
        Returns:
            List of dimension dictionaries
        """
        dimension_map = {
            'AWS/EC2': [{'Name': 'InstanceId', 'Value': resource_id}],
            'AWS/ECS': [{'Name': 'ServiceName', 'Value': resource_id}],
            'AWS/ApplicationELB': [{'Name': 'LoadBalancer', 'Value': resource_id}],
            'AWS/NetworkELB': [{'Name': 'LoadBalancer', 'Value': resource_id}],
            'AWS/Lambda': [{'Name': 'FunctionName', 'Value': resource_id}]
        }
        
        return dimension_map.get(namespace, [{'Name': 'ResourceId', 'Value': resource_id}])
    
    def _format_metrics_response(
        self,
        response: Dict[str, Any],
        namespace: str,
        metric_name: str,
        resource_id: str,
        time_window: str
    ) -> Dict[str, Any]:
        """
        Format CloudWatch metrics response for human-readable display
        
        Args:
            response: CloudWatch API response
            namespace: AWS service namespace
            metric_name: Metric name
            resource_id: Resource identifier
            time_window: Time window string
            
        Returns:
            Formatted metrics data
        """
        datapoints = response.get('Datapoints', [])
        
        if not datapoints:
            return {
                'metric_name': metric_name,
                'namespace': namespace,
                'resource_id': resource_id,
                'time_window': time_window,
                'status': 'no_data',
                'message': f'No data points found for {metric_name} in the last {time_window}',
                'summary': f'No metrics available for {resource_id}'
            }
        
        # Sort datapoints by timestamp
        datapoints.sort(key=lambda x: x['Timestamp'])
        
        # Calculate summary statistics
        avg_values = [dp.get('Average', 0) for dp in datapoints if 'Average' in dp]
        max_values = [dp.get('Maximum', 0) for dp in datapoints if 'Maximum' in dp]
        min_values = [dp.get('Minimum', 0) for dp in datapoints if 'Minimum' in dp]
        
        latest_datapoint = datapoints[-1]
        latest_value = latest_datapoint.get('Average', latest_datapoint.get('Sum', 0))
        
        # Generate human-readable summary
        summary = self._generate_metrics_summary(
            metric_name, namespace, resource_id, latest_value, max_values, min_values, time_window
        )
        
        return {
            'metric_name': metric_name,
            'namespace': namespace,
            'resource_id': resource_id,
            'time_window': time_window,
            'status': 'success',
            'latest_value': round(latest_value, 2) if latest_value else 0,
            'max_value': round(max(max_values), 2) if max_values else 0,
            'min_value': round(min(min_values), 2) if min_values else 0,
            'average_value': round(sum(avg_values) / len(avg_values), 2) if avg_values else 0,
            'datapoint_count': len(datapoints),
            'unit': response.get('Label', 'Unknown'),
            'latest_timestamp': latest_datapoint['Timestamp'].isoformat(),
            'summary': summary
        }
    
    def _generate_metrics_summary(
        self,
        metric_name: str,
        namespace: str,
        resource_id: str,
        latest_value: float,
        max_values: List[float],
        min_values: List[float],
        time_window: str
    ) -> str:
        """
        Generate human-readable summary of metrics data
        
        Args:
            metric_name: Metric name
            namespace: AWS service namespace
            resource_id: Resource identifier
            latest_value: Latest metric value
            max_values: List of maximum values
            min_values: List of minimum values
            time_window: Time window string
            
        Returns:
            Human-readable summary string
        """
        service_name = namespace.replace('AWS/', '')
        max_val = max(max_values) if max_values else 0
        min_val = min(min_values) if min_values else 0
        
        # Generate context-aware summary based on metric type
        if 'CPU' in metric_name or 'Utilization' in metric_name:
            if latest_value > 80:
                status = "HIGH"
            elif latest_value > 50:
                status = "MODERATE"
            else:
                status = "NORMAL"
            
            return (f"{service_name} {metric_name} for {resource_id}: "
                   f"Current: {latest_value:.1f}% ({status}), "
                   f"Peak: {max_val:.1f}%, Low: {min_val:.1f}% over last {time_window}")
        
        elif 'Error' in metric_name or 'Fault' in metric_name:
            if latest_value > 0:
                status = "ERRORS DETECTED"
            else:
                status = "NO ERRORS"
            
            return (f"{service_name} {metric_name} for {resource_id}: "
                   f"Current: {latest_value:.0f} ({status}), "
                   f"Peak: {max_val:.0f} over last {time_window}")
        
        elif 'Latency' in metric_name or 'Duration' in metric_name:
            if latest_value > 1000:  # > 1 second
                status = "HIGH LATENCY"
            elif latest_value > 500:  # > 500ms
                status = "MODERATE LATENCY"
            else:
                status = "NORMAL LATENCY"
            
            return (f"{service_name} {metric_name} for {resource_id}: "
                   f"Current: {latest_value:.0f}ms ({status}), "
                   f"Peak: {max_val:.0f}ms over last {time_window}")
        
        else:
            # Generic summary
            return (f"{service_name} {metric_name} for {resource_id}: "
                   f"Current: {latest_value:.2f}, "
                   f"Range: {min_val:.2f} - {max_val:.2f} over last {time_window}")
    
    def _format_aws_error(self, error: ClientError, service: str) -> str:
        """
        Format AWS API error for user-friendly display
        
        Args:
            error: ClientError from boto3
            service: AWS service name
            
        Returns:
            User-friendly error message
        """
        error_code = error.response.get('Error', {}).get('Code', 'Unknown')
        error_message = error.response.get('Error', {}).get('Message', str(error))
        
        # Map common error codes to user-friendly messages
        error_map = {
            'InvalidParameterValue': f"Invalid parameter provided to {service} API",
            'AccessDenied': f"Insufficient permissions to access {service} metrics",
            'UnauthorizedOperation': f"Not authorized to perform {service} operations",
            'Throttling': f"{service} API rate limit exceeded, please try again later",
            'InternalServiceError': f"{service} service is temporarily unavailable",
            'InvalidMetricName': "The specified metric name does not exist",
            'InvalidNamespace': "The specified namespace is not valid"
        }
        
        user_message = error_map.get(error_code, f"{service} API error: {error_message}")
        
        # Don't expose sensitive details in error messages
        if 'credential' in error_message.lower() or 'token' in error_message.lower():
            user_message = f"Authentication error accessing {service} service"
        
        return user_message
    
    def _mock_metrics_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Generate mock metrics response for testing
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            Mock ToolResult with sample metrics data
        """
        namespace = tool_call.args['namespace']
        metric_name = tool_call.args['metric_name']
        resource_id = tool_call.args['resource_id']
        time_window = tool_call.args.get('time_window', '15m')
        
        # Generate realistic mock data based on metric type
        if 'CPU' in metric_name:
            latest_value = 45.2
            max_value = 78.5
            min_value = 12.1
            unit = 'Percent'
        elif 'Error' in metric_name:
            latest_value = 2.0
            max_value = 5.0
            min_value = 0.0
            unit = 'Count'
        elif 'Latency' in metric_name:
            latest_value = 250.0
            max_value = 890.0
            min_value = 120.0
            unit = 'Milliseconds'
        else:
            latest_value = 100.0
            max_value = 150.0
            min_value = 50.0
            unit = 'Count'
        
        summary = self._generate_metrics_summary(
            metric_name, namespace, resource_id, latest_value, [max_value], [min_value], time_window
        )
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'metric_name': metric_name,
                'namespace': namespace,
                'resource_id': resource_id,
                'time_window': time_window,
                'status': 'success',
                'latest_value': latest_value,
                'max_value': max_value,
                'min_value': min_value,
                'average_value': (latest_value + max_value + min_value) / 3,
                'datapoint_count': 15,
                'unit': unit,
                'latest_timestamp': datetime.utcnow().isoformat(),
                'summary': summary,
                'mock': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )


class EC2DescribeTool:
    """
    EC2 instance description tool for infrastructure information retrieval
    Requirements: 2.2, 2.4, 2.5
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.LOCAL_MOCK):
        self.execution_mode = execution_mode
        self.ec2_client = None
        
        if execution_mode != ExecutionMode.LOCAL_MOCK:
            self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize EC2 client"""
        try:
            self.ec2_client = boto3.client('ec2')
            logger.info("EC2 client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize EC2 client: {e}")
            # Don't raise exception - continue without client for graceful degradation
            self.ec2_client = None
    
    def execute(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute EC2 instance description
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with instance data or error
        """
        logger.info(f"Executing EC2 describe tool for correlation_id: {correlation_id}")
        
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_describe_response(tool_call, correlation_id)
        
        try:
            if not self.ec2_client:
                raise AWSToolError("EC2 client not available")
            
            # Build describe_instances parameters
            describe_params = {}
            
            # Add instance IDs if specified
            if 'instance_ids' in tool_call.args and tool_call.args['instance_ids']:
                describe_params['InstanceIds'] = tool_call.args['instance_ids']
            
            # Add filters if specified
            if 'filters' in tool_call.args:
                filters = self._build_filters(tool_call.args['filters'])
                if filters:
                    describe_params['Filters'] = filters
            
            # Call EC2 API
            response = self.ec2_client.describe_instances(**describe_params)
            
            # Process and format response
            instances = self._process_instances_response(response)
            
            # Generate human-readable summary
            summary = self._generate_instances_summary(instances)
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={
                    'instances': instances,
                    'instance_count': len(instances),
                    'summary': summary
                },
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except ClientError as e:
            error_msg = self._format_aws_error(e, "EC2")
            logger.error(f"EC2 API error: {error_msg}")
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        except Exception as e:
            error_msg = f"Unexpected error describing EC2 instances: {str(e)}"
            logger.error(error_msg)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
    
    def _build_filters(self, filter_args: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build EC2 API filters from tool arguments
        
        Args:
            filter_args: Filter arguments from tool call
            
        Returns:
            List of EC2 API filter dictionaries
        """
        filters = []
        
        # State filter
        if 'state' in filter_args and filter_args['state']:
            filters.append({
                'Name': 'instance-state-name',
                'Values': filter_args['state'] if isinstance(filter_args['state'], list) else [filter_args['state']]
            })
        
        # Tag filters
        if 'tags' in filter_args and filter_args['tags']:
            for tag_key, tag_value in filter_args['tags'].items():
                filters.append({
                    'Name': f'tag:{tag_key}',
                    'Values': [tag_value] if isinstance(tag_value, str) else tag_value
                })
        
        return filters
    
    def _process_instances_response(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process EC2 describe_instances response and sanitize for security
        
        Args:
            response: EC2 API response
            
        Returns:
            List of sanitized instance data
        """
        instances = []
        
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                # Sanitize instance data - only include safe, relevant information
                instance_data = {
                    'instance_id': instance.get('InstanceId'),
                    'instance_type': instance.get('InstanceType'),
                    'state': instance.get('State', {}).get('Name'),
                    'state_reason': instance.get('StateReason', {}).get('Message'),
                    'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                    'availability_zone': instance.get('Placement', {}).get('AvailabilityZone'),
                    'vpc_id': instance.get('VpcId'),
                    'subnet_id': instance.get('SubnetId'),
                    'private_ip': instance.get('PrivateIpAddress'),
                    'public_ip': instance.get('PublicIpAddress'),
                    'security_groups': [
                        {
                            'group_id': sg.get('GroupId'),
                            'group_name': sg.get('GroupName')
                        }
                        for sg in instance.get('SecurityGroups', [])
                    ],
                    'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                    'monitoring': instance.get('Monitoring', {}).get('State'),
                    'platform': instance.get('Platform'),  # Windows instances
                    'architecture': instance.get('Architecture'),
                    'virtualization_type': instance.get('VirtualizationType'),
                    'root_device_type': instance.get('RootDeviceType')
                }
                
                # Add health status if available
                if 'StatusChecks' in instance:
                    instance_data['status_checks'] = {
                        'instance_status': instance.get('InstanceStatus', {}).get('Status'),
                        'system_status': instance.get('SystemStatus', {}).get('Status')
                    }
                
                instances.append(instance_data)
        
        return instances
    
    def _generate_instances_summary(self, instances: List[Dict[str, Any]]) -> str:
        """
        Generate human-readable summary of EC2 instances
        
        Args:
            instances: List of instance data
            
        Returns:
            Human-readable summary string
        """
        if not instances:
            return "No EC2 instances found matching the specified criteria"
        
        # Count instances by state
        state_counts = {}
        instance_types = set()
        ops_managed_count = 0
        
        for instance in instances:
            state = instance.get('state', 'unknown')
            state_counts[state] = state_counts.get(state, 0) + 1
            
            if instance.get('instance_type'):
                instance_types.add(instance['instance_type'])
            
            if instance.get('tags', {}).get('OpsAgentManaged') == 'true':
                ops_managed_count += 1
        
        # Build summary
        summary_parts = [f"Found {len(instances)} EC2 instance(s)"]
        
        # Add state breakdown
        if state_counts:
            state_summary = ", ".join([f"{count} {state}" for state, count in state_counts.items()])
            summary_parts.append(f"States: {state_summary}")
        
        # Add instance types
        if instance_types:
            types_summary = ", ".join(sorted(instance_types))
            summary_parts.append(f"Types: {types_summary}")
        
        # Add OpsAgent managed count
        if ops_managed_count > 0:
            summary_parts.append(f"{ops_managed_count} OpsAgent-managed")
        
        return ". ".join(summary_parts)
    
    def _format_aws_error(self, error: ClientError, service: str) -> str:
        """
        Format AWS API error for user-friendly display
        
        Args:
            error: ClientError from boto3
            service: AWS service name
            
        Returns:
            User-friendly error message
        """
        error_code = error.response.get('Error', {}).get('Code', 'Unknown')
        error_message = error.response.get('Error', {}).get('Message', str(error))
        
        # Map common error codes to user-friendly messages
        error_map = {
            'InvalidInstanceID.NotFound': "One or more specified instance IDs do not exist",
            'InvalidParameterValue': f"Invalid parameter provided to {service} API",
            'AccessDenied': f"Insufficient permissions to describe {service} instances",
            'UnauthorizedOperation': f"Not authorized to perform {service} operations",
            'Throttling': f"{service} API rate limit exceeded, please try again later",
            'InternalError': f"{service} service is temporarily unavailable"
        }
        
        user_message = error_map.get(error_code, f"{service} API error: {error_message}")
        
        # Don't expose sensitive details in error messages
        if 'credential' in error_message.lower() or 'token' in error_message.lower():
            user_message = f"Authentication error accessing {service} service"
        
        return user_message
    
    def _mock_describe_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Generate mock EC2 describe response for testing
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            Mock ToolResult with sample instance data
        """
        # Generate mock instances based on filters
        mock_instances = [
            {
                'instance_id': 'i-1234567890abcdef0',
                'instance_type': 't3.medium',
                'state': 'running',
                'state_reason': 'User initiated',
                'launch_time': '2024-01-15T10:30:00Z',
                'availability_zone': 'us-east-1a',
                'vpc_id': 'vpc-12345678',
                'subnet_id': 'subnet-12345678',
                'private_ip': '10.0.1.100',
                'public_ip': '54.123.45.67',
                'security_groups': [
                    {'group_id': 'sg-12345678', 'group_name': 'default'}
                ],
                'tags': {
                    'Name': 'test-instance-1',
                    'Environment': 'sandbox',
                    'OpsAgentManaged': 'true'
                },
                'monitoring': 'enabled',
                'platform': None,
                'architecture': 'x86_64',
                'virtualization_type': 'hvm',
                'root_device_type': 'ebs'
            },
            {
                'instance_id': 'i-0987654321fedcba0',
                'instance_type': 't3.small',
                'state': 'stopped',
                'state_reason': 'User initiated',
                'launch_time': '2024-01-10T14:20:00Z',
                'availability_zone': 'us-east-1b',
                'vpc_id': 'vpc-12345678',
                'subnet_id': 'subnet-87654321',
                'private_ip': '10.0.2.50',
                'public_ip': None,
                'security_groups': [
                    {'group_id': 'sg-87654321', 'group_name': 'web-servers'}
                ],
                'tags': {
                    'Name': 'test-instance-2',
                    'Environment': 'sandbox',
                    'OpsAgentManaged': 'false'
                },
                'monitoring': 'disabled',
                'platform': None,
                'architecture': 'x86_64',
                'virtualization_type': 'hvm',
                'root_device_type': 'ebs'
            }
        ]
        
        # Filter instances based on tool call parameters
        filtered_instances = self._apply_mock_filters(mock_instances, tool_call.args)
        
        summary = self._generate_instances_summary(filtered_instances)
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'instances': filtered_instances,
                'instance_count': len(filtered_instances),
                'summary': summary,
                'mock': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )
    
    def _apply_mock_filters(self, instances: List[Dict[str, Any]], args: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Apply filters to mock instances
        
        Args:
            instances: List of mock instances
            args: Tool call arguments with filters
            
        Returns:
            Filtered list of instances
        """
        filtered = instances.copy()
        
        # Filter by instance IDs
        if 'instance_ids' in args and args['instance_ids']:
            filtered = [inst for inst in filtered if inst['instance_id'] in args['instance_ids']]
        
        # Apply other filters
        if 'filters' in args:
            filters = args['filters']
            
            # State filter
            if 'state' in filters:
                target_states = filters['state'] if isinstance(filters['state'], list) else [filters['state']]
                filtered = [inst for inst in filtered if inst['state'] in target_states]
            
            # Tag filters
            if 'tags' in filters:
                for tag_key, tag_value in filters['tags'].items():
                    filtered = [
                        inst for inst in filtered
                        if inst.get('tags', {}).get(tag_key) == tag_value
                    ]
        
        return filtered
