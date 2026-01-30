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

from models import ToolCall, ToolResult, ExecutionMode

logger = logging.getLogger(__name__)


class AWSToolError(Exception):
    """Base exception for AWS tool errors"""
    pass


class CloudWatchMetricsTool:
    """
    CloudWatch metrics retrieval tool with AWS SDK integration
    Requirements: 2.1, 2.4, 2.5
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE):
        self.execution_mode = execution_mode
        self.cloudwatch_client = None
        
        # Only initialize client if not in LOCAL_MOCK mode
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
        
        # Check for LOCAL_MOCK mode first
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_metrics_response(tool_call, correlation_id)
        
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
        
        # Always execute in sandbox mode
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
        try:
            namespace = tool_call.args['namespace']
            metric_name = tool_call.args['metric_name']
            resource_id = tool_call.args['resource_id']
            time_window = tool_call.args.get('time_window', '15m')
        except KeyError as e:
            error_msg = f"Missing required parameter: {e}"
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        
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
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE):
        self.execution_mode = execution_mode
        self.ec2_client = None
        
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
        
        # Check for LOCAL_MOCK mode first
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_describe_response(tool_call, correlation_id)
        
        # Always execute in sandbox mode
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


class ALBTargetHealthTool:
    """
    ALB/Target Group health status checking tool
    Requirements: 4.1, 4.2, 4.3
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE):
        self.execution_mode = execution_mode
        self.elbv2_client = None
        
        # Only initialize client if not in LOCAL_MOCK mode
        if execution_mode != ExecutionMode.LOCAL_MOCK:
            self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize ELBv2 client"""
        try:
            self.elbv2_client = boto3.client('elbv2')
            logger.info("ELBv2 client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize ELBv2 client: {e}")
            # Don't raise exception - continue without client for graceful degradation
            self.elbv2_client = None
    
    def execute(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute ALB target health check
        
        Args:
            tool_call: Tool call with ALB ARN or Target Group ARN
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with target health information
        """
        logger.info(f"Executing ALB target health tool for correlation_id: {correlation_id}")
        
        # Check for LOCAL_MOCK mode first
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_target_health_response(tool_call, correlation_id)
        
        try:
            # Extract and validate parameters
            alb_arn = tool_call.args.get("alb_arn")
            target_group_arn = tool_call.args.get("target_group_arn")
            
            if not alb_arn and not target_group_arn:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="Either alb_arn or target_group_arn is required",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            if not self.elbv2_client:
                raise AWSToolError("ELBv2 client not available")
            
            # Execute based on parameter type
            if target_group_arn:
                # Direct target group health check
                return self._check_target_group_health(target_group_arn, tool_call, correlation_id)
            else:
                # Get target groups for ALB and check their health
                return self._check_alb_target_health(alb_arn, tool_call, correlation_id)
                
        except ClientError as e:
            error_msg = self._format_aws_error(e, "ELBv2")
            logger.error(f"ELBv2 API error: {error_msg}")
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        except AWSToolError as e:
            logger.error(f"AWS tool error: {str(e)}")
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=str(e),
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        except Exception as e:
            error_msg = f"Unexpected error checking ALB target health: {str(e)}"
            logger.error(error_msg)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
    
    def _check_target_group_health(self, target_group_arn: str, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Check health of targets in a specific target group
        
        Args:
            target_group_arn: Target group ARN
            tool_call: Original tool call
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with target group health details
        """
        try:
            # Get target group details first
            tg_response = self.elbv2_client.describe_target_groups(
                TargetGroupArns=[target_group_arn]
            )
            
            if not tg_response.get('TargetGroups'):
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=f"Target group not found: {target_group_arn}",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            target_group = tg_response['TargetGroups'][0]
            
            # Get target health
            health_response = self.elbv2_client.describe_target_health(
                TargetGroupArn=target_group_arn
            )
            
            targets = health_response.get('TargetHealthDescriptions', [])
            
            # Analyze target health
            health_analysis = self._analyze_target_health(targets)
            
            # Generate human-readable summary
            summary = self._generate_target_group_summary(
                target_group['TargetGroupName'], 
                health_analysis
            )
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={
                    'target_group_arn': target_group_arn,
                    'target_group_name': target_group['TargetGroupName'],
                    'target_type': target_group.get('TargetType', 'instance'),
                    'protocol': target_group.get('Protocol', 'HTTP'),
                    'port': target_group.get('Port', 80),
                    'health_check_path': target_group.get('HealthCheckPath', '/'),
                    'health_check_interval': target_group.get('HealthCheckIntervalSeconds', 30),
                    'healthy_threshold': target_group.get('HealthyThresholdCount', 5),
                    'unhealthy_threshold': target_group.get('UnhealthyThresholdCount', 2),
                    'total_targets': health_analysis['total_targets'],
                    'healthy_targets': health_analysis['healthy_count'],
                    'unhealthy_targets': health_analysis['unhealthy_count'],
                    'draining_targets': health_analysis['draining_count'],
                    'unavailable_targets': health_analysis['unavailable_count'],
                    'target_details': health_analysis['target_details'],
                    'unhealthy_details': health_analysis['unhealthy_details'],
                    'overall_health': health_analysis['overall_health'],
                    'health_issues': health_analysis['health_issues'],
                    'summary': summary
                },
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except ClientError as e:
            raise e  # Re-raise to be handled by main execute method
    
    def _check_alb_target_health(self, alb_arn: str, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Check health of all target groups associated with an ALB
        
        Args:
            alb_arn: Application Load Balancer ARN
            tool_call: Original tool call
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with ALB and all target group health details
        """
        try:
            # Get ALB details first
            alb_response = self.elbv2_client.describe_load_balancers(
                LoadBalancerArns=[alb_arn]
            )
            
            if not alb_response.get('LoadBalancers'):
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=f"Load balancer not found: {alb_arn}",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            load_balancer = alb_response['LoadBalancers'][0]
            
            # Get target groups for the ALB
            tg_response = self.elbv2_client.describe_target_groups(
                LoadBalancerArn=alb_arn
            )
            
            target_groups = tg_response.get('TargetGroups', [])
            if not target_groups:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=True,
                    data={
                        'alb_arn': alb_arn,
                        'alb_name': load_balancer['LoadBalancerName'],
                        'alb_state': load_balancer['State']['Code'],
                        'alb_scheme': load_balancer.get('Scheme', 'internet-facing'),
                        'alb_type': load_balancer.get('Type', 'application'),
                        'target_groups': [],
                        'total_targets': 0,
                        'total_healthy': 0,
                        'overall_health': 'no_targets',
                        'summary': f'ALB {load_balancer["LoadBalancerName"]} has no target groups configured'
                    },
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            # Check health for each target group
            target_group_health = []
            total_healthy = 0
            total_targets = 0
            all_health_issues = []
            
            for tg in target_groups:
                tg_arn = tg['TargetGroupArn']
                
                # Get target health for this target group
                health_response = self.elbv2_client.describe_target_health(
                    TargetGroupArn=tg_arn
                )
                
                targets = health_response.get('TargetHealthDescriptions', [])
                health_analysis = self._analyze_target_health(targets)
                
                target_group_info = {
                    'target_group_name': tg['TargetGroupName'],
                    'target_group_arn': tg_arn,
                    'target_type': tg.get('TargetType', 'instance'),
                    'protocol': tg.get('Protocol', 'HTTP'),
                    'port': tg.get('Port', 80),
                    'health_check_path': tg.get('HealthCheckPath', '/'),
                    'total_targets': health_analysis['total_targets'],
                    'healthy_targets': health_analysis['healthy_count'],
                    'unhealthy_targets': health_analysis['unhealthy_count'],
                    'draining_targets': health_analysis['draining_count'],
                    'unavailable_targets': health_analysis['unavailable_count'],
                    'health_status': health_analysis['overall_health'],
                    'health_issues': health_analysis['health_issues'],
                    'unhealthy_details': health_analysis['unhealthy_details']
                }
                
                target_group_health.append(target_group_info)
                total_healthy += health_analysis['healthy_count']
                total_targets += health_analysis['total_targets']
                all_health_issues.extend(health_analysis['health_issues'])
            
            # Determine overall ALB health
            overall_health = self._determine_overall_alb_health(
                load_balancer['State']['Code'], 
                total_healthy, 
                total_targets,
                all_health_issues
            )
            
            # Generate comprehensive summary
            summary = self._generate_alb_summary(
                load_balancer['LoadBalancerName'],
                load_balancer['State']['Code'],
                target_group_health,
                total_targets,
                total_healthy,
                overall_health
            )
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={
                    'alb_arn': alb_arn,
                    'alb_name': load_balancer['LoadBalancerName'],
                    'alb_state': load_balancer['State']['Code'],
                    'alb_scheme': load_balancer.get('Scheme', 'internet-facing'),
                    'alb_type': load_balancer.get('Type', 'application'),
                    'alb_dns_name': load_balancer.get('DNSName'),
                    'availability_zones': [az['ZoneName'] for az in load_balancer.get('AvailabilityZones', [])],
                    'target_groups': target_group_health,
                    'target_group_count': len(target_groups),
                    'total_targets': total_targets,
                    'total_healthy': total_healthy,
                    'overall_health': overall_health,
                    'health_issues': all_health_issues,
                    'summary': summary
                },
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except ClientError as e:
            raise e  # Re-raise to be handled by main execute method
    
    def _analyze_target_health(self, targets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze target health descriptions and categorize targets
        
        Args:
            targets: List of target health descriptions from ELBv2 API
            
        Returns:
            Dictionary with health analysis results
        """
        if not targets:
            return {
                'total_targets': 0,
                'healthy_count': 0,
                'unhealthy_count': 0,
                'draining_count': 0,
                'unavailable_count': 0,
                'target_details': [],
                'unhealthy_details': [],
                'overall_health': 'no_targets',
                'health_issues': []
            }
        
        healthy_count = 0
        unhealthy_count = 0
        draining_count = 0
        unavailable_count = 0
        target_details = []
        unhealthy_details = []
        health_issues = []
        
        for target_desc in targets:
            target = target_desc['Target']
            health = target_desc['TargetHealth']
            
            target_id = target['Id']
            target_port = target.get('Port', 'default')
            health_state = health['State']
            health_reason = health.get('Reason', 'Unknown')
            health_description = health.get('Description', '')
            
            target_info = {
                'target_id': target_id,
                'port': target_port,
                'state': health_state,
                'reason': health_reason,
                'description': health_description
            }
            
            target_details.append(target_info)
            
            # Categorize by health state
            if health_state == 'healthy':
                healthy_count += 1
            elif health_state == 'draining':
                draining_count += 1
            elif health_state == 'unavailable':
                unavailable_count += 1
            else:
                # unhealthy, initial, unused, etc.
                unhealthy_count += 1
                unhealthy_details.append(target_info)
                
                # Generate specific health issues
                if health_reason == 'Target.FailedHealthChecks':
                    health_issues.append(f"Target {target_id} failing health checks")
                elif health_reason == 'Target.Timeout':
                    health_issues.append(f"Target {target_id} health check timeout")
                elif health_reason == 'Target.ResponseCodeMismatch':
                    health_issues.append(f"Target {target_id} returning wrong response code")
                elif health_reason == 'Target.InvalidState':
                    health_issues.append(f"Target {target_id} in invalid state")
                else:
                    health_issues.append(f"Target {target_id} unhealthy: {health_reason}")
        
        # Determine overall health
        total_targets = len(targets)
        if healthy_count == total_targets:
            overall_health = 'healthy'
        elif healthy_count == 0:
            overall_health = 'critical'
        elif healthy_count < total_targets * 0.5:
            overall_health = 'degraded'
        else:
            overall_health = 'partial'
        
        return {
            'total_targets': total_targets,
            'healthy_count': healthy_count,
            'unhealthy_count': unhealthy_count,
            'draining_count': draining_count,
            'unavailable_count': unavailable_count,
            'target_details': target_details,
            'unhealthy_details': unhealthy_details,
            'overall_health': overall_health,
            'health_issues': health_issues
        }
    
    def _determine_overall_alb_health(
        self, 
        alb_state: str, 
        total_healthy: int, 
        total_targets: int,
        health_issues: List[str]
    ) -> str:
        """
        Determine overall ALB health based on ALB state and target health
        
        Args:
            alb_state: ALB state (active, provisioning, etc.)
            total_healthy: Total number of healthy targets
            total_targets: Total number of targets
            health_issues: List of health issues
            
        Returns:
            Overall health status string
        """
        if alb_state != 'active':
            return f'alb_{alb_state.lower()}'
        
        if total_targets == 0:
            return 'no_targets'
        
        if total_healthy == 0:
            return 'critical'
        elif total_healthy == total_targets:
            return 'healthy'
        elif total_healthy < total_targets * 0.5:
            return 'degraded'
        else:
            return 'partial'
    
    def _generate_target_group_summary(self, tg_name: str, health_analysis: Dict[str, Any]) -> str:
        """
        Generate human-readable summary for a target group
        
        Args:
            tg_name: Target group name
            health_analysis: Health analysis results
            
        Returns:
            Human-readable summary string
        """
        total = health_analysis['total_targets']
        healthy = health_analysis['healthy_count']
        unhealthy = health_analysis['unhealthy_count']
        draining = health_analysis['draining_count']
        overall_health = health_analysis['overall_health']
        
        if total == 0:
            return f"Target group {tg_name} has no registered targets"
        
        status_parts = [f"Target group {tg_name}: {healthy}/{total} healthy"]
        
        if unhealthy > 0:
            status_parts.append(f"{unhealthy} unhealthy")
        if draining > 0:
            status_parts.append(f"{draining} draining")
        
        # Add health status indicator
        health_indicators = {
            'healthy': '✓ All targets healthy',
            'partial': '⚠ Some targets unhealthy',
            'degraded': '⚠ Most targets unhealthy',
            'critical': '✗ No healthy targets',
            'no_targets': 'ℹ No targets registered'
        }
        
        status_indicator = health_indicators.get(overall_health, f'Status: {overall_health}')
        status_parts.append(status_indicator)
        
        # Add specific issues if any
        if health_analysis['health_issues']:
            issues = health_analysis['health_issues'][:3]  # Limit to first 3 issues
            status_parts.append(f"Issues: {'; '.join(issues)}")
        
        return '. '.join(status_parts)
    
    def _generate_alb_summary(
        self, 
        alb_name: str, 
        alb_state: str,
        target_groups: List[Dict[str, Any]], 
        total_targets: int, 
        total_healthy: int,
        overall_health: str
    ) -> str:
        """
        Generate human-readable summary for an ALB
        
        Args:
            alb_name: ALB name
            alb_state: ALB state
            target_groups: List of target group health info
            total_targets: Total number of targets across all target groups
            total_healthy: Total number of healthy targets
            overall_health: Overall health status
            
        Returns:
            Human-readable summary string
        """
        summary_parts = [f"ALB {alb_name}"]
        
        # ALB state
        if alb_state != 'active':
            summary_parts.append(f"State: {alb_state}")
            return '. '.join(summary_parts) + '. ALB is not active'
        
        # Target group count
        tg_count = len(target_groups)
        summary_parts.append(f"{tg_count} target group{'s' if tg_count != 1 else ''}")
        
        # Overall target health
        if total_targets == 0:
            summary_parts.append("No targets configured")
        else:
            summary_parts.append(f"{total_healthy}/{total_targets} targets healthy")
        
        # Health status indicator
        health_indicators = {
            'healthy': '✓ All systems operational',
            'partial': '⚠ Some targets unhealthy',
            'degraded': '⚠ Degraded performance',
            'critical': '✗ Critical: No healthy targets',
            'no_targets': 'ℹ No targets configured'
        }
        
        status_indicator = health_indicators.get(overall_health, f'Status: {overall_health}')
        summary_parts.append(status_indicator)
        
        # Add problematic target groups
        unhealthy_tgs = [tg for tg in target_groups if tg['health_status'] not in ['healthy', 'no_targets']]
        if unhealthy_tgs:
            tg_names = [tg['target_group_name'] for tg in unhealthy_tgs[:2]]  # Limit to 2
            summary_parts.append(f"Issues in: {', '.join(tg_names)}")
        
        return '. '.join(summary_parts)
    
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
            'LoadBalancerNotFound': "The specified load balancer does not exist",
            'TargetGroupNotFound': "The specified target group does not exist",
            'InvalidParameterValue': f"Invalid parameter provided to {service} API",
            'AccessDenied': f"Insufficient permissions to access {service} service",
            'UnauthorizedOperation': f"Not authorized to perform {service} operations",
            'Throttling': f"{service} API rate limit exceeded, please try again later",
            'InternalError': f"{service} service is temporarily unavailable"
        }
        
        user_message = error_map.get(error_code, f"{service} API error: {error_message}")
        
        # Don't expose sensitive details in error messages
        if 'credential' in error_message.lower() or 'token' in error_message.lower():
            user_message = f"Authentication error accessing {service} service"
        
        return user_message

    def _mock_target_health_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Generate mock ALB target health response for testing
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            Mock ToolResult with sample target health data
        """
        alb_arn = tool_call.args.get("alb_arn")
        target_group_arn = tool_call.args.get("target_group_arn")
        
        # Check for missing parameters (same validation as real implementation)
        if not alb_arn and not target_group_arn:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error="Either alb_arn or target_group_arn is required",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        
        if target_group_arn:
            # Mock single target group response
            mock_targets = [
                {
                    'target_id': 'i-1234567890abcdef0',
                    'port': 80,
                    'state': 'healthy',
                    'reason': 'Target.HealthCheckSuccess',
                    'description': 'Health checks succeeded'
                },
                {
                    'target_id': 'i-0987654321fedcba0',
                    'port': 80,
                    'state': 'healthy',
                    'reason': 'Target.HealthCheckSuccess',
                    'description': 'Health checks succeeded'
                },
                {
                    'target_id': 'i-abcdef1234567890',
                    'port': 80,
                    'state': 'unhealthy',
                    'reason': 'Target.FailedHealthChecks',
                    'description': 'Health check failed'
                }
            ]
            
            health_analysis = self._analyze_target_health([
                {
                    'Target': {'Id': t['target_id'], 'Port': t['port']},
                    'TargetHealth': {
                        'State': t['state'],
                        'Reason': t['reason'],
                        'Description': t['description']
                    }
                }
                for t in mock_targets
            ])
            
            summary = self._generate_target_group_summary('mock-target-group', health_analysis)
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={
                    'target_group_arn': target_group_arn,
                    'target_group_name': 'mock-target-group',
                    'target_type': 'instance',
                    'protocol': 'HTTP',
                    'port': 80,
                    'health_check_path': '/health',
                    'health_check_interval': 30,
                    'healthy_threshold': 5,
                    'unhealthy_threshold': 2,
                    'total_targets': health_analysis['total_targets'],
                    'healthy_targets': health_analysis['healthy_count'],
                    'unhealthy_targets': health_analysis['unhealthy_count'],
                    'draining_targets': health_analysis['draining_count'],
                    'unavailable_targets': health_analysis['unavailable_count'],
                    'target_details': health_analysis['target_details'],
                    'unhealthy_details': health_analysis['unhealthy_details'],
                    'overall_health': health_analysis['overall_health'],
                    'health_issues': health_analysis['health_issues'],
                    'summary': summary,
                    'mock': True
                },
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        else:
            # Mock ALB with multiple target groups response
            mock_target_groups = [
                {
                    'target_group_name': 'web-servers',
                    'target_group_arn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web-servers/1234567890123456',
                    'target_type': 'instance',
                    'protocol': 'HTTP',
                    'port': 80,
                    'health_check_path': '/health',
                    'total_targets': 3,
                    'healthy_targets': 2,
                    'unhealthy_targets': 1,
                    'draining_targets': 0,
                    'unavailable_targets': 0,
                    'health_status': 'partial',
                    'health_issues': ['Target i-abcdef1234567890 failing health checks'],
                    'unhealthy_details': [
                        {
                            'target_id': 'i-abcdef1234567890',
                            'port': 80,
                            'state': 'unhealthy',
                            'reason': 'Target.FailedHealthChecks',
                            'description': 'Health check failed'
                        }
                    ]
                },
                {
                    'target_group_name': 'api-servers',
                    'target_group_arn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/api-servers/2345678901234567',
                    'target_type': 'instance',
                    'protocol': 'HTTP',
                    'port': 8080,
                    'health_check_path': '/api/health',
                    'total_targets': 2,
                    'healthy_targets': 2,
                    'unhealthy_targets': 0,
                    'draining_targets': 0,
                    'unavailable_targets': 0,
                    'health_status': 'healthy',
                    'health_issues': [],
                    'unhealthy_details': []
                }
            ]
            
            total_targets = sum(tg['total_targets'] for tg in mock_target_groups)
            total_healthy = sum(tg['healthy_targets'] for tg in mock_target_groups)
            all_health_issues = []
            for tg in mock_target_groups:
                all_health_issues.extend(tg['health_issues'])
            
            overall_health = self._determine_overall_alb_health('active', total_healthy, total_targets, all_health_issues)
            summary = self._generate_alb_summary('mock-alb', 'active', mock_target_groups, total_targets, total_healthy, overall_health)
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={
                    'alb_arn': alb_arn or 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/mock-alb/1234567890123456',
                    'alb_name': 'mock-alb',
                    'alb_state': 'active',
                    'alb_scheme': 'internet-facing',
                    'alb_type': 'application',
                    'alb_dns_name': 'mock-alb-1234567890.us-east-1.elb.amazonaws.com',
                    'availability_zones': ['us-east-1a', 'us-east-1b', 'us-east-1c'],
                    'target_groups': mock_target_groups,
                    'target_group_count': len(mock_target_groups),
                    'total_targets': total_targets,
                    'total_healthy': total_healthy,
                    'overall_health': overall_health,
                    'health_issues': all_health_issues,
                    'summary': summary,
                    'mock': True
                },
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )


class EC2StatusTool:
    """
    EC2 instance status and metrics tool combining EC2 describe with CloudWatch metrics
    Requirements: 4.1, 4.2
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE):
        self.execution_mode = execution_mode
        self.ec2_client = None
        self.cloudwatch_client = None
        
        self._initialize_clients()
    
    def _initialize_clients(self) -> None:
        """Initialize EC2 and CloudWatch clients"""
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return
            
        try:
            self.ec2_client = boto3.client('ec2')
            logger.info("EC2 client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize EC2 client: {e}")
            self.ec2_client = None
        
        try:
            self.cloudwatch_client = boto3.client('cloudwatch')
            logger.info("CloudWatch client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize CloudWatch client: {e}")
            self.cloudwatch_client = None
    
    def execute(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute EC2 status retrieval with metrics integration
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with EC2 status and metrics data
        """
        logger.info(f"Executing EC2 status tool for correlation_id: {correlation_id}")
        
        # Check for LOCAL_MOCK mode first
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_ec2_status_response(tool_call, correlation_id)
        
        try:
            # Extract and validate parameters
            instance_id = tool_call.args.get('instance_id')
            tag_filter = tool_call.args.get('tag_filter', {})
            metrics = tool_call.args.get('metrics', ['cpu', 'memory', 'network'])
            time_window = tool_call.args.get('time_window', '15m')
            
            # Validate that we have either instance_id or tag_filter
            if not instance_id and not tag_filter:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="Either instance_id or tag_filter is required",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            # Get EC2 instances
            instances_data = self._get_ec2_instances(instance_id, tag_filter)
            if not instances_data['success']:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=instances_data['error'],
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            instances = instances_data['instances']
            if not instances:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=True,
                    data={
                        'instances': [],
                        'instance_count': 0,
                        'summary': 'No EC2 instances found matching the specified criteria'
                    },
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            # Enhance instances with CloudWatch metrics
            enhanced_instances = []
            for instance in instances:
                enhanced_instance = instance.copy()
                
                # Only get metrics for running instances
                if instance.get('state') == 'running':
                    metrics_data = self._get_instance_metrics(
                        instance['instance_id'], metrics, time_window
                    )
                    enhanced_instance['metrics'] = metrics_data
                else:
                    enhanced_instance['metrics'] = {
                        'status': 'instance_not_running',
                        'message': f"Metrics not available for {instance.get('state', 'unknown')} instance"
                    }
                
                enhanced_instances.append(enhanced_instance)
            
            # Generate comprehensive summary
            summary = self._generate_ec2_status_summary(enhanced_instances, metrics, time_window)
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={
                    'instances': enhanced_instances,
                    'instance_count': len(enhanced_instances),
                    'metrics_requested': metrics,
                    'time_window': time_window,
                    'summary': summary
                },
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except ClientError as e:
            error_msg = self._format_aws_error(e, "EC2/CloudWatch")
            logger.error(f"AWS API error: {error_msg}")
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        except Exception as e:
            error_msg = f"Unexpected error retrieving EC2 status: {str(e)}"
            logger.error(error_msg)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
    
    def _get_ec2_instances(self, instance_id: Optional[str], tag_filter: Dict[str, str]) -> Dict[str, Any]:
        """
        Get EC2 instances by ID or tag filter
        
        Args:
            instance_id: Specific instance ID
            tag_filter: Tag-based filter
            
        Returns:
            Dictionary with success status and instances data
        """
        if not self.ec2_client:
            return {
                'success': False,
                'error': 'EC2 client not available'
            }
        
        try:
            # Build describe_instances parameters
            describe_params = {}
            
            if instance_id:
                describe_params['InstanceIds'] = [instance_id]
            elif tag_filter:
                filters = []
                for tag_key, tag_value in tag_filter.items():
                    filters.append({
                        'Name': f'tag:{tag_key}',
                        'Values': [tag_value] if isinstance(tag_value, str) else tag_value
                    })
                describe_params['Filters'] = filters
            
            # Call EC2 API
            response = self.ec2_client.describe_instances(**describe_params)
            
            # Process instances
            instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instances.append(self._process_instance_data(instance))
            
            return {
                'success': True,
                'instances': instances
            }
            
        except ClientError as e:
            return {
                'success': False,
                'error': self._format_aws_error(e, "EC2")
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"Unexpected error describing EC2 instances: {str(e)}"
            }
    
    def _process_instance_data(self, instance: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process and sanitize EC2 instance data
        
        Args:
            instance: Raw EC2 instance data from API
            
        Returns:
            Sanitized instance data dictionary
        """
        return {
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
            'platform': instance.get('Platform'),
            'architecture': instance.get('Architecture'),
            'virtualization_type': instance.get('VirtualizationType'),
            'root_device_type': instance.get('RootDeviceType')
        }
    
    def _get_instance_metrics(self, instance_id: str, metrics: List[str], time_window: str) -> Dict[str, Any]:
        """
        Get CloudWatch metrics for an EC2 instance
        
        Args:
            instance_id: EC2 instance ID
            metrics: List of metric types to retrieve
            time_window: Time window for metrics
            
        Returns:
            Dictionary with metrics data
        """
        if not self.cloudwatch_client:
            return {
                'status': 'cloudwatch_unavailable',
                'message': 'CloudWatch client not available'
            }
        
        try:
            # Parse time window
            time_delta = self._parse_time_window(time_window)
            end_time = datetime.utcnow()
            start_time = end_time - time_delta
            
            metrics_data = {}
            
            # Define metric mappings
            metric_mappings = {
                'cpu': 'CPUUtilization',
                'memory': 'MemoryUtilization',  # Note: Requires CloudWatch agent
                'network': ['NetworkIn', 'NetworkOut'],
                'disk': ['DiskReadOps', 'DiskWriteOps']
            }
            
            for metric_type in metrics:
                if metric_type not in metric_mappings:
                    continue
                
                metric_names = metric_mappings[metric_type]
                if isinstance(metric_names, str):
                    metric_names = [metric_names]
                
                for metric_name in metric_names:
                    try:
                        response = self.cloudwatch_client.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName=metric_name,
                            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=300,  # 5-minute periods
                            Statistics=['Average', 'Maximum', 'Minimum']
                        )
                        
                        datapoints = response.get('Datapoints', [])
                        if datapoints:
                            # Sort by timestamp and get latest
                            datapoints.sort(key=lambda x: x['Timestamp'])
                            latest = datapoints[-1]
                            
                            metrics_data[metric_name.lower()] = {
                                'latest_value': round(latest.get('Average', 0), 2),
                                'max_value': round(max(dp.get('Maximum', 0) for dp in datapoints), 2),
                                'min_value': round(min(dp.get('Minimum', 0) for dp in datapoints), 2),
                                'datapoint_count': len(datapoints),
                                'unit': self._get_metric_unit(metric_name),
                                'status': self._assess_metric_status(metric_name, latest.get('Average', 0))
                            }
                        else:
                            metrics_data[metric_name.lower()] = {
                                'status': 'no_data',
                                'message': f'No data available for {metric_name}'
                            }
                    
                    except ClientError as e:
                        logger.warning(f"Failed to get {metric_name} for {instance_id}: {e}")
                        metrics_data[metric_name.lower()] = {
                            'status': 'error',
                            'message': f'Failed to retrieve {metric_name}: {e.response["Error"]["Code"]}'
                        }
            
            return {
                'status': 'success',
                'time_window': time_window,
                'metrics': metrics_data
            }
            
        except Exception as e:
            logger.error(f"Error getting metrics for {instance_id}: {e}")
            return {
                'status': 'error',
                'message': f'Failed to retrieve metrics: {str(e)}'
            }
    
    def _parse_time_window(self, time_window: str) -> timedelta:
        """Parse time window string to timedelta"""
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
            logger.warning(f"Invalid time window: {time_window}, defaulting to 15m")
            return timedelta(minutes=15)
        
        return time_map[time_window]
    
    def _get_metric_unit(self, metric_name: str) -> str:
        """Get unit for a metric"""
        unit_map = {
            'CPUUtilization': 'Percent',
            'MemoryUtilization': 'Percent',
            'NetworkIn': 'Bytes',
            'NetworkOut': 'Bytes',
            'DiskReadOps': 'Count/Second',
            'DiskWriteOps': 'Count/Second'
        }
        return unit_map.get(metric_name, 'Unknown')
    
    def _assess_metric_status(self, metric_name: str, value: float) -> str:
        """Assess metric status based on value"""
        if 'CPU' in metric_name or 'Memory' in metric_name:
            if value > 80:
                return 'HIGH'
            elif value > 50:
                return 'MODERATE'
            else:
                return 'NORMAL'
        elif 'Network' in metric_name:
            # Network metrics are harder to assess without context
            return 'NORMAL'
        else:
            return 'NORMAL'
    
    def _generate_ec2_status_summary(self, instances: List[Dict[str, Any]], metrics: List[str], time_window: str) -> str:
        """
        Generate human-readable summary of EC2 status
        
        Args:
            instances: List of enhanced instance data
            metrics: Requested metrics
            time_window: Time window for metrics
            
        Returns:
            Human-readable summary string
        """
        if not instances:
            return "No EC2 instances found matching the specified criteria"
        
        # Count instances by state
        state_counts = {}
        running_instances = []
        ops_managed_count = 0
        
        for instance in instances:
            state = instance.get('state', 'unknown')
            state_counts[state] = state_counts.get(state, 0) + 1
            
            if state == 'running':
                running_instances.append(instance)
            
            if instance.get('tags', {}).get('OpsAgentManaged') == 'true':
                ops_managed_count += 1
        
        # Build summary parts
        summary_parts = [f"Found {len(instances)} EC2 instance(s)"]
        
        # Add state breakdown
        if state_counts:
            state_summary = ", ".join([f"{count} {state}" for state, count in state_counts.items()])
            summary_parts.append(f"States: {state_summary}")
        
        # Add metrics summary for running instances
        if running_instances and 'cpu' in metrics:
            cpu_issues = []
            for instance in running_instances:
                metrics_data = instance.get('metrics', {}).get('metrics', {})
                cpu_data = metrics_data.get('cpuutilization', {})
                if cpu_data.get('status') == 'HIGH':
                    cpu_issues.append(f"{instance['instance_id']} ({cpu_data.get('latest_value', 0):.1f}%)")
            
            if cpu_issues:
                summary_parts.append(f"High CPU: {', '.join(cpu_issues)}")
            elif running_instances:
                summary_parts.append("CPU levels normal")
        
        # Add OpsAgent managed count
        if ops_managed_count > 0:
            summary_parts.append(f"{ops_managed_count} OpsAgent-managed")
        
        # Add metrics info
        if running_instances:
            summary_parts.append(f"Metrics: {', '.join(metrics)} over {time_window}")
        
        return ". ".join(summary_parts)
    
    def _format_aws_error(self, error: ClientError, service: str) -> str:
        """Format AWS API error for user-friendly display"""
        error_code = error.response.get('Error', {}).get('Code', 'Unknown')
        error_message = error.response.get('Error', {}).get('Message', str(error))
        
        # Map common error codes to user-friendly messages
        error_map = {
            'InvalidInstanceID.NotFound': "One or more specified instance IDs do not exist",
            'InvalidParameterValue': f"Invalid parameter provided to {service} API",
            'AccessDenied': f"Insufficient permissions to access {service} service",
            'UnauthorizedOperation': f"Not authorized to perform {service} operations",
            'Throttling': f"{service} API rate limit exceeded, please try again later",
            'InternalError': f"{service} service is temporarily unavailable",
            'InvalidMetricName': "The specified metric name does not exist",
            'InvalidNamespace': "The specified namespace is not valid"
        }
        
        user_message = error_map.get(error_code, f"{service} API error: {error_message}")
        
        # Don't expose sensitive details in error messages
        if 'credential' in error_message.lower() or 'token' in error_message.lower():
            user_message = f"Authentication error accessing {service} service"
        
        return user_message
    
    def _mock_ec2_status_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Generate mock EC2 status response for testing
        
        Args:
            tool_call: Tool call with parameters
            correlation_id: Request correlation ID
            
        Returns:
            Mock ToolResult with sample EC2 status and metrics data
        """
        instance_id = tool_call.args.get('instance_id')
        tag_filter = tool_call.args.get('tag_filter', {})
        metrics = tool_call.args.get('metrics', ['cpu', 'memory', 'network'])
        time_window = tool_call.args.get('time_window', '15m')
        
        # Validate that we have either instance_id or tag_filter (same as real implementation)
        if not instance_id and not tag_filter:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error="Either instance_id or tag_filter is required",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        
        # Generate mock instances
        mock_instances = []
        
        if instance_id:
            # Single instance by ID
            mock_instances = [{
                'instance_id': instance_id,
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
                    'Name': 'test-instance',
                    'Environment': 'sandbox',
                    'OpsAgentManaged': 'true'
                },
                'monitoring': 'enabled',
                'platform': None,
                'architecture': 'x86_64',
                'virtualization_type': 'hvm',
                'root_device_type': 'ebs',
                'metrics': {
                    'status': 'success',
                    'time_window': time_window,
                    'metrics': {
                        'cpuutilization': {
                            'latest_value': 45.2,
                            'max_value': 78.5,
                            'min_value': 12.1,
                            'datapoint_count': 15,
                            'unit': 'Percent',
                            'status': 'NORMAL'
                        },
                        'networkin': {
                            'latest_value': 1200000,
                            'max_value': 2500000,
                            'min_value': 800000,
                            'datapoint_count': 15,
                            'unit': 'Bytes',
                            'status': 'NORMAL'
                        },
                        'networkout': {
                            'latest_value': 800000,
                            'max_value': 1500000,
                            'min_value': 500000,
                            'datapoint_count': 15,
                            'unit': 'Bytes',
                            'status': 'NORMAL'
                        }
                    }
                }
            }]
        else:
            # Multiple instances by tag filter
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
                        'Name': 'web-server-1',
                        'Environment': 'sandbox',
                        'OpsAgentManaged': 'true'
                    },
                    'monitoring': 'enabled',
                    'platform': None,
                    'architecture': 'x86_64',
                    'virtualization_type': 'hvm',
                    'root_device_type': 'ebs',
                    'metrics': {
                        'status': 'success',
                        'time_window': time_window,
                        'metrics': {
                            'cpuutilization': {
                                'latest_value': 85.3,
                                'max_value': 92.1,
                                'min_value': 45.2,
                                'datapoint_count': 15,
                                'unit': 'Percent',
                                'status': 'HIGH'
                            },
                            'networkin': {
                                'latest_value': 2100000,
                                'max_value': 3200000,
                                'min_value': 1200000,
                                'datapoint_count': 15,
                                'unit': 'Bytes',
                                'status': 'NORMAL'
                            }
                        }
                    }
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
                        'Name': 'web-server-2',
                        'Environment': 'sandbox',
                        'OpsAgentManaged': 'true'
                    },
                    'monitoring': 'disabled',
                    'platform': None,
                    'architecture': 'x86_64',
                    'virtualization_type': 'hvm',
                    'root_device_type': 'ebs',
                    'metrics': {
                        'status': 'instance_not_running',
                        'message': 'Metrics not available for stopped instance'
                    }
                }
            ]
        
        # Apply tag filters to mock data
        if tag_filter:
            filtered_instances = []
            for instance in mock_instances:
                match = True
                for tag_key, tag_value in tag_filter.items():
                    if instance.get('tags', {}).get(tag_key) != tag_value:
                        match = False
                        break
                if match:
                    filtered_instances.append(instance)
            mock_instances = filtered_instances
        
        summary = self._generate_ec2_status_summary(mock_instances, metrics, time_window)
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'instances': mock_instances,
                'instance_count': len(mock_instances),
                'metrics_requested': metrics,
                'time_window': time_window,
                'summary': summary,
                'mock': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )


class CloudTrailSearchTool:
    """
    CloudTrail event search tool with filtering capabilities and pagination support
    Requirements: 4.1, 4.2, 4.3
    """
    
    def __init__(self, execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE):
        self.execution_mode = execution_mode
        self.cloudtrail_client = None
        
        # Only initialize client if not in LOCAL_MOCK mode
        if execution_mode != ExecutionMode.LOCAL_MOCK:
            self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize CloudTrail client"""
        try:
            self.cloudtrail_client = boto3.client('cloudtrail')
            logger.info("CloudTrail client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize CloudTrail client: {e}")
            # Don't raise exception - continue without client for graceful degradation
            self.cloudtrail_client = None
    
    def execute(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """
        Execute CloudTrail event search with enhanced filtering and pagination
        
        Args:
            tool_call: Tool call with search parameters
            correlation_id: Request correlation ID
            
        Returns:
            ToolResult with CloudTrail events formatted for chat display
        """
        logger.info(f"Executing CloudTrail search tool for correlation_id: {correlation_id}")
        
        # Check for LOCAL_MOCK mode first
        if self.execution_mode == ExecutionMode.LOCAL_MOCK:
            return self._mock_cloudtrail_response(tool_call, correlation_id)
        
        if not self.cloudtrail_client:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error="CloudTrail client not available",
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        
        try:
            # Extract and validate parameters
            time_window = tool_call.args.get("time_window", "1h")
            event_name = tool_call.args.get("event_name")
            resource_name = tool_call.args.get("resource_name")
            user_name = tool_call.args.get("user_name")
            source_ip = tool_call.args.get("source_ip")
            max_results = min(tool_call.args.get("max_results", 50), 100)  # Limit to 100 for API constraints
            
            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - self._parse_time_window(time_window)
            
            # Validate time range (CloudTrail has limitations)
            if (end_time - start_time).days > 90:
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="Time window cannot exceed 90 days due to CloudTrail API limitations",
                    execution_mode=self.execution_mode,
                    correlation_id=correlation_id
                )
            
            # Build lookup attributes with enhanced filtering
            lookup_attributes = []
            if event_name:
                lookup_attributes.append({
                    'AttributeKey': 'EventName',
                    'AttributeValue': event_name
                })
            if resource_name:
                lookup_attributes.append({
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': resource_name
                })
            if user_name:
                lookup_attributes.append({
                    'AttributeKey': 'Username',
                    'AttributeValue': user_name
                })
            
            # Search CloudTrail events with pagination handling
            all_events = []
            next_token = None
            pages_fetched = 0
            max_pages = 5  # Limit to prevent excessive API calls
            
            while pages_fetched < max_pages:
                kwargs = {
                    'StartTime': start_time,
                    'EndTime': end_time,
                    'MaxItems': min(max_results - len(all_events), 50)  # CloudTrail max per call is 50
                }
                
                if lookup_attributes:
                    kwargs['LookupAttributes'] = lookup_attributes
                
                if next_token:
                    kwargs['NextToken'] = next_token
                
                response = self.cloudtrail_client.lookup_events(**kwargs)
                
                events = response.get('Events', [])
                all_events.extend(events)
                
                next_token = response.get('NextToken')
                pages_fetched += 1
                
                # Stop if we have enough events or no more pages
                if len(all_events) >= max_results or not next_token:
                    break
            
            # Limit to requested max_results
            all_events = all_events[:max_results]
            
            # Apply additional filtering if source_ip is specified (not supported by lookup_attributes)
            if source_ip:
                all_events = [event for event in all_events if event.get('SourceIPAddress') == source_ip]
            
            # Format events for chat display
            formatted_events = []
            for event in all_events:
                formatted_event = self._format_event_for_display(event)
                formatted_events.append(formatted_event)
            
            # Generate human-readable summary
            summary = self._generate_cloudtrail_summary(
                formatted_events, time_window, event_name, resource_name, user_name
            )
            
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                data={
                    'events': formatted_events,
                    'event_count': len(formatted_events),
                    'time_range': {
                        'start_time': start_time.isoformat() + 'Z',
                        'end_time': end_time.isoformat() + 'Z',
                        'window': time_window
                    },
                    'search_criteria': {
                        'event_name': event_name,
                        'resource_name': resource_name,
                        'user_name': user_name,
                        'source_ip': source_ip
                    },
                    'pagination_info': {
                        'pages_fetched': pages_fetched,
                        'has_more_results': next_token is not None,
                        'max_results_limit': max_results
                    },
                    'summary': summary
                },
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
            
        except ClientError as e:
            error_msg = self._format_aws_error(e, "CloudTrail")
            logger.error(f"CloudTrail API error: {error_msg}")
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
        except Exception as e:
            error_msg = f"Unexpected error searching CloudTrail events: {str(e)}"
            logger.error(error_msg)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=error_msg,
                execution_mode=self.execution_mode,
                correlation_id=correlation_id
            )
    
    def _parse_time_window(self, time_window: str) -> timedelta:
        """Parse time window string into timedelta"""
        try:
            if time_window.endswith('m'):
                return timedelta(minutes=int(time_window[:-1]))
            elif time_window.endswith('h'):
                return timedelta(hours=int(time_window[:-1]))
            elif time_window.endswith('d'):
                return timedelta(days=int(time_window[:-1]))
            else:
                return timedelta(hours=1)  # Default to 1 hour
        except (ValueError, IndexError):
            return timedelta(hours=1)  # Default to 1 hour
    
    def _mock_cloudtrail_response(self, tool_call: ToolCall, correlation_id: str) -> ToolResult:
        """Mock CloudTrail search response for testing with enhanced formatting"""
        time_window = tool_call.args.get("time_window", "1h")
        event_name = tool_call.args.get("event_name")
        resource_name = tool_call.args.get("resource_name")
        user_name = tool_call.args.get("user_name")
        
        end_time = datetime.utcnow()
        start_time = end_time - self._parse_time_window(time_window)
        
        # Generate mock events with realistic data
        mock_raw_events = [
            {
                'EventTime': end_time - timedelta(minutes=30),
                'EventName': event_name or 'RunInstances',
                'Username': user_name or 'test-user@company.com',
                'SourceIPAddress': '203.0.113.1',
                'UserAgent': 'aws-cli/2.0.0',
                'AwsRegion': 'us-east-1',
                'Resources': [
                    {
                        'ResourceType': 'AWS::EC2::Instance',
                        'ResourceName': resource_name or 'i-1234567890abcdef0',
                        'ResourceArn': f'arn:aws:ec2:us-east-1:123456789012:instance/{resource_name or "i-1234567890abcdef0"}'
                    }
                ]
            },
            {
                'EventTime': end_time - timedelta(minutes=15),
                'EventName': event_name or 'StopInstances',
                'Username': user_name or 'admin-user@company.com',
                'SourceIPAddress': '203.0.113.2',
                'UserAgent': 'console.aws.amazon.com',
                'AwsRegion': 'us-east-1',
                'Resources': [
                    {
                        'ResourceType': 'AWS::EC2::Instance',
                        'ResourceName': resource_name or 'i-1234567890abcdef0',
                        'ResourceArn': f'arn:aws:ec2:us-east-1:123456789012:instance/{resource_name or "i-1234567890abcdef0"}'
                    }
                ]
            },
            {
                'EventTime': end_time - timedelta(minutes=5),
                'EventName': 'ConsoleLogin',
                'Username': 'security-admin@company.com',
                'SourceIPAddress': '203.0.113.3',
                'UserAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                'AwsRegion': 'us-east-1',
                'Resources': []
            }
        ]
        
        # Format events using the new formatting method
        formatted_events = []
        for event in mock_raw_events:
            formatted_event = self._format_event_for_display(event)
            formatted_events.append(formatted_event)
        
        # Generate summary using the new method
        summary = self._generate_cloudtrail_summary(
            formatted_events, time_window, event_name, resource_name, user_name
        )
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'events': formatted_events,
                'event_count': len(formatted_events),
                'time_range': {
                    'start_time': start_time.isoformat() + 'Z',
                    'end_time': end_time.isoformat() + 'Z',
                    'window': time_window
                },
                'search_criteria': {
                    'event_name': event_name,
                    'resource_name': resource_name,
                    'user_name': user_name,
                    'source_ip': tool_call.args.get("source_ip")
                },
                'pagination_info': {
                    'pages_fetched': 1,
                    'has_more_results': False,
                    'max_results_limit': 50
                },
                'summary': summary + " (mock data)",
                'mock': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )
        
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=True,
            data={
                'events': mock_events,
                'event_count': len(mock_events),
                'time_range': {
                    'start_time': start_time.isoformat() + 'Z',
                    'end_time': end_time.isoformat() + 'Z',
                    'window': time_window
                },
                'search_criteria': {
                    'event_name': event_name,
                    'resource_name': resource_name,
                    'user_name': tool_call.args.get("user_name")
                },
                'summary': f"Found {len(mock_events)} CloudTrail event(s) in the last {time_window} (mock data)",
                'mock': True
            },
            execution_mode=self.execution_mode,
            correlation_id=correlation_id
        )
    
    def _format_event_for_display(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format CloudTrail event for human-readable chat display
        
        Args:
            event: Raw CloudTrail event from API
            
        Returns:
            Formatted event data optimized for chat display
        """
        # Extract basic event information
        event_time = event['EventTime']
        event_name = event['EventName']
        user_name = event.get('Username', 'Unknown')
        source_ip = event.get('SourceIPAddress', 'Unknown')
        user_agent = event.get('UserAgent', 'Unknown')
        aws_region = event.get('AwsRegion', 'Unknown')
        
        # Process resources with better formatting
        resources = []
        for resource in event.get('Resources', []):
            resource_info = {
                'resource_type': resource.get('ResourceType', 'Unknown'),
                'resource_name': resource.get('ResourceName', 'Unknown')
            }
            # Add resource ARN if available for better identification
            if 'ResourceArn' in resource:
                resource_info['resource_arn'] = resource['ResourceArn']
            resources.append(resource_info)
        
        # Extract error information if present
        error_code = None
        error_message = None
        if 'ErrorCode' in event:
            error_code = event['ErrorCode']
            error_message = event.get('ErrorMessage', 'Unknown error')
        
        # Determine event category for better display
        event_category = self._categorize_event(event_name)
        
        # Generate human-readable description
        description = self._generate_event_description(
            event_name, user_name, resources, error_code
        )
        
        return {
            'event_time': event_time.isoformat() + 'Z',
            'event_name': event_name,
            'event_category': event_category,
            'user_name': user_name,
            'source_ip': source_ip,
            'user_agent': user_agent,
            'aws_region': aws_region,
            'resources': resources,
            'resource_count': len(resources),
            'error_code': error_code,
            'error_message': error_message,
            'success': error_code is None,
            'description': description,
            # Add additional context for security-relevant events
            'security_relevant': self._is_security_relevant_event(event_name),
            'read_only': self._is_read_only_event(event_name)
        }
    
    def _categorize_event(self, event_name: str) -> str:
        """
        Categorize CloudTrail event for better organization
        
        Args:
            event_name: CloudTrail event name
            
        Returns:
            Event category string
        """
        if any(action in event_name for action in ['Create', 'Run', 'Launch', 'Start']):
            return 'create'
        elif any(action in event_name for action in ['Delete', 'Terminate', 'Stop']):
            return 'delete'
        elif any(action in event_name for action in ['Modify', 'Update', 'Change', 'Put', 'Attach', 'Detach']):
            return 'modify'
        elif any(action in event_name for action in ['Describe', 'List', 'Get']):
            return 'read'
        elif any(action in event_name for action in ['Assume', 'Login', 'Signin']):
            return 'auth'
        else:
            return 'other'
    
    def _is_security_relevant_event(self, event_name: str) -> bool:
        """
        Determine if event is security-relevant
        
        Args:
            event_name: CloudTrail event name
            
        Returns:
            True if event is security-relevant
        """
        security_events = [
            'AssumeRole', 'CreateUser', 'DeleteUser', 'CreateRole', 'DeleteRole',
            'AttachUserPolicy', 'DetachUserPolicy', 'AttachRolePolicy', 'DetachRolePolicy',
            'CreateAccessKey', 'DeleteAccessKey', 'CreateLoginProfile', 'DeleteLoginProfile',
            'ConsoleLogin', 'CreatePolicy', 'DeletePolicy', 'ModifyDBInstance',
            'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
            'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress'
        ]
        return any(security_event in event_name for security_event in security_events)
    
    def _is_read_only_event(self, event_name: str) -> bool:
        """
        Determine if event is read-only
        
        Args:
            event_name: CloudTrail event name
            
        Returns:
            True if event is read-only
        """
        read_only_prefixes = ['Describe', 'List', 'Get', 'Head']
        return any(event_name.startswith(prefix) for prefix in read_only_prefixes)
    
    def _generate_event_description(
        self, 
        event_name: str, 
        user_name: str, 
        resources: List[Dict[str, Any]], 
        error_code: Optional[str]
    ) -> str:
        """
        Generate human-readable description of the event
        
        Args:
            event_name: CloudTrail event name
            user_name: User who performed the action
            resources: List of affected resources
            error_code: Error code if action failed
            
        Returns:
            Human-readable event description
        """
        # Build resource description
        if resources:
            if len(resources) == 1:
                resource_desc = f"{resources[0]['resource_type']} {resources[0]['resource_name']}"
            else:
                resource_desc = f"{len(resources)} resources"
        else:
            resource_desc = "unknown resource"
        
        # Build action description
        action_map = {
            'RunInstances': 'launched EC2 instance',
            'TerminateInstances': 'terminated EC2 instance',
            'StopInstances': 'stopped EC2 instance',
            'StartInstances': 'started EC2 instance',
            'RebootInstances': 'rebooted EC2 instance',
            'CreateBucket': 'created S3 bucket',
            'DeleteBucket': 'deleted S3 bucket',
            'PutObject': 'uploaded object to S3',
            'DeleteObject': 'deleted object from S3',
            'AssumeRole': 'assumed IAM role',
            'ConsoleLogin': 'logged into AWS console',
            'CreateUser': 'created IAM user',
            'DeleteUser': 'deleted IAM user'
        }
        
        action_desc = action_map.get(event_name, f"performed {event_name}")
        
        # Build complete description
        if error_code:
            return f"{user_name} attempted to {action_desc} on {resource_desc} but failed with error: {error_code}"
        else:
            return f"{user_name} successfully {action_desc} on {resource_desc}"
    
    def _generate_cloudtrail_summary(
        self, 
        events: List[Dict[str, Any]], 
        time_window: str,
        event_name: Optional[str],
        resource_name: Optional[str],
        user_name: Optional[str]
    ) -> str:
        """
        Generate human-readable summary of CloudTrail search results
        
        Args:
            events: List of formatted events
            time_window: Search time window
            event_name: Event name filter (if any)
            resource_name: Resource name filter (if any)
            user_name: User name filter (if any)
            
        Returns:
            Human-readable summary string
        """
        if not events:
            filter_desc = []
            if event_name:
                filter_desc.append(f"event '{event_name}'")
            if resource_name:
                filter_desc.append(f"resource '{resource_name}'")
            if user_name:
                filter_desc.append(f"user '{user_name}'")
            
            filter_text = " with " + " and ".join(filter_desc) if filter_desc else ""
            return f"No CloudTrail events found in the last {time_window}{filter_text}"
        
        # Count events by category
        category_counts = {}
        user_counts = {}
        error_count = 0
        security_event_count = 0
        
        for event in events:
            category = event.get('event_category', 'other')
            category_counts[category] = category_counts.get(category, 0) + 1
            
            user = event.get('user_name', 'Unknown')
            user_counts[user] = user_counts.get(user, 0) + 1
            
            if not event.get('success', True):
                error_count += 1
            
            if event.get('security_relevant', False):
                security_event_count += 1
        
        # Build summary parts
        summary_parts = [f"Found {len(events)} CloudTrail event(s) in the last {time_window}"]
        
        # Add category breakdown
        if category_counts:
            category_summary = ", ".join([
                f"{count} {category}" for category, count in 
                sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
            ])
            summary_parts.append(f"Categories: {category_summary}")
        
        # Add user breakdown (top 3 users)
        if user_counts:
            top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            user_summary = ", ".join([f"{user} ({count})" for user, count in top_users])
            summary_parts.append(f"Top users: {user_summary}")
        
        # Add error information
        if error_count > 0:
            summary_parts.append(f"⚠ {error_count} failed event(s)")
        
        # Add security information
        if security_event_count > 0:
            summary_parts.append(f"🔒 {security_event_count} security-relevant event(s)")
        
        # Add time range info
        if events:
            latest_event = max(events, key=lambda x: x['event_time'])
            oldest_event = min(events, key=lambda x: x['event_time'])
            
            latest_time = datetime.fromisoformat(latest_event['event_time'].replace('Z', '+00:00'))
            oldest_time = datetime.fromisoformat(oldest_event['event_time'].replace('Z', '+00:00'))
            
            time_span = latest_time - oldest_time
            if time_span.total_seconds() > 3600:  # More than 1 hour
                summary_parts.append(f"Time span: {time_span.days}d {time_span.seconds//3600}h")
            else:
                summary_parts.append(f"Time span: {time_span.seconds//60}m")
        
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
            'InvalidParameterValue': f"Invalid parameter provided to {service} API",
            'AccessDenied': f"Insufficient permissions to access {service} service",
            'UnauthorizedOperation': f"Not authorized to perform {service} operations",
            'Throttling': f"{service} API rate limit exceeded, please try again later",
            'InternalServiceError': f"{service} service is temporarily unavailable",
            'InvalidTimeRange': "The specified time range is invalid or too large",
            'InvalidLookupAttribute': "One or more lookup attributes are invalid",
            'InvalidMaxResults': "The maximum number of results is invalid",
            'InvalidNextToken': "The pagination token is invalid or expired"
        }
        
        user_message = error_map.get(error_code, f"{service} API error: {error_message}")
        
        # Don't expose sensitive details in error messages
        if 'credential' in error_message.lower() or 'token' in error_message.lower():
            user_message = f"Authentication error accessing {service} service"
        
        return user_message