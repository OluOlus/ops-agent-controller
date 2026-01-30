"""
Unit tests for AWS remediation tools
Requirements: 3.2, 3.4, 3.5, 11.12, 11.13
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from botocore.exceptions import ClientError

from src.aws_remediation_tools import EC2RebootTool, RemediationToolError
from src.models import ToolCall, ToolResult, ExecutionMode


class TestEC2RebootTool:
    """Test EC2 reboot remediation tool functionality"""
    
    def test_init_local_mock_mode(self):
        """Test initialization in LOCAL_MOCK mode"""
        tool = EC2RebootTool(ExecutionMode.LOCAL_MOCK)
        assert tool.execution_mode == ExecutionMode.LOCAL_MOCK
        assert tool.ec2_client is None
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_init_dry_run_mode(self, mock_boto_client):
        """Test initialization in DRY_RUN mode"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        tool = EC2RebootTool(ExecutionMode.DRY_RUN)
        assert tool.execution_mode == ExecutionMode.DRY_RUN
        assert tool.ec2_client == mock_client
        mock_boto_client.assert_called_once_with('ec2')
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_init_sandbox_live_mode(self, mock_boto_client):
        """Test initialization in SANDBOX_LIVE mode"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        assert tool.execution_mode == ExecutionMode.SANDBOX_LIVE
        assert tool.ec2_client == mock_client
        mock_boto_client.assert_called_once_with('ec2')
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_init_client_failure(self, mock_boto_client):
        """Test client initialization failure"""
        mock_boto_client.side_effect = Exception("AWS credentials not found")
        
        # Should not raise exception, just log error and continue with None client
        tool = EC2RebootTool(ExecutionMode.DRY_RUN)
        assert tool.ec2_client is None
    
    def test_validate_instance_id_format_valid(self):
        """Test instance ID format validation with valid IDs"""
        tool = EC2RebootTool()
        
        # Test various valid formats
        assert tool._validate_instance_id_format('i-1234567890abcdef0') is True
        assert tool._validate_instance_id_format('i-12345678') is True
        assert tool._validate_instance_id_format('i-0123456789abcdef0') is True
        assert tool._validate_instance_id_format('i-abcdef1234567890a') is True
    
    def test_validate_instance_id_format_invalid(self):
        """Test instance ID format validation with invalid IDs"""
        tool = EC2RebootTool()
        
        # Test various invalid formats
        assert tool._validate_instance_id_format('invalid-id') is False
        assert tool._validate_instance_id_format('i-') is False
        assert tool._validate_instance_id_format('i-1234567') is False  # Too short
        assert tool._validate_instance_id_format('i-123456789012345678') is False  # Too long
        assert tool._validate_instance_id_format('i-123456789012345g') is False  # Invalid character
        assert tool._validate_instance_id_format('') is False
        assert tool._validate_instance_id_format('i-ABCDEF1234567890') is False  # Uppercase not allowed
    
    def test_execute_missing_instance_id(self):
        """Test execution with missing instance_id parameter"""
        tool = EC2RebootTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={}  # Missing instance_id
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Missing required parameter: instance_id" in result.error
        assert result.correlation_id == 'test-correlation-id'
    
    def test_execute_invalid_instance_id_format(self):
        """Test execution with invalid instance ID format"""
        tool = EC2RebootTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={'instance_id': 'invalid-id'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Invalid instance ID format: invalid-id" in result.error
    
    def test_execute_mock_mode(self):
        """Test execution in LOCAL_MOCK mode"""
        tool = EC2RebootTool(ExecutionMode.LOCAL_MOCK)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={'instance_id': 'i-1234567890abcdef0'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.tool_name == "reboot_ec2_instance"
        assert result.execution_mode == ExecutionMode.LOCAL_MOCK
        assert result.correlation_id == 'test-correlation-id'
        assert result.data['action'] == 'MOCK_EXECUTED'
        assert result.data['instance_id'] == 'i-1234567890abcdef0'
        assert result.data['mock'] is True
        assert 'execution_confirmation' in result.data
        assert 'timestamp' in result.data
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_execute_dry_run_mode(self, mock_boto_client):
        """Test execution in DRY_RUN mode"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock successful describe_instances call
        mock_client.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'State': {'Name': 'running'},
                    'InstanceType': 't3.medium',
                    'Placement': {'AvailabilityZone': 'us-east-1a'}
                }]
            }]
        }
        
        tool = EC2RebootTool(ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={'instance_id': 'i-1234567890abcdef0'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.execution_mode == ExecutionMode.DRY_RUN
        assert result.data['action'] == 'WOULD_EXECUTE'
        assert result.data['instance_id'] == 'i-1234567890abcdef0'
        assert 'would be executed' in result.data['message'].lower()
        assert 'target_instance' in result.data
        assert result.data['target_instance']['current_state'] == 'running'
        assert result.data['target_instance']['instance_type'] == 't3.medium'
        
        # Verify only describe_instances was called (read-only)
        mock_client.describe_instances.assert_called_once_with(InstanceIds=['i-1234567890abcdef0'])
        mock_client.reboot_instances.assert_not_called()
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_execute_dry_run_mode_describe_failure(self, mock_boto_client):
        """Test execution in DRY_RUN mode when describe_instances fails"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock describe_instances failure
        mock_client.describe_instances.side_effect = ClientError(
            {'Error': {'Code': 'InvalidInstanceID.NotFound', 'Message': 'Instance not found'}},
            'DescribeInstances'
        )
        
        tool = EC2RebootTool(ExecutionMode.DRY_RUN)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={'instance_id': 'i-1234567890abcdef0'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        # Should still succeed in dry-run mode even if describe fails
        assert result.success is True
        assert result.data['action'] == 'WOULD_EXECUTE'
        assert 'target_instance' not in result.data  # No instance info due to describe failure
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_execute_sandbox_live_mode_success(self, mock_boto_client):
        """Test successful execution in SANDBOX_LIVE mode"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock successful describe_instances call
        mock_client.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'State': {'Name': 'running'},
                    'InstanceType': 't3.medium',
                    'Placement': {'AvailabilityZone': 'us-east-1a'}
                }]
            }]
        }
        
        # Mock successful reboot_instances call
        mock_client.reboot_instances.return_value = {
            'ResponseMetadata': {'RequestId': 'test-request-id-123'}
        }
        
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={'instance_id': 'i-1234567890abcdef0'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is True
        assert result.execution_mode == ExecutionMode.SANDBOX_LIVE
        assert result.data['action'] == 'EXECUTED'
        assert result.data['instance_id'] == 'i-1234567890abcdef0'
        assert result.data['status'] == 'reboot_initiated'
        assert result.data['previous_state'] == 'running'
        assert result.data['aws_request_id'] == 'test-request-id-123'
        assert 'execution_confirmation' in result.data
        assert 'target_instance' in result.data
        
        # Verify both describe and reboot were called
        mock_client.describe_instances.assert_called_once_with(InstanceIds=['i-1234567890abcdef0'])
        mock_client.reboot_instances.assert_called_once_with(InstanceIds=['i-1234567890abcdef0'])
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_execute_sandbox_live_instance_not_found(self, mock_boto_client):
        """Test execution in SANDBOX_LIVE mode with instance not found"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock describe_instances returning no reservations
        mock_client.describe_instances.return_value = {'Reservations': []}
        
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={'instance_id': 'i-1234567890abcdef0'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Instance i-1234567890abcdef0 not found" in result.error
        
        # Verify describe was called but reboot was not
        mock_client.describe_instances.assert_called_once()
        mock_client.reboot_instances.assert_not_called()
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_execute_sandbox_live_incorrect_state(self, mock_boto_client):
        """Test execution in SANDBOX_LIVE mode with instance in incorrect state"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock instance in terminating state
        mock_client.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'State': {'Name': 'terminating'},
                    'InstanceType': 't3.medium',
                    'Placement': {'AvailabilityZone': 'us-east-1a'}
                }]
            }]
        }
        
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={'instance_id': 'i-1234567890abcdef0'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "is in state 'terminating' which does not allow rebooting" in result.error
        assert "Only 'running' or 'stopped' instances can be rebooted" in result.error
        
        # Verify reboot was not called
        mock_client.reboot_instances.assert_not_called()
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_execute_sandbox_live_reboot_api_error(self, mock_boto_client):
        """Test execution in SANDBOX_LIVE mode with reboot API error"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock successful describe
        mock_client.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'State': {'Name': 'running'},
                    'InstanceType': 't3.medium',
                    'Placement': {'AvailabilityZone': 'us-east-1a'}
                }]
            }]
        }
        
        # Mock reboot failure
        mock_client.reboot_instances.side_effect = ClientError(
            {'Error': {'Code': 'UnauthorizedOperation', 'Message': 'Access denied'}},
            'RebootInstances'
        )
        
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={'instance_id': 'i-1234567890abcdef0'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Insufficient permissions to reboot instance" in result.error
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_execute_sandbox_live_no_client(self, mock_boto_client):
        """Test execution in SANDBOX_LIVE mode without EC2 client"""
        mock_boto_client.side_effect = Exception("Client init failed")
        
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        # Client should be None due to init failure
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={'instance_id': 'i-1234567890abcdef0'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "EC2 client not available for live execution" in result.error
    
    def test_execute_unsupported_mode(self):
        """Test execution with unsupported execution mode"""
        tool = EC2RebootTool(ExecutionMode.LOCAL_MOCK)
        # Manually set an invalid mode for testing
        tool.execution_mode = "INVALID_MODE"
        
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args={'instance_id': 'i-1234567890abcdef0'}
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Unsupported execution mode: INVALID_MODE" in result.error
    
    def test_get_status_report_mock_mode(self):
        """Test status report in LOCAL_MOCK mode"""
        tool = EC2RebootTool(ExecutionMode.LOCAL_MOCK)
        
        result = tool.get_status_report('i-1234567890abcdef0', 'test-correlation-id')
        
        assert result.success is True
        assert result.tool_name == "get_reboot_status"
        assert result.data['instance_id'] == 'i-1234567890abcdef0'
        assert result.data['current_state'] == 'running'
        assert result.data['mock'] is True
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_get_status_report_live_mode(self, mock_boto_client):
        """Test status report in live mode"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock describe_instances response
        mock_client.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'State': {'Name': 'running'},
                    'StateReason': {'Message': 'running'}
                }]
            }]
        }
        
        # Mock describe_instance_status response
        mock_client.describe_instance_status.return_value = {
            'InstanceStatuses': [{
                'InstanceStatus': {'Status': 'ok'},
                'SystemStatus': {'Status': 'ok'}
            }]
        }
        
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        
        result = tool.get_status_report('i-1234567890abcdef0', 'test-correlation-id')
        
        assert result.success is True
        assert result.data['instance_id'] == 'i-1234567890abcdef0'
        assert result.data['current_state'] == 'running'
        assert result.data['instance_status'] == 'ok'
        assert result.data['system_status'] == 'ok'
        
        # Verify both API calls were made
        mock_client.describe_instances.assert_called_once_with(InstanceIds=['i-1234567890abcdef0'])
        mock_client.describe_instance_status.assert_called_once_with(InstanceIds=['i-1234567890abcdef0'])
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_get_status_report_status_check_unavailable(self, mock_boto_client):
        """Test status report when status checks are unavailable"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock describe_instances response
        mock_client.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'State': {'Name': 'running'},
                    'StateReason': {'Message': 'running'}
                }]
            }]
        }
        
        # Mock describe_instance_status failure (normal after reboot)
        mock_client.describe_instance_status.side_effect = ClientError(
            {'Error': {'Code': 'InvalidInstanceID.NotFound', 'Message': 'Status not available'}},
            'DescribeInstanceStatus'
        )
        
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        
        result = tool.get_status_report('i-1234567890abcdef0', 'test-correlation-id')
        
        assert result.success is True
        assert result.data['current_state'] == 'running'
        assert 'instance_status' not in result.data  # Status checks not available
        assert 'system_status' not in result.data
    
    @patch('src.aws_remediation_tools.boto3.client')
    def test_get_status_report_instance_not_found(self, mock_boto_client):
        """Test status report with instance not found"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock describe_instances returning no reservations
        mock_client.describe_instances.return_value = {'Reservations': []}
        
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        
        result = tool.get_status_report('i-1234567890abcdef0', 'test-correlation-id')
        
        assert result.success is False
        assert "Instance i-1234567890abcdef0 not found" in result.error
    
    def test_get_status_report_no_client(self):
        """Test status report without EC2 client"""
        tool = EC2RebootTool(ExecutionMode.SANDBOX_LIVE)
        tool.ec2_client = None  # Simulate client initialization failure
        
        result = tool.get_status_report('i-1234567890abcdef0', 'test-correlation-id')
        
        assert result.success is False
        assert "EC2 client not available for status check" in result.error
    
    def test_parameter_validation_error_handling(self):
        """Test parameter validation error handling"""
        tool = EC2RebootTool(ExecutionMode.LOCAL_MOCK)
        
        # Test with None args
        tool_call = ToolCall(
            tool_name="reboot_ec2_instance",
            args=None
        )
        
        result = tool.execute(tool_call, 'test-correlation-id')
        
        assert result.success is False
        assert "Parameter validation error" in result.error