"""
Unit tests for LLM provider
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from src.llm_provider import (
    BedrockLLMProvider, MockLLMProvider, LLMResponse,
    LLMProviderError, LLMProviderTimeoutError, LLMProviderValidationError,
    create_llm_provider
)
from src.models import ToolCall, ExecutionMode


class TestMockLLMProvider:
    """Test MockLLMProvider for LOCAL_MOCK mode"""
    
    def test_initialization(self):
        """Test MockLLMProvider initialization"""
        provider = MockLLMProvider()
        assert provider.call_count == 0
    
    def test_generate_tool_calls_cpu_metrics(self):
        """Test generating tool calls for CPU metrics request"""
        provider = MockLLMProvider()
        response = provider.generate_tool_calls("Check CPU usage", "test-correlation-id")
        
        assert isinstance(response, LLMResponse)
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].tool_name == "get_cloudwatch_metrics"
        assert response.tool_calls[0].args["namespace"] == "AWS/EC2"
        assert response.tool_calls[0].args["metric_name"] == "CPUUtilization"
        assert response.tool_calls[0].requires_approval is False
        assert response.confidence == 0.9
        assert provider.call_count == 1
    
    def test_generate_tool_calls_ec2_describe(self):
        """Test generating tool calls for EC2 describe request"""
        provider = MockLLMProvider()
        response = provider.generate_tool_calls("Describe EC2 instances", "test-correlation-id")
        
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].tool_name == "describe_ec2_instances"
        assert "instance_ids" in response.tool_calls[0].args
        assert response.tool_calls[0].requires_approval is False
    
    def test_generate_tool_calls_reboot(self):
        """Test generating tool calls for reboot request"""
        provider = MockLLMProvider()
        response = provider.generate_tool_calls("Reboot the server", "test-correlation-id")
        
        # Should generate both describe and reboot tools since "reboot" matches both keywords
        assert len(response.tool_calls) >= 1
        
        # Find the reboot tool call
        reboot_calls = [tc for tc in response.tool_calls if tc.tool_name == "reboot_ec2_instance"]
        assert len(reboot_calls) == 1
        assert reboot_calls[0].requires_approval is True
    
    def test_generate_tool_calls_default(self):
        """Test generating default tool calls for unknown request"""
        provider = MockLLMProvider()
        response = provider.generate_tool_calls("Random request", "test-correlation-id")
        
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].tool_name == "get_cloudwatch_metrics"
    
    def test_generate_summary_empty_results(self):
        """Test generating summary with empty results"""
        provider = MockLLMProvider()
        summary = provider.generate_summary([], "test-correlation-id")
        
        assert summary == "No results to summarize."
    
    def test_generate_summary_successful_results(self):
        """Test generating summary with successful results"""
        provider = MockLLMProvider()
        tool_results = [
            {
                "tool_name": "get_cloudwatch_metrics",
                "success": True,
                "data": {"cpu_utilization": 75.5}
            }
        ]
        
        summary = provider.generate_summary(tool_results, "test-correlation-id")
        
        assert "Successfully executed 1 tool(s)" in summary
        assert "get_cloudwatch_metrics: Completed successfully" in summary
    
    def test_generate_summary_failed_results(self):
        """Test generating summary with failed results"""
        provider = MockLLMProvider()
        tool_results = [
            {
                "tool_name": "get_cloudwatch_metrics",
                "success": False,
                "error": "Access denied"
            }
        ]
        
        summary = provider.generate_summary(tool_results, "test-correlation-id")
        
        assert "Failed to execute 1 tool(s)" in summary
        assert "get_cloudwatch_metrics: Access denied" in summary
    
    def test_generate_summary_mixed_results(self):
        """Test generating summary with mixed results"""
        provider = MockLLMProvider()
        tool_results = [
            {
                "tool_name": "get_cloudwatch_metrics",
                "success": True,
                "data": {"cpu_utilization": 75.5}
            },
            {
                "tool_name": "describe_ec2_instances",
                "success": False,
                "error": "Instance not found"
            }
        ]
        
        summary = provider.generate_summary(tool_results, "test-correlation-id")
        
        assert "Successfully executed 1 tool(s)" in summary
        assert "Failed to execute 1 tool(s)" in summary


class TestBedrockLLMProvider:
    """Test BedrockLLMProvider"""
    
    @patch('boto3.client')
    def test_initialization_success(self, mock_boto_client):
        """Test successful BedrockLLMProvider initialization"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        provider = BedrockLLMProvider()
        
        assert provider.model_id == "anthropic.claude-3-sonnet-20240229-v1:0"
        assert provider.region_name == "us-east-1"
        assert provider.max_retries == 3
        assert provider.timeout == 30
        assert provider.bedrock_client == mock_client
        
        mock_boto_client.assert_called_once_with(
            'bedrock-runtime',
            region_name='us-east-1'
        )
    
    @patch('boto3.client')
    def test_initialization_failure(self, mock_boto_client):
        """Test BedrockLLMProvider initialization failure"""
        mock_boto_client.side_effect = Exception("AWS credentials not found")
        
        with pytest.raises(LLMProviderError, match="Failed to initialize Bedrock client"):
            BedrockLLMProvider()
    
    @patch('boto3.client')
    def test_custom_parameters(self, mock_boto_client):
        """Test BedrockLLMProvider with custom parameters"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        provider = BedrockLLMProvider(
            model_id="custom-model",
            region_name="us-west-2",
            max_retries=5,
            timeout=60
        )
        
        assert provider.model_id == "custom-model"
        assert provider.region_name == "us-west-2"
        assert provider.max_retries == 5
        assert provider.timeout == 60
    
    def test_get_tool_definitions(self):
        """Test getting tool definitions"""
        with patch('boto3.client'):
            provider = BedrockLLMProvider()
            tools = provider._get_tool_definitions()
            
            assert len(tools) == 3
            tool_names = [tool["name"] for tool in tools]
            assert "get_cloudwatch_metrics" in tool_names
            assert "describe_ec2_instances" in tool_names
            assert "reboot_ec2_instance" in tool_names
            
            # Check tool schema structure
            for tool in tools:
                assert "name" in tool
                assert "description" in tool
                assert "input_schema" in tool
                assert "type" in tool["input_schema"]
                assert "properties" in tool["input_schema"]
    
    def test_create_system_prompt(self):
        """Test creating system prompt"""
        with patch('boto3.client'):
            provider = BedrockLLMProvider()
            prompt = provider._create_system_prompt()
            
            assert "OpsAgent" in prompt
            assert "operations assistant" in prompt
            assert "get_cloudwatch_metrics" in prompt
            assert "describe_ec2_instances" in prompt
            assert "reboot_ec2_instance" in prompt
    
    @patch('boto3.client')
    def test_generate_tool_calls_success(self, mock_boto_client):
        """Test successful tool call generation"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock Bedrock response
        mock_response = {
            'output': {
                'message': {
                    'content': [
                        {
                            'text': 'I\'ll check the CPU metrics for you.'
                        },
                        {
                            'toolUse': {
                                'name': 'get_cloudwatch_metrics',
                                'input': {
                                    'namespace': 'AWS/EC2',
                                    'metric_name': 'CPUUtilization',
                                    'resource_id': 'i-1234567890abcdef0',
                                    'time_window': '15m'
                                }
                            }
                        }
                    ]
                }
            }
        }
        
        mock_client.converse.return_value = mock_response
        
        provider = BedrockLLMProvider()
        response = provider.generate_tool_calls("Check CPU usage", "test-correlation-id")
        
        assert isinstance(response, LLMResponse)
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].tool_name == "get_cloudwatch_metrics"
        assert response.tool_calls[0].args["namespace"] == "AWS/EC2"
        assert response.tool_calls[0].requires_approval is False
        assert response.assistant_message == "I'll check the CPU metrics for you."
        assert response.confidence > 0
        
        # Verify API call
        mock_client.converse.assert_called_once()
        call_args = mock_client.converse.call_args
        assert call_args[1]['modelId'] == provider.model_id
        assert len(call_args[1]['messages']) == 1
        assert call_args[1]['messages'][0]['role'] == 'user'
    
    @patch('boto3.client')
    def test_generate_tool_calls_with_approval(self, mock_boto_client):
        """Test tool call generation for tools requiring approval"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock Bedrock response for reboot tool
        mock_response = {
            'output': {
                'message': {
                    'content': [
                        {
                            'text': 'I can reboot the instance for you.'
                        },
                        {
                            'toolUse': {
                                'name': 'reboot_ec2_instance',
                                'input': {
                                    'instance_id': 'i-1234567890abcdef0'
                                }
                            }
                        }
                    ]
                }
            }
        }
        
        mock_client.converse.return_value = mock_response
        
        provider = BedrockLLMProvider()
        response = provider.generate_tool_calls("Reboot instance", "test-correlation-id")
        
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].tool_name == "reboot_ec2_instance"
        assert response.tool_calls[0].requires_approval is True
    
    @patch('boto3.client')
    def test_generate_tool_calls_api_error(self, mock_boto_client):
        """Test tool call generation with API error"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        from botocore.exceptions import ClientError
        mock_client.converse.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'converse'
        )
        
        provider = BedrockLLMProvider()
        
        with pytest.raises(LLMProviderError, match="Non-retryable error"):
            provider.generate_tool_calls("Check CPU", "test-correlation-id")
    
    @patch('boto3.client')
    def test_generate_summary_success(self, mock_boto_client):
        """Test successful summary generation"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        # Mock Bedrock response
        mock_response = {
            'output': {
                'message': {
                    'content': [
                        {
                            'text': 'The CPU utilization check was successful. The instance is running at 75% CPU usage, which is within normal parameters.'
                        }
                    ]
                }
            }
        }
        
        mock_client.converse.return_value = mock_response
        
        provider = BedrockLLMProvider()
        tool_results = [
            {
                "tool_name": "get_cloudwatch_metrics",
                "success": True,
                "data": {"cpu_utilization": 75.0}
            }
        ]
        
        summary = provider.generate_summary(tool_results, "test-correlation-id")
        
        assert "CPU utilization check was successful" in summary
        assert "75% CPU usage" in summary
        
        # Verify API call
        mock_client.converse.assert_called_once()
    
    @patch('boto3.client')
    def test_generate_summary_empty_results(self, mock_boto_client):
        """Test summary generation with empty results"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        provider = BedrockLLMProvider()
        summary = provider.generate_summary([], "test-correlation-id")
        
        assert summary == "No tool results to summarize."
        mock_client.converse.assert_not_called()
    
    @patch('boto3.client')
    def test_generate_summary_api_error(self, mock_boto_client):
        """Test summary generation with API error"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        from botocore.exceptions import ClientError
        mock_client.converse.side_effect = ClientError(
            {'Error': {'Code': 'ThrottlingException', 'Message': 'Rate exceeded'}},
            'converse'
        )
        
        provider = BedrockLLMProvider(max_retries=1)  # Reduce retries for faster test
        tool_results = [{"tool_name": "test", "success": True, "data": {}}]
        
        summary = provider.generate_summary(tool_results, "test-correlation-id")
        
        assert "Error generating summary" in summary
    
    @patch('boto3.client')
    def test_retry_with_backoff_success_after_retry(self, mock_boto_client):
        """Test retry logic with success after retry"""
        mock_client = Mock()
        mock_boto_client.return_value = mock_client
        
        from botocore.exceptions import ClientError
        
        # First call fails with throttling, second succeeds
        mock_client.converse.side_effect = [
            ClientError(
                {'Error': {'Code': 'ThrottlingException', 'Message': 'Rate exceeded'}},
                'converse'
            ),
            {
                'output': {
                    'message': {
                        'content': [{'text': 'Success after retry'}]
                    }
                }
            }
        ]
        
        provider = BedrockLLMProvider(max_retries=2)
        
        with patch('time.sleep'):  # Mock sleep to speed up test
            response = provider.generate_tool_calls("Test message", "test-correlation-id")
        
        assert response.assistant_message == "Success after retry"
        assert mock_client.converse.call_count == 2


class TestCreateLLMProvider:
    """Test LLM provider factory function"""
    
    def test_create_mock_provider(self):
        """Test creating mock provider for LOCAL_MOCK mode"""
        provider = create_llm_provider(ExecutionMode.LOCAL_MOCK)
        assert isinstance(provider, MockLLMProvider)
    
    @patch('src.llm_provider.BedrockLLMProvider')
    def test_create_bedrock_provider_dry_run(self, mock_bedrock_class):
        """Test creating Bedrock provider for DRY_RUN mode"""
        mock_provider = Mock()
        mock_bedrock_class.return_value = mock_provider
        
        provider = create_llm_provider(ExecutionMode.DRY_RUN, model_id="custom-model")
        
        assert provider == mock_provider
        mock_bedrock_class.assert_called_once_with(model_id="custom-model")
    
    @patch('src.llm_provider.BedrockLLMProvider')
    def test_create_bedrock_provider_sandbox_live(self, mock_bedrock_class):
        """Test creating Bedrock provider for SANDBOX_LIVE mode"""
        mock_provider = Mock()
        mock_bedrock_class.return_value = mock_provider
        
        provider = create_llm_provider(ExecutionMode.SANDBOX_LIVE, region_name="us-west-2")
        
        assert provider == mock_provider
        mock_bedrock_class.assert_called_once_with(region_name="us-west-2")