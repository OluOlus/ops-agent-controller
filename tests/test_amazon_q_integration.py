"""
Tests for Amazon Q Developer integration
"""
import pytest
import os
from unittest.mock import Mock, patch, MagicMock
from src.amazon_q_provider import AmazonQProvider, AmazonQConfig, HybridLLMProvider, create_amazon_q_provider
from src.llm_provider import LLMProviderError
from src.models import ToolCall, ExecutionMode


class TestAmazonQProvider:
    """Test Amazon Q Developer provider functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.config = AmazonQConfig(
            application_id="test-app-123",
            user_id="test-user",
            session_id="test-session",
            region="us-east-1"
        )
    
    @patch('src.amazon_q_provider.boto3.client')
    def test_amazon_q_provider_initialization(self, mock_boto3_client):
        """Test Amazon Q provider initializes correctly"""
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        provider = AmazonQProvider(self.config)
        
        assert provider.config == self.config
        assert provider.q_client == mock_client
        mock_boto3_client.assert_called_once_with('qbusiness', region_name='us-east-1')
    
    def test_intent_classification_operational(self):
        """Test intent classification for operational tasks"""
        with patch('src.amazon_q_provider.boto3.client'):
            provider = AmazonQProvider(self.config)
            
            # Test operational keywords
            assert provider.classify_intent("reboot the server") == "operational"
            assert provider.classify_intent("restart the instance") == "operational"
            assert provider.classify_intent("delete the resource") == "operational"
            assert provider.classify_intent("create a new instance") == "operational"
    
    def test_intent_classification_diagnostic(self):
        """Test intent classification for diagnostic tasks"""
        with patch('src.amazon_q_provider.boto3.client'):
            provider = AmazonQProvider(self.config)
            
            # Test diagnostic keywords
            assert provider.classify_intent("show me the CPU metrics") == "diagnostic"
            assert provider.classify_intent("describe the instance") == "diagnostic"
            assert provider.classify_intent("check the status") == "diagnostic"
            assert provider.classify_intent("get the logs") == "diagnostic"
    
    def test_intent_classification_knowledge(self):
        """Test intent classification for knowledge queries"""
        with patch('src.amazon_q_provider.boto3.client'):
            provider = AmazonQProvider(self.config)
            
            # Test knowledge keywords
            assert provider.classify_intent("how do I configure CloudWatch?") == "knowledge"
            assert provider.classify_intent("what is the best practice for EC2?") == "knowledge"
            assert provider.classify_intent("explain AWS IAM roles") == "knowledge"
            assert provider.classify_intent("help me understand VPC") == "knowledge"
    
    @patch('src.amazon_q_provider.boto3.client')
    def test_generate_operational_tools(self, mock_boto3_client):
        """Test generating operational tool calls"""
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        provider = AmazonQProvider(self.config)
        
        # Test reboot operation
        response = provider.generate_tool_calls("reboot instance i-123456789", "test-correlation")
        
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].tool_name == "reboot_ec2_instance"
        assert response.tool_calls[0].args["instance_id"] == "i-123456789"
        assert response.tool_calls[0].requires_approval is True
        assert "approval" in response.assistant_message.lower()
    
    @patch('src.amazon_q_provider.boto3.client')
    def test_generate_diagnostic_tools(self, mock_boto3_client):
        """Test generating diagnostic tool calls"""
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        provider = AmazonQProvider(self.config)
        
        # Test CPU metrics request
        response = provider.generate_tool_calls("show CPU metrics for i-123456789", "test-correlation")
        
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].tool_name == "get_cloudwatch_metrics"
        assert response.tool_calls[0].args["namespace"] == "AWS/EC2"
        assert response.tool_calls[0].args["metric_name"] == "CPUUtilization"
        assert response.tool_calls[0].args["resource_id"] == "i-123456789"
        assert response.tool_calls[0].requires_approval is False
    
    @patch('src.amazon_q_provider.boto3.client')
    def test_query_amazon_q_success(self, mock_boto3_client):
        """Test successful Amazon Q query"""
        mock_client = Mock()
        mock_response = {
            'systemMessage': 'Amazon EC2 is a web service that provides secure, resizable compute capacity in the cloud.'
        }
        mock_client.chat_sync.return_value = mock_response
        mock_boto3_client.return_value = mock_client
        
        provider = AmazonQProvider(self.config)
        
        response = provider.generate_tool_calls("what is EC2?", "test-correlation")
        
        assert len(response.tool_calls) == 0  # Knowledge queries don't need tools
        assert "Amazon EC2 is a web service" in response.assistant_message
        assert response.confidence == 0.95
        
        mock_client.chat_sync.assert_called_once_with(
            applicationId="test-app-123",
            userId="test-user",
            userMessage="what is EC2?",
            conversationId="test-session"
        )
    
    @patch('src.amazon_q_provider.boto3.client')
    def test_query_amazon_q_with_sources(self, mock_boto3_client):
        """Test Amazon Q query with source attributions"""
        mock_client = Mock()
        mock_response = {
            'systemMessage': 'EC2 provides scalable computing capacity.',
            'sourceAttributions': [
                {'title': 'AWS EC2 Documentation'},
                {'title': 'EC2 User Guide'}
            ]
        }
        mock_client.chat_sync.return_value = mock_response
        mock_boto3_client.return_value = mock_client
        
        provider = AmazonQProvider(self.config)
        
        response = provider.generate_tool_calls("what is EC2?", "test-correlation")
        
        assert "EC2 provides scalable computing capacity" in response.assistant_message
        assert "Sources:" in response.assistant_message
        assert "AWS EC2 Documentation" in response.assistant_message
    
    @patch('src.amazon_q_provider.boto3.client')
    def test_query_amazon_q_error_handling(self, mock_boto3_client):
        """Test Amazon Q error handling"""
        mock_client = Mock()
        mock_client.chat_sync.side_effect = Exception("API Error")
        mock_boto3_client.return_value = mock_client
        
        provider = AmazonQProvider(self.config)
        
        response = provider.generate_tool_calls("what is EC2?", "test-correlation")
        
        assert len(response.tool_calls) == 0
        assert "having trouble accessing my knowledge base" in response.assistant_message
        assert response.confidence == 0.3
    
    def test_extract_instance_id(self):
        """Test instance ID extraction from messages"""
        with patch('src.amazon_q_provider.boto3.client'):
            provider = AmazonQProvider(self.config)
            
            # Test valid instance IDs
            assert provider._extract_instance_id("reboot i-1234567890abcdef0") == "i-1234567890abcdef0"
            assert provider._extract_instance_id("check i-abc123def456") == "i-abc123def456"
            
            # Test no instance ID
            assert provider._extract_instance_id("reboot the server") is None
            assert provider._extract_instance_id("show metrics") is None


class TestHybridLLMProvider:
    """Test hybrid LLM provider functionality"""
    
    @patch('src.amazon_q_provider.AmazonQProvider')
    @patch('src.llm_provider.BedrockLLMProvider')
    def test_hybrid_provider_initialization(self, mock_bedrock, mock_amazon_q):
        """Test hybrid provider initializes both providers"""
        config = AmazonQConfig(
            application_id="test-app",
            user_id="test-user"
        )
        
        hybrid = HybridLLMProvider(config, "test-model", "us-east-1")
        
        mock_amazon_q.assert_called_once_with(config)
        mock_bedrock.assert_called_once_with(
            model_id="test-model",
            region_name="us-east-1"
        )
    
    @patch('src.amazon_q_provider.AmazonQProvider')
    @patch('src.llm_provider.BedrockLLMProvider')
    def test_hybrid_provider_amazon_q_success(self, mock_bedrock, mock_amazon_q):
        """Test hybrid provider uses Amazon Q when it succeeds"""
        config = AmazonQConfig(application_id="test-app", user_id="test-user")
        
        # Mock successful Amazon Q response
        mock_q_instance = Mock()
        mock_q_response = Mock()
        mock_q_instance.generate_tool_calls.return_value = mock_q_response
        mock_amazon_q.return_value = mock_q_instance
        
        hybrid = HybridLLMProvider(config)
        
        result = hybrid.generate_tool_calls("test message", "correlation-123")
        
        assert result == mock_q_response
        mock_q_instance.generate_tool_calls.assert_called_once_with("test message", "correlation-123")
    
    @patch('src.amazon_q_provider.AmazonQProvider')
    @patch('src.llm_provider.BedrockLLMProvider')
    def test_hybrid_provider_bedrock_fallback(self, mock_bedrock, mock_amazon_q):
        """Test hybrid provider falls back to Bedrock when Amazon Q fails"""
        config = AmazonQConfig(application_id="test-app", user_id="test-user")
        
        # Mock Amazon Q failure
        mock_q_instance = Mock()
        mock_q_instance.generate_tool_calls.side_effect = Exception("Q API Error")
        mock_amazon_q.return_value = mock_q_instance
        
        # Mock successful Bedrock response
        mock_bedrock_instance = Mock()
        mock_bedrock_response = Mock()
        mock_bedrock_instance.generate_tool_calls.return_value = mock_bedrock_response
        mock_bedrock.return_value = mock_bedrock_instance
        
        hybrid = HybridLLMProvider(config)
        
        result = hybrid.generate_tool_calls("test message", "correlation-123")
        
        assert result == mock_bedrock_response
        mock_bedrock_instance.generate_tool_calls.assert_called_once_with("test message", "correlation-123")


class TestAmazonQFactory:
    """Test Amazon Q provider factory function"""
    
    @patch('src.amazon_q_provider.HybridLLMProvider')
    def test_create_amazon_q_provider(self, mock_hybrid):
        """Test factory function creates hybrid provider correctly"""
        mock_provider = Mock()
        mock_hybrid.return_value = mock_provider
        
        result = create_amazon_q_provider(
            application_id="test-app-123",
            user_id="test-user",
            session_id="test-session",
            region="us-west-2",
            bedrock_model_id="anthropic.claude-3-haiku-20240307-v1:0"
        )
        
        assert result == mock_provider
        
        # Verify HybridLLMProvider was called with correct arguments
        args, kwargs = mock_hybrid.call_args
        config, bedrock_model, region = args
        
        assert config.application_id == "test-app-123"
        assert config.user_id == "test-user"
        assert config.session_id == "test-session"
        assert config.region == "us-west-2"
        assert bedrock_model == "anthropic.claude-3-haiku-20240307-v1:0"
        assert region == "us-west-2"
    
    @patch('src.amazon_q_provider.HybridLLMProvider')
    def test_create_amazon_q_provider_defaults(self, mock_hybrid):
        """Test factory function with default values"""
        mock_provider = Mock()
        mock_hybrid.return_value = mock_provider
        
        result = create_amazon_q_provider(
            application_id="test-app-123",
            user_id="test-user"
        )
        
        assert result == mock_provider
        
        # Verify defaults were applied
        args, kwargs = mock_hybrid.call_args
        config, bedrock_model, region = args
        
        assert config.application_id == "test-app-123"
        assert config.user_id == "test-user"
        assert config.session_id is None
        assert config.region == "us-east-1"
        assert bedrock_model is None
        assert region == "us-east-1"


@pytest.mark.integration
class TestAmazonQIntegration:
    """Integration tests for Amazon Q (requires real AWS credentials and Q app)"""
    
    @pytest.mark.skipif(
        not os.environ.get("AMAZON_Q_APP_ID"),
        reason="AMAZON_Q_APP_ID not configured for integration testing"
    )
    def test_real_amazon_q_query(self):
        """Test real Amazon Q query (integration test)"""
        app_id = os.environ.get("AMAZON_Q_APP_ID")
        user_id = os.environ.get("AMAZON_Q_USER_ID", "test-user")
        
        config = AmazonQConfig(
            application_id=app_id,
            user_id=user_id,
            region=os.environ.get("AWS_REGION", "us-east-1")
        )
        
        provider = AmazonQProvider(config)
        
        # Test knowledge query
        response = provider.generate_tool_calls("What is Amazon EC2?", "integration-test")
        
        assert len(response.tool_calls) == 0  # Knowledge queries don't generate tools
        assert len(response.assistant_message) > 0
        assert response.confidence > 0.5
    
    @pytest.mark.skipif(
        not os.environ.get("AMAZON_Q_APP_ID"),
        reason="AMAZON_Q_APP_ID not configured for integration testing"
    )
    def test_real_hybrid_provider(self):
        """Test real hybrid provider (integration test)"""
        app_id = os.environ.get("AMAZON_Q_APP_ID")
        user_id = os.environ.get("AMAZON_Q_USER_ID", "test-user")
        
        hybrid = create_amazon_q_provider(
            application_id=app_id,
            user_id=user_id,
            region=os.environ.get("AWS_REGION", "us-east-1")
        )
        
        # Test operational query (should generate tools)
        response = hybrid.generate_tool_calls("describe instance i-1234567890abcdef0", "integration-test")
        
        assert len(response.tool_calls) >= 1
        assert response.tool_calls[0].tool_name == "describe_ec2_instances"
        assert response.tool_calls[0].args["instance_ids"] == ["i-1234567890abcdef0"]