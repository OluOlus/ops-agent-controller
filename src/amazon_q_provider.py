"""
Amazon Q Business integration for OpsAgent Controller
Provides hybrid LLM capabilities with Amazon Q Business as backend service
"""
import json
import logging
import boto3
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from botocore.exceptions import ClientError

try:
    from src.models import ToolCall, ExecutionMode
    from src.llm_provider import LLMProvider, LLMResponse, LLMProviderError
except ImportError:
    # Fallback for direct execution
    from src.models import ToolCall, ExecutionMode
    from src.llm_provider import LLMProvider, LLMResponse, LLMProviderError

logger = logging.getLogger(__name__)


@dataclass
class AmazonQConfig:
    """Configuration for Amazon Q Business integration"""
    application_id: str
    user_id: str
    session_id: Optional[str] = None
    region: str = "us-east-1"


class AmazonQProvider(LLMProvider):
    """
    Amazon Q Business LLM provider for hybrid operations
    Integrates Amazon Q Business as backend service while maintaining OpsAgent workflows
    """
    
    def __init__(self, config: AmazonQConfig):
        self.config = config
        self.q_client = None
        self._initialize_client()
        
        # Intent classification keywords
        self.operational_keywords = {
            'reboot', 'restart', 'stop', 'start', 'terminate', 'launch',
            'create', 'delete', 'modify', 'update', 'scale', 'deploy',
            'approve', 'deny', 'execute', 'run', 'perform', 'action'
        }
        
        self.diagnostic_keywords = {
            'describe', 'list', 'show', 'get', 'check', 'status', 'health',
            'metrics', 'logs', 'monitor', 'inspect', 'view', 'display'
        }
        
        self.knowledge_keywords = {
            'how', 'what', 'why', 'when', 'where', 'explain', 'help',
            'documentation', 'guide', 'tutorial', 'example', 'best practice'
        }
    
    def _initialize_client(self) -> None:
        """Initialize Amazon Q Business client"""
        try:
            self.q_client = boto3.client('qbusiness', region_name=self.config.region)
            logger.info("Amazon Q Business client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Amazon Q Business client: {e}")
            raise LLMProviderError(f"Failed to initialize Amazon Q Business: {e}")
    
    def classify_intent(self, user_message: str) -> str:
        """
        Classify user intent to determine routing strategy
        
        Returns:
            'operational' - Requires OpsAgent approval workflows
            'diagnostic' - Can use either service, prefer OpsAgent for structured data
            'knowledge' - Route to Amazon Q Developer for general knowledge
        """
        message_lower = user_message.lower()
        
        # Check for operational intent (requires approval workflows)
        operational_score = sum(1 for keyword in self.operational_keywords 
                              if keyword in message_lower)
        
        # Check for diagnostic intent (structured AWS data)
        diagnostic_score = sum(1 for keyword in self.diagnostic_keywords 
                             if keyword in message_lower)
        
        # Check for knowledge intent (general questions)
        knowledge_score = sum(1 for keyword in self.knowledge_keywords 
                            if keyword in message_lower)
        
        # Determine primary intent
        if operational_score > 0:
            return 'operational'
        elif diagnostic_score > knowledge_score:
            return 'diagnostic'
        else:
            return 'knowledge'
    
    def generate_tool_calls(self, user_message: str, correlation_id: str) -> LLMResponse:
        """
        Generate tool calls using hybrid Amazon Q + OpsAgent approach
        """
        logger.info(f"Processing message with Amazon Q hybrid approach: {correlation_id}")
        
        intent = self.classify_intent(user_message)
        logger.info(f"Classified intent as: {intent}")
        
        if intent == 'operational':
            # Route to OpsAgent for approval workflows
            return self._generate_opsagent_tools(user_message, correlation_id)
        
        elif intent == 'diagnostic':
            # Use OpsAgent for structured data, but enhance with Q knowledge
            return self._generate_diagnostic_tools(user_message, correlation_id)
        
        else:  # knowledge
            # Route to Amazon Q Business for general knowledge
            return self._generate_knowledge_response(user_message, correlation_id)
    
    def _generate_opsagent_tools(self, user_message: str, correlation_id: str) -> LLMResponse:
        """Generate OpsAgent tool calls for operational tasks"""
        tool_calls = []
        
        # Simple keyword-based tool selection for operational tasks
        message_lower = user_message.lower()
        
        if any(keyword in message_lower for keyword in ['reboot', 'restart']):
            # Extract instance ID if present
            instance_id = self._extract_instance_id(user_message)
            if instance_id:
                tool_calls.append(ToolCall(
                    tool_name="reboot_ec2_instance",
                    args={"instance_id": instance_id},
                    requires_approval=True,
                    correlation_id=correlation_id
                ))
        
        assistant_message = (
            "I'll help you with that operational task. This requires approval "
            "due to the potential impact on your AWS resources."
        )
        
        return LLMResponse(
            tool_calls=tool_calls,
            assistant_message=assistant_message,
            confidence=0.8
        )
    
    def _generate_diagnostic_tools(self, user_message: str, correlation_id: str) -> LLMResponse:
        """Generate diagnostic tool calls enhanced with Amazon Q knowledge"""
        tool_calls = []
        message_lower = user_message.lower()
        
        # Generate appropriate diagnostic tools
        if any(keyword in message_lower for keyword in ['cpu', 'metrics', 'performance']):
            instance_id = self._extract_instance_id(user_message)
            if instance_id:
                tool_calls.append(ToolCall(
                    tool_name="get_cloudwatch_metrics",
                    args={
                        "namespace": "AWS/EC2",
                        "metric_name": "CPUUtilization",
                        "resource_id": instance_id,
                        "time_window": "15m"
                    },
                    requires_approval=False,
                    correlation_id=correlation_id
                ))
        
        if any(keyword in message_lower for keyword in ['describe', 'instance', 'ec2']):
            instance_id = self._extract_instance_id(user_message)
            if instance_id:
                tool_calls.append(ToolCall(
                    tool_name="describe_ec2_instances",
                    args={"instance_ids": [instance_id]},
                    requires_approval=False,
                    correlation_id=correlation_id
                ))
        
        # Enhance with Amazon Q context if available
        try:
            q_context = self._get_amazon_q_context(user_message)
            assistant_message = f"I'll gather that information for you. {q_context}"
        except Exception as e:
            logger.warning(f"Failed to get Amazon Q context: {e}")
            assistant_message = "I'll gather that diagnostic information for you."
        
        return LLMResponse(
            tool_calls=tool_calls,
            assistant_message=assistant_message,
            confidence=0.9
        )
    
    def _generate_knowledge_response(self, user_message: str, correlation_id: str) -> LLMResponse:
        """Generate knowledge response using Amazon Q Business"""
        try:
            # Query Amazon Q Business for knowledge
            q_response = self._query_amazon_q(user_message)
            
            return LLMResponse(
                tool_calls=[],  # Knowledge queries don't need tool execution
                assistant_message=q_response,
                confidence=0.95
            )
            
        except Exception as e:
            logger.error(f"Failed to query Amazon Q Business: {e}")
            fallback_message = (
                "I'd be happy to help with that question. However, I'm currently "
                "having trouble accessing my knowledge base. Please try again or "
                "rephrase your question."
            )
            
            return LLMResponse(
                tool_calls=[],
                assistant_message=fallback_message,
                confidence=0.3
            )
    
    def _query_amazon_q(self, user_message: str) -> str:
        """Query Amazon Q Business for knowledge responses"""
        try:
            response = self.q_client.chat_sync(
                applicationId=self.config.application_id,
                userId=self.config.user_id,
                userMessage=user_message,
                conversationId=self.config.session_id
            )
            
            # Extract response text from Amazon Q Business
            message = response.get('systemMessage', '')
            sources = response.get('sourceAttributions', [])
            
            # Add source attributions if present
            if sources:
                source_text = "\n\nSources:\n" + "\n".join([
                    f"- {source.get('title', 'Unknown')}" 
                    for source in sources[:3]  # Limit to 3 sources
                ])
                message += source_text
            
            if message:
                return message
            else:
                return "I found some information, but couldn't format it properly. Please try rephrasing your question."
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == 'AccessDeniedException':
                raise LLMProviderError("Access denied to Amazon Q Business. Check permissions.")
            elif error_code == 'ResourceNotFoundException':
                raise LLMProviderError("Amazon Q Business application not found. Check application ID.")
            else:
                raise LLMProviderError(f"Amazon Q Business API error: {error_code}")
    
    def _get_amazon_q_context(self, user_message: str) -> str:
        """Get contextual information from Amazon Q to enhance diagnostic responses"""
        try:
            # Create a context-seeking query
            context_query = f"Provide brief context about: {user_message}"
            context = self._query_amazon_q(context_query)
            
            # Truncate context to keep responses concise
            if len(context) > 200:
                context = context[:200] + "..."
            
            return context
            
        except Exception:
            return ""
    
    def _extract_instance_id(self, message: str) -> Optional[str]:
        """Extract EC2 instance ID from message text"""
        import re
        
        # Look for instance ID pattern (i-xxxxxxxxx)
        pattern = r'i-[0-9a-f]{8,17}'
        match = re.search(pattern, message)
        
        if match:
            return match.group(0)
        
        return None
    
    def generate_summary(self, tool_results: List[Dict[str, Any]], correlation_id: str) -> str:
        """Generate summary using Amazon Q Developer enhanced analysis"""
        if not tool_results:
            return "No results to summarize."
        
        try:
            # Create a summary prompt for Amazon Q
            results_summary = []
            for result in tool_results:
                tool_name = result.get('tool_name', 'unknown')
                success = result.get('success', False)
                
                if success:
                    data = result.get('data', {})
                    results_summary.append(f"{tool_name}: {json.dumps(data, indent=2)}")
                else:
                    error = result.get('error', 'Unknown error')
                    results_summary.append(f"{tool_name} failed: {error}")
            
            summary_prompt = (
                "Analyze these AWS operation results and provide a clear, "
                "actionable summary for a platform engineer:\n\n" +
                "\n".join(results_summary)
            )
            
            # Get enhanced summary from Amazon Q
            q_summary = self._query_amazon_q(summary_prompt)
            
            return q_summary
            
        except Exception as e:
            logger.warning(f"Failed to generate Amazon Q summary: {e}")
            
            # Fallback to basic summary
            successful_tools = [r for r in tool_results if r.get('success', False)]
            failed_tools = [r for r in tool_results if not r.get('success', False)]
            
            summary_parts = []
            if successful_tools:
                summary_parts.append(f"Successfully executed {len(successful_tools)} operation(s)")
            if failed_tools:
                summary_parts.append(f"{len(failed_tools)} operation(s) failed")
            
            return "\n".join(summary_parts) if summary_parts else "Operations completed."


class HybridLLMProvider(LLMProvider):
    """
    Hybrid LLM provider that combines Amazon Q Business with Bedrock
    Routes requests based on intent and complexity
    """
    
    def __init__(self, amazon_q_config: AmazonQConfig, bedrock_model_id: str = None, region: str = "us-east-1"):
        self.amazon_q = AmazonQProvider(amazon_q_config)
        
        # Import and initialize Bedrock provider for fallback
        try:
            from .llm_provider import BedrockLLMProvider
        except ImportError:
            from llm_provider import BedrockLLMProvider
        self.bedrock = BedrockLLMProvider(
            model_id=bedrock_model_id or "anthropic.claude-3-sonnet-20240229-v1:0",
            region_name=region
        )
        
        logger.info("Hybrid LLM provider initialized with Amazon Q Business + Bedrock")
    
    def generate_tool_calls(self, user_message: str, correlation_id: str) -> LLMResponse:
        """Generate tool calls using hybrid approach"""
        try:
            # Try Amazon Q first
            return self.amazon_q.generate_tool_calls(user_message, correlation_id)
        except Exception as e:
            logger.warning(f"Amazon Q failed, falling back to Bedrock: {e}")
            # Fallback to Bedrock
            return self.bedrock.generate_tool_calls(user_message, correlation_id)
    
    def generate_summary(self, tool_results: List[Dict[str, Any]], correlation_id: str) -> str:
        """Generate summary using hybrid approach"""
        try:
            # Try Amazon Q first for enhanced summaries
            return self.amazon_q.generate_summary(tool_results, correlation_id)
        except Exception as e:
            logger.warning(f"Amazon Q summary failed, falling back to Bedrock: {e}")
            # Fallback to Bedrock
            return self.bedrock.generate_summary(tool_results, correlation_id)


def create_amazon_q_provider(
    application_id: str,
    user_id: str,
    session_id: Optional[str] = None,
    region: str = "us-east-1",
    bedrock_model_id: Optional[str] = None
) -> HybridLLMProvider:
    """
    Factory function to create Amazon Q Business hybrid provider
    
    Args:
        application_id: Amazon Q Business application ID
        user_id: User identifier for Amazon Q Business sessions
        session_id: Optional session ID for conversation continuity
        region: AWS region for Amazon Q Business and Bedrock
        bedrock_model_id: Optional Bedrock model for fallback
    
    Returns:
        HybridLLMProvider configured with Amazon Q Business + Bedrock
    """
    config = AmazonQConfig(
        application_id=application_id,
        user_id=user_id,
        session_id=session_id,
        region=region
    )
    
    return HybridLLMProvider(config, bedrock_model_id, region)