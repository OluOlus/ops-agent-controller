"""
LLM Provider client with Bedrock integration
Requirements: 4.1, 4.5
"""
import json
import logging
import os
import time
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
from abc import ABC, abstractmethod
import boto3
from botocore.exceptions import ClientError, BotoCoreError
try:
    from models import ToolCall, ExecutionMode
except ImportError:
    # Fallback for direct execution
    from models import ToolCall, ExecutionMode

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from LLM provider"""
    tool_calls: List[ToolCall]
    assistant_message: str
    confidence: float = 0.0
    raw_response: Optional[Dict[str, Any]] = None


class LLMProviderError(Exception):
    """Base exception for LLM provider errors"""
    pass


class LLMProviderTimeoutError(LLMProviderError):
    """Timeout error for LLM provider"""
    pass


class LLMProviderValidationError(LLMProviderError):
    """Validation error for LLM provider responses"""
    pass


class LLMProvider(ABC):
    """Abstract base class for LLM providers"""
    
    @abstractmethod
    def generate_tool_calls(self, user_message: str, correlation_id: str) -> LLMResponse:
        """Generate structured tool calls from user message"""
        pass
    
    @abstractmethod
    def generate_summary(self, tool_results: List[Dict[str, Any]], correlation_id: str) -> str:
        """Generate human-readable summary from tool results"""
        pass


class BedrockLLMProvider(LLMProvider):
    """
    AWS Bedrock LLM provider implementation
    Requirements: 4.1, 4.5
    """
    
    def __init__(
        self,
        model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
        region_name: str = "us-east-1",
        max_retries: int = 3,
        timeout: int = 30
    ):
        self.model_id = model_id
        self.region_name = region_name
        self.max_retries = max_retries
        self.timeout = timeout
        
        try:
            self.bedrock_client = boto3.client(
                'bedrock-runtime',
                region_name=region_name
            )
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {e}")
            raise LLMProviderError(f"Failed to initialize Bedrock client: {e}")
    
    def _get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Get available tool definitions for the LLM"""
        return [
            {
                "name": "get_cloudwatch_metrics",
                "description": "Retrieve CloudWatch metrics for AWS resources",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": "CloudWatch namespace (e.g., AWS/EC2, AWS/ECS)"
                        },
                        "metric_name": {
                            "type": "string",
                            "description": "Metric name (e.g., CPUUtilization, NetworkIn)"
                        },
                        "resource_id": {
                            "type": "string",
                            "description": "Resource identifier (instance ID, load balancer name, etc.)"
                        },
                        "time_window": {
                            "type": "string",
                            "description": "Time window for metrics (e.g., '15m', '1h', '24h')",
                            "default": "15m"
                        }
                    },
                    "required": ["namespace", "metric_name", "resource_id"]
                }
            },
            {
                "name": "describe_ec2_instances",
                "description": "Get information about EC2 instances",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "instance_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of instance IDs to describe"
                        },
                        "filters": {
                            "type": "object",
                            "description": "Filters for instance selection (e.g., tags, state)"
                        }
                    }
                }
            },
            {
                "name": "reboot_ec2_instance",
                "description": "Reboot an EC2 instance (requires approval)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "instance_id": {
                            "type": "string",
                            "description": "EC2 instance ID to reboot"
                        }
                    },
                    "required": ["instance_id"]
                }
            }
        ]
    
    def _create_system_prompt(self) -> str:
        """Create system prompt for the LLM"""
        return """You are OpsAgent, a Tier-1 operations assistant that helps platform engineers diagnose and remediate AWS infrastructure issues.

Your role:
- Analyze user requests and select appropriate AWS diagnostic tools
- Provide clear, actionable insights based on telemetry data
- Recommend remediation actions when appropriate
- Always prioritize safety and require approval for write operations

Available tools:
- get_cloudwatch_metrics: Retrieve metrics data (read-only)
- describe_ec2_instances: Get instance information (read-only)
- reboot_ec2_instance: Restart an instance (requires approval)

Guidelines:
- Use read-only tools first to gather information
- Only suggest write operations when necessary
- Be specific about resource identifiers
- Explain your reasoning clearly
- If unsure, ask for clarification

Respond with structured tool calls in JSON format."""
    
    def _retry_with_backoff(self, func, *args, **kwargs):
        """Execute function with exponential backoff retry logic"""
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except (ClientError, BotoCoreError) as e:
                if attempt == self.max_retries - 1:
                    raise LLMProviderError(f"Max retries exceeded: {e}")
                
                # Check if error is retryable
                if hasattr(e, 'response') and e.response.get('Error', {}).get('Code') in [
                    'ThrottlingException', 'ServiceUnavailable', 'InternalServerError'
                ]:
                    wait_time = (2 ** attempt) + (time.time() % 1)  # Add jitter
                    logger.warning(f"Retryable error on attempt {attempt + 1}: {e}. Waiting {wait_time:.2f}s")
                    time.sleep(wait_time)
                else:
                    raise LLMProviderError(f"Non-retryable error: {e}")
            except Exception as e:
                raise LLMProviderError(f"Unexpected error: {e}")
    
    def _validate_tool_call_response(self, response_data: Dict[str, Any]) -> List[ToolCall]:
        """Validate and parse tool calls from LLM response"""
        tool_calls = []
        
        if 'tool_calls' not in response_data:
            logger.warning("No tool_calls in LLM response")
            return tool_calls
        
        for tool_call_data in response_data['tool_calls']:
            try:
                # Validate required fields
                if 'tool_name' not in tool_call_data:
                    logger.warning("Missing tool_name in tool call")
                    continue
                
                tool_name = tool_call_data['tool_name']
                args = tool_call_data.get('args', {})
                
                # Determine if approval is required based on tool name
                requires_approval = tool_name in ['reboot_ec2_instance']
                
                tool_call = ToolCall(
                    tool_name=tool_name,
                    args=args,
                    requires_approval=requires_approval
                )
                
                tool_calls.append(tool_call)
                
            except Exception as e:
                logger.warning(f"Failed to parse tool call: {e}")
                continue
        
        return tool_calls
    
    def generate_tool_calls(self, user_message: str, correlation_id: str) -> LLMResponse:
        """
        Generate structured tool calls from user message
        Requirements: 4.1
        """
        logger.info(f"Generating tool calls for correlation_id: {correlation_id}")
        
        try:
            # Prepare the request
            system_prompt = self._create_system_prompt()
            tools = self._get_tool_definitions()
            
            # Create the message payload for Bedrock Converse API
            messages = [
                {
                    "role": "user",
                    "content": [{"text": user_message}]
                }
            ]
            
            # Prepare tool configuration
            tool_config = {
                "tools": [
                    {
                        "toolSpec": {
                            "name": tool["name"],
                            "description": tool["description"],
                            "inputSchema": {
                                "json": tool["input_schema"]
                            }
                        }
                    }
                    for tool in tools
                ]
            }
            
            # Make the API call with retry logic
            def _make_bedrock_call():
                return self.bedrock_client.converse(
                    modelId=self.model_id,
                    messages=messages,
                    system=[{"text": system_prompt}],
                    toolConfig=tool_config,
                    inferenceConfig={
                        "maxTokens": 1000,
                        "temperature": 0.1
                    }
                )
            
            response = self._retry_with_backoff(_make_bedrock_call)
            
            # Parse the response
            output_message = response.get('output', {}).get('message', {})
            content = output_message.get('content', [])
            
            tool_calls = []
            assistant_message = ""
            
            # Process response content
            for content_item in content:
                if 'text' in content_item:
                    assistant_message += content_item['text']
                elif 'toolUse' in content_item:
                    tool_use = content_item['toolUse']
                    tool_name = tool_use.get('name', '')
                    tool_input = tool_use.get('input', {})
                    
                    # Determine if approval is required
                    requires_approval = tool_name in ['reboot_ec2_instance']
                    
                    tool_call = ToolCall(
                        tool_name=tool_name,
                        args=tool_input,
                        requires_approval=requires_approval,
                        correlation_id=correlation_id
                    )
                    tool_calls.append(tool_call)
            
            # Calculate confidence based on response quality
            confidence = 0.8 if tool_calls else 0.3
            
            llm_response = LLMResponse(
                tool_calls=tool_calls,
                assistant_message=assistant_message.strip(),
                confidence=confidence,
                raw_response=response
            )
            
            logger.info(f"Generated {len(tool_calls)} tool calls with confidence {confidence}")
            return llm_response
            
        except Exception as e:
            logger.error(f"Failed to generate tool calls: {e}")
            raise LLMProviderError(f"Failed to generate tool calls: {e}")
    
    def generate_summary(self, tool_results: List[Dict[str, Any]], correlation_id: str) -> str:
        """
        Generate human-readable summary from tool results
        Requirements: 4.5
        """
        logger.info(f"Generating summary for correlation_id: {correlation_id}")
        
        if not tool_results:
            return "No tool results to summarize."
        
        try:
            # Prepare context from tool results
            results_context = []
            for result in tool_results:
                tool_name = result.get('tool_name', 'unknown')
                success = result.get('success', False)
                data = result.get('data', {})
                error = result.get('error')
                
                if success:
                    results_context.append(f"Tool '{tool_name}' succeeded with data: {json.dumps(data, indent=2)}")
                else:
                    results_context.append(f"Tool '{tool_name}' failed with error: {error}")
            
            context_text = "\n".join(results_context)
            
            # Create summary prompt
            summary_prompt = f"""Based on the following tool execution results, provide a clear, concise summary for a platform engineer:

Tool Results:
{context_text}

Please provide:
1. A brief overview of what was checked/executed
2. Key findings or results
3. Any recommended next actions
4. If there were errors, explain what went wrong

Keep the summary professional and actionable."""
            
            messages = [
                {
                    "role": "user",
                    "content": [{"text": summary_prompt}]
                }
            ]
            
            # Make the API call with retry logic
            def _make_summary_call():
                return self.bedrock_client.converse(
                    modelId=self.model_id,
                    messages=messages,
                    inferenceConfig={
                        "maxTokens": 500,
                        "temperature": 0.3
                    }
                )
            
            response = self._retry_with_backoff(_make_summary_call)
            
            # Extract summary text
            output_message = response.get('output', {}).get('message', {})
            content = output_message.get('content', [])
            
            summary = ""
            for content_item in content:
                if 'text' in content_item:
                    summary += content_item['text']
            
            summary = summary.strip()
            if not summary:
                summary = "Unable to generate summary from tool results."
            
            logger.info(f"Generated summary of length {len(summary)}")
            return summary
            
        except Exception as e:
            logger.error(f"Failed to generate summary: {e}")
            return f"Error generating summary: {str(e)}"


class MockLLMProvider(LLMProvider):
    """
    Mock LLM provider for testing and SANDBOX_LIVE mode
    Requirements: 7.1
    """
    
    def __init__(self):
        self.call_count = 0
    
    def generate_tool_calls(self, user_message: str, correlation_id: str) -> LLMResponse:
        """Generate mock tool calls for testing"""
        self.call_count += 1
        
        # Simple keyword-based tool selection for testing
        tool_calls = []
        
        if any(keyword in user_message.lower() for keyword in ['cpu', 'metrics', 'performance']):
            tool_calls.append(ToolCall(
                tool_name="get_cloudwatch_metrics",
                args={
                    "namespace": "AWS/EC2",
                    "metric_name": "CPUUtilization",
                    "resource_id": "i-1234567890abcdef0",
                    "time_window": "15m"
                },
                requires_approval=False,
                correlation_id=correlation_id
            ))
        
        if any(keyword in user_message.lower() for keyword in ['instance', 'ec2', 'describe']):
            tool_calls.append(ToolCall(
                tool_name="describe_ec2_instances",
                args={
                    "instance_ids": ["i-1234567890abcdef0"]
                },
                requires_approval=False,
                correlation_id=correlation_id
            ))
        
        if any(keyword in user_message.lower() for keyword in ['reboot', 'restart']):
            tool_calls.append(ToolCall(
                tool_name="reboot_ec2_instance",
                args={
                    "instance_id": "i-1234567890abcdef0"
                },
                requires_approval=True,
                correlation_id=correlation_id
            ))
        
        # Default tool call if no keywords match
        if not tool_calls:
            tool_calls.append(ToolCall(
                tool_name="get_cloudwatch_metrics",
                args={
                    "namespace": "AWS/EC2",
                    "metric_name": "CPUUtilization",
                    "resource_id": "i-1234567890abcdef0",
                    "time_window": "15m"
                },
                requires_approval=False,
                correlation_id=correlation_id
            ))
        
        return LLMResponse(
            tool_calls=tool_calls,
            assistant_message=f"I'll help you with that. Let me check the relevant AWS resources. (Mock response #{self.call_count})",
            confidence=0.9
        )
    
    def generate_summary(self, tool_results: List[Dict[str, Any]], correlation_id: str) -> str:
        """Generate mock summary for testing"""
        if not tool_results:
            return "No results to summarize."
        
        successful_tools = [r for r in tool_results if r.get('success', False)]
        failed_tools = [r for r in tool_results if not r.get('success', False)]
        
        summary_parts = []
        
        if successful_tools:
            summary_parts.append(f"Successfully executed {len(successful_tools)} tool(s):")
            for result in successful_tools:
                tool_name = result.get('tool_name', 'unknown')
                summary_parts.append(f"- {tool_name}: Completed successfully")
        
        if failed_tools:
            summary_parts.append(f"Failed to execute {len(failed_tools)} tool(s):")
            for result in failed_tools:
                tool_name = result.get('tool_name', 'unknown')
                error = result.get('error', 'Unknown error')
                summary_parts.append(f"- {tool_name}: {error}")
        
        return "\n".join(summary_parts)


def create_llm_provider(execution_mode: ExecutionMode, **kwargs) -> LLMProvider:
    """
    Factory function to create appropriate LLM provider based on execution mode
    Requirements: 7.1, 7.4
    """
    # Check if Amazon Q integration is configured
    amazon_q_app_id = kwargs.get('amazon_q_app_id') or os.environ.get('AMAZON_Q_APP_ID')
    
    if amazon_q_app_id:
        # Use Amazon Q hybrid provider
        try:
            from .amazon_q_provider import create_amazon_q_provider
        except ImportError:
            from amazon_q_provider import create_amazon_q_provider
        
        user_id = kwargs.get('amazon_q_user_id') or os.environ.get('AMAZON_Q_USER_ID', 'opsagent-user')
        session_id = kwargs.get('amazon_q_session_id')
        region = kwargs.get('region_name') or os.environ.get('AWS_REGION', 'us-east-1')
        bedrock_model_id = kwargs.get('bedrock_model_id') or os.environ.get('BEDROCK_MODEL_ID')
        
        logger.info(f"Creating Amazon Q hybrid provider for app {amazon_q_app_id}")
        return create_amazon_q_provider(
            application_id=amazon_q_app_id,
            user_id=user_id,
            session_id=session_id,
            region=region,
            bedrock_model_id=bedrock_model_id
        )
    
    # For SANDBOX_LIVE, use real Bedrock
    return BedrockLLMProvider(**kwargs)
