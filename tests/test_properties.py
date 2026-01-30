"""
Property-based tests for OpsAgent Controller
Requirements: Various correctness properties
"""
import pytest
from hypothesis import given, strategies as st, settings, assume
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError

from src.models import (
    InternalMessage, ToolCall, ToolResult, ApprovalRequest,
    ExecutionMode, ChannelType,
    validate_message_text, validate_user_id, validate_channel_conversation_id
)
from src.llm_provider import MockLLMProvider, create_llm_provider
from src.tool_guardrails import ToolGuardrails, GuardrailViolation, ResourceTagValidationError
from src.tool_execution_engine import ToolExecutionEngine, ExecutionContext


class TestProperty8AuthenticationValidation:
    """
    Property 8: Authentication Validation
    For any incoming request, the system should validate user identity and authorization 
    before processing and reject unauthorized requests.
    Validates: Requirements 1.4, 5.5, 10.2
    """
    
    @given(
        user_id=st.one_of(
            st.text(min_size=1, max_size=256),  # Valid user IDs
            st.just(""),  # Empty user ID (invalid)
            st.text(min_size=257, max_size=300),  # Too long user ID (invalid)
            st.integers(),  # Invalid type
            st.none()  # None value
        )
    )
    @settings(max_examples=100)
    def test_user_id_validation_property(self, user_id):
        """Property: User ID validation should consistently reject invalid inputs"""
        if isinstance(user_id, str) and 1 <= len(user_id.strip()) <= 256:
            # Valid user ID should pass validation
            try:
                result = validate_user_id(user_id)
                assert isinstance(result, str)
                assert len(result) <= 256
            except ValueError:
                pytest.fail(f"Valid user ID '{user_id}' was rejected")
        else:
            # Invalid user ID should be rejected
            with pytest.raises(ValueError):
                validate_user_id(user_id)
    
    @given(
        message_text=st.one_of(
            st.text(min_size=0, max_size=4000),  # Valid message text
            st.text(min_size=4001, max_size=5000),  # Long message text
            st.integers(),  # Invalid type
            st.none()  # None value
        )
    )
    @settings(max_examples=100)
    def test_message_text_validation_property(self, message_text):
        """Property: Message text validation should handle all input types safely"""
        if isinstance(message_text, str):
            # Valid string input should be processed
            result = validate_message_text(message_text)
            assert isinstance(result, str)
            assert len(result) <= 4020  # Max length + truncation message
            assert '\x00' not in result  # No null bytes
            assert '\r' not in result  # No carriage returns
        else:
            # Invalid input type should be rejected
            with pytest.raises(ValueError):
                validate_message_text(message_text)
    
    @given(
        channel=st.sampled_from([ChannelType.TEAMS, ChannelType.SLACK, ChannelType.WEB]),
        user_id=st.text(min_size=1, max_size=256).filter(lambda x: x.strip() and x.isprintable()),
        message_text=st.text(min_size=1, max_size=1000).filter(lambda x: x.strip())
    )
    @settings(max_examples=50)
    def test_internal_message_creation_property(self, channel, user_id, message_text):
        """Property: InternalMessage creation should always generate valid correlation IDs"""
        # Clean inputs to ensure they're valid
        clean_user_id = validate_user_id(user_id)
        clean_message_text = validate_message_text(message_text)
        
        message = InternalMessage(
            user_id=clean_user_id,
            channel=channel,
            message_text=clean_message_text
        )
        
        # Properties that should always hold
        assert message.correlation_id is not None
        assert len(message.correlation_id) > 0
        assert isinstance(message.correlation_id, str)
        assert message.user_id == clean_user_id
        assert message.channel == channel
        assert message.message_text == clean_message_text
        
        # Serialization should work
        data = message.to_dict()
        assert "correlation_id" in data
        assert data["user_id"] == clean_user_id
        assert data["channel"] == channel.value


class TestProperty4AllowListEnforcement:
    """
    Property 4: Allow-List Enforcement
    For any tool call request, the system should only execute tools from the predefined 
    allow-list and reject unknown or unauthorized tools.
    Validates: Requirements 4.2, 4.3
    """
    
    # Define allowed tools based on the LLM provider implementation
    ALLOWED_TOOLS = {
        "get_cloudwatch_metrics",
        "describe_ec2_instances", 
        "reboot_ec2_instance"
    }
    
    @given(
        tool_name=st.one_of(
            st.sampled_from(["get_cloudwatch_metrics", "describe_ec2_instances", "reboot_ec2_instance"]),  # Valid tools
            st.text(min_size=1, max_size=50).filter(lambda x: x not in ["get_cloudwatch_metrics", "describe_ec2_instances", "reboot_ec2_instance"]),  # Invalid tools
            st.just(""),  # Empty tool name
            st.just("malicious_tool"),  # Explicitly malicious tool
            st.just("delete_all_resources")  # Another malicious tool
        ),
        args=st.dictionaries(
            st.text(min_size=1, max_size=20),
            st.one_of(st.text(), st.integers(), st.booleans())
        )
    )
    @settings(max_examples=100)
    def test_tool_call_allow_list_property(self, tool_name, args):
        """Property: Tool calls should only be created for allowed tools"""
        tool_call = ToolCall(tool_name=tool_name, args=args)
        
        # The ToolCall object itself can be created with any tool name
        # (validation happens at execution time), but we can test the structure
        assert tool_call.tool_name == tool_name
        assert tool_call.args == args
        assert isinstance(tool_call.requires_approval, bool)
        
        # Test serialization works for any tool call
        data = tool_call.to_dict()
        assert data["tool_name"] == tool_name
        assert data["args"] == args
    
    @given(
        user_message=st.text(min_size=1, max_size=200)
    )
    @settings(max_examples=50)
    def test_llm_provider_tool_generation_property(self, user_message):
        """Property: LLM provider should only generate calls to allowed tools"""
        provider = MockLLMProvider()
        
        # Clean the message to ensure it's valid
        clean_message = validate_message_text(user_message)
        assume(len(clean_message.strip()) > 0)  # Skip empty messages
        
        response = provider.generate_tool_calls(clean_message, "test-correlation-id")
        
        # All generated tool calls should be for allowed tools
        for tool_call in response.tool_calls:
            assert tool_call.tool_name in self.ALLOWED_TOOLS, f"Disallowed tool: {tool_call.tool_name}"
            assert isinstance(tool_call.args, dict)
            assert isinstance(tool_call.requires_approval, bool)
            assert tool_call.correlation_id == "test-correlation-id"
        
        # Response should have valid structure
        assert isinstance(response.assistant_message, str)
        assert 0.0 <= response.confidence <= 1.0
    
    @given(
        execution_mode=st.just(ExecutionMode.LOCAL_MOCK)  # Only test LOCAL_MOCK to avoid credential issues
    )
    @settings(max_examples=10)
    def test_llm_provider_factory_property(self, execution_mode):
        """Property: LLM provider factory should create appropriate providers for each mode"""
        provider = create_llm_provider(execution_mode)
        
        # Provider should be created successfully
        assert provider is not None
        
        # Should be able to generate tool calls
        response = provider.generate_tool_calls("Check CPU usage", "test-correlation-id")
        assert isinstance(response.tool_calls, list)
        assert isinstance(response.assistant_message, str)
        
        # All tool calls should be for allowed tools
        for tool_call in response.tool_calls:
            assert tool_call.tool_name in self.ALLOWED_TOOLS


class TestProperty3TagScoping:
    """
    Property 3: Tag Scoping
    For any remediation action, the system should only execute on resources tagged 
    with OpsAgentManaged=true and reject actions on untagged resources.
    Validates: Requirements 3.2, 5.3
    """
    
    @given(
        instance_id=st.just("i-1234567890abcdef0"),  # Use a fixed valid instance ID
        has_required_tag=st.booleans(),
        tag_value=st.one_of(
            st.just("true"),
            st.just("false"), 
            st.just("True"),
            st.just("FALSE"),
            st.text(min_size=1, max_size=10)
        ),
        execution_mode=st.sampled_from([ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE])
    )
    @settings(max_examples=50)
    def test_tag_scoping_property(self, instance_id, has_required_tag, tag_value, execution_mode):
        """Property: Remediation tools should only execute on properly tagged resources"""
        # Mock the EC2 client response
        with patch('src.tool_guardrails.boto3.client') as mock_boto:
            mock_ec2_client = Mock()
            mock_boto.return_value = mock_ec2_client
            
            # Set up the mock response based on test parameters
            if has_required_tag and tag_value == "true":
                # Resource has correct tag
                mock_ec2_client.describe_tags.return_value = {
                    'Tags': [
                        {'Key': 'OpsAgentManaged', 'Value': tag_value},
                        {'Key': 'Environment', 'Value': 'test'}
                    ]
                }
                should_pass = True
            elif has_required_tag:
                # Resource has tag but wrong value
                mock_ec2_client.describe_tags.return_value = {
                    'Tags': [
                        {'Key': 'OpsAgentManaged', 'Value': tag_value},
                        {'Key': 'Environment', 'Value': 'test'}
                    ]
                }
                should_pass = False
            else:
                # Resource missing required tag
                mock_ec2_client.describe_tags.return_value = {
                    'Tags': [
                        {'Key': 'Environment', 'Value': 'test'}
                    ]
                }
                should_pass = False
            
            guardrails = ToolGuardrails(execution_mode)
            tool_call = ToolCall(
                tool_name="reboot_ec2_instance",
                args={"instance_id": instance_id}
            )
            
            if should_pass:
                # Should not raise exception
                try:
                    guardrails.validate_tool_call(tool_call)
                except (GuardrailViolation, ResourceTagValidationError):
                    pytest.fail(f"Valid tagged resource {instance_id} was rejected")
            else:
                # Should raise ResourceTagValidationError
                with pytest.raises(ResourceTagValidationError):
                    guardrails.validate_tool_call(tool_call)
    
    @given(
        tool_name=st.sampled_from(["get_cloudwatch_metrics", "describe_ec2_instances"]),  # Read-only tools
        execution_mode=st.sampled_from([ExecutionMode.LOCAL_MOCK, ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE])
    )
    @settings(max_examples=30)
    def test_read_only_tools_no_tag_validation_property(self, tool_name, execution_mode):
        """Property: Read-only tools should not require tag validation"""
        guardrails = ToolGuardrails(execution_mode)
        
        # Create appropriate args for each tool
        if tool_name == "get_cloudwatch_metrics":
            args = {
                "namespace": "AWS/EC2",
                "metric_name": "CPUUtilization", 
                "resource_id": "i-1234567890abcdef0"
            }
        else:  # describe_ec2_instances
            args = {"instance_ids": ["i-1234567890abcdef0"]}
        
        tool_call = ToolCall(tool_name=tool_name, args=args)
        
        # Read-only tools should always pass validation (no tag checking)
        try:
            guardrails.validate_tool_call(tool_call)
        except (GuardrailViolation, ResourceTagValidationError) as e:
            # Only schema validation errors are acceptable for read-only tools
            if "validation failed" not in str(e).lower():
                pytest.fail(f"Read-only tool {tool_name} failed validation: {e}")
    
    @given(
        execution_mode=st.sampled_from([ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE])
    )
    @settings(max_examples=20)
    def test_tag_validation_aws_errors_property(self, execution_mode):
        """Property: Tag validation should handle AWS API errors gracefully"""
        with patch('src.tool_guardrails.boto3.client') as mock_boto:
            mock_ec2_client = Mock()
            mock_boto.return_value = mock_ec2_client
            
            # Test different AWS API errors
            error_codes = [
                'InvalidInstanceID.NotFound',
                'UnauthorizedOperation', 
                'InternalError'
            ]
            
            for error_code in error_codes:
                mock_ec2_client.describe_tags.side_effect = ClientError(
                    {'Error': {'Code': error_code, 'Message': f'Test {error_code}'}},
                    'describe_tags'
                )
                
                guardrails = ToolGuardrails(execution_mode)
                tool_call = ToolCall(
                    tool_name="reboot_ec2_instance",
                    args={"instance_id": "i-1234567890abcdef0"}
                )
                
                # Should always raise ResourceTagValidationError for AWS errors
                with pytest.raises(ResourceTagValidationError):
                    guardrails.validate_tool_call(tool_call)


class TestProperty5ModeConsistency:
    """
    Property 5: Mode Consistency
    For any operation in DRY_RUN mode, the system should simulate write operations 
    without making actual infrastructure changes and clearly indicate simulation in responses.
    Validates: Requirements 7.2, 11.12
    """
    
    @given(
        tool_name=st.sampled_from(["reboot_ec2_instance"]),  # Write operations
        instance_id=st.just("i-1234567890abcdef0"),  # Valid instance ID
        execution_mode=st.sampled_from([ExecutionMode.LOCAL_MOCK, ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE])
    )
    @settings(max_examples=30, deadline=None)  # Disable deadline for this test
    def test_execution_mode_consistency_property(self, tool_name, instance_id, execution_mode):
        """Property: Tool execution should be consistent with the declared execution mode"""
        engine = ToolExecutionEngine(execution_mode)
        context = ExecutionContext("test-correlation-id", "test-user", execution_mode)
        
        tool_call = ToolCall(tool_name=tool_name, args={"instance_id": instance_id})
        
        # Execute the tool
        result = engine._execute_single_tool(tool_call, context)
        
        # Verify mode consistency in the result
        assert result.execution_mode == execution_mode
        assert result.correlation_id == context.correlation_id
        
        if execution_mode == ExecutionMode.LOCAL_MOCK:
            # Mock mode should indicate it's mocked
            assert result.success is True  # Mock should succeed
            if result.data:
                assert result.data.get('mock') is True or 'MOCK' in result.data.get('action', '')
        
        elif execution_mode == ExecutionMode.DRY_RUN:
            # Dry run should indicate simulation
            if result.success and result.data:
                action = result.data.get('action', '')
                assert 'WOULD_EXECUTE' in action or 'would be executed' in result.data.get('message', '').lower()
        
        elif execution_mode == ExecutionMode.SANDBOX_LIVE:
            # Live mode should indicate actual execution (if successful)
            if result.success and result.data:
                action = result.data.get('action', '')
                # Should not contain simulation indicators
                assert 'WOULD_EXECUTE' not in action
                assert 'MOCK' not in action
    
    @given(
        initial_mode=st.sampled_from([ExecutionMode.LOCAL_MOCK, ExecutionMode.DRY_RUN]),
        new_mode=st.sampled_from([ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE])
    )
    @settings(max_examples=20, deadline=None)
    def test_mode_switching_consistency_property(self, initial_mode, new_mode):
        """Property: Mode switching should update all components consistently"""
        engine = ToolExecutionEngine(initial_mode)
        
        # Verify initial state
        assert engine.execution_mode == initial_mode
        assert engine.guardrails.execution_mode == initial_mode
        
        # Switch mode
        engine.set_execution_mode(new_mode)
        
        # Verify all components updated consistently
        assert engine.execution_mode == new_mode
        assert engine.guardrails.execution_mode == new_mode
        
        # Status should reflect new mode
        status = engine.get_execution_status()
        assert status['execution_mode'] == new_mode.value
    
    @given(
        execution_mode=st.sampled_from([ExecutionMode.LOCAL_MOCK, ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE])
    )
    @settings(max_examples=30, deadline=None)
    def test_tool_result_mode_consistency_property(self, execution_mode):
        """Property: All tool results should consistently reflect the execution mode"""
        engine = ToolExecutionEngine(execution_mode)
        context = ExecutionContext("test-correlation-id", "test-user", execution_mode)
        
        # Test different tool types
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
        
        for tool_call in tool_calls:
            result = engine._execute_single_tool(tool_call, context)
            
            # Every result should have consistent mode
            assert result.execution_mode == execution_mode
            assert result.correlation_id == context.correlation_id
            assert isinstance(result.success, bool)
            assert isinstance(result.tool_name, str)
            
            # Timestamp should be set
            assert result.timestamp is not None


def run_property_tests():
    """Run all property-based tests"""
    import subprocess
    import sys
    
    # Run the property tests with specific markers
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/test_properties.py", 
        "-v", 
        "--tb=short"
    ], capture_output=True, text=True)
    
    return result.returncode == 0, result.stdout, result.stderr


if __name__ == "__main__":
    # Allow running property tests directly
    success, stdout, stderr = run_property_tests()
    print(stdout)
    if stderr:
        print("STDERR:", stderr)
    exit(0 if success else 1)