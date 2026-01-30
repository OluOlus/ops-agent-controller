#!/usr/bin/env python3
"""
Demonstration script for WebChannelAdapter functionality
This script shows how the Web/CLI channel adapter works with different scenarios.
"""
import json
from datetime import datetime, timedelta
from src.channel_adapters import WebChannelAdapter
from src.models import ToolCall, ApprovalRequest, ExecutionMode


def demo_basic_message_processing():
    """Demonstrate basic message processing"""
    print("=== Demo: Basic Message Processing ===")
    
    adapter = WebChannelAdapter()
    
    # Simulate incoming web request
    raw_request = {
        "body": json.dumps({
            "userId": "demo-user",
            "messageText": "Hello, OpsAgent! What's the system status?",
            "channelConversationId": "demo-conversation-123",
            "executionMode": "DRY_RUN"
        })
    }
    
    # Normalize the message
    internal_message = adapter.normalize_message(raw_request)
    print(f"✅ Normalized message:")
    print(f"   User ID: {internal_message.user_id}")
    print(f"   Message: {internal_message.message_text}")
    print(f"   Channel: {internal_message.channel.value}")
    print(f"   Mode: {internal_message.execution_mode.value}")
    print(f"   Correlation ID: {internal_message.correlation_id}")
    
    # Format a response
    response = adapter.format_response(
        f"Hello {internal_message.user_id}! I'm running in {internal_message.execution_mode.value} mode.",
        internal_message.correlation_id,
        {"execution_mode": internal_message.execution_mode.value}
    )
    
    print(f"\n✅ Formatted response:")
    print(f"   Message: {response.message}")
    print(f"   Correlation ID: {response.correlation_id}")
    print(f"   Channel Data: {json.dumps(response.channel_data, indent=2)}")
    print()


def demo_approval_card_rendering():
    """Demonstrate approval card rendering"""
    print("=== Demo: Approval Card Rendering ===")
    
    adapter = WebChannelAdapter()
    
    # Create a tool call that requires approval
    tool_call = ToolCall(
        tool_name="reboot_ec2_instance",
        args={
            "instance_id": "i-1234567890abcdef0",
            "force": False,
            "wait_for_running": True
        },
        requires_approval=True,
        correlation_id="demo-approval-123"
    )
    
    # Create approval request
    approval_request = ApprovalRequest(
        token="demo-approval-token-xyz789",
        expires_at=datetime.utcnow() + timedelta(minutes=15),
        requested_by="demo-user",
        tool_call=tool_call,
        risk_level="medium",
        correlation_id="demo-approval-123"
    )
    
    # Format approval card for different execution modes
    for mode in [ExecutionMode.DRY_RUN, ExecutionMode.SANDBOX_LIVE]:
        print(f"\n--- {mode.value} Mode ---")
        
        response = adapter.format_approval_card(approval_request, mode)
        
        print(f"✅ Approval card generated:")
        print(f"   Title: {response.approval_data['title']}")
        print(f"   Tool: {response.approval_data['tool']['name']}")
        print(f"   Risk Level: {response.approval_data['risk']['icon']} {response.approval_data['risk']['level'].upper()}")
        print(f"   Execution Mode: {response.approval_data['execution']['description']}")
        print(f"   Will Modify Infrastructure: {response.approval_data['execution']['will_modify_infrastructure']}")
        print(f"   Expires In: {response.approval_data['expiry']['expires_in_minutes']} minutes")
        
        print(f"   Actions:")
        for action in response.approval_data['actions']:
            confirmation = " (requires confirmation)" if action.get('confirmation_required') else ""
            print(f"     - {action['label']}{confirmation}")
    
    print()


def demo_system_status_formatting():
    """Demonstrate system status formatting"""
    print("=== Demo: System Status Formatting ===")
    
    adapter = WebChannelAdapter()
    
    # Mock system status data
    status_scenarios = [
        {
            "name": "Healthy System",
            "data": {
                "execution_mode": "DRY_RUN",
                "llm_provider_status": "configured",
                "aws_tool_access_status": "configured",
                "environment": "lambda",
                "version": "1.0.0"
            }
        },
        {
            "name": "Degraded System",
            "data": {
                "execution_mode": "LOCAL_MOCK",
                "llm_provider_status": "error",
                "aws_tool_access_status": "not_configured",
                "environment": "local",
                "version": "1.0.0"
            }
        }
    ]
    
    for scenario in status_scenarios:
        print(f"\n--- {scenario['name']} ---")
        
        response = adapter.format_system_status(scenario['data'])
        
        print(f"✅ Status formatted:")
        print(f"   Overall Status: {response.channel_data['status']}")
        print(f"   Message Preview:")
        for line in response.message.split('\n')[:5]:  # Show first 5 lines
            print(f"     {line}")
        print(f"   Format Type: {response.channel_data['format']}")
    
    print()


def demo_error_handling():
    """Demonstrate error handling"""
    print("=== Demo: Error Handling ===")
    
    adapter = WebChannelAdapter()
    
    # Test various error scenarios
    error_scenarios = [
        ("VALIDATION_ERROR", "Invalid instance ID format"),
        ("AUTH_ERROR", "Insufficient permissions for this operation"),
        ("SYSTEM_ERROR", "AWS service temporarily unavailable")
    ]
    
    for error_code, error_message in error_scenarios:
        response = adapter.format_error_response(
            error_message,
            error_code,
            f"error-demo-{error_code.lower()}"
        )
        
        print(f"✅ Error formatted ({error_code}):")
        print(f"   Message: {response.message}")
        print(f"   Error Code: {response.channel_data['error_code']}")
        print(f"   Correlation ID: {response.correlation_id}")
        print()


def demo_message_validation():
    """Demonstrate message validation"""
    print("=== Demo: Message Validation ===")
    
    adapter = WebChannelAdapter()
    
    # Test valid and invalid messages
    test_cases = [
        {
            "name": "Valid Message",
            "request": {
                "body": json.dumps({
                    "userId": "valid-user",
                    "messageText": "This is a valid message",
                    "executionMode": "DRY_RUN"
                })
            },
            "should_succeed": True
        },
        {
            "name": "Missing User ID",
            "request": {
                "body": json.dumps({
                    "messageText": "Message without user ID"
                })
            },
            "should_succeed": False
        },
        {
            "name": "Empty Message Text",
            "request": {
                "body": json.dumps({
                    "userId": "test-user",
                    "messageText": ""
                })
            },
            "should_succeed": False
        },
        {
            "name": "Invalid JSON",
            "request": {
                "body": "invalid json content"
            },
            "should_succeed": False
        }
    ]
    
    for test_case in test_cases:
        print(f"\n--- {test_case['name']} ---")
        
        try:
            message = adapter.normalize_message(test_case['request'])
            if test_case['should_succeed']:
                print(f"✅ Message validated successfully:")
                print(f"   User: {message.user_id}")
                print(f"   Text: {message.message_text}")
            else:
                print(f"❌ Expected validation to fail, but it succeeded")
        except ValueError as e:
            if not test_case['should_succeed']:
                print(f"✅ Validation failed as expected: {str(e)}")
            else:
                print(f"❌ Unexpected validation failure: {str(e)}")
    
    print()


def main():
    """Run all demonstrations"""
    print("🤖 WebChannelAdapter Demonstration")
    print("=" * 50)
    
    demo_basic_message_processing()
    demo_approval_card_rendering()
    demo_system_status_formatting()
    demo_error_handling()
    demo_message_validation()
    
    print("✅ All demonstrations completed!")
    print("\nThe WebChannelAdapter provides:")
    print("  • Message normalization from HTTP requests to internal format")
    print("  • Response formatting for web display")
    print("  • Rich approval card rendering with execution mode awareness")
    print("  • System status formatting with health indicators")
    print("  • Comprehensive error handling and validation")
    print("  • CORS support and rate limiting integration")


if __name__ == "__main__":
    main()