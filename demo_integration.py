#!/usr/bin/env python3
"""
Demo script showing the integrated OpsAgent Controller system
This demonstrates the complete flow from user message to response
"""
import json
import os
from src.main import lambda_handler

def demo_diagnosis_flow():
    """Demonstrate a diagnosis flow"""
    print("🔍 Demo: Diagnosis Flow")
    print("=" * 50)
    
    # Set LOCAL_MOCK mode for demo
    os.environ["EXECUTION_MODE"] = "LOCAL_MOCK"
    
    # Simulate a diagnosis request
    event = {
        "httpMethod": "POST",
        "path": "/chat",
        "body": json.dumps({
            "userId": "demo-user",
            "messageText": "Check CPU metrics for instance i-1234567890abcdef0",
            "channel": "web"
        })
    }
    
    print(f"📤 User Request: {json.loads(event['body'])['messageText']}")
    
    # Process the request
    response = lambda_handler(event, None)
    
    print(f"📥 Response Status: {response['statusCode']}")
    
    if response["statusCode"] == 200:
        body = json.loads(response["body"])
        if body["success"]:
            data = body["data"]
            print(f"✅ Success: {data['message'][:100]}...")
            print(f"🔗 Correlation ID: {body.get('correlationId', 'N/A')}")
            
            # Show tool execution results
            channel_data = data.get("channel_data", {})
            tool_results = channel_data.get("tool_results", [])
            if tool_results:
                print(f"🔧 Tools Executed: {len(tool_results)}")
                for result in tool_results:
                    status = "✅" if result["success"] else "❌"
                    print(f"   {status} {result['tool_name']}")
        else:
            print(f"❌ Error: {body.get('error', 'Unknown error')}")
    else:
        print(f"❌ HTTP Error: {response['statusCode']}")
    
    print()


def demo_approval_flow():
    """Demonstrate an approval flow"""
    print("🔐 Demo: Approval Flow")
    print("=" * 50)
    
    # Set LOCAL_MOCK mode for demo
    os.environ["EXECUTION_MODE"] = "LOCAL_MOCK"
    
    # Step 1: Request remediation
    event = {
        "httpMethod": "POST",
        "path": "/chat",
        "body": json.dumps({
            "userId": "demo-user",
            "messageText": "Reboot instance i-1234567890abcdef0",
            "channel": "web"
        })
    }
    
    print(f"📤 User Request: {json.loads(event['body'])['messageText']}")
    
    # Process the request
    response = lambda_handler(event, None)
    
    print(f"📥 Response Status: {response['statusCode']}")
    
    if response["statusCode"] == 200:
        body = json.loads(response["body"])
        if body["success"]:
            data = body["data"]
            
            if data.get("approval_required"):
                print("🔐 Approval Required!")
                approval_data = data["approval_data"]
                print(f"   Token: {approval_data['token'][:8]}...")
                print(f"   Risk Level: {approval_data['risk']['level']}")
                print(f"   Expires: {approval_data['expiry']['expires_in_minutes']} minutes")
                
                # Step 2: Approve the request
                approval_token = approval_data["token"]
                approval_event = {
                    "httpMethod": "POST",
                    "path": "/chat",
                    "body": json.dumps({
                        "userId": "demo-user",
                        "messageText": f"approve token:{approval_token}",
                        "channel": "web"
                    })
                }
                
                print(f"📤 Approval: approve token:{approval_token[:8]}...")
                
                approval_response = lambda_handler(approval_event, None)
                
                if approval_response["statusCode"] == 200:
                    approval_body = json.loads(approval_response["body"])
                    if approval_body["success"]:
                        approval_data = approval_body["data"]
                        print(f"✅ Approved & Executed: {approval_data['message'][:100]}...")
                        
                        channel_data = approval_data.get("channel_data", {})
                        if channel_data.get("tool_executed"):
                            print(f"🔧 Tool Executed: {channel_data['tool_executed']}")
                            print(f"📊 Success: {channel_data.get('success', 'Unknown')}")
                    else:
                        print(f"❌ Approval Error: {approval_body.get('error', 'Unknown error')}")
                else:
                    print(f"❌ Approval HTTP Error: {approval_response['statusCode']}")
            else:
                print(f"✅ Direct Execution: {data['message'][:100]}...")
        else:
            print(f"❌ Error: {body.get('error', 'Unknown error')}")
    else:
        print(f"❌ HTTP Error: {response['statusCode']}")
    
    print()


def demo_health_check():
    """Demonstrate health check with component status"""
    print("🏥 Demo: Health Check")
    print("=" * 50)
    
    # Set LOCAL_MOCK mode for demo
    os.environ["EXECUTION_MODE"] = "LOCAL_MOCK"
    
    # Health check request
    event = {
        "httpMethod": "GET",
        "path": "/health"
    }
    
    print("📤 Health Check Request")
    
    # Process the request
    response = lambda_handler(event, None)
    
    print(f"📥 Response Status: {response['statusCode']}")
    
    if response["statusCode"] == 200:
        body = json.loads(response["body"])
        if body["success"]:
            system_data = body["data"]["system"]
            print(f"✅ System Status: {body['data']['status']}")
            print(f"🔧 Execution Mode: {system_data['execution_mode']}")
            print(f"🤖 LLM Provider: {system_data['llm_provider_status']}")
            print(f"☁️  AWS Tools: {system_data['aws_tool_access_status']}")
            
            # Show component status
            components = system_data.get("components", {})
            if components:
                print("📦 Components:")
                for name, status in components.items():
                    initialized = "✅" if status.get("initialized") else "❌"
                    print(f"   {initialized} {name}")
        else:
            print(f"❌ Error: {body.get('error', 'Unknown error')}")
    else:
        print(f"❌ HTTP Error: {response['statusCode']}")
    
    print()


def main():
    """Run all demos"""
    print("🤖 OpsAgent Controller Integration Demo")
    print("=" * 60)
    print()
    
    # Run demos
    demo_health_check()
    demo_diagnosis_flow()
    demo_approval_flow()
    
    print("🎉 Demo Complete!")
    print("=" * 60)
    print()
    print("Key Integration Points Demonstrated:")
    print("✅ Channel Adapter (Web) - Message normalization and response formatting")
    print("✅ LLM Provider (Mock) - Tool call generation and summary creation")
    print("✅ Tool Execution Engine - Tool validation and execution")
    print("✅ Approval Gate - Approval request creation and validation")
    print("✅ Audit Logger - Comprehensive logging throughout the flow")
    print("✅ Error Handling - Graceful error handling and user feedback")
    print("✅ Health Monitoring - System status and component health")


if __name__ == "__main__":
    main()