# Microsoft Teams Integration Guide

## Overview

This guide provides step-by-step instructions for integrating the OpsAgent Controller with Microsoft Teams, enabling platform engineers to interact with the system directly through Teams chat.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Azure Bot Service Setup](#azure-bot-service-setup)
3. [Teams App Creation](#teams-app-creation)
4. [Configuration and Deployment](#configuration-and-deployment)
5. [Testing and Validation](#testing-and-validation)
6. [Advanced Configuration](#advanced-configuration)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Accounts and Permissions

- **Microsoft 365 Tenant**: With Teams enabled
- **Azure Subscription**: For Bot Service registration
- **AWS Account**: With OpsAgent Controller deployed
- **Admin Permissions**: 
  - Azure: Application Administrator or Global Administrator
  - Teams: Teams Administrator or Global Administrator
  - AWS: CloudFormation and SSM Parameter Store access

### Required Tools

- Azure CLI or Azure Portal access
- Teams App Studio or Developer Portal
- AWS CLI configured
- Text editor for manifest creation

## Azure Bot Service Setup

### Step 1: Create Bot Registration

#### Using Azure Portal

1. **Navigate to Azure Portal**
   - Go to https://portal.azure.com
   - Sign in with your Azure account

2. **Create Bot Service**
   - Click "Create a resource"
   - Search for "Bot Service" or "Azure Bot"
   - Select "Azure Bot" and click "Create"

3. **Configure Bot Registration**
   ```
   Bot handle: opsagent-prod (must be globally unique)
   Subscription: Your Azure subscription
   Resource group: Create new or select existing
   Pricing tier: F0 (Free) for testing, S1 for production
   Microsoft App ID: Create new
   Microsoft App Type: Multi Tenant
   ```

4. **Create the Bot**
   - Click "Review + create"
   - Click "Create" after validation

#### Using Azure CLI

```bash
# Login to Azure
az login

# Create resource group (if needed)
az group create --name opsagent-rg --location eastus

# Create bot registration
az bot create \
    --resource-group opsagent-rg \
    --name opsagent-prod \
    --kind registration \
    --app-type MultiTenant \
    --description "OpsAgent Controller Teams Bot"
```

### Step 2: Configure Bot Credentials

1. **Get App ID and Secret**
   - Go to your bot resource in Azure Portal
   - Navigate to "Configuration" in the left menu
   - Copy the "Microsoft App ID"
   - Click "Manage" next to the App ID

2. **Create Client Secret**
   - In the App Registration page, go to "Certificates & secrets"
   - Click "New client secret"
   - Add description: "OpsAgent Teams Bot Secret"
   - Set expiration: 24 months (recommended)
   - Click "Add" and copy the secret value immediately

3. **Store Credentials in AWS**
   ```bash
   # Using the configuration script
   ./infrastructure/configure-environment.sh setup-teams production
   
   # Or manually
   aws ssm put-parameter \
       --name "/opsagent/production/teams-bot-app-id" \
       --value "your-app-id-here" \
       --type String \
       --overwrite
   
   aws ssm put-parameter \
       --name "/opsagent/production/teams-bot-app-secret" \
       --value "your-secret-here" \
       --type SecureString \
       --overwrite
   ```

### Step 3: Configure Messaging Endpoint

1. **Get OpsAgent Chat Endpoint**
   ```bash
   # Get the chat endpoint URL from CloudFormation
   CHAT_URL=$(aws cloudformation describe-stacks \
       --stack-name opsagent-controller-production \
       --query 'Stacks[0].Outputs[?OutputKey==`ChatEndpoint`].OutputValue' \
       --output text)
   
   echo "Chat endpoint: $CHAT_URL"
   ```

2. **Set Messaging Endpoint in Azure**
   - Go back to your bot resource in Azure Portal
   - Navigate to "Configuration"
   - Set "Messaging endpoint" to your chat URL
   - Click "Apply"

## Teams App Creation

### Step 1: Create App Manifest

Create a file named `manifest.json` with the following content:

```json
{
  "$schema": "https://developer.microsoft.com/en-us/json-schemas/teams/v1.16/MicrosoftTeams.schema.json",
  "manifestVersion": "1.16",
  "version": "1.0.0",
  "id": "YOUR_BOT_APP_ID",
  "packageName": "com.yourcompany.opsagent",
  "developer": {
    "name": "Your Company Name",
    "websiteUrl": "https://yourcompany.com",
    "privacyUrl": "https://yourcompany.com/privacy",
    "termsOfUseUrl": "https://yourcompany.com/terms"
  },
  "name": {
    "short": "OpsAgent",
    "full": "OpsAgent Controller"
  },
  "description": {
    "short": "Conversational Tier-1 Ops assistant for AWS incident response",
    "full": "OpsAgent Controller helps platform teams diagnose AWS incidents and perform controlled remediation actions through chat interfaces with approval gates and comprehensive audit logging."
  },
  "icons": {
    "outline": "outline.png",
    "color": "color.png"
  },
  "accentColor": "#FF6B35",
  "bots": [
    {
      "botId": "YOUR_BOT_APP_ID",
      "scopes": ["personal", "team", "groupchat"],
      "commandLists": [
        {
          "scopes": ["personal", "team", "groupchat"],
          "commands": [
            {
              "title": "health",
              "description": "Check OpsAgent system health and status"
            },
            {
              "title": "cpu metrics for i-1234567890abcdef0",
              "description": "Get CPU utilization metrics for an EC2 instance"
            },
            {
              "title": "describe instance i-1234567890abcdef0",
              "description": "Get detailed information about an EC2 instance"
            },
            {
              "title": "cloudwatch metrics for MyService",
              "description": "Get CloudWatch metrics for a service"
            },
            {
              "title": "reboot instance i-1234567890abcdef0",
              "description": "Request to reboot an EC2 instance (requires approval)"
            },
            {
              "title": "help",
              "description": "Show available commands and usage examples"
            }
          ]
        }
      ],
      "isNotificationOnly": false
    }
  ],
  "permissions": ["identity", "messageTeamMembers"],
  "validDomains": [],
  "webApplicationInfo": {
    "id": "YOUR_BOT_APP_ID",
    "resource": "https://RscBasedStoreApp"
  }
}
```

### Step 2: Create App Icons

Create two PNG icons:

1. **color.png**: 192x192 pixels, full color icon
2. **outline.png**: 32x32 pixels, transparent background with white outline

You can use simple placeholder icons or create custom ones that represent your organization.

### Step 3: Package the App

1. **Create App Package**
   ```bash
   # Create a directory for the app
   mkdir opsagent-teams-app
   cd opsagent-teams-app
   
   # Copy your files
   cp /path/to/manifest.json .
   cp /path/to/color.png .
   cp /path/to/outline.png .
   
   # Create ZIP package
   zip -r opsagent-teams-app.zip manifest.json color.png outline.png
   ```

2. **Validate Package**
   - The ZIP file should contain exactly 3 files
   - manifest.json should be valid JSON
   - Icons should be the correct sizes

## Configuration and Deployment

### Step 1: Update OpsAgent Configuration

1. **Enable Teams Channel**
   ```bash
   # Update the Lambda environment variables
   aws lambda update-function-configuration \
       --function-name opsagent-controller-production \
       --environment Variables='{
           "EXECUTION_MODE": "SANDBOX_LIVE",
           "ENVIRONMENT": "production",
           "LLM_PROVIDER": "bedrock",
           "TEAMS_INTEGRATION_ENABLED": "true"
       }'
   ```

2. **Verify Configuration**
   ```bash
   # Test the configuration
   ./infrastructure/configure-environment.sh validate-config production
   ```

### Step 2: Deploy Teams App

#### Using Teams App Studio (Recommended)

1. **Open Teams App Studio**
   - In Microsoft Teams, go to Apps
   - Search for "App Studio" or "Developer Portal"
   - Install and open the app

2. **Import App Package**
   - Click "Import an existing app"
   - Upload your `opsagent-teams-app.zip` file
   - Review the app details

3. **Install App**
   - Click "Install" to install in your tenant
   - Choose installation scope (personal, team, or organization)

#### Using Teams Admin Center

1. **Upload Custom App**
   - Go to Teams Admin Center (admin.teams.microsoft.com)
   - Navigate to "Teams apps" > "Manage apps"
   - Click "Upload new app"
   - Upload your ZIP file

2. **Set App Policies**
   - Go to "Teams apps" > "Setup policies"
   - Create or edit a policy to include your app
   - Assign the policy to users or groups

### Step 3: Test Installation

1. **Find the App**
   - In Teams, go to Apps
   - Search for "OpsAgent"
   - Click on your app

2. **Start Conversation**
   - Click "Add" or "Open"
   - Start a conversation with the bot
   - Send a test message: "health"

## Testing and Validation

### Basic Functionality Tests

#### 1. Health Check Test
```
User: health
Expected Response: System health status with execution mode and component status
```

#### 2. Diagnosis Test
```
User: describe instance i-1234567890abcdef0
Expected Response: EC2 instance details or appropriate error message
```

#### 3. Metrics Test
```
User: cpu metrics for i-1234567890abcdef0
Expected Response: CPU utilization data or appropriate error message
```

#### 4. Approval Gate Test
```
User: reboot instance i-1234567890abcdef0
Expected Response: Approval request with approval button/card
```

### Advanced Testing

#### 1. Error Handling Test
```bash
# Test with invalid instance ID
User: describe instance i-invalid
Expected Response: User-friendly error message
```

#### 2. Authentication Test
```bash
# Test without proper permissions
User: reboot instance i-untagged-instance
Expected Response: Permission denied with explanation
```

#### 3. Audit Logging Test
```bash
# Check audit logs after interaction
aws logs filter-log-events \
    --log-group-name /aws/lambda/opsagent-audit-production \
    --filter-pattern "teams" \
    --start-time $(date -d '1 hour ago' +%s)000
```

### Load Testing

```bash
# Simple load test script
#!/bin/bash
for i in {1..10}; do
    echo "Test message $i" | \
    curl -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer YOUR_BOT_TOKEN" \
        -d @- \
        "https://smba.trafficmanager.net/apis/v3/conversations/CONVERSATION_ID/activities" &
done
wait
```

## Advanced Configuration

### Custom Commands and Cards

#### 1. Adaptive Cards for Approvals

The OpsAgent can send rich adaptive cards for approval workflows:

```json
{
  "type": "AdaptiveCard",
  "version": "1.3",
  "body": [
    {
      "type": "TextBlock",
      "text": "Approval Required",
      "weight": "Bolder",
      "size": "Medium"
    },
    {
      "type": "TextBlock",
      "text": "Reboot EC2 instance i-1234567890abcdef0?",
      "wrap": true
    },
    {
      "type": "FactSet",
      "facts": [
        {
          "title": "Instance ID:",
          "value": "i-1234567890abcdef0"
        },
        {
          "title": "Instance Type:",
          "value": "t3.medium"
        },
        {
          "title": "Current State:",
          "value": "running"
        }
      ]
    }
  ],
  "actions": [
    {
      "type": "Action.Submit",
      "title": "Approve",
      "data": {
        "action": "approve",
        "token": "approval-token-here"
      }
    },
    {
      "type": "Action.Submit",
      "title": "Deny",
      "data": {
        "action": "deny",
        "token": "approval-token-here"
      }
    }
  ]
}
```

#### 2. Custom Bot Commands

Add custom commands to the manifest for common operations:

```json
{
  "commands": [
    {
      "title": "incident status",
      "description": "Get current incident status and active alerts"
    },
    {
      "title": "scale service MyService to 5",
      "description": "Scale an ECS service to specified capacity"
    },
    {
      "title": "logs for MyService last 1h",
      "description": "Get recent logs for a service"
    }
  ]
}
```

### Multi-Environment Support

#### 1. Environment-Specific Bots

Create separate bot registrations for each environment:

```bash
# Production bot
az bot create --name opsagent-prod --resource-group opsagent-rg

# Staging bot  
az bot create --name opsagent-staging --resource-group opsagent-rg

# Sandbox bot
az bot create --name opsagent-sandbox --resource-group opsagent-rg
```

#### 2. Environment Routing

Configure the Lambda function to route based on bot ID:

```python
def determine_environment(bot_app_id):
    env_mapping = {
        'prod-bot-id': 'production',
        'staging-bot-id': 'staging', 
        'sandbox-bot-id': 'sandbox'
    }
    return env_mapping.get(bot_app_id, 'sandbox')
```

### Security Enhancements

#### 1. Message Signature Validation

Implement Teams message signature validation:

```python
import hmac
import hashlib
import base64

def validate_teams_signature(request_body, signature, secret):
    expected_signature = base64.b64encode(
        hmac.new(
            secret.encode('utf-8'),
            request_body.encode('utf-8'),
            hashlib.sha256
        ).digest()
    ).decode('utf-8')
    
    return hmac.compare_digest(signature, expected_signature)
```

#### 2. User Authorization

Implement user-based authorization:

```python
def is_authorized_user(user_id, required_role='ops-engineer'):
    # Check against Azure AD groups or custom authorization
    authorized_users = get_authorized_users(required_role)
    return user_id in authorized_users
```

## Troubleshooting

### Common Issues

#### 1. Bot Not Responding

**Symptoms**: Messages sent to bot receive no response

**Debugging Steps**:
```bash
# Check Lambda logs
aws logs tail /aws/lambda/opsagent-controller-production --follow

# Check API Gateway logs
aws logs tail /aws/apigateway/opsagent-production --follow

# Test endpoint directly
curl -X POST \
    -H "Content-Type: application/json" \
    -d '{"type":"message","text":"health","from":{"id":"test-user"}}' \
    YOUR_CHAT_ENDPOINT
```

**Common Causes**:
- Incorrect messaging endpoint URL
- Lambda function errors
- API Gateway configuration issues
- Missing or incorrect credentials

#### 2. Authentication Failures

**Symptoms**: "Authentication failed" errors in logs

**Debugging Steps**:
```bash
# Check stored credentials
aws ssm get-parameter \
    --name "/opsagent/production/teams-bot-app-id" \
    --query 'Parameter.Value'

# Verify bot registration
az bot show --name opsagent-prod --resource-group opsagent-rg
```

**Common Causes**:
- Incorrect App ID or Secret
- Expired client secret
- Wrong parameter names in SSM

#### 3. Approval Cards Not Working

**Symptoms**: Approval buttons don't respond or cause errors

**Debugging Steps**:
```bash
# Check approval token generation
aws logs filter-log-events \
    --log-group-name /aws/lambda/opsagent-controller-production \
    --filter-pattern "approval_token"

# Test approval endpoint
curl -X POST \
    -H "Content-Type: application/json" \
    -d '{"action":"approve","token":"test-token"}' \
    YOUR_CHAT_ENDPOINT
```

**Common Causes**:
- Invalid adaptive card format
- Approval token expiration
- Missing approval gate configuration

#### 4. Permission Denied Errors

**Symptoms**: "Permission denied" for AWS operations

**Debugging Steps**:
```bash
# Check IAM role permissions
aws iam get-role-policy \
    --role-name OpsAgentExecutionRole-production \
    --policy-name OpsAgentDiagnosisToolsPolicy

# Test AWS permissions directly
aws ec2 describe-instances --instance-ids i-1234567890abcdef0
```

**Common Causes**:
- Insufficient IAM permissions
- Missing resource tags
- Wrong execution mode

### Diagnostic Commands

#### Teams-Specific Diagnostics

```bash
# Check Teams integration status
./infrastructure/configure-environment.sh validate-config production

# Test Teams webhook
curl -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer YOUR_BOT_TOKEN" \
    -d '{
        "type": "message",
        "text": "Test message",
        "from": {"id": "test-user", "name": "Test User"},
        "conversation": {"id": "test-conversation"}
    }' \
    YOUR_CHAT_ENDPOINT

# Check bot registration status
az bot show \
    --name opsagent-prod \
    --resource-group opsagent-rg \
    --query '{name:name,endpoint:endpoint,appId:appId}'
```

#### Log Analysis

```bash
# Teams-specific log queries
aws logs filter-log-events \
    --log-group-name /aws/lambda/opsagent-controller-production \
    --filter-pattern "teams" \
    --start-time $(date -d '1 hour ago' +%s)000

# Approval workflow logs
aws logs filter-log-events \
    --log-group-name /aws/lambda/opsagent-controller-production \
    --filter-pattern "approval" \
    --start-time $(date -d '1 hour ago' +%s)000

# Error analysis
aws logs filter-log-events \
    --log-group-name /aws/lambda/opsagent-controller-production \
    --filter-pattern "ERROR" \
    --start-time $(date -d '1 hour ago' +%s)000
```

### Performance Optimization

#### 1. Response Time Optimization

```python
# Implement async processing for long-running operations
import asyncio

async def process_long_running_request(request):
    # Send immediate acknowledgment
    await send_typing_indicator(request.conversation_id)
    
    # Process in background
    result = await process_request_async(request)
    
    # Send final response
    await send_response(request.conversation_id, result)
```

#### 2. Caching Strategy

```python
# Cache frequently accessed data
import redis

cache = redis.Redis(host='elasticache-endpoint')

def get_instance_info(instance_id):
    cache_key = f"instance:{instance_id}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return json.loads(cached_data)
    
    # Fetch from AWS
    data = ec2.describe_instances(InstanceIds=[instance_id])
    
    # Cache for 5 minutes
    cache.setex(cache_key, 300, json.dumps(data))
    
    return data
```

This comprehensive Teams integration guide provides all the necessary information to successfully integrate the OpsAgent Controller with Microsoft Teams, including setup, configuration, testing, and troubleshooting procedures.