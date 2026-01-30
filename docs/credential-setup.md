# OpsAgent Controller Credential Setup Guide

## Overview

This guide provides detailed instructions for setting up and managing credentials for the OpsAgent Controller across different environments and integrations.

## Table of Contents

1. [AWS Credentials](#aws-credentials)
2. [LLM Provider Credentials](#llm-provider-credentials)
3. [Chat Channel Credentials](#chat-channel-credentials)
4. [Security Best Practices](#security-best-practices)
5. [Credential Rotation](#credential-rotation)
6. [Troubleshooting](#troubleshooting)

## AWS Credentials

### IAM Setup

The OpsAgent Controller uses IAM roles for AWS service access. The deployment automatically creates the necessary roles with least privilege permissions.

#### Required AWS Permissions

**For Deployment:**
- CloudFormation: Full access for stack management
- IAM: Create/manage roles and policies
- Lambda: Create/manage functions
- API Gateway: Create/manage APIs
- KMS: Create/manage encryption keys
- SSM: Create/manage parameters
- DynamoDB: Create/manage tables
- CloudWatch: Create/manage log groups

**For Runtime:**
- CloudWatch: Read metrics and logs
- EC2: Describe instances (read-only)
- ECS/ALB: Describe services (read-only)
- Bedrock: Invoke models (if using Bedrock)
- SSM: Get parameters
- DynamoDB: Read/write audit data
- KMS: Encrypt/decrypt data

#### AWS CLI Configuration

```bash
# Configure AWS CLI with your credentials
aws configure

# Verify configuration
aws sts get-caller-identity

# Test permissions
aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE
```

#### Cross-Account Access (Optional)

For multi-account deployments:

```bash
# Create cross-account role
aws iam create-role \
    --role-name OpsAgentCrossAccountRole \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::ACCOUNT-ID:role/OpsAgentExecutionRole-ENV"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }'

# Attach necessary policies
aws iam attach-role-policy \
    --role-name OpsAgentCrossAccountRole \
    --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

## LLM Provider Credentials

### AWS Bedrock (Recommended)

Bedrock is the recommended LLM provider as it integrates natively with AWS and doesn't require additional credentials.

#### Setup Steps

1. **Enable Bedrock Model Access:**
   ```bash
   # Check available models
   aws bedrock list-foundation-models --region us-east-1
   
   # Request model access in AWS Console
   # Go to: AWS Console > Bedrock > Model access
   ```

2. **Verify Access:**
   ```bash
   # Test model invocation
   aws bedrock-runtime invoke-model \
       --model-id anthropic.claude-3-sonnet-20240229-v1:0 \
       --body '{"messages":[{"role":"user","content":"Hello"}],"max_tokens":100}' \
       --cli-binary-format raw-in-base64-out \
       response.json
   ```

3. **Configure in Deployment:**
   ```bash
   # Deploy with Bedrock
   ./infrastructure/deploy-environment.sh sandbox \
       --llm-provider bedrock \
       --execution-mode DRY_RUN
   ```

#### Supported Models

- `anthropic.claude-3-sonnet-20240229-v1:0` (Recommended)
- `anthropic.claude-3-haiku-20240307-v1:0` (Cost-optimized)
- `anthropic.claude-instant-v1` (Legacy)

### OpenAI

#### Setup Steps

1. **Get OpenAI API Key:**
   - Visit https://platform.openai.com/api-keys
   - Create a new API key
   - Copy the key (starts with `sk-`)

2. **Store Credentials:**
   ```bash
   # Using configuration script
   ./infrastructure/configure-environment.sh setup-credentials sandbox
   
   # Or manually
   aws ssm put-parameter \
       --name "/opsagent/sandbox/openai-api-key" \
       --value "sk-your-openai-api-key" \
       --type SecureString \
       --overwrite \
       --description "OpenAI API key for OpsAgent Controller"
   ```

3. **Deploy with OpenAI:**
   ```bash
   ./infrastructure/deploy-environment.sh sandbox \
       --llm-provider openai \
       --execution-mode DRY_RUN
   ```

#### Configuration Parameters

```bash
# Optional: Set custom OpenAI endpoint
aws ssm put-parameter \
    --name "/opsagent/sandbox/openai-endpoint" \
    --value "https://api.openai.com/v1" \
    --type String \
    --overwrite

# Optional: Set model name
aws ssm put-parameter \
    --name "/opsagent/sandbox/openai-model" \
    --value "gpt-4" \
    --type String \
    --overwrite
```

### Azure OpenAI

#### Setup Steps

1. **Create Azure OpenAI Resource:**
   - Go to Azure Portal
   - Create an Azure OpenAI resource
   - Deploy a model (e.g., GPT-4)
   - Get the endpoint URL and API key

2. **Store Credentials:**
   ```bash
   # Using configuration script
   ./infrastructure/configure-environment.sh setup-credentials sandbox
   
   # Or manually
   aws ssm put-parameter \
       --name "/opsagent/sandbox/azure-openai-api-key" \
       --value "your-azure-openai-key" \
       --type SecureString \
       --overwrite
   
   aws ssm put-parameter \
       --name "/opsagent/sandbox/azure-openai-endpoint" \
       --value "https://your-resource.openai.azure.com/" \
       --type String \
       --overwrite
   
   aws ssm put-parameter \
       --name "/opsagent/sandbox/azure-openai-deployment" \
       --value "your-deployment-name" \
       --type String \
       --overwrite
   ```

3. **Deploy with Azure OpenAI:**
   ```bash
   ./infrastructure/deploy-environment.sh sandbox \
       --llm-provider azure_openai \
       --execution-mode DRY_RUN
   ```

## Chat Channel Credentials

### Microsoft Teams

#### Prerequisites

- Microsoft 365 tenant with Teams enabled
- Azure subscription for Bot Service registration
- Global Administrator or Application Administrator role

#### Setup Process

1. **Create Bot Registration:**
   ```bash
   # Go to Azure Portal
   # Navigate to: Create a resource > AI + Machine Learning > Bot Service
   # Or use direct link: https://portal.azure.com/#create/Microsoft.BotService
   ```

2. **Configure Bot Registration:**
   - **Bot handle**: Choose a unique name (e.g., `opsagent-prod`)
   - **Subscription**: Select your Azure subscription
   - **Resource group**: Create or select existing
   - **Pricing tier**: F0 (free) for testing, S1 for production
   - **Microsoft App ID**: Create new
   - **Microsoft App Password**: Auto-generate

3. **Get Credentials:**
   ```bash
   # After creation, go to Configuration
   # Copy the Microsoft App ID
   # Create a new client secret and copy the value
   ```

4. **Store Credentials:**
   ```bash
   # Using configuration script
   ./infrastructure/configure-environment.sh setup-teams production
   
   # Or manually
   aws ssm put-parameter \
       --name "/opsagent/production/teams-bot-app-id" \
       --value "your-bot-app-id" \
       --type String \
       --overwrite
   
   aws ssm put-parameter \
       --name "/opsagent/production/teams-bot-app-secret" \
       --value "your-bot-app-secret" \
       --type SecureString \
       --overwrite
   ```

5. **Configure Messaging Endpoint:**
   ```bash
   # Get the chat endpoint URL
   CHAT_URL=$(aws cloudformation describe-stacks \
       --stack-name opsagent-controller-production \
       --query 'Stacks[0].Outputs[?OutputKey==`ChatEndpoint`].OutputValue' \
       --output text)
   
   echo "Set messaging endpoint to: $CHAT_URL"
   ```

6. **Create Teams App:**
   - Create app manifest (see deployment guide)
   - Package the app with icons
   - Upload to Teams App Studio or Developer Portal

#### Teams App Manifest Template

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
    "short": "Conversational Tier-1 Ops assistant",
    "full": "OpsAgent Controller helps platform teams diagnose and remediate AWS incidents through chat interfaces with approval gates and audit logging."
  },
  "icons": {
    "outline": "outline.png",
    "color": "color.png"
  },
  "accentColor": "#FFFFFF",
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
              "description": "Check system health status"
            },
            {
              "title": "cpu metrics",
              "description": "Get CPU utilization metrics"
            },
            {
              "title": "describe instance i-1234567890abcdef0",
              "description": "Get EC2 instance details"
            },
            {
              "title": "help",
              "description": "Show available commands"
            }
          ]
        }
      ]
    }
  ],
  "permissions": ["identity", "messageTeamMembers"],
  "validDomains": []
}
```

### Slack (Future Implementation)

Slack integration is planned for future releases. The credential setup will follow a similar pattern:

```bash
# Future Slack setup
./infrastructure/configure-environment.sh setup-slack production

# Manual setup (future)
aws ssm put-parameter \
    --name "/opsagent/production/slack-bot-token" \
    --value "xoxb-your-slack-bot-token" \
    --type SecureString \
    --overwrite

aws ssm put-parameter \
    --name "/opsagent/production/slack-signing-secret" \
    --value "your-slack-signing-secret" \
    --type SecureString \
    --overwrite
```

## Security Best Practices

### Credential Management

#### 1. Use AWS Systems Manager Parameter Store
- **SecureString** type for sensitive data
- **KMS encryption** for all parameters
- **Least privilege** access policies
- **Parameter hierarchies** for organization

#### 2. Avoid Hardcoded Credentials
```bash
# ❌ Bad: Hardcoded in code
API_KEY = "sk-1234567890abcdef"

# ✅ Good: Retrieved from Parameter Store
import boto3
ssm = boto3.client('ssm')
api_key = ssm.get_parameter(
    Name='/opsagent/production/api-key',
    WithDecryption=True
)['Parameter']['Value']
```

#### 3. Environment Separation
```bash
# Separate credentials by environment
/opsagent/sandbox/api-key
/opsagent/staging/api-key
/opsagent/production/api-key
```

#### 4. Access Logging
```bash
# Enable CloudTrail for parameter access
aws cloudtrail create-trail \
    --name opsagent-parameter-access \
    --s3-bucket-name your-cloudtrail-bucket \
    --include-global-service-events \
    --is-multi-region-trail
```

### Network Security

#### 1. VPC Endpoints (Optional)
```yaml
# For enhanced security, use VPC endpoints
VPCEndpoints:
  - ServiceName: com.amazonaws.region.ssm
  - ServiceName: com.amazonaws.region.kms
  - ServiceName: com.amazonaws.region.bedrock-runtime
```

#### 2. Security Groups
```yaml
# Restrictive egress rules
SecurityGroupEgress:
  - IpProtocol: tcp
    FromPort: 443
    ToPort: 443
    CidrIp: 0.0.0.0/0
    Description: HTTPS for AWS API calls
```

### Encryption

#### 1. KMS Key Management
```bash
# Create dedicated KMS key for OpsAgent
aws kms create-key \
    --description "OpsAgent Controller encryption key" \
    --key-usage ENCRYPT_DECRYPT \
    --key-spec SYMMETRIC_DEFAULT

# Create alias
aws kms create-alias \
    --alias-name alias/opsagent-production \
    --target-key-id key-id
```

#### 2. Parameter Encryption
```bash
# Always use SecureString for sensitive data
aws ssm put-parameter \
    --name "/opsagent/production/api-key" \
    --value "sensitive-value" \
    --type SecureString \
    --key-id alias/opsagent-production
```

## Credential Rotation

### Automated Rotation

#### 1. API Key Rotation Script
```bash
#!/bin/bash
# rotate-api-key.sh

ENVIRONMENT=$1
NEW_API_KEY=$(openssl rand -base64 32)

# Update parameter
aws ssm put-parameter \
    --name "/opsagent/$ENVIRONMENT/api-key" \
    --value "$NEW_API_KEY" \
    --type SecureString \
    --overwrite

# Restart Lambda to pick up new key
aws lambda update-function-configuration \
    --function-name "opsagent-controller-$ENVIRONMENT" \
    --environment Variables='{}'

echo "API key rotated for environment: $ENVIRONMENT"
```

#### 2. Scheduled Rotation with Lambda
```python
import boto3
import json
import secrets
import string

def lambda_handler(event, context):
    ssm = boto3.client('ssm')
    lambda_client = boto3.client('lambda')
    
    environment = event['environment']
    
    # Generate new API key
    alphabet = string.ascii_letters + string.digits
    new_api_key = ''.join(secrets.choice(alphabet) for _ in range(32))
    
    # Update parameter
    ssm.put_parameter(
        Name=f'/opsagent/{environment}/api-key',
        Value=new_api_key,
        Type='SecureString',
        Overwrite=True
    )
    
    # Trigger Lambda restart (optional)
    lambda_client.update_function_configuration(
        FunctionName=f'opsagent-controller-{environment}',
        Environment={'Variables': {}}
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps(f'API key rotated for {environment}')
    }
```

### Manual Rotation

#### 1. Teams Bot Credentials
```bash
# Generate new client secret in Azure Portal
# Update parameter
aws ssm put-parameter \
    --name "/opsagent/production/teams-bot-app-secret" \
    --value "new-secret-value" \
    --type SecureString \
    --overwrite

# Test the integration
./infrastructure/configure-environment.sh validate-config production
```

#### 2. LLM Provider Keys
```bash
# For OpenAI
aws ssm put-parameter \
    --name "/opsagent/production/openai-api-key" \
    --value "sk-new-openai-key" \
    --type SecureString \
    --overwrite

# For Azure OpenAI
aws ssm put-parameter \
    --name "/opsagent/production/azure-openai-api-key" \
    --value "new-azure-key" \
    --type SecureString \
    --overwrite
```

### Rotation Schedule

| Credential Type | Rotation Frequency | Method |
|----------------|-------------------|---------|
| API Keys | Monthly | Automated |
| Teams Bot Secret | Quarterly | Manual |
| LLM Provider Keys | Quarterly | Manual |
| AWS IAM Keys | Not applicable (using roles) | N/A |

## Troubleshooting

### Common Issues

#### 1. "Parameter not found"
```bash
# Check parameter exists
aws ssm get-parameter --name "/opsagent/sandbox/api-key"

# List all parameters
aws ssm get-parameters-by-path --path "/opsagent/sandbox/"
```

#### 2. "Access denied to parameter"
```bash
# Check IAM permissions
aws iam get-role-policy \
    --role-name OpsAgentExecutionRole-sandbox \
    --policy-name OpsAgentLLMProviderPolicy
```

#### 3. "KMS access denied"
```bash
# Check KMS key policy
aws kms get-key-policy \
    --key-id alias/opsagent-sandbox \
    --policy-name default
```

#### 4. "Teams bot not responding"
```bash
# Check bot credentials
aws ssm get-parameter \
    --name "/opsagent/production/teams-bot-app-id" \
    --query 'Parameter.Value'

# Verify messaging endpoint
curl -X POST \
    -H "Content-Type: application/json" \
    -d '{"type":"message","text":"test"}' \
    YOUR_CHAT_ENDPOINT
```

### Debugging Commands

#### Parameter Store Debugging
```bash
# List all OpsAgent parameters
aws ssm describe-parameters \
    --parameter-filters "Key=Name,Option=BeginsWith,Values=/opsagent/" \
    --query 'Parameters[*].[Name,Type,LastModifiedDate]' \
    --output table

# Check parameter history
aws ssm get-parameter-history \
    --name "/opsagent/production/api-key" \
    --query 'Parameters[*].[Version,LastModifiedDate,LastModifiedUser]' \
    --output table
```

#### KMS Debugging
```bash
# List KMS keys
aws kms list-keys --query 'Keys[*].KeyId'

# Check key usage
aws kms describe-key --key-id alias/opsagent-production
```

#### IAM Debugging
```bash
# Check role policies
aws iam list-attached-role-policies \
    --role-name OpsAgentExecutionRole-production

# Simulate policy
aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::ACCOUNT:role/OpsAgentExecutionRole-production \
    --action-names ssm:GetParameter \
    --resource-arns arn:aws:ssm:us-east-1:ACCOUNT:parameter/opsagent/production/api-key
```

### Security Validation

#### 1. Credential Exposure Check
```bash
# Check CloudWatch logs for exposed credentials
aws logs filter-log-events \
    --log-group-name /aws/lambda/opsagent-controller-production \
    --filter-pattern "sk-" \
    --start-time $(date -d '1 day ago' +%s)000
```

#### 2. Access Pattern Analysis
```bash
# Check parameter access patterns
aws logs filter-log-events \
    --log-group-name CloudTrail/OpsAgentParameterAccess \
    --filter-pattern "GetParameter" \
    --start-time $(date -d '7 days ago' +%s)000
```

#### 3. Failed Authentication Attempts
```bash
# Check for authentication failures
aws logs filter-log-events \
    --log-group-name /aws/lambda/opsagent-controller-production \
    --filter-pattern "Authentication failed" \
    --start-time $(date -d '1 day ago' +%s)000
```

This comprehensive credential setup guide ensures secure and proper configuration of all authentication and authorization mechanisms for the OpsAgent Controller across different environments and integrations.