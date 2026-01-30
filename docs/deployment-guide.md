# OpsAgent Controller Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the OpsAgent Controller across different environments (sandbox, staging, production) with proper configuration management and security controls.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Overview](#environment-overview)
3. [Quick Start](#quick-start)
4. [Detailed Deployment](#detailed-deployment)
5. [Configuration Management](#configuration-management)
6. [Security Setup](#security-setup)
7. [Testing and Validation](#testing-and-validation)
8. [Troubleshooting](#troubleshooting)
9. [Maintenance](#maintenance)

## Prerequisites

### Required Tools

- **AWS CLI** (v2.0+) - configured with appropriate credentials
- **AWS SAM CLI** (v1.50+) - for serverless application deployment
- **jq** - for JSON processing in scripts
- **curl** - for testing endpoints
- **openssl** - for generating secure keys

### AWS Account Requirements

- **IAM Permissions**: CloudFormation, Lambda, API Gateway, IAM, KMS, SSM, DynamoDB, CloudWatch
- **Service Limits**: Ensure sufficient limits for Lambda functions and API Gateway
- **Bedrock Access**: If using Bedrock, ensure model access is enabled in your region

### Installation Commands

```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Install SAM CLI
pip install aws-sam-cli

# Install jq (Ubuntu/Debian)
sudo apt-get install jq

# Install jq (macOS)
brew install jq
```

## Environment Overview

### Sandbox Environment
- **Purpose**: Development and testing
- **Execution Mode**: LOCAL_MOCK or DRY_RUN
- **Resources**: Minimal, cost-optimized
- **Security**: Relaxed for development

### Staging Environment
- **Purpose**: Pre-production testing
- **Execution Mode**: DRY_RUN or SANDBOX_LIVE
- **Resources**: Production-like but smaller scale
- **Security**: Production-like controls

### Production Environment
- **Purpose**: Live operations
- **Execution Mode**: SANDBOX_LIVE
- **Resources**: Full scale with redundancy
- **Security**: Maximum security controls

## Quick Start

### 1. Clone and Setup
```bash
git clone <repository-url>
cd ops-agent-controller
chmod +x infrastructure/*.sh
```

### 2. Deploy Sandbox Environment
```bash
# Deploy with defaults
./infrastructure/deploy-environment.sh sandbox

# Or with custom settings
./infrastructure/deploy-environment.sh sandbox \
    --region us-west-2 \
    --execution-mode DRY_RUN
```

### 3. Configure Credentials
```bash
./infrastructure/configure-environment.sh setup-credentials sandbox
```

### 4. Test Deployment
```bash
./infrastructure/configure-environment.sh validate-config sandbox
```
## Detailed Deployment

### Environment-Specific Deployment

#### Sandbox Deployment
```bash
# Basic sandbox deployment
./infrastructure/deploy-environment.sh sandbox

# Sandbox with custom configuration
./infrastructure/deploy-environment.sh sandbox \
    --region us-east-1 \
    --execution-mode LOCAL_MOCK \
    --llm-provider bedrock \
    --api-key "your-secure-api-key"
```

#### Staging Deployment
```bash
# Staging deployment with dry-run mode
./infrastructure/deploy-environment.sh staging \
    --region us-west-2 \
    --execution-mode DRY_RUN \
    --llm-provider bedrock
```

#### Production Deployment
```bash
# Production deployment with live execution
./infrastructure/deploy-environment.sh production \
    --region us-east-1 \
    --execution-mode SANDBOX_LIVE \
    --llm-provider bedrock
```

### Manual Deployment with SAM

If you prefer manual control over the deployment process:

```bash
# Navigate to infrastructure directory
cd infrastructure

# Validate template
sam validate --template-file template.yaml

# Build application
sam build --template-file template.yaml

# Deploy with guided setup
sam deploy --guided

# Or deploy with specific parameters
sam deploy \
    --stack-name opsagent-controller-sandbox \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
        Environment=sandbox \
        ExecutionMode=LOCAL_MOCK \
        LLMProvider=bedrock \
        CreateTestResources=true
```

### Deployment Parameters

| Parameter | Description | Default | Options |
|-----------|-------------|---------|---------|
| `Environment` | Deployment environment | `sandbox` | `sandbox`, `staging`, `production` |
| `ExecutionMode` | OpsAgent execution mode | `LOCAL_MOCK` | `LOCAL_MOCK`, `DRY_RUN`, `SANDBOX_LIVE` |
| `LLMProvider` | LLM provider to use | `bedrock` | `bedrock`, `openai`, `azure_openai` |
| `BedrockModelId` | Bedrock model identifier | `anthropic.claude-3-sonnet-20240229-v1:0` | Any supported Bedrock model |
| `EnableDynamoDBEncryption` | Enable DynamoDB encryption | `true` | `true`, `false` |
| `CreateTestResources` | Create test EC2 instance | `true` | `true`, `false` |

## Configuration Management

### Setting Up Credentials

#### AWS and API Key Setup
```bash
# Interactive credential setup
./infrastructure/configure-environment.sh setup-credentials sandbox

# Manual API key setup
aws ssm put-parameter \
    --name "/opsagent/sandbox/api-key" \
    --value "your-secure-api-key" \
    --type SecureString \
    --overwrite
```

#### LLM Provider Configuration

**For Bedrock (Recommended):**
```bash
# Ensure Bedrock model access is enabled
aws bedrock list-foundation-models --region us-east-1

# No additional credentials needed
```

**For OpenAI:**
```bash
# Store OpenAI API key
aws ssm put-parameter \
    --name "/opsagent/sandbox/openai-api-key" \
    --value "sk-your-openai-key" \
    --type SecureString \
    --overwrite
```

**For Azure OpenAI:**
```bash
# Store Azure OpenAI credentials
aws ssm put-parameter \
    --name "/opsagent/sandbox/azure-openai-api-key" \
    --value "your-azure-key" \
    --type SecureString \
    --overwrite

aws ssm put-parameter \
    --name "/opsagent/sandbox/azure-openai-endpoint" \
    --value "https://your-resource.openai.azure.com/" \
    --type String \
    --overwrite
```

### Microsoft Teams Integration

#### Prerequisites
1. Microsoft 365 tenant with Teams enabled
2. Azure subscription for Bot Service registration
3. Appropriate permissions to create bot registrations

#### Setup Process
```bash
# Interactive Teams setup
./infrastructure/configure-environment.sh setup-teams production
```

#### Manual Teams Setup

1. **Create Bot Registration in Azure Portal:**
   - Go to https://portal.azure.com/#create/Microsoft.BotService
   - Create a new Bot Service registration
   - Note the App ID and generate an App Secret

2. **Configure Bot Endpoint:**
   ```bash
   # Get the chat endpoint URL
   CHAT_URL=$(aws cloudformation describe-stacks \
       --stack-name opsagent-controller-production \
       --query 'Stacks[0].Outputs[?OutputKey==`ChatEndpoint`].OutputValue' \
       --output text)
   
   echo "Configure bot messaging endpoint to: $CHAT_URL"
   ```

3. **Store Teams Credentials:**
   ```bash
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

4. **Create Teams App Manifest:**
   ```json
   {
     "$schema": "https://developer.microsoft.com/en-us/json-schemas/teams/v1.16/MicrosoftTeams.schema.json",
     "manifestVersion": "1.16",
     "version": "1.0.0",
     "id": "your-bot-app-id",
     "packageName": "com.company.opsagent",
     "developer": {
       "name": "Your Company",
       "websiteUrl": "https://your-company.com",
       "privacyUrl": "https://your-company.com/privacy",
       "termsOfUseUrl": "https://your-company.com/terms"
     },
     "name": {
       "short": "OpsAgent",
       "full": "OpsAgent Controller"
     },
     "description": {
       "short": "Conversational Tier-1 Ops assistant",
       "full": "OpsAgent Controller helps platform teams diagnose and remediate incidents through chat interfaces"
     },
     "icons": {
       "outline": "outline.png",
       "color": "color.png"
     },
     "accentColor": "#FFFFFF",
     "bots": [
       {
         "botId": "your-bot-app-id",
         "scopes": ["personal", "team"],
         "commandLists": [
           {
             "scopes": ["personal", "team"],
             "commands": [
               {
                 "title": "Check system status",
                 "description": "Get overall system health status"
               },
               {
                 "title": "Check CPU metrics",
                 "description": "Get CPU utilization metrics"
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

## Security Setup

### IAM Permissions

The deployment creates several IAM policies with least privilege access:

#### Audit Logging Policy
- CloudWatch Logs: CreateLogStream, PutLogEvents
- DynamoDB: PutItem, GetItem, Query, UpdateItem
- KMS: Encrypt, Decrypt, GenerateDataKey

#### Diagnosis Tools Policy
- CloudWatch: GetMetricStatistics, ListMetrics (read-only)
- EC2: DescribeInstances, DescribeTags (read-only)
- ECS/ALB: DescribeServices, DescribeLoadBalancers (read-only)

#### Remediation Tools Policy
- EC2: RebootInstances, StartInstances, StopInstances (tagged resources only)
- Condition: `ec2:ResourceTag/OpsAgentManaged = true`

#### LLM Provider Policy
- Bedrock: InvokeModel (specific models only)
- SSM: GetParameter (OpsAgent parameters only)
- Secrets Manager: GetSecretValue (OpsAgent secrets only)

### Encryption

#### Data at Rest
- **KMS Encryption**: All data encrypted with customer-managed KMS key
- **CloudWatch Logs**: Encrypted with KMS key
- **DynamoDB**: Encrypted with KMS key
- **SSM Parameters**: SecureString type with KMS encryption

#### Data in Transit
- **API Gateway**: TLS 1.2+ enforced
- **AWS Service Calls**: HTTPS only
- **LLM Provider Calls**: TLS encryption

### Network Security

#### API Gateway Security
```yaml
# CORS Configuration
Cors:
  AllowMethods: "'GET,POST,OPTIONS'"
  AllowHeaders: "'Content-Type,X-Amz-Date,Authorization,X-Api-Key'"
  AllowOrigin: "'*'"  # Restrict in production
  MaxAge: "'600'"

# Rate Limiting
MethodSettings:
  - ThrottlingRateLimit: 100
    ThrottlingBurstLimit: 200
```

#### Lambda Security
- **VPC**: Optional VPC deployment for network isolation
- **Security Groups**: Restrictive egress rules
- **Environment Variables**: No secrets in environment variables

### Resource Tagging

All resources are tagged for security and compliance:

```yaml
Tags:
  Project: OpsAgent
  Environment: !Ref Environment
  Owner: Platform-Team
  DeployedBy: !Ref AWS::AccountId
  DeployedAt: !Ref AWS::StackId
```

### Compliance Features

#### SOC 2 Compliance
- **Audit Logging**: Complete audit trail of all actions
- **Access Controls**: Role-based access with least privilege
- **Encryption**: Data encrypted at rest and in transit
- **Monitoring**: CloudWatch metrics and alarms

#### GDPR Compliance
- **Data Retention**: DynamoDB TTL for automatic cleanup
- **Data Minimization**: Only necessary data collected
- **Right to Erasure**: Manual data deletion capabilities

## Testing and Validation

### Automated Testing

#### Infrastructure Validation
```bash
# Validate SAM template
./infrastructure/validate.sh

# Validate configuration
./infrastructure/configure-environment.sh validate-config sandbox
```

#### Smoke Tests
```bash
# Test health endpoint
HEALTH_URL=$(aws cloudformation describe-stacks \
    --stack-name opsagent-controller-sandbox \
    --query 'Stacks[0].Outputs[?OutputKey==`HealthEndpoint`].OutputValue' \
    --output text)

API_KEY=$(aws ssm get-parameter \
    --name "/opsagent/sandbox/api-key" \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text)

curl -H "X-API-Key: $API_KEY" "$HEALTH_URL"
```

#### Integration Tests
```bash
# Test chat endpoint
CHAT_URL=$(aws cloudformation describe-stacks \
    --stack-name opsagent-controller-sandbox \
    --query 'Stacks[0].Outputs[?OutputKey==`ChatEndpoint`].OutputValue' \
    --output text)

curl -X POST \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d '{"userId":"test-user","messageText":"Check system status","channel":"web"}' \
    "$CHAT_URL"
```

### Manual Testing

#### Test Scenarios

1. **Health Check Test**
   - Verify health endpoint returns 200
   - Check execution mode is correct
   - Validate LLM provider status

2. **Authentication Test**
   - Test with valid API key
   - Test with invalid API key
   - Test with missing API key

3. **Diagnosis Tools Test**
   - Request CloudWatch metrics
   - Request EC2 instance information
   - Verify read-only operations

4. **Approval Gate Test**
   - Request remediation action
   - Verify approval prompt is returned
   - Test approval token validation

5. **Audit Logging Test**
   - Verify all actions are logged
   - Check correlation IDs are present
   - Validate no secrets in logs

### Performance Testing

#### Load Testing
```bash
# Simple load test with curl
for i in {1..100}; do
    curl -s -H "X-API-Key: $API_KEY" "$HEALTH_URL" &
done
wait
```

#### Monitoring
- **CloudWatch Metrics**: Lambda duration, error rate, throttles
- **API Gateway Metrics**: Request count, latency, 4xx/5xx errors
- **Custom Metrics**: Business logic metrics

## Troubleshooting

### Common Issues

#### 1. "LLM provider not configured"
**Symptoms**: Health endpoint shows LLM provider as not configured
**Solutions**:
- Verify Bedrock model access is enabled
- Check IAM permissions for `bedrock:InvokeModel`
- Validate model ID in parameters

#### 2. "AWS tool access error"
**Symptoms**: Diagnosis tools fail with permission errors
**Solutions**:
- Check IAM permissions for CloudWatch and EC2
- Verify correct AWS region
- Test with AWS CLI directly

#### 3. "Authentication failed"
**Symptoms**: API returns 401 or 403 errors
**Solutions**:
- Update API key in SSM Parameter Store
- Check header format: `X-API-Key: your-key`
- Verify parameter name matches environment

#### 4. "Rate limit exceeded"
**Symptoms**: API returns 429 errors
**Solutions**:
- Check API Gateway throttling settings
- Implement client-side rate limiting
- Consider increasing limits for production

#### 5. "Stack deployment failed"
**Symptoms**: CloudFormation deployment errors
**Solutions**:
- Check IAM permissions for CloudFormation
- Verify resource limits and quotas
- Review CloudFormation events for specific errors

### Debugging Commands

#### Check Stack Status
```bash
aws cloudformation describe-stacks \
    --stack-name opsagent-controller-sandbox \
    --query 'Stacks[0].StackStatus'
```

#### View Stack Events
```bash
aws cloudformation describe-stack-events \
    --stack-name opsagent-controller-sandbox \
    --query 'StackEvents[*].[Timestamp,ResourceStatus,ResourceStatusReason]' \
    --output table
```

#### Check Lambda Logs
```bash
aws logs tail /aws/lambda/opsagent-controller-sandbox --follow
```

#### Check Parameter Store
```bash
aws ssm get-parameters-by-path \
    --path "/opsagent/sandbox/" \
    --query 'Parameters[*].[Name,Type]' \
    --output table
```

### Log Analysis

#### CloudWatch Insights Queries

**Error Analysis:**
```sql
fields @timestamp, @message
| filter @message like /ERROR/
| sort @timestamp desc
| limit 100
```

**Performance Analysis:**
```sql
fields @timestamp, @duration, @requestId
| filter @type = "REPORT"
| stats avg(@duration), max(@duration), min(@duration) by bin(5m)
```

**Audit Trail:**
```sql
fields @timestamp, correlationId, userId, action, outcome
| filter @message like /AUDIT/
| sort @timestamp desc
| limit 100
```

## Maintenance

### Regular Maintenance Tasks

#### Weekly Tasks
1. **Review CloudWatch Logs** for errors and warnings
2. **Check API Gateway metrics** for performance issues
3. **Validate backup and recovery** procedures
4. **Review security alerts** and recommendations

#### Monthly Tasks
1. **Update dependencies** and security patches
2. **Review IAM permissions** and access patterns
3. **Analyze cost optimization** opportunities
4. **Test disaster recovery** procedures

#### Quarterly Tasks
1. **Security audit** and penetration testing
2. **Performance optimization** review
3. **Capacity planning** and scaling review
4. **Documentation updates** and training

### Backup and Recovery

#### Configuration Backup
```bash
# Export configuration
./infrastructure/configure-environment.sh export-config production \
    --file "backup-prod-$(date +%Y%m%d).json"

# Store backup securely
aws s3 cp "backup-prod-$(date +%Y%m%d).json" \
    s3://your-backup-bucket/opsagent/configs/
```

#### Disaster Recovery
```bash
# Restore from backup
./infrastructure/configure-environment.sh import-config production \
    --file "backup-prod-20240101.json"

# Redeploy infrastructure
./infrastructure/deploy-environment.sh production --validate-only
./infrastructure/deploy-environment.sh production
```

### Monitoring and Alerting

#### CloudWatch Alarms
```bash
# Create error rate alarm
aws cloudwatch put-metric-alarm \
    --alarm-name "OpsAgent-ErrorRate-High" \
    --alarm-description "OpsAgent error rate is high" \
    --metric-name "Errors" \
    --namespace "AWS/Lambda" \
    --statistic "Sum" \
    --period 300 \
    --threshold 10 \
    --comparison-operator "GreaterThanThreshold" \
    --dimensions Name=FunctionName,Value=opsagent-controller-production \
    --evaluation-periods 2
```

#### Custom Metrics
```python
# In Lambda function
import boto3
cloudwatch = boto3.client('cloudwatch')

cloudwatch.put_metric_data(
    Namespace='OpsAgent/Controller',
    MetricData=[
        {
            'MetricName': 'SuccessfulRequests',
            'Value': 1,
            'Unit': 'Count',
            'Dimensions': [
                {
                    'Name': 'Environment',
                    'Value': os.environ['ENVIRONMENT']
                }
            ]
        }
    ]
)
```

### Cost Optimization

#### Cost Monitoring
```bash
# Get cost and usage data
aws ce get-cost-and-usage \
    --time-period Start=2024-01-01,End=2024-01-31 \
    --granularity MONTHLY \
    --metrics BlendedCost \
    --group-by Type=DIMENSION,Key=SERVICE
```

#### Optimization Strategies
1. **Lambda Memory Optimization**: Monitor and adjust based on usage
2. **API Gateway Caching**: Enable caching for read-heavy workloads
3. **DynamoDB On-Demand**: Use on-demand billing for variable workloads
4. **CloudWatch Logs Retention**: Set appropriate retention periods
5. **Reserved Capacity**: Consider reserved capacity for predictable workloads

### Security Updates

#### Regular Security Tasks
1. **Rotate API Keys** quarterly
2. **Update IAM Policies** based on least privilege principle
3. **Review Access Logs** for suspicious activity
4. **Update Dependencies** for security patches
5. **Scan for Vulnerabilities** using AWS Inspector

#### Security Incident Response
1. **Immediate Response**: Disable compromised credentials
2. **Investigation**: Review audit logs and access patterns
3. **Containment**: Isolate affected resources
4. **Recovery**: Restore from known good state
5. **Lessons Learned**: Update procedures and controls

This comprehensive deployment guide provides all the necessary information to successfully deploy, configure, and maintain the OpsAgent Controller across different environments with proper security controls and operational procedures.