# OpsAgent Controller - Production Implementation Guide

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture Deep Dive](#architecture-deep-dive)
3. [Production Deployment Steps](#production-deployment-steps)
4. [Security Configuration](#security-configuration)
5. [Monitoring and Observability](#monitoring-and-observability)
6. [Operational Procedures](#operational-procedures)
7. [Troubleshooting Guide](#troubleshooting-guide)
8. [Performance Optimization](#performance-optimization)
9. [Disaster Recovery](#disaster-recovery)
10. [Compliance and Governance](#compliance-and-governance)

## System Overview

The OpsAgent Controller is a serverless conversational AI system that provides secure AWS operations through natural language interactions. It integrates with Amazon Q Business to provide a chat-based interface for platform engineers to perform diagnostic and remediation tasks.

### Key Capabilities

**Diagnostic Operations** (No Approval Required):
- `get_ec2_status` - Get EC2 instance status and health
- `get_cloudwatch_metrics` - Retrieve CloudWatch metrics and alarms
- `describe_alb_target_health` - Check ALB target group health
- `search_cloudtrail_events` - Search CloudTrail for specific events

**Write Operations** (Approval Required):
- `reboot_ec2` - Reboot EC2 instances (requires OpsAgentManaged=true tag)
- `scale_ecs_service` - Scale ECS services up/down

**Workflow Operations** (Fully Audited):
- `create_incident_record` - Create incident records in DynamoDB
- `post_summary_to_channel` - Send notifications to Teams/Slack

### Execution Modes

- **LOCAL_MOCK**: Development/testing with mocked AWS calls
- **DRY_RUN**: Validation without actual execution
- **SANDBOX_LIVE**: Live operations in sandbox environment (production default)

## Architecture Deep Dive

### Core Components

#### 1. Lambda Function (`main.py`)
- **Entry Point**: `lambda_handler()` routes requests to appropriate handlers
- **Chat Handler**: Processes conversational requests from Teams/Slack/Web
- **Plugin Handler**: Handles Amazon Q Business plugin requests
- **Health Handler**: System status and health checks

#### 2. Tool Execution Engine (`tool_execution_engine.py`)
- **Purpose**: Executes AWS operations with security controls
- **Guardrails**: Validates resource tags and permissions before execution
- **Tool Implementations**: Wraps AWS SDK calls with error handling and logging

#### 3. Approval Gate (`approval_gate.py`)
- **Purpose**: Manages approval workflow for write operations
- **Token Generation**: Creates secure approval tokens with 15-minute expiry
- **Risk Assessment**: Categorizes operations by risk level (low/medium/high)

#### 4. Audit Logger (`audit_logger.py`)
- **CloudWatch Logs**: Real-time logging for monitoring and debugging
- **DynamoDB**: Structured audit records for compliance and analysis
- **Event Types**: Request received, tool executed, approval granted/denied, errors

#### 5. Authentication System (`authentication.py`)
- **User Validation**: Validates users against allow-list in SSM Parameter Store
- **Amazon Q Integration**: Extracts user context from Q Business requests
- **API Key Validation**: Validates plugin API keys for external access

### Data Flow

```
1. User Request → Amazon Q Business Plugin
2. Plugin → API Gateway → Lambda (plugin_handler)
3. Authentication & Authorization Check
4. Operation Routing:
   - Diagnostic → Direct Execution
   - Write → Approval Workflow (propose_action → approve_action)
   - Workflow → Direct Execution with Full Audit
5. Tool Execution Engine → AWS APIs
6. Response → Amazon Q Business → User
7. Audit Logging → CloudWatch + DynamoDB
```

### AWS Resources

**Core Infrastructure**:
- Lambda Function (Python 3.11, 1024MB memory, 30s timeout)
- API Gateway (Regional, with usage plans and API keys)
- DynamoDB Tables (audit logs, incident records)
- CloudWatch Log Groups (application logs, API Gateway logs)
- SNS Topic (notifications)
- KMS Key (encryption at rest)

**Security**:
- IAM Roles with least-privilege permissions
- Resource-based policies with tag conditions
- API Gateway authentication with API keys
- SSM Parameter Store for configuration

## Production Deployment Steps

### Prerequisites

1. **AWS Account Setup**
   ```bash
   # Configure AWS CLI with production credentials
   aws configure --profile production
   export AWS_PROFILE=production
   
   # Verify account and permissions
   aws sts get-caller-identity
   aws iam get-user
   ```

2. **Required Tools**
   ```bash
   # Install AWS SAM CLI
   pip install aws-sam-cli
   
   # Install dependencies
   pip install -r requirements.txt
   ```

3. **Environment Configuration**
   ```bash
   # Set production environment variables
   export ENVIRONMENT=production
   export EXECUTION_MODE=SANDBOX_LIVE
   export AWS_REGION=us-east-1
   ```

### Step 1: Infrastructure Deployment

```bash
# Navigate to infrastructure directory
cd infrastructure

# Build the application
sam build --use-container

# Deploy with production parameters
sam deploy \
  --template-file .aws-sam/build/template.yaml \
  --stack-name opsagent-controller-production \
  --s3-bucket your-production-deployment-bucket \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    Environment=production \
    ExecutionMode=SANDBOX_LIVE \
    CreateTestResources=false \
    EnableDynamoDBEncryption=true \
    LLMProvider=bedrock \
    BedrockModelId=anthropic.claude-3-sonnet-20240229-v1:0 \
  --tags \
    Project=OpsAgent \
    Environment=production \
    Owner=Platform-Team \
    CostCenter=Infrastructure
```

### Step 2: Security Configuration

1. **Update API Key**
   ```bash
   # Generate secure API key
   SECURE_API_KEY=$(openssl rand -base64 32)
   
   # Store in SSM Parameter Store
   aws ssm put-parameter \
     --name "/opsagent/api-key" \
     --value "$SECURE_API_KEY" \
     --type "SecureString" \
     --overwrite
   ```

2. **Configure User Allow-List**
   ```bash
   # Set production users (replace with actual email addresses)
   aws ssm put-parameter \
     --name "/opsagent/allowed-users" \
     --value "senior-platform-engineer@company.com,ops-lead@company.com,incident-commander@company.com" \
     --type "StringList" \
     --overwrite
   ```

3. **Set Up Amazon Q Business Integration**
   ```bash
   # Get plugin API endpoint
   API_ENDPOINT=$(aws cloudformation describe-stacks \
     --stack-name opsagent-controller-production \
     --query 'Stacks[0].Outputs[?OutputKey==`PluginApiEndpointUrl`].OutputValue' \
     --output text)
   
   # Get plugin API key
   PLUGIN_API_KEY=$(aws ssm get-parameter \
     --name "/opsagent/plugin-api-key-production" \
     --with-decryption \
     --query 'Parameter.Value' \
     --output text)
   
   echo "Plugin API Endpoint: $API_ENDPOINT"
   echo "Plugin API Key: $PLUGIN_API_KEY"
   ```

### Step 3: Amazon Q Business Plugin Setup

1. **Create Plugin in Amazon Q Business Console**
   - Navigate to Amazon Q Business Console
   - Go to Applications → Your Application → Plugins
   - Click "Create plugin"
   - Choose "Custom plugin"

2. **Configure Plugin**
   ```yaml
   # Plugin Configuration
   Name: "OpsAgent Actions - Production"
   Description: "Secure AWS operations for platform engineers"
   
   # OpenAPI Schema
   # Use: infrastructure/openapi-schema.yaml
   # Update server URL with your API endpoint
   
   # Authentication
   Type: API Key
   Location: Header
   Name: X-API-Key
   Value: [Your Plugin API Key]
   ```

3. **Test Plugin Integration**
   ```bash
   # Test health endpoint
   curl -f "$API_ENDPOINT/health"
   
   # Test diagnostic operation
   curl -X POST "$API_ENDPOINT/operations/diagnostic" \
     -H "Content-Type: application/json" \
     -H "X-API-Key: $PLUGIN_API_KEY" \
     -d '{
       "operation": "get_ec2_status",
       "parameters": {"instance_id": "i-1234567890abcdef0"},
       "user_context": {"user_id": "test@company.com"}
     }'
   ```

## Security Configuration

### Resource Tagging Requirements

All AWS resources that can be modified by OpsAgent must have the following tags:

```yaml
Required Tags:
  - Key: "OpsAgentManaged"
    Value: "true"
  - Key: "Environment"
    Value: "production"
  - Key: "CriticalityLevel"
    Value: "high" | "critical"
```

**Example: Tag EC2 Instance**
```bash
aws ec2 create-tags \
  --resources i-1234567890abcdef0 \
  --tags \
    Key=OpsAgentManaged,Value=true \
    Key=Environment,Value=production \
    Key=CriticalityLevel,Value=high \
    Key=Owner,Value=platform-team
```

### IAM Permissions

The Lambda execution role has carefully scoped permissions:

**Diagnostic Operations** (Read-Only):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "elasticloadbalancing:DescribeTargetHealth",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

**Write Operations** (Tag-Restricted):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:RebootInstances",
        "ecs:UpdateService"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/OpsAgentManaged": "true",
          "aws:ResourceTag/Environment": "production"
        }
      }
    }
  ]
}
```

### API Security

1. **API Gateway Configuration**
   - API Keys required for all endpoints except health
   - Usage plans with rate limiting (500 req/min, 1000 burst)
   - CORS configured for specific origins only

2. **Request Validation**
   - JSON schema validation on all inputs
   - Parameter sanitization to prevent injection
   - User ID validation against allow-list

3. **Encryption**
   - TLS 1.2+ for all API communications
   - KMS encryption for DynamoDB and CloudWatch Logs
   - Encrypted SSM parameters for sensitive configuration

## Monitoring and Observability

### CloudWatch Alarms

```bash
# High error rate alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "OpsAgent-Production-HighErrorRate" \
  --alarm-description "High error rate in OpsAgent Controller" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=opsagent-controller-production \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:opsagent-notifications-production

# High latency alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "OpsAgent-Production-HighLatency" \
  --alarm-description "High latency in OpsAgent Controller" \
  --metric-name Duration \
  --namespace AWS/Lambda \
  --statistic Average \
  --period 300 \
  --threshold 10000 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=opsagent-controller-production \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:opsagent-notifications-production

# Unauthorized access alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "OpsAgent-Production-UnauthorizedAccess" \
  --alarm-description "High number of unauthorized access attempts" \
  --metric-name 4XXError \
  --namespace AWS/ApiGateway \
  --statistic Sum \
  --period 300 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=ApiName,Value=opsagent-controller-production \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:opsagent-notifications-production
```

### Log Analysis Queries

**CloudWatch Insights Queries**:

1. **Error Analysis**
   ```sql
   fields @timestamp, @message, correlation_id, user_id
   | filter @message like /ERROR/
   | sort @timestamp desc
   | limit 100
   ```

2. **Approval Workflow Tracking**
   ```sql
   fields @timestamp, event_type, user_id, tool_name, approval_token
   | filter event_type in ["approval_requested", "approval_granted", "approval_denied"]
   | sort @timestamp desc
   | limit 50
   ```

3. **Performance Analysis**
   ```sql
   fields @timestamp, @duration, @requestId, operation
   | filter @type = "REPORT"
   | stats avg(@duration), max(@duration), min(@duration) by bin(5m)
   ```

### Dashboards

Create CloudWatch Dashboard with:
- Lambda function metrics (invocations, errors, duration)
- API Gateway metrics (requests, latency, 4xx/5xx errors)
- DynamoDB metrics (read/write capacity, throttles)
- Custom metrics (approval requests, tool executions by type)

## Operational Procedures

### Daily Operations

1. **Health Check**
   ```bash
   # Automated health check
   curl -f https://your-api-endpoint.com/health
   
   # Check system status
   aws logs tail /aws/lambda/opsagent-controller-production --since 1h
   ```

2. **Audit Review**
   ```bash
   # Check recent audit events
   aws dynamodb scan \
     --table-name opsagent-audit-production \
     --filter-expression "event_type = :type" \
     --expression-attribute-values '{":type":{"S":"error_occurred"}}' \
     --limit 10
   ```

### Weekly Operations

1. **User Access Review**
   ```bash
   # Review current allowed users
   aws ssm get-parameter \
     --name "/opsagent/allowed-users" \
     --query 'Parameter.Value' \
     --output text
   
   # Update if needed
   aws ssm put-parameter \
     --name "/opsagent/allowed-users" \
     --value "updated-user-list" \
     --type "StringList" \
     --overwrite
   ```

2. **Performance Review**
   ```bash
   # Check Lambda performance metrics
   aws cloudwatch get-metric-statistics \
     --namespace AWS/Lambda \
     --metric-name Duration \
     --dimensions Name=FunctionName,Value=opsagent-controller-production \
     --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%S) \
     --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
     --period 3600 \
     --statistics Average,Maximum
   ```

### Monthly Operations

1. **API Key Rotation**
   ```bash
   # Generate new API key
   NEW_API_KEY=$(openssl rand -base64 32)
   
   # Update in SSM
   aws ssm put-parameter \
     --name "/opsagent/api-key" \
     --value "$NEW_API_KEY" \
     --type "SecureString" \
     --overwrite
   
   # Update Amazon Q Business plugin configuration
   # (Manual step in Q Business console)
   ```

2. **Security Review**
   ```bash
   # Review CloudTrail events for OpsAgent
   aws logs filter-log-events \
     --log-group-name /aws/lambda/opsagent-controller-production \
     --start-time $(date -d '30 days ago' +%s)000 \
     --filter-pattern "ERROR"
   ```

### Incident Response

1. **High Error Rate**
   ```bash
   # Check recent errors
   aws logs filter-log-events \
     --log-group-name /aws/lambda/opsagent-controller-production \
     --start-time $(date -d '1 hour ago' +%s)000 \
     --filter-pattern "ERROR"
   
   # Check Lambda metrics
   aws cloudwatch get-metric-statistics \
     --namespace AWS/Lambda \
     --metric-name Errors \
     --dimensions Name=FunctionName,Value=opsagent-controller-production \
     --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
     --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
     --period 300 \
     --statistics Sum
   ```

2. **Unauthorized Access**
   ```bash
   # Check API Gateway access logs
   aws logs filter-log-events \
     --log-group-name /aws/apigateway/opsagent-production \
     --start-time $(date -d '1 hour ago' +%s)000 \
     --filter-pattern "401"
   
   # Review user authentication failures
   aws logs filter-log-events \
     --log-group-name /aws/lambda/opsagent-controller-production \
     --start-time $(date -d '1 hour ago' +%s)000 \
     --filter-pattern "Authentication failed"
   ```

## Troubleshooting Guide

### Common Issues

#### 1. Lambda Function Timeouts

**Symptoms**: 
- 504 Gateway Timeout errors
- Incomplete operations

**Diagnosis**:
```bash
# Check Lambda duration metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=opsagent-controller-production \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average,Maximum
```

**Solutions**:
- Increase Lambda timeout (current: 30s, max: 15min)
- Increase memory allocation (current: 1024MB)
- Optimize code for better performance

#### 2. Authentication Failures

**Symptoms**:
- 401 Unauthorized errors
- Users unable to access system

**Diagnosis**:
```bash
# Check user allow-list
aws ssm get-parameter --name "/opsagent/allowed-users"

# Check API key
aws ssm get-parameter --name "/opsagent/api-key" --with-decryption

# Review authentication logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-controller-production \
  --filter-pattern "Authentication"
```

**Solutions**:
- Verify user is in allow-list
- Check API key configuration in Amazon Q Business
- Validate user email format matches exactly

#### 3. Resource Tag Validation Failures

**Symptoms**:
- Write operations rejected with tag validation errors
- "Resource validation failed" messages

**Diagnosis**:
```bash
# Check resource tags
aws ec2 describe-tags --filters "Name=resource-id,Values=i-1234567890abcdef0"

# Review tag validation logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-controller-production \
  --filter-pattern "Tag validation"
```

**Solutions**:
- Add required tags to resources:
  ```bash
  aws ec2 create-tags \
    --resources i-1234567890abcdef0 \
    --tags Key=OpsAgentManaged,Value=true Key=Environment,Value=production
  ```

#### 4. DynamoDB Throttling

**Symptoms**:
- Slow audit logging
- ProvisionedThroughputExceededException errors

**Diagnosis**:
```bash
# Check DynamoDB metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/DynamoDB \
  --metric-name ThrottledRequests \
  --dimensions Name=TableName,Value=opsagent-audit-production \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

**Solutions**:
- Enable auto-scaling (should be enabled by default)
- Increase provisioned capacity temporarily
- Review write patterns for optimization

## Performance Optimization

### Lambda Optimization

1. **Memory and CPU**
   ```bash
   # Increase memory for better CPU performance
   aws lambda update-function-configuration \
     --function-name opsagent-controller-production \
     --memory-size 1536  # Increase from 1024MB
   ```

2. **Provisioned Concurrency**
   ```bash
   # Keep warm instances for better response times
   aws lambda put-provisioned-concurrency-config \
     --function-name opsagent-controller-production \
     --qualifier $LATEST \
     --provisioned-concurrency-config ProvisionedConcurrencyConfig=10
   ```

### API Gateway Optimization

1. **Caching**
   ```bash
   # Enable caching for GET requests
   aws apigateway put-method \
     --rest-api-id your-api-id \
     --resource-id your-resource-id \
     --http-method GET \
     --caching-enabled \
     --cache-ttl 300
   ```

2. **Compression**
   ```bash
   # Enable response compression
   aws apigateway put-request-validator \
     --rest-api-id your-api-id \
     --content-handling CONVERT_TO_TEXT
   ```

### DynamoDB Optimization

1. **Auto Scaling**
   ```bash
   # Configure auto scaling for audit table
   aws application-autoscaling register-scalable-target \
     --service-namespace dynamodb \
     --resource-id table/opsagent-audit-production \
     --scalable-dimension dynamodb:table:WriteCapacityUnits \
     --min-capacity 5 \
     --max-capacity 100
   ```

## Disaster Recovery

### Backup Strategy

1. **DynamoDB Backups**
   ```bash
   # Enable point-in-time recovery (already enabled in template)
   aws dynamodb put-backup-policy \
     --table-name opsagent-audit-production \
     --backup-policy BackupEnabled=true
   
   # Create on-demand backup
   aws dynamodb create-backup \
     --table-name opsagent-audit-production \
     --backup-name opsagent-audit-backup-$(date +%Y%m%d)
   ```

2. **Configuration Backup**
   ```bash
   # Export CloudFormation template
   aws cloudformation get-template \
     --stack-name opsagent-controller-production \
     --template-stage Processed > backup/template-$(date +%Y%m%d).json
   
   # Backup SSM parameters
   aws ssm get-parameters-by-path \
     --path "/opsagent/" \
     --recursive \
     --with-decryption > backup/ssm-parameters-$(date +%Y%m%d).json
   ```

### Recovery Procedures

1. **Lambda Function Recovery**
   ```bash
   # Redeploy from source
   sam build && sam deploy \
     --template-file .aws-sam/build/template.yaml \
     --stack-name opsagent-controller-production \
     --capabilities CAPABILITY_IAM \
     --no-confirm-changeset
   ```

2. **DynamoDB Recovery**
   ```bash
   # Restore from backup
   aws dynamodb restore-table-from-backup \
     --target-table-name opsagent-audit-production-restored \
     --backup-arn arn:aws:dynamodb:us-east-1:123456789012:table/opsagent-audit-production/backup/01234567890123-abcdefgh
   ```

### Multi-Region Setup

For high availability, consider deploying to multiple regions:

```bash
# Deploy to secondary region
export AWS_REGION=us-west-2
sam deploy \
  --template-file .aws-sam/build/template.yaml \
  --stack-name opsagent-controller-production-west \
  --s3-bucket your-west-deployment-bucket \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides Environment=production-west
```

## Compliance and Governance

### Audit Requirements

1. **Log Retention**
   - CloudWatch Logs: 90 days (configurable)
   - DynamoDB Audit Records: 7 years (with TTL)
   - API Gateway Logs: 30 days

2. **Data Classification**
   - Audit logs: Confidential
   - User data: Restricted
   - System metrics: Internal

### Access Control

1. **Role-Based Access**
   ```yaml
   Production Users:
     - Senior Platform Engineers
     - Operations Lead
     - Incident Commanders
   
   Permissions:
     - Diagnostic operations: All authorized users
     - Write operations: Requires approval workflow
     - System administration: Platform team only
   ```

2. **Approval Workflow**
   - All write operations require explicit approval
   - Approval tokens expire after 15 minutes
   - All approvals are logged and auditable

### Change Management

1. **Deployment Process**
   - All changes require pull request review
   - Automated testing in staging environment
   - Change management approval for production
   - Rollback procedures documented

2. **Configuration Changes**
   - User access changes require security team approval
   - API key rotation follows established schedule
   - All configuration changes are logged

## Production Readiness Checklist

### Pre-Deployment
- [ ] AWS account and permissions configured
- [ ] Security review completed
- [ ] Change management approval obtained
- [ ] Backup procedures tested
- [ ] Monitoring and alerting configured

### Deployment
- [ ] Infrastructure deployed successfully
- [ ] API keys configured and tested
- [ ] User allow-list updated
- [ ] Amazon Q Business plugin configured
- [ ] Health checks passing

### Post-Deployment
- [ ] End-to-end testing completed
- [ ] Monitoring dashboards created
- [ ] Incident response procedures documented
- [ ] Team training completed
- [ ] Documentation updated

### Ongoing Operations
- [ ] Daily health checks automated
- [ ] Weekly performance reviews scheduled
- [ ] Monthly security reviews scheduled
- [ ] Quarterly disaster recovery testing
- [ ] Annual security assessments

## Support and Maintenance

### Team Responsibilities

**Platform Team**:
- System administration and configuration
- Performance monitoring and optimization
- Security updates and patches
- User access management

**Security Team**:
- Security reviews and assessments
- Compliance monitoring
- Incident response coordination
- Access control validation

**Operations Team**:
- Daily monitoring and health checks
- Incident response and troubleshooting
- User support and training
- Documentation maintenance

### Escalation Procedures

1. **Level 1**: Automated monitoring alerts
2. **Level 2**: Platform team investigation
3. **Level 3**: Security team involvement (for security incidents)
4. **Level 4**: Executive escalation (for critical business impact)

### Contact Information

- **Platform Team**: platform-team@company.com
- **Security Team**: security-team@company.com
- **Operations Team**: ops-team@company.com
- **Emergency**: ops-oncall@company.com

---

This production implementation guide provides comprehensive coverage of deploying, securing, monitoring, and maintaining the OpsAgent Controller in a production environment. Follow the procedures and checklists to ensure a secure and reliable deployment.