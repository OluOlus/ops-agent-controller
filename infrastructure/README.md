# OpsAgent Controller Infrastructure

This directory contains comprehensive deployment scripts, AWS SAM templates, and documentation for the OpsAgent Controller serverless application.

## 📁 Directory Structure

```
infrastructure/
├── template.yaml              # AWS SAM CloudFormation template
├── samconfig.toml            # SAM configuration for different environments
├── deploy.sh                 # Basic deployment script (legacy)
├── deploy-environment.sh     # Advanced environment-specific deployment
├── configure-environment.sh  # Configuration and credential management
├── test-deployment.sh        # Comprehensive testing suite
├── cleanup.sh               # Safe resource cleanup
├── validate.sh              # Template validation
└── README.md                # This file
```

## 🚀 Quick Start

### 1. Prerequisites Check
```bash
# Install required tools
brew install awscli sam-cli jq  # macOS
# or
sudo apt-get install awscli jq  # Ubuntu

# Configure AWS credentials
aws configure
```

### 2. Deploy to Sandbox
```bash
# Simple deployment
./deploy-environment.sh sandbox

# With custom settings
./deploy-environment.sh sandbox \
    --region us-west-2 \
    --execution-mode DRY_RUN \
    --api-key "your-secure-key"
```

### 3. Configure Credentials
```bash
# Interactive setup
./configure-environment.sh setup-credentials sandbox

# Setup Teams integration
./configure-environment.sh setup-teams production
```

### 4. Test Deployment
```bash
# Run comprehensive tests
./test-deployment.sh sandbox

# Run only smoke tests
./test-deployment.sh sandbox --smoke-only
```

## 🏗️ Architecture Overview

### Core Infrastructure
- **API Gateway**: HTTPS endpoint with CORS, rate limiting, and authentication
- **Lambda Function**: Main application logic (Python 3.11, 512MB, 30s timeout)
- **IAM Roles**: Least privilege permissions with separate policies
- **KMS Key**: Customer-managed encryption for all data at rest

### Security & Audit
- **CloudWatch Logs**: Encrypted audit logging with retention policies
- **DynamoDB Table**: Structured audit storage with TTL and encryption
- **SSM Parameter Store**: Secure configuration and credential storage
- **Dead Letter Queue**: Failed invocation handling with encryption

### Testing Resources (Optional)
- **Test EC2 Instance**: Tagged for remediation testing with CloudWatch agent
- **Security Groups**: Restrictive rules for test resources
- **IAM Instance Profile**: Minimal permissions for test instance

## 🛠️ Deployment Scripts

### deploy-environment.sh
**Advanced environment-specific deployment with configuration management**

```bash
# Usage
./deploy-environment.sh [OPTIONS] <environment>

# Examples
./deploy-environment.sh sandbox                    # Basic sandbox deployment
./deploy-environment.sh staging --region us-west-2 # Staging in different region
./deploy-environment.sh production --validate-only # Validate without deploying
./deploy-environment.sh sandbox --cleanup          # Delete sandbox stack
```

**Features:**
- Environment-specific configurations (sandbox/staging/production)
- Automatic parameter validation and defaults
- Template validation before deployment
- Comprehensive error handling and logging
- Post-deployment instructions and testing commands

### configure-environment.sh
**Configuration and credential management across environments**

```bash
# Usage
./configure-environment.sh [OPTIONS] <command> <environment>

# Commands
setup-credentials    # Set up AWS and LLM provider credentials
setup-teams         # Configure Microsoft Teams integration
update-config       # Update environment configuration
validate-config     # Validate current configuration
export-config       # Export configuration for backup
import-config       # Import configuration from backup
```

**Features:**
- Secure credential storage in SSM Parameter Store
- Multi-LLM provider support (Bedrock, OpenAI, Azure OpenAI)
- Teams bot registration and configuration
- Configuration backup and restore
- Environment validation and health checks

### test-deployment.sh
**Comprehensive testing suite for deployed environments**

```bash
# Usage
./test-deployment.sh [OPTIONS] <environment>

# Test Types
--smoke-only        # Basic functionality tests
--integration-only  # End-to-end integration tests
--load-test        # Performance and load testing
```

**Test Coverage:**
- Health endpoint validation
- Authentication and authorization
- Diagnosis tool functionality
- Approval gate workflows
- Audit logging verification
- Load testing with concurrent requests
- Error handling and edge cases

### cleanup.sh
**Safe and comprehensive resource cleanup**

```bash
# Usage
./cleanup.sh [OPTIONS] <environment>

# Options
--force            # Skip confirmation prompts
--keep-data        # Preserve audit logs and data
--keep-params      # Preserve SSM parameters
--dry-run          # Show what would be deleted
```

**Features:**
- Automatic backup creation before deletion
- Comprehensive resource discovery and cleanup
- Orphaned resource detection
- Safe deletion with confirmations
- Dry-run mode for validation

## 🔧 Configuration Parameters

### Environment-Specific Defaults

| Environment | Execution Mode | LLM Provider | Encryption | Test Resources |
|-------------|---------------|--------------|------------|----------------|
| sandbox     | LOCAL_MOCK    | bedrock      | true       | true           |
| staging     | DRY_RUN       | bedrock      | true       | false          |
| production  | SANDBOX_LIVE  | bedrock      | true       | false          |

### Customizable Parameters

| Parameter | Description | Default | Options |
|-----------|-------------|---------|---------|
| `Environment` | Deployment environment | `sandbox` | `sandbox`, `staging`, `production` |
| `ExecutionMode` | OpsAgent execution mode | `LOCAL_MOCK` | `LOCAL_MOCK`, `DRY_RUN`, `SANDBOX_LIVE` |
| `LLMProvider` | LLM provider to use | `bedrock` | `bedrock`, `openai`, `azure_openai` |
| `BedrockModelId` | Bedrock model identifier | `anthropic.claude-3-sonnet-20240229-v1:0` | Any supported model |
| `EnableDynamoDBEncryption` | Enable DynamoDB encryption | `true` | `true`, `false` |
| `CreateTestResources` | Create test EC2 instance | `true` | `true`, `false` |

## 🔐 Security Features

### Encryption at Rest
- **KMS Customer-Managed Keys**: All data encrypted with dedicated KMS key
- **CloudWatch Logs**: Encrypted with KMS key
- **DynamoDB**: Encrypted with KMS key
- **SSM Parameters**: SecureString type with KMS encryption
- **SQS Dead Letter Queue**: Encrypted with KMS key

### IAM Permissions (Least Privilege)

#### Audit Logging Policy
```yaml
- CloudWatch Logs: CreateLogStream, PutLogEvents, DescribeLogGroups
- DynamoDB: PutItem, GetItem, Query, UpdateItem (audit table only)
- KMS: Encrypt, Decrypt, GenerateDataKey (OpsAgent key only)
- SQS: SendMessage (dead letter queue only)
```

#### Diagnosis Tools Policy
```yaml
- CloudWatch: GetMetricStatistics, ListMetrics (read-only)
- EC2: DescribeInstances, DescribeTags (read-only)
- ECS/ALB: DescribeServices, DescribeLoadBalancers (read-only)
- Application Auto Scaling: DescribeScalingPolicies (read-only)
```

#### Remediation Tools Policy
```yaml
- EC2: RebootInstances, StartInstances, StopInstances
  Condition: ec2:ResourceTag/OpsAgentManaged = true
- ECS: UpdateService, RestartTask
  Condition: aws:ResourceTag/OpsAgentManaged = true
- Auto Scaling: SetDesiredCapacity, UpdateAutoScalingGroup
  Condition: aws:ResourceTag/OpsAgentManaged = true
```

#### LLM Provider Policy
```yaml
- Bedrock: InvokeModel (specific models only)
- SSM: GetParameter (OpsAgent parameters only)
- Secrets Manager: GetSecretValue (OpsAgent secrets only)
```

### Network Security
- **API Gateway**: TLS 1.2+ enforced, CORS configured
- **Lambda**: VPC deployment optional, restrictive security groups
- **VPC Endpoints**: Optional for enhanced security

## 🔍 Monitoring and Observability

### CloudWatch Logs
- **Lambda Function**: `/aws/lambda/opsagent-controller-<env>`
- **Audit Logs**: `/aws/lambda/opsagent-audit-<env>`
- **API Gateway**: `/aws/apigateway/opsagent-<env>`

### CloudWatch Metrics
- **Lambda**: Duration, Errors, Throttles, Concurrent Executions
- **API Gateway**: Count, Latency, 4XXError, 5XXError
- **DynamoDB**: ConsumedReadCapacityUnits, ConsumedWriteCapacityUnits

### DynamoDB Audit Table
```yaml
Table Name: opsagent-audit-<environment>
Primary Key: 
  - correlationId (Hash)
  - timestamp (Range)
Global Secondary Index:
  - UserIdIndex: userId (Hash), timestamp (Range)
TTL: Automatic cleanup of old records
```

### Custom Dashboards
```bash
# Create CloudWatch dashboard
aws cloudwatch put-dashboard \
    --dashboard-name "OpsAgent-Production" \
    --dashboard-body file://dashboard-config.json
```

## 🧪 Testing Strategy

### Test Types

#### Smoke Tests
- Health endpoint accessibility and response format
- Authentication with valid/invalid API keys
- Basic system status checks
- LLM provider and AWS tool access validation

#### Integration Tests
- End-to-end chat message processing
- Diagnosis tool execution
- Approval gate workflows
- Error handling and edge cases
- Audit logging verification

#### Load Tests
- Concurrent request handling
- Performance under load
- Rate limiting behavior
- Resource utilization monitoring

#### Security Tests
- Authentication bypass attempts
- Authorization boundary testing
- Input validation and sanitization
- Credential exposure checks

### Test Execution

```bash
# Full test suite
./test-deployment.sh production

# Specific test types
./test-deployment.sh staging --smoke-only
./test-deployment.sh sandbox --integration-only
./test-deployment.sh production --load-test

# Verbose output for debugging
./test-deployment.sh sandbox --verbose
```

## 🔄 Environment Management

### Environment Promotion

```bash
# Export configuration from staging
./configure-environment.sh export-config staging \
    --file staging-config.json

# Import to production
./configure-environment.sh import-config production \
    --file staging-config.json

# Deploy to production
./deploy-environment.sh production
```

### Configuration Validation

```bash
# Validate all environments
for env in sandbox staging production; do
    ./configure-environment.sh validate-config $env
done
```

### Backup and Recovery

```bash
# Create backup before changes
./configure-environment.sh export-config production \
    --file "backup-$(date +%Y%m%d).json"

# Store in S3 for safekeeping
aws s3 cp backup-*.json s3://your-backup-bucket/opsagent/
```

## 🚨 Troubleshooting

### Common Issues and Solutions

#### 1. Deployment Failures
```bash
# Check CloudFormation events
aws cloudformation describe-stack-events \
    --stack-name opsagent-controller-sandbox

# Validate template before deployment
./validate.sh
```

#### 2. Authentication Issues
```bash
# Check API key
aws ssm get-parameter \
    --name "/opsagent/sandbox/api-key" \
    --with-decryption

# Test authentication
curl -H "X-API-Key: $API_KEY" "$HEALTH_URL"
```

#### 3. LLM Provider Issues
```bash
# Check Bedrock model access
aws bedrock list-foundation-models --region us-east-1

# Verify IAM permissions
aws iam simulate-principal-policy \
    --policy-source-arn "$LAMBDA_ROLE_ARN" \
    --action-names bedrock:InvokeModel
```

#### 4. Performance Issues
```bash
# Check Lambda metrics
aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name Duration \
    --dimensions Name=FunctionName,Value=opsagent-controller-production \
    --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Average,Maximum
```

### Diagnostic Commands

```bash
# Health check
./configure-environment.sh validate-config production

# Log analysis
aws logs tail /aws/lambda/opsagent-controller-production --follow

# Resource utilization
aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name ConcurrentExecutions \
    --dimensions Name=FunctionName,Value=opsagent-controller-production
```

## 💰 Cost Optimization

### Cost Breakdown (Monthly Estimates)

| Component | Low Usage | Medium Usage | High Usage |
|-----------|-----------|--------------|------------|
| Lambda | $1-2 | $5-10 | $20-40 |
| API Gateway | $1-2 | $3-6 | $15-30 |
| DynamoDB | $1-2 | $2-5 | $10-20 |
| CloudWatch | $1-2 | $3-8 | $15-35 |
| KMS | $1 | $1 | $1-2 |
| **Total** | **$5-9** | **$14-30** | **$61-127** |

### Optimization Strategies

1. **Lambda Memory Tuning**
   ```bash
   # Monitor and adjust based on usage
   aws lambda get-function-configuration \
       --function-name opsagent-controller-production
   ```

2. **API Gateway Caching**
   ```yaml
   # Enable caching for read-heavy endpoints
   CachingEnabled: true
   CacheTtlInSeconds: 300
   ```

3. **DynamoDB Optimization**
   ```yaml
   # Use on-demand billing for variable workloads
   BillingMode: PAY_PER_REQUEST
   # Set TTL for automatic cleanup
   TimeToLiveSpecification:
     AttributeName: ttl
     Enabled: true
   ```

4. **CloudWatch Logs Retention**
   ```bash
   # Set appropriate retention periods
   aws logs put-retention-policy \
       --log-group-name /aws/lambda/opsagent-controller-production \
       --retention-in-days 30
   ```

## 📚 Additional Documentation

- **[Deployment Guide](../docs/deployment-guide.md)**: Comprehensive deployment instructions
- **[Credential Setup](../docs/credential-setup.md)**: Detailed credential management
- **[Teams Integration](../docs/teams-integration.md)**: Microsoft Teams setup guide
- **[Main README](../README.md)**: Application overview and development guide

## 🆘 Support and Maintenance

### Regular Maintenance Tasks

#### Weekly
- Review CloudWatch Logs for errors
- Check API Gateway metrics
- Validate backup procedures

#### Monthly
- Update dependencies and security patches
- Review IAM permissions
- Analyze cost optimization opportunities

#### Quarterly
- Security audit and penetration testing
- Performance optimization review
- Disaster recovery testing

### Getting Help

1. **Check Logs**: Start with CloudWatch Logs for error details
2. **Run Diagnostics**: Use the validation and testing scripts
3. **Review Documentation**: Consult the comprehensive guides
4. **Check AWS Service Health**: Verify AWS service status in your region

### Emergency Procedures

```bash
# Emergency shutdown
./cleanup.sh production --force

# Emergency rollback
aws cloudformation cancel-update-stack \
    --stack-name opsagent-controller-production

# Emergency credential rotation
./configure-environment.sh update-config production
```

This infrastructure setup provides a production-ready, secure, and maintainable deployment of the OpsAgent Controller with comprehensive tooling for management, testing, and troubleshooting.