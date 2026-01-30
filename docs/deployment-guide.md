# OpsAgent Controller Deployment Guide

This comprehensive guide covers deploying the OpsAgent Controller infrastructure across different environments, from initial setup to production deployment.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Environment Setup](#environment-setup)
4. [Deployment Process](#deployment-process)
5. [Configuration Management](#configuration-management)
6. [Amazon Q Business Integration](#amazon-q-business-integration)
7. [Validation and Testing](#validation-and-testing)
8. [Troubleshooting](#troubleshooting)
9. [Maintenance](#maintenance)

## Prerequisites

### Required Tools

1. **AWS CLI v2.x**
   ```bash
   # Install AWS CLI
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip
   sudo ./aws/install
   
   # Verify installation
   aws --version
   ```

2. **SAM CLI v1.x**
   ```bash
   # Install SAM CLI
   pip install aws-sam-cli
   
   # Verify installation
   sam --version
   ```

3. **Python 3.11**
   ```bash
   # Verify Python version
   python3 --version
   ```

4. **jq (for JSON processing)**
   ```bash
   # Install jq
   sudo apt-get install jq  # Ubuntu/Debian
   brew install jq          # macOS
   ```

### AWS Account Setup

1. **AWS Credentials**
   ```bash
   # Configure AWS credentials
   aws configure
   
   # Or use environment variables
   export AWS_ACCESS_KEY_ID=your-access-key
   export AWS_SECRET_ACCESS_KEY=your-secret-key
   export AWS_DEFAULT_REGION=us-east-1
   ```

2. **Required Permissions**
   
   Your AWS user/role needs the following permissions:
   - CloudFormation: Full access
   - Lambda: Full access
   - API Gateway: Full access
   - DynamoDB: Full access
   - IAM: Create/manage roles and policies
   - CloudWatch: Create log groups and metrics
   - SSM: Parameter Store access
   - SNS: Topic creation and publishing
   - KMS: Key creation and management
   - S3: Bucket creation for SAM deployments

3. **Service Limits**
   
   Verify your account has sufficient limits:
   - Lambda concurrent executions: 100+
   - API Gateway requests per second: 1000+
   - DynamoDB read/write capacity: Auto-scaling enabled
   - CloudWatch log retention: 90+ days

## Quick Start

For a rapid sandbox deployment:

```bash
# Clone the repository
git clone <repository-url>
cd ops-agent-controller

# Deploy to sandbox
./infrastructure/deploy.sh --environment sandbox

# Configure the deployment
./infrastructure/configure.sh init --environment sandbox

# Validate the deployment
./infrastructure/configure.sh validate --environment sandbox
```

## Environment Setup

### Sandbox Environment

**Purpose**: Development, testing, and experimentation

**Configuration**:
```bash
# Deploy sandbox environment
./infrastructure/deploy.sh \
  --environment sandbox \
  --execution-mode SANDBOX_LIVE \
  --test-resources true \
  --region us-east-1
```

**Characteristics**:
- Test resources created automatically
- Relaxed security policies
- Extended logging for debugging
- Lower rate limits
- Cost-optimized settings

### Staging Environment

**Purpose**: Pre-production validation and integration testing

**Configuration**:
```bash
# Deploy staging environment
./infrastructure/deploy.sh \
  --environment staging \
  --execution-mode SANDBOX_LIVE \
  --test-resources false \
  --region us-east-1
```

**Characteristics**:
- Production-like configuration
- No test resources
- Moderate security policies
- Performance monitoring enabled
- Limited user access

### Production Environment

**Purpose**: Live operational environment

**Configuration**:
```bash
# Deploy production environment (requires approval)
./infrastructure/deploy.sh \
  --environment production \
  --execution-mode SANDBOX_LIVE \
  --test-resources false \
  --encryption true \
  --region us-east-1
```

**Characteristics**:
- Maximum security settings
- Encryption at rest and in transit
- Comprehensive monitoring
- Strict access controls
- High availability configuration

## Deployment Process

### Step 1: Pre-Deployment Checklist

- [ ] AWS credentials configured
- [ ] Required tools installed
- [ ] Target environment determined
- [ ] Network configuration reviewed
- [ ] Security requirements understood
- [ ] Change management approval (production)

### Step 2: Infrastructure Deployment

#### Option A: Automated Deployment (Recommended)

```bash
# Use the deployment script
./infrastructure/deploy.sh --environment <environment>
```

#### Option B: Manual SAM Deployment

```bash
# Navigate to infrastructure directory
cd infrastructure

# Build the application
sam build

# Deploy with guided setup (first time)
sam deploy --guided

# Or deploy with parameters
sam deploy \
  --template-file .aws-sam/build/template.yaml \
  --stack-name opsagent-controller-sandbox \
  --s3-bucket your-deployment-bucket \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    Environment=sandbox \
    ExecutionMode=SANDBOX_LIVE \
    CreateTestResources=true
```

### Step 3: Post-Deployment Configuration

```bash
# Initialize configuration
./infrastructure/configure.sh init --environment <environment>

# Validate deployment
./infrastructure/configure.sh validate --environment <environment>

# View configuration
./infrastructure/configure.sh show --environment <environment>
```

### Step 4: Amazon Q Business Integration

1. **Retrieve API Configuration**
   ```bash
   # Get API endpoint
   aws cloudformation describe-stacks \
     --stack-name opsagent-controller-<environment> \
     --query 'Stacks[0].Outputs[?OutputKey==`PluginApiEndpointUrl`].OutputValue' \
     --output text
   
   # Get API key
   aws ssm get-parameter \
     --name "/opsagent/plugin-api-key-<environment>" \
     --with-decryption \
     --query 'Parameter.Value' \
     --output text
   ```

2. **Create Amazon Q Business Plugin**
   - Use `infrastructure/amazon-q-plugin-schema.yaml`
   - Configure with API endpoint and key
   - Follow `docs/amazon-q-plugin-setup.md`

### Step 5: Validation and Testing

```bash
# Run validation tests
python infrastructure/validate_plugin.py <api_endpoint> <api_key>

# Test health endpoint
curl -f https://<api_endpoint>/health

# Test diagnostic operation
curl -X POST https://<api_endpoint>/operations/diagnostic \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <api_key>" \
  -d '{
    "operation": "get_ec2_status",
    "parameters": {"instance_id": "i-1234567890abcdef0"},
    "user_context": {"user_id": "test@company.com"}
  }'
```

## Configuration Management

### Execution Modes

Change execution mode based on your needs:

```bash
# Set to dry-run mode for testing
./infrastructure/configure.sh set-mode --environment sandbox DRY_RUN

# Set to live mode for actual operations
./infrastructure/configure.sh set-mode --environment sandbox SANDBOX_LIVE

# Mock mode for development (not production)
./infrastructure/configure.sh set-mode --environment sandbox LOCAL_MOCK
```

### User Management

Update the user allow-list:

```bash
# Update allowed users
./infrastructure/configure.sh update-users --environment sandbox \
  "user1@company.com,user2@company.com,user3@company.com"

# View current users
aws ssm get-parameter \
  --name "/opsagent/allowed-users" \
  --query 'Parameter.Value' \
  --output text
```

### API Key Rotation

Rotate API keys regularly:

```bash
# Rotate API keys
./infrastructure/configure.sh rotate-keys --environment sandbox

# Get new API key for plugin update
aws ssm get-parameter \
  --name "/opsagent/plugin-api-key-sandbox" \
  --with-decryption \
  --query 'Parameter.Value' \
  --output text
```

## Amazon Q Business Integration

### Plugin Creation Process

1. **Prepare OpenAPI Schema**
   ```bash
   # Update schema with your API endpoint
   sed -i 's/${PLUGIN_API_ENDPOINT}/https:\/\/your-api-endpoint.com/g' \
     infrastructure/amazon-q-plugin-schema.yaml
   ```

2. **Create Plugin in Console**
   - Navigate to Amazon Q Business Console
   - Go to Plugins section
   - Create new custom plugin
   - Upload OpenAPI schema
   - Configure authentication with API key

3. **Test Plugin Integration**
   ```bash
   # Test through Amazon Q Business chat
   # Send message: "Get status of EC2 instance i-1234567890abcdef0"
   ```

### Plugin Configuration Examples

#### Basic Plugin Setup
```yaml
# Plugin configuration in Amazon Q Business
name: "OpsAgent Actions"
description: "Secure AWS operations for platform engineers"
authentication:
  type: "API_KEY"
  location: "HEADER"
  name: "X-API-Key"
  value: "<your-api-key>"
```

#### Advanced Plugin Settings
```yaml
# Advanced configuration
timeout: 30
retry_attempts: 2
rate_limiting:
  requests_per_minute: 60
  burst_capacity: 10
security:
  allowed_users: ["platform-team@company.com"]
  require_approval: false  # Handled by plugin internally
```

## Validation and Testing

### Automated Testing

Run the comprehensive test suite:

```bash
# Full validation suite
python infrastructure/validate_plugin.py \
  https://your-api-endpoint.com \
  your-api-key

# Specific test categories
python infrastructure/validate_plugin.py \
  --tests health,auth,diagnostic \
  https://your-api-endpoint.com \
  your-api-key
```

### Manual Testing Checklist

#### Health Check
- [ ] Health endpoint returns 200 OK
- [ ] All services show "ok" status
- [ ] Response time < 5 seconds

#### Authentication
- [ ] Requests without API key rejected (401)
- [ ] Invalid API key rejected (401)
- [ ] Unauthorized users rejected (403)

#### Diagnostic Operations
- [ ] get_ec2_status works correctly
- [ ] get_cloudwatch_metrics returns data
- [ ] describe_alb_target_health shows status
- [ ] search_cloudtrail_events finds events

#### Approval Workflow
- [ ] Propose action generates token
- [ ] Approve action executes successfully
- [ ] Token expiration enforced (15 minutes)
- [ ] Resource tagging validated

#### Workflow Operations
- [ ] Incident records created
- [ ] Channel notifications sent
- [ ] Audit logs generated

### Performance Testing

```bash
# Load testing with Apache Bench
ab -n 100 -c 10 -H "X-API-Key: your-api-key" \
  https://your-api-endpoint.com/health

# Monitor CloudWatch metrics during testing
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=opsagent-controller-sandbox \
  --start-time 2024-01-15T10:00:00Z \
  --end-time 2024-01-15T11:00:00Z \
  --period 300 \
  --statistics Average,Maximum
```

## Troubleshooting

### Common Issues

#### Deployment Failures

**Issue**: SAM build fails
```bash
# Solution: Check Python dependencies
pip install -r src/requirements.txt

# Verify Python version
python3 --version  # Should be 3.11+
```

**Issue**: CloudFormation stack creation fails
```bash
# Check stack events
aws cloudformation describe-stack-events \
  --stack-name opsagent-controller-sandbox

# Common causes:
# - Insufficient IAM permissions
# - Resource limits exceeded
# - Invalid parameter values
```

#### Runtime Issues

**Issue**: Lambda function timeouts
```bash
# Check CloudWatch logs
aws logs tail /aws/lambda/opsagent-controller-sandbox --follow

# Increase memory/timeout if needed
aws lambda update-function-configuration \
  --function-name opsagent-controller-sandbox \
  --memory-size 1024 \
  --timeout 60
```

**Issue**: API Gateway 5xx errors
```bash
# Check API Gateway logs
aws logs tail /aws/apigateway/opsagent-sandbox --follow

# Common causes:
# - Lambda function errors
# - Integration configuration issues
# - Rate limiting
```

#### Authentication Issues

**Issue**: API key not working
```bash
# Verify API key exists
aws ssm get-parameter --name "/opsagent/plugin-api-key-sandbox"

# Check API Gateway usage plan
aws apigateway get-usage-plans
```

**Issue**: User authorization failures
```bash
# Check user allow-list
aws ssm get-parameter --name "/opsagent/allowed-users"

# Verify user email format
# Must match exactly with Amazon Q Business user ID
```

### Debug Mode

Enable debug logging:

```bash
# Update Lambda environment variables
aws lambda update-function-configuration \
  --function-name opsagent-controller-sandbox \
  --environment Variables='{
    "EXECUTION_MODE": "SANDBOX_LIVE",
    "LOG_LEVEL": "DEBUG",
    "ENVIRONMENT": "sandbox"
  }'
```

### Support Resources

- **CloudWatch Logs**: `/aws/lambda/opsagent-controller-<environment>`
- **API Gateway Logs**: `/aws/apigateway/opsagent-<environment>`
- **DynamoDB Audit Table**: `opsagent-audit-<environment>`
- **SNS Topic**: `opsagent-notifications-<environment>`

## Maintenance

### Regular Tasks

#### Weekly
- [ ] Review CloudWatch metrics and alarms
- [ ] Check audit logs for anomalies
- [ ] Verify backup integrity
- [ ] Update user access if needed

#### Monthly
- [ ] Rotate API keys
- [ ] Review and update user allow-lists
- [ ] Check for AWS service updates
- [ ] Performance optimization review

#### Quarterly
- [ ] Security review and penetration testing
- [ ] Disaster recovery testing
- [ ] Cost optimization review
- [ ] Documentation updates

### Monitoring Setup

```bash
# Create CloudWatch alarms
aws cloudwatch put-metric-alarm \
  --alarm-name "OpsAgent-HighErrorRate" \
  --alarm-description "High error rate in OpsAgent Controller" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=opsagent-controller-sandbox \
  --evaluation-periods 2

# Set up SNS notifications
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789012:opsagent-notifications-sandbox \
  --protocol email \
  --notification-endpoint platform-team@company.com
```

### Backup and Recovery

```bash
# Backup configuration
./infrastructure/configure.sh backup --environment production

# Export CloudFormation template
aws cloudformation get-template \
  --stack-name opsagent-controller-production \
  --template-stage Processed > backup/template-$(date +%Y%m%d).json

# Backup DynamoDB tables
aws dynamodb create-backup \
  --table-name opsagent-audit-production \
  --backup-name opsagent-audit-backup-$(date +%Y%m%d)
```

### Updates and Upgrades

```bash
# Update to new version
git pull origin main

# Deploy updates
./infrastructure/deploy.sh --environment sandbox

# Validate updates
./infrastructure/configure.sh validate --environment sandbox

# Promote to production (after testing)
./infrastructure/deploy.sh --environment production
```

## Security Best Practices

### Access Control
- Use least-privilege IAM policies
- Regularly review user access
- Enable MFA for administrative access
- Implement IP restrictions where possible

### Data Protection
- Enable encryption at rest and in transit
- Rotate keys regularly
- Sanitize logs to prevent data leakage
- Implement data retention policies

### Monitoring
- Enable CloudTrail for API calls
- Monitor for unusual access patterns
- Set up alerts for security events
- Regular security assessments

### Compliance
- Maintain audit trails for 90+ days
- Document all configuration changes
- Regular compliance reviews
- Incident response procedures

This deployment guide provides comprehensive coverage of deploying and maintaining the OpsAgent Controller across different environments. Follow the appropriate sections based on your deployment needs and environment requirements.