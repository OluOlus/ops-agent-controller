# OpsAgent Controller Troubleshooting Guide

This guide provides solutions for common issues encountered during deployment, configuration, and operation of the OpsAgent Controller.

## Table of Contents

1. [Deployment Issues](#deployment-issues)
2. [Runtime Issues](#runtime-issues)
3. [Authentication Problems](#authentication-problems)
4. [Amazon Q Business Integration Issues](#amazon-q-business-integration-issues)
5. [Performance Issues](#performance-issues)
6. [Monitoring and Logging](#monitoring-and-logging)
7. [Emergency Procedures](#emergency-procedures)

## Deployment Issues

### SAM Build Failures

#### Issue: Python Dependencies Not Found
```
Error: Unable to import module 'main': No module named 'boto3'
```

**Cause**: Missing Python dependencies or incorrect Python version

**Solution**:
```bash
# Verify Python version (must be 3.11)
python3 --version

# Install dependencies locally for testing
cd src/
pip install -r requirements.txt

# Ensure requirements.txt is complete
cat requirements.txt
```

**Prevention**: Always test locally before deployment

#### Issue: SAM Template Validation Errors
```
Error: Template format error: Unresolved resource dependencies
```

**Cause**: Circular dependencies or missing resource references

**Solution**:
```bash
# Validate template syntax
sam validate --template template.yaml

# Check for circular dependencies
aws cloudformation validate-template --template-body file://template.yaml

# Common fixes:
# - Check DependsOn attributes
# - Verify resource names match references
# - Ensure all required parameters are provided
```

### CloudFormation Stack Failures

#### Issue: Insufficient IAM Permissions
```
User: arn:aws:iam::123456789012:user/deployer is not authorized to perform: iam:CreateRole
```

**Cause**: Deployment user lacks required permissions

**Solution**:
```bash
# Check current permissions
aws sts get-caller-identity

# Required permissions for deployment:
# - CloudFormation: Full access
# - IAM: CreateRole, AttachRolePolicy, CreatePolicy
# - Lambda: Full access
# - API Gateway: Full access
# - DynamoDB: Full access
# - CloudWatch: CreateLogGroup, PutMetricAlarm
# - SSM: PutParameter, GetParameter
# - KMS: CreateKey, CreateAlias

# Create deployment policy (admin should do this)
aws iam attach-user-policy \
  --user-name deployer \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
```

#### Issue: Resource Limits Exceeded
```
Error: Cannot exceed quota for PoliciesPerRole: 10
```

**Cause**: AWS service limits reached

**Solution**:
```bash
# Check current limits
aws service-quotas get-service-quota \
  --service-code iam \
  --quota-code L-0DA4ABF3

# Request limit increase if needed
aws service-quotas request-service-quota-increase \
  --service-code iam \
  --quota-code L-0DA4ABF3 \
  --desired-value 20

# Temporary workaround: Consolidate IAM policies
# Combine multiple policies into fewer, larger policies
```

#### Issue: Stack Rollback Due to Resource Creation Failure
```
Error: Resource creation cancelled, rollback initiated
```

**Cause**: Various resource-specific issues

**Solution**:
```bash
# Check stack events for specific error
aws cloudformation describe-stack-events \
  --stack-name opsagent-controller-sandbox \
  --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`]'

# Common causes and solutions:
# 1. VPC/Subnet not found: Update template with correct IDs
# 2. KMS key permissions: Check key policy
# 3. Lambda deployment package too large: Optimize dependencies
# 4. DynamoDB table already exists: Use different table name
```

### S3 Deployment Bucket Issues

#### Issue: Bucket Access Denied
```
Error: Unable to upload artifact. Access Denied
```

**Cause**: Insufficient S3 permissions or bucket policy

**Solution**:
```bash
# Check bucket exists and is accessible
aws s3 ls s3://your-deployment-bucket

# Create bucket if needed
aws s3 mb s3://opsagent-deployments-sandbox-$(aws sts get-caller-identity --query Account --output text)

# Set bucket policy for deployment
aws s3api put-bucket-policy --bucket your-deployment-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:user/deployer"},
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::your-deployment-bucket/*"
    }
  ]
}'
```

## Runtime Issues

### Lambda Function Errors

#### Issue: Function Timeout
```
Task timed out after 30.00 seconds
```

**Cause**: Function execution exceeds configured timeout

**Solution**:
```bash
# Check CloudWatch logs for slow operations
aws logs tail /aws/lambda/opsagent-controller-sandbox --follow

# Increase timeout (max 15 minutes)
aws lambda update-function-configuration \
  --function-name opsagent-controller-sandbox \
  --timeout 60

# Optimize code:
# - Add connection pooling for AWS clients
# - Implement caching for repeated calls
# - Use async operations where possible
```

#### Issue: Memory Limit Exceeded
```
Runtime.OutOfMemoryError: Memory limit exceeded
```

**Cause**: Function uses more memory than allocated

**Solution**:
```bash
# Check memory usage in CloudWatch
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name MemoryUtilization \
  --dimensions Name=FunctionName,Value=opsagent-controller-sandbox \
  --start-time 2024-01-15T10:00:00Z \
  --end-time 2024-01-15T11:00:00Z \
  --period 300 \
  --statistics Maximum

# Increase memory allocation
aws lambda update-function-configuration \
  --function-name opsagent-controller-sandbox \
  --memory-size 1024

# Memory optimization tips:
# - Use generators instead of lists for large datasets
# - Clear variables after use
# - Avoid loading large files into memory
```

#### Issue: Cold Start Performance
```
Duration: 5000ms (init: 3000ms)
```

**Cause**: Lambda cold starts causing slow response times

**Solution**:
```bash
# Enable provisioned concurrency for critical functions
aws lambda put-provisioned-concurrency-config \
  --function-name opsagent-controller-sandbox \
  --qualifier $LATEST \
  --provisioned-concurrency-config ProvisionedConcurrencyUnits=2

# Optimize cold start:
# - Minimize import statements
# - Initialize AWS clients outside handler
# - Use Lambda layers for common dependencies
# - Consider using Lambda SnapStart (Java only)
```

### API Gateway Issues

#### Issue: 502 Bad Gateway
```
{"message": "Internal server error"}
```

**Cause**: Lambda function error or integration misconfiguration

**Solution**:
```bash
# Check Lambda function logs
aws logs tail /aws/lambda/opsagent-controller-sandbox --follow

# Check API Gateway integration
aws apigateway get-integration \
  --rest-api-id YOUR_API_ID \
  --resource-id YOUR_RESOURCE_ID \
  --http-method POST

# Common fixes:
# - Verify Lambda function permissions
# - Check integration request/response mapping
# - Ensure Lambda function returns proper response format
```

#### Issue: 429 Too Many Requests
```
{"message": "Too Many Requests"}
```

**Cause**: Rate limiting or throttling

**Solution**:
```bash
# Check usage plan limits
aws apigateway get-usage-plans

# Increase rate limits if needed
aws apigateway update-usage-plan \
  --usage-plan-id YOUR_USAGE_PLAN_ID \
  --patch-ops op=replace,path=/throttle/rateLimit,value=1000

# Implement client-side retry with exponential backoff
# Monitor CloudWatch metrics for throttling patterns
```

### DynamoDB Issues

#### Issue: ProvisionedThroughputExceededException
```
Request rate is too high. Please retry after some time
```

**Cause**: Read/write capacity exceeded

**Solution**:
```bash
# Check table metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/DynamoDB \
  --metric-name ConsumedReadCapacityUnits \
  --dimensions Name=TableName,Value=opsagent-audit-sandbox \
  --start-time 2024-01-15T10:00:00Z \
  --end-time 2024-01-15T11:00:00Z \
  --period 300 \
  --statistics Sum

# Enable auto-scaling (if not already enabled)
aws application-autoscaling register-scalable-target \
  --service-namespace dynamodb \
  --resource-id table/opsagent-audit-sandbox \
  --scalable-dimension dynamodb:table:ReadCapacityUnits \
  --min-capacity 5 \
  --max-capacity 100

# Optimize queries:
# - Use batch operations
# - Implement exponential backoff
# - Consider using DynamoDB Accelerator (DAX)
```

## Authentication Problems

### API Key Issues

#### Issue: Invalid API Key
```
{"message": "Forbidden"}
```

**Cause**: API key not configured or incorrect

**Solution**:
```bash
# Check if API key parameter exists
aws ssm get-parameter --name "/opsagent/plugin-api-key-sandbox"

# Regenerate API key if needed
./infrastructure/configure.sh rotate-keys --environment sandbox

# Verify API key in Amazon Q Business plugin configuration
# Ensure header name is exactly "X-API-Key"
```

#### Issue: API Key Not Found in Request
```
{"message": "Missing Authentication Token"}
```

**Cause**: API key not included in request headers

**Solution**:
```bash
# Test with correct header
curl -X POST https://your-api-endpoint.com/operations/diagnostic \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"operation":"get_ec2_status","parameters":{"instance_id":"i-123"},"user_context":{"user_id":"test@company.com"}}'

# Check Amazon Q Business plugin configuration:
# - Authentication type: API Key
# - Location: Header
# - Name: X-API-Key
# - Value: [your-api-key]
```

### User Authorization Issues

#### Issue: User Not Authorized
```
{"success": false, "error": {"code": "AUTHORIZATION_ERROR", "message": "User not authorized"}}
```

**Cause**: User not in allow-list

**Solution**:
```bash
# Check current allow-list
aws ssm get-parameter \
  --name "/opsagent/allowed-users" \
  --query 'Parameter.Value' \
  --output text

# Add user to allow-list
./infrastructure/configure.sh update-users --environment sandbox \
  "existing-user@company.com,new-user@company.com"

# Verify user ID format matches Amazon Q Business user ID exactly
# Common issues:
# - Case sensitivity
# - Extra spaces
# - Different email domains
```

## Amazon Q Business Integration Issues

### Plugin Creation Problems

#### Issue: OpenAPI Schema Validation Failed
```
Error: Invalid OpenAPI specification
```

**Cause**: Schema format issues or missing required fields

**Solution**:
```bash
# Validate OpenAPI schema
npx swagger-parser validate infrastructure/amazon-q-plugin-schema.yaml

# Common issues:
# - Missing required fields in schema
# - Invalid parameter types
# - Circular references
# - Incorrect server URL format

# Update schema with correct API endpoint
sed -i 's/${PLUGIN_API_ENDPOINT}/https:\/\/your-actual-endpoint.com/g' \
  infrastructure/amazon-q-plugin-schema.yaml
```

#### Issue: Plugin Not Responding
```
Plugin timeout after 30 seconds
```

**Cause**: API endpoint not accessible or slow response

**Solution**:
```bash
# Test API endpoint directly
curl -f https://your-api-endpoint.com/health

# Check API Gateway logs
aws logs tail /aws/apigateway/opsagent-sandbox --follow

# Common causes:
# - Lambda cold start (increase memory)
# - Network connectivity issues
# - API Gateway throttling
# - Lambda function errors
```

### Plugin Operation Issues

#### Issue: Operations Not Working in Amazon Q Business
```
I couldn't complete that action using the plugin
```

**Cause**: Various integration issues

**Solution**:
```bash
# Check plugin configuration in Amazon Q Business console
# Verify:
# - Plugin is enabled
# - API key is correct
# - Base URL is correct
# - Operations are properly defined

# Test operations directly
curl -X POST https://your-api-endpoint.com/operations/diagnostic \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "operation": "get_ec2_status",
    "parameters": {"instance_id": "i-1234567890abcdef0"},
    "user_context": {"user_id": "test@company.com"}
  }'

# Check CloudWatch logs for errors
aws logs tail /aws/lambda/opsagent-controller-sandbox --follow
```

## Performance Issues

### Slow Response Times

#### Issue: High Latency
```
Average response time > 10 seconds
```

**Cause**: Various performance bottlenecks

**Solution**:
```bash
# Check CloudWatch metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=opsagent-controller-sandbox \
  --start-time 2024-01-15T10:00:00Z \
  --end-time 2024-01-15T11:00:00Z \
  --period 300 \
  --statistics Average,Maximum

# Performance optimization:
# 1. Increase Lambda memory (improves CPU)
aws lambda update-function-configuration \
  --function-name opsagent-controller-sandbox \
  --memory-size 1024

# 2. Enable connection pooling in code
# 3. Cache frequently accessed data
# 4. Use async operations
# 5. Optimize database queries
```

### High Error Rates

#### Issue: Frequent 5xx Errors
```
Error rate > 5%
```

**Cause**: System instability or resource constraints

**Solution**:
```bash
# Check error patterns in CloudWatch
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-controller-sandbox \
  --filter-pattern "ERROR" \
  --start-time 1642248000000

# Common causes and solutions:
# 1. AWS API throttling: Implement exponential backoff
# 2. Resource limits: Increase Lambda memory/timeout
# 3. Database issues: Check DynamoDB metrics
# 4. Network issues: Add retry logic
# 5. Code bugs: Review error logs and fix issues
```

## Monitoring and Logging

### CloudWatch Logs Issues

#### Issue: Logs Not Appearing
```
No log events found
```

**Cause**: Log group not created or permissions issue

**Solution**:
```bash
# Check if log group exists
aws logs describe-log-groups \
  --log-group-name-prefix /aws/lambda/opsagent-controller

# Create log group if missing
aws logs create-log-group \
  --log-group-name /aws/lambda/opsagent-controller-sandbox

# Check Lambda execution role permissions
aws iam get-role-policy \
  --role-name opsagent-execution-role \
  --policy-name CloudWatchLogsPolicy
```

#### Issue: Log Retention Not Working
```
Old logs not being deleted
```

**Cause**: Retention policy not set

**Solution**:
```bash
# Set log retention policy
aws logs put-retention-policy \
  --log-group-name /aws/lambda/opsagent-controller-sandbox \
  --retention-in-days 30

# Verify retention policy
aws logs describe-log-groups \
  --log-group-name-prefix /aws/lambda/opsagent-controller \
  --query 'logGroups[*].[logGroupName,retentionInDays]'
```

### Metrics and Alarms

#### Issue: CloudWatch Alarms Not Triggering
```
Alarm remains in INSUFFICIENT_DATA state
```

**Cause**: Metric not being published or incorrect configuration

**Solution**:
```bash
# Check if metrics are being published
aws cloudwatch list-metrics \
  --namespace AWS/Lambda \
  --dimensions Name=FunctionName,Value=opsagent-controller-sandbox

# Verify alarm configuration
aws cloudwatch describe-alarms \
  --alarm-names OpsAgent-HighErrorRate

# Test alarm manually
aws cloudwatch set-alarm-state \
  --alarm-name OpsAgent-HighErrorRate \
  --state-value ALARM \
  --state-reason "Testing alarm"
```

## Emergency Procedures

### Service Outage

#### Immediate Response
1. **Check System Status**
   ```bash
   # Check health endpoint
   curl -f https://your-api-endpoint.com/health
   
   # Check AWS service status
   # Visit: https://status.aws.amazon.com/
   ```

2. **Identify Scope**
   ```bash
   # Check error rates
   aws cloudwatch get-metric-statistics \
     --namespace AWS/Lambda \
     --metric-name Errors \
     --dimensions Name=FunctionName,Value=opsagent-controller-sandbox \
     --start-time $(date -d '1 hour ago' -u +%Y-%m-%dT%H:%M:%SZ) \
     --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
     --period 300 \
     --statistics Sum
   ```

3. **Emergency Rollback**
   ```bash
   # Rollback to previous version
   aws cloudformation cancel-update-stack \
     --stack-name opsagent-controller-sandbox
   
   # Or deploy previous version
   git checkout previous-working-commit
   ./infrastructure/deploy.sh --environment sandbox
   ```

### Data Recovery

#### DynamoDB Table Recovery
```bash
# List available backups
aws dynamodb list-backups \
  --table-name opsagent-audit-sandbox

# Restore from backup
aws dynamodb restore-table-from-backup \
  --target-table-name opsagent-audit-sandbox-restored \
  --backup-arn arn:aws:dynamodb:us-east-1:123456789012:table/opsagent-audit-sandbox/backup/01234567890123-abcdefgh
```

#### Configuration Recovery
```bash
# Restore from backup
./infrastructure/configure.sh restore --environment sandbox --backup-file backup-20240115.json

# Or reconfigure from scratch
./infrastructure/configure.sh init --environment sandbox
```

### Security Incident Response

#### Suspected Compromise
1. **Immediate Actions**
   ```bash
   # Rotate all API keys
   ./infrastructure/configure.sh rotate-keys --environment sandbox
   
   # Disable plugin temporarily
   aws lambda update-function-configuration \
     --function-name opsagent-controller-sandbox \
     --environment Variables='{"EXECUTION_MODE":"LOCAL_MOCK"}'
   ```

2. **Investigation**
   ```bash
   # Check audit logs for suspicious activity
   aws dynamodb scan \
     --table-name opsagent-audit-sandbox \
     --filter-expression "contains(#op, :suspicious)" \
     --expression-attribute-names '{"#op": "operation"}' \
     --expression-attribute-values '{":suspicious": {"S": "unauthorized"}}'
   
   # Review CloudTrail logs
   aws logs filter-log-events \
     --log-group-name CloudTrail/OpsAgentController \
     --start-time $(date -d '24 hours ago' +%s)000
   ```

3. **Recovery**
   ```bash
   # Update user allow-list (remove compromised users)
   ./infrastructure/configure.sh update-users --environment sandbox \
     "verified-user1@company.com,verified-user2@company.com"
   
   # Re-enable with new security measures
   aws lambda update-function-configuration \
     --function-name opsagent-controller-sandbox \
     --environment Variables='{"EXECUTION_MODE":"SANDBOX_LIVE"}'
   ```

## Getting Help

### Support Channels
- **Internal Documentation**: Check `docs/` directory
- **CloudWatch Logs**: Primary source for debugging
- **AWS Support**: For AWS service-specific issues
- **GitHub Issues**: For code-related problems

### Escalation Procedures
1. **Level 1**: Check this troubleshooting guide
2. **Level 2**: Review CloudWatch logs and metrics
3. **Level 3**: Contact platform team
4. **Level 4**: Engage AWS support for service issues

### Useful Commands for Support
```bash
# Collect diagnostic information
echo "=== System Information ===" > diagnostic-report.txt
aws sts get-caller-identity >> diagnostic-report.txt
echo "=== Stack Status ===" >> diagnostic-report.txt
aws cloudformation describe-stacks --stack-name opsagent-controller-sandbox >> diagnostic-report.txt
echo "=== Recent Errors ===" >> diagnostic-report.txt
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-controller-sandbox \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 hour ago' +%s)000 >> diagnostic-report.txt
```

This troubleshooting guide covers the most common issues you may encounter. For issues not covered here, collect diagnostic information and contact the appropriate support channel.