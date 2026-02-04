# OpsAgent Controller Live Testing Guide

This guide provides comprehensive instructions for setting up and testing the OpsAgent Controller in a live AWS environment before production deployment.

## Overview

The live testing infrastructure creates a complete AWS environment with:
- Real AWS resources (EC2 instances, ECS services) for testing all 8 operations
- Comprehensive test suites covering all functionality
- Validation scripts for deployment readiness
- Automated cleanup procedures

## Prerequisites

### Required Tools
- AWS CLI v2 or later
- SAM CLI v1.50 or later
- Python 3.11 or later
- boto3, pytest, hypothesis Python packages

### AWS Credentials
You need AWS credentials with permissions for:
- CloudFormation (full access)
- Lambda (full access)
- API Gateway (full access)
- DynamoDB (full access)
- EC2 (full access for test resources)
- ECS (full access for test resources)
- IAM (role creation and policy attachment)
- CloudWatch Logs (full access)
- SSM Parameter Store (read/write)
- KMS (key creation and usage)

### Installation
```bash
# Install AWS CLI (if not already installed)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Install SAM CLI (if not already installed)
pip3 install aws-sam-cli

# Install Python dependencies
pip3 install boto3 pytest hypothesis requests
```

## Quick Start

### 1. Configure AWS Credentials
```bash
# Set your AWS credentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-west-2"

# Or use AWS CLI configure
aws configure
```

### 2. Run Complete Setup and Testing
```bash
# Navigate to the project directory
cd ops-agent-controller

# Run the complete setup and test process
./setup-and-test-live-environment.sh
```

This single command will:
- Set up the complete live testing infrastructure
- Deploy all AWS resources
- Run comprehensive tests
- Generate detailed reports
- Provide cleanup instructions

## Manual Step-by-Step Process

If you prefer to run each step manually or need to troubleshoot:

### Step 1: Infrastructure Setup
```bash
# Run the live testing setup script
./infrastructure/live-testing-setup.sh
```

This script will:
- Check prerequisites and install missing tools
- Create test resources (EC2 instances, ECS cluster)
- Deploy the OpsAgent Controller infrastructure
- Configure environment variables
- Run initial validation

### Step 2: Run Live Tests
```bash
# Load the environment configuration
source .env.test

# Run comprehensive live tests
./infrastructure/run-live-tests.sh
```

### Step 3: Validate Environment
```bash
# Run detailed environment validation
python3 ./infrastructure/validate-live-environment.py
```

### Step 4: Review Results
```bash
# Check test reports
ls -la *_report_*.json

# View the latest test report
cat $(ls -t live_test_report_*.json | head -1) | jq '.'

# View the latest validation report
cat $(ls -t validation_report_*.json | head -1) | jq '.'
```

## Test Coverage

### Infrastructure Tests
- ✅ CloudFormation stack deployment and status
- ✅ Lambda function configuration and health
- ✅ DynamoDB table creation and accessibility
- ✅ API Gateway endpoint availability
- ✅ CloudWatch Logs configuration
- ✅ SSM Parameter Store setup
- ✅ KMS key creation and permissions

### Functional Tests
- ✅ Health endpoint validation
- ✅ All 8 plugin operations:
  - **Diagnostic Operations** (no approval required):
    - `get_ec2_status` - EC2 instance health and metrics
    - `get_cloudwatch_metrics` - CloudWatch metrics retrieval
    - `describe_alb_target_health` - ALB/Target Group health
    - `search_cloudtrail_events` - CloudTrail event search
  - **Write Operations** (approval required):
    - `reboot_ec2` - EC2 instance reboot (tag-gated)
    - `scale_ecs_service` - ECS service scaling (tag-gated)
  - **Workflow Operations** (no approval, fully audited):
    - `create_incident_record` - Incident management
    - `post_summary_to_channel` - Teams notifications

### Security Tests
- ✅ Authentication and authorization validation
- ✅ API key validation
- ✅ Tag-based resource scoping (OpsAgentManaged=true)
- ✅ Approval workflow enforcement
- ✅ Audit logging verification

### Performance Tests
- ✅ Concurrent request handling
- ✅ Response time validation
- ✅ Error handling and recovery

## Environment Configuration

### Test Environment Variables
The setup creates a `.env.test` file with all necessary configuration:

```bash
# OpsAgent Controller Test Environment
ENVIRONMENT=test
AWS_REGION=us-west-2
EXECUTION_MODE=SANDBOX_LIVE
HEALTH_ENDPOINT=https://api-id.execute-api.us-west-2.amazonaws.com/test/health
CHAT_ENDPOINT=https://api-id.execute-api.us-west-2.amazonaws.com/test/chat
API_KEY=your-api-key
STACK_NAME=opsagent-controller-test
ADMIN_EMAIL=admin@oluofnotts.onmicrosoft.com

# Test Resource IDs
TEST_INSTANCE_1_ID=i-1234567890abcdef0
TEST_INSTANCE_2_ID=i-0987654321fedcba0
TEST_CLUSTER_NAME=opsagent-test-cluster-test
TEST_SERVICE_NAME=opsagent-test-service-test
```

### Execution Modes
- **SANDBOX_LIVE**: Safe testing mode with real AWS resources but limited scope
- **DRY_RUN**: Simulation mode that doesn't execute actual changes
- **LOCAL_MOCK**: Local testing with mocked AWS services

## Test Operations

### Diagnostic Operations (No Approval Required)

#### 1. Get EC2 Status
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "operation": "get_ec2_status",
    "parameters": {
      "instance_id": "'$TEST_INSTANCE_1_ID'"
    },
    "user_context": {
      "user_id": "test@oluofnotts.onmicrosoft.com"
    }
  }' \
  "$CHAT_ENDPOINT/operations/diagnostic"
```

#### 2. Get CloudWatch Metrics
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "operation": "get_cloudwatch_metrics",
    "parameters": {
      "namespace": "AWS/EC2",
      "metric_name": "CPUUtilization",
      "instance_id": "'$TEST_INSTANCE_1_ID'",
      "start_time": "2024-01-01T00:00:00Z",
      "end_time": "2024-01-01T01:00:00Z"
    },
    "user_context": {
      "user_id": "test@oluofnotts.onmicrosoft.com"
    }
  }' \
  "$CHAT_ENDPOINT/operations/diagnostic"
```

### Write Operations (Approval Required)

#### 1. Propose EC2 Reboot
```bash
# Step 1: Propose the action
APPROVAL_TOKEN=$(curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "operation": "reboot_ec2",
    "parameters": {
      "instance_id": "'$TEST_INSTANCE_1_ID'",
      "reason": "Live testing reboot"
    },
    "user_context": {
      "user_id": "test@oluofnotts.onmicrosoft.com"
    }
  }' \
  "$CHAT_ENDPOINT/operations/propose" | jq -r '.data.approval_token')

echo "Approval token: $APPROVAL_TOKEN"
```

#### 2. Approve and Execute
```bash
# Step 2: Approve and execute the action
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "approval_token": "'$APPROVAL_TOKEN'",
    "user_context": {
      "user_id": "test@oluofnotts.onmicrosoft.com"
    }
  }' \
  "$CHAT_ENDPOINT/operations/approve"
```

### Workflow Operations

#### 1. Create Incident Record
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "operation": "create_incident_record",
    "parameters": {
      "summary": "Live test incident",
      "severity": "low",
      "description": "This is a test incident created during live testing",
      "affected_resources": ["'$TEST_INSTANCE_1_ID'"]
    },
    "user_context": {
      "user_id": "test@oluofnotts.onmicrosoft.com"
    }
  }' \
  "$CHAT_ENDPOINT/operations/workflow"
```

## Troubleshooting

### Common Issues

#### 1. AWS Credentials Not Working
```bash
# Verify credentials
aws sts get-caller-identity

# Check permissions
aws iam get-user
```

#### 2. CloudFormation Stack Deployment Fails
```bash
# Check stack events
aws cloudformation describe-stack-events --stack-name opsagent-controller-test

# View stack resources
aws cloudformation describe-stack-resources --stack-name opsagent-controller-test
```

#### 3. Lambda Function Not Working
```bash
# Check function logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-controller-test \
  --start-time $(date -d '1 hour ago' +%s)000

# Test function directly
aws lambda invoke \
  --function-name opsagent-controller-test \
  --payload '{"httpMethod":"GET","path":"/health"}' \
  response.json
```

#### 4. API Gateway Issues
```bash
# Test health endpoint directly
curl -v "$HEALTH_ENDPOINT"

# Check API Gateway logs
aws logs filter-log-events \
  --log-group-name /aws/apigateway/opsagent-test \
  --start-time $(date -d '1 hour ago' +%s)000
```

#### 5. Test Resources Not Created
```bash
# Check test resources stack
aws cloudformation describe-stacks --stack-name opsagent-test-resources-test

# List EC2 instances with OpsAgentManaged tag
aws ec2 describe-instances \
  --filters "Name=tag:OpsAgentManaged,Values=true" \
  --query 'Reservations[].Instances[].{InstanceId:InstanceId,State:State.Name,Tags:Tags}'
```

### Debug Mode

Enable debug mode for more detailed logging:

```bash
# Set debug environment variables
export DEBUG=true
export LOG_LEVEL=DEBUG

# Run tests with verbose output
./infrastructure/run-live-tests.sh --verbose

# Run validation with verbose output
python3 ./infrastructure/validate-live-environment.py --verbose
```

### Log Analysis

```bash
# View recent Lambda logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-controller-test \
  --start-time $(date -d '10 minutes ago' +%s)000 \
  --query 'events[].message' \
  --output text

# View audit logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-audit-test \
  --start-time $(date -d '10 minutes ago' +%s)000 \
  --query 'events[].message' \
  --output text

# Check DynamoDB audit records
aws dynamodb scan \
  --table-name opsagent-audit-test \
  --limit 10 \
  --query 'Items[].{CorrelationId:correlationId.S,Operation:operation.S,Timestamp:timestamp.S}'
```

## Cleanup

### Automatic Cleanup
```bash
# Run the cleanup script
./infrastructure/cleanup.sh --environment test
```

### Manual Cleanup
```bash
# Delete OpsAgent Controller stack
aws cloudformation delete-stack --stack-name opsagent-controller-test

# Delete test resources stack
aws cloudformation delete-stack --stack-name opsagent-test-resources-test

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete --stack-name opsagent-controller-test
aws cloudformation wait stack-delete-complete --stack-name opsagent-test-resources-test

# Clean up local files
rm -f .env.test
rm -f *_report_*.json
rm -f /tmp/*_response.json
```

### Verify Cleanup
```bash
# Check that stacks are deleted
aws cloudformation list-stacks \
  --stack-status-filter DELETE_COMPLETE \
  --query 'StackSummaries[?contains(StackName, `opsagent`)].{Name:StackName,Status:StackStatus}'

# Check for any remaining resources
aws ec2 describe-instances \
  --filters "Name=tag:OpsAgentManaged,Values=true" \
  --query 'Reservations[].Instances[].{InstanceId:InstanceId,State:State.Name}'
```

## Production Readiness Checklist

Before deploying to production, ensure:

- [ ] All live tests pass (100% success rate)
- [ ] Environment validation passes
- [ ] Security configuration is correct
- [ ] Audit logging is working
- [ ] Performance meets requirements
- [ ] Error handling works correctly
- [ ] Cleanup procedures are tested
- [ ] Documentation is complete
- [ ] Team is trained on operations

## Next Steps

After successful live testing:

1. **Update Configuration**: Modify parameters for production environment
2. **Deploy to Production**: Use the same infrastructure templates
3. **Configure Monitoring**: Set up CloudWatch alarms and dashboards
4. **Set Up Amazon Q Business Plugin**: Use the generated OpenAPI schema
5. **Train Users**: Provide training on available operations
6. **Establish Procedures**: Create runbooks for common scenarios

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review CloudFormation events and Lambda logs
3. Run validation script for detailed diagnostics
4. Check the main README.md for additional documentation

## Security Considerations

### Test Environment Security
- Test environment uses `SANDBOX_LIVE` execution mode
- All write operations are tag-scoped to `OpsAgentManaged=true`
- API keys are stored in SSM Parameter Store
- All data is encrypted at rest using KMS
- Audit logging captures all operations

### Production Security
- Use dedicated AWS account for production
- Implement least privilege IAM policies
- Enable CloudTrail for additional auditing
- Set up monitoring and alerting
- Regular security reviews and updates

## Cost Optimization

### Test Environment Costs
- EC2 instances: t3.micro (minimal cost)
- DynamoDB: Pay-per-request (minimal cost for testing)
- Lambda: Pay-per-invocation (minimal cost)
- API Gateway: Pay-per-request (minimal cost)
- CloudWatch Logs: Pay-per-GB (minimal cost)

### Cost Management
- Clean up test resources after testing
- Use AWS Cost Explorer to monitor spending
- Set up billing alerts for unexpected costs
- Consider using AWS Free Tier resources where possible