# Amazon Q Business Plugin Setup Guide

This guide walks you through setting up the OpsAgent Actions plugin in Amazon Q Business console.

## Prerequisites

1. **Deployed OpsAgent Infrastructure**: Complete SAM deployment with API Gateway endpoint
2. **Amazon Q Business Application**: Existing Amazon Q Business application in your AWS account
3. **API Key**: Retrieved from SSM Parameter Store after deployment
4. **Permissions**: Admin access to Amazon Q Business console

## Step 1: Retrieve Plugin Configuration

After deploying the OpsAgent infrastructure, gather the required configuration:

### 1.1 Get API Endpoint URL

From your SAM deployment outputs:
```bash
# Get the plugin API endpoint
aws cloudformation describe-stacks \
  --stack-name opsagent-controller-sandbox \
  --query 'Stacks[0].Outputs[?OutputKey==`PluginApiEndpointUrl`].OutputValue' \
  --output text
```

Expected format: `https://abc123def456.execute-api.us-east-1.amazonaws.com/sandbox`

### 1.2 Get API Key

Retrieve the API key from SSM Parameter Store:
```bash
# Get the plugin API key
aws ssm get-parameter \
  --name "/opsagent/plugin-api-key-sandbox" \
  --with-decryption \
  --query 'Parameter.Value' \
  --output text
```

### 1.3 Prepare OpenAPI Schema

Use the provided schema file:
- **File**: `infrastructure/amazon-q-plugin-schema.yaml`
- **Update**: Replace `${PLUGIN_API_ENDPOINT}` with your actual API endpoint URL

## Step 2: Create Plugin in Amazon Q Business Console

### 2.1 Access Amazon Q Business Console

1. Navigate to [Amazon Q Business Console](https://console.aws.amazon.com/amazonq/business/)
2. Select your Amazon Q Business application
3. Go to **Plugins** section in the left navigation

### 2.2 Create New Plugin

1. Click **Create plugin**
2. Choose **Custom plugin**
3. Fill in the plugin details:

#### Basic Information
- **Plugin name**: `OpsAgent Actions`
- **Description**: `Secure AWS operations for platform engineers`
- **Plugin type**: `Custom plugin`

#### API Configuration
- **API schema source**: `Upload file`
- **Upload file**: Select `infrastructure/amazon-q-plugin-schema.yaml`
- **Base URL**: Your API endpoint URL (from Step 1.1)

#### Authentication
- **Authentication type**: `API Key`
- **API Key location**: `Header`
- **API Key name**: `X-API-Key`
- **API Key value**: Your API key (from Step 1.2)

### 2.3 Configure Plugin Settings

#### Security Settings
- **Enable plugin**: `Yes`
- **Require approval**: `No` (approval is handled internally by the plugin)
- **Allowed users**: Configure based on your organization's needs

#### Advanced Settings
- **Timeout**: `30 seconds`
- **Retry attempts**: `2`
- **Rate limiting**: Use default settings

## Step 3: Test Plugin Integration

### 3.1 Health Check Test

Test the plugin connection:
1. In Amazon Q Business console, go to **Plugins** → **OpsAgent Actions**
2. Click **Test connection**
3. Verify the health endpoint returns `200 OK`

### 3.2 Basic Operation Test

Test a diagnostic operation:
1. Open Amazon Q Business chat interface
2. Send a message: `"Get status of EC2 instance i-1234567890abcdef0"`
3. Amazon Q Business should invoke the plugin and return results

### 3.3 Approval Workflow Test

Test the approval workflow:
1. Send: `"Reboot EC2 instance i-1234567890abcdef0 due to high CPU"`
2. Plugin should return approval token and instructions
3. Send: `"Approve action with token approve-abc123def456"`
4. Plugin should execute the action (or simulate in DRY_RUN mode)

## Step 4: Environment-Specific Configuration

### 4.1 Sandbox Environment

For sandbox/testing environments:
- **Execution Mode**: `SANDBOX_LIVE` or `DRY_RUN`
- **Resource Tagging**: Ensure test resources have `OpsAgentManaged=true` tag
- **User Allow-list**: Configure in SSM Parameter `/opsagent/allowed-users`

### 4.2 Production Environment

For production environments:
- **Execution Mode**: `SANDBOX_LIVE` (never `LOCAL_MOCK`)
- **Resource Tagging**: Strict enforcement of `OpsAgentManaged=true` tag
- **User Allow-list**: Restricted to authorized platform engineers
- **Monitoring**: Enable CloudWatch alarms for plugin usage

## Step 5: User Training and Documentation

### 5.1 User Guide

Create user documentation covering:
- Available operations and their purposes
- Approval workflow for write operations
- Safety guidelines and best practices
- Troubleshooting common issues

### 5.2 Example Commands

Provide users with example commands:

#### Diagnostic Operations
```
"Get EC2 status for instance i-1234567890abcdef0"
"Show CloudWatch metrics for instance i-1234567890abcdef0 over last hour"
"Check ALB target health for arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456"
"Search CloudTrail events for RunInstances in last 24 hours"
```

#### Write Operations (Approval Required)
```
"Reboot EC2 instance i-1234567890abcdef0 due to high CPU utilization"
"Scale ECS service web-service in production-cluster to 5 tasks for increased traffic"
```

#### Workflow Operations
```
"Create incident record for high CPU utilization with medium severity"
"Post summary to channel: Resolved high CPU issue on production instances"
```

## Step 6: Monitoring and Maintenance

### 6.1 Plugin Monitoring

Monitor plugin usage through:
- **CloudWatch Logs**: `/aws/lambda/opsagent-controller-sandbox`
- **DynamoDB Audit Table**: `opsagent-audit-sandbox`
- **API Gateway Metrics**: Request count, latency, error rates

### 6.2 Regular Maintenance

- **API Key Rotation**: Rotate API keys quarterly
- **User Access Review**: Review allowed users monthly
- **Resource Tag Audit**: Ensure proper tagging of managed resources
- **Plugin Updates**: Update plugin schema when new operations are added

## Troubleshooting

### Common Issues

#### Plugin Connection Failed
- **Cause**: Incorrect API endpoint or API key
- **Solution**: Verify endpoint URL and API key from deployment outputs

#### Authentication Error
- **Cause**: Invalid or expired API key
- **Solution**: Regenerate API key and update plugin configuration

#### Operation Not Found
- **Cause**: Plugin schema mismatch or outdated schema
- **Solution**: Update plugin with latest OpenAPI schema

#### Resource Not Tagged
- **Cause**: Target resource missing `OpsAgentManaged=true` tag
- **Solution**: Add required tag to resource or use different resource

#### Token Expired
- **Cause**: Approval token expired (15-minute limit)
- **Solution**: Generate new approval token by re-proposing the action

### Support Contacts

- **Platform Team**: platform-team@company.com
- **Documentation**: https://docs.opsagent.company.com
- **Issue Tracking**: https://github.com/company/opsagent-controller/issues

## Security Considerations

### Best Practices

1. **Least Privilege**: Only grant plugin access to necessary users
2. **Resource Tagging**: Strictly enforce `OpsAgentManaged=true` tagging
3. **Audit Monitoring**: Regularly review audit logs for suspicious activity
4. **API Key Security**: Store API keys securely and rotate regularly
5. **Network Security**: Use VPC endpoints if possible for internal traffic

### Compliance

- **Audit Trail**: All operations logged with correlation IDs
- **Data Retention**: Audit logs retained for 90 days minimum
- **Access Control**: User authorization via allow-lists
- **Encryption**: All data encrypted in transit and at rest

## Advanced Configuration

### Custom Execution Modes

Configure different execution modes for different environments:

```bash
# Set execution mode via environment variable
aws lambda update-function-configuration \
  --function-name opsagent-controller-sandbox \
  --environment Variables='{
    "EXECUTION_MODE": "DRY_RUN",
    "ENVIRONMENT": "sandbox"
  }'
```

### Integration with Other Tools

- **PagerDuty**: Configure SNS topic for incident notifications
- **Slack**: Set up webhook URLs for channel notifications
- **Monitoring**: Integrate with existing monitoring dashboards

This completes the Amazon Q Business plugin setup. The plugin should now be available for use within your Amazon Q Business application.