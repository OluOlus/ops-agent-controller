# Amazon Q Business Integration

This document describes the Amazon Q Business integration with OpsAgent Controller, providing hybrid LLM capabilities that combine Amazon Q Business's knowledge base with OpsAgent's operational workflows.

## Overview

The Amazon Q Business integration enables a hybrid approach where:

- **Knowledge queries** → Routed to Amazon Q Business for comprehensive AWS documentation and best practices
- **Operational tasks** → Handled by OpsAgent with approval workflows and audit logging
- **Diagnostic tasks** → Enhanced with Amazon Q Business context while using OpsAgent's structured data tools
- **Automatic fallback** → Falls back to Bedrock if Amazon Q Business is unavailable

## Architecture

```
User Query → Intent Classification → Route to Appropriate Provider
                                  ↓
┌─────────────────┬─────────────────┬─────────────────┐
│   Knowledge     │   Diagnostic    │   Operational   │
│ (Amazon Q Bus.) │   (Hybrid)      │   (OpsAgent)    │
├─────────────────┼─────────────────┼─────────────────┤
│ • What is EC2?  │ • Show metrics  │ • Reboot server │
│ • Best practices│ • Describe inst │ • Scale service │
│ • How-to guides │ • Check status  │ • Deploy app    │
│ • Documentation │ • Get logs      │ • Delete resource│
└─────────────────┴─────────────────┴─────────────────┘
```

## Configuration

### Prerequisites

1. **Amazon Q Business Application**: You need an Amazon Q Business application configured in your AWS account
2. **IAM Permissions**: The Lambda execution role needs Amazon Q Business permissions
3. **Application ID**: The Amazon Q Business application ID from the Q Business console

### Environment Variables

The following environment variables configure Amazon Q Business integration:

```bash
# Required for Amazon Q Business integration
AMAZON_Q_APP_ID=your-amazon-q-business-application-id

# Optional configuration
AMAZON_Q_USER_ID=opsagent-user          # Default user ID for Q Business sessions
AMAZON_Q_SESSION_ID=session-123         # Optional session ID for continuity
```

### CloudFormation Parameters

When deploying via CloudFormation/SAM:

```yaml
Parameters:
  AmazonQAppId: your-amazon-q-application-id
  AmazonQUserId: opsagent-user
  AmazonQSessionId: ""  # Optional
```

## Intent Classification

The system automatically classifies user intents based on keywords:

### Operational Intent
**Keywords**: reboot, restart, stop, start, terminate, launch, create, delete, modify, update, scale, deploy, approve, deny, execute, run, perform, action

**Examples**:
- "reboot instance i-1234567890abcdef0"
- "scale the ECS service to 5 tasks"
- "delete the S3 bucket"

**Behavior**: Routes to OpsAgent with approval workflows

### Diagnostic Intent
**Keywords**: describe, list, show, get, check, status, health, metrics, logs, monitor, inspect, view, display

**Examples**:
- "show CPU metrics for i-1234567890abcdef0"
- "describe the EC2 instances"
- "check the status of the load balancer"

**Behavior**: Uses OpsAgent tools enhanced with Amazon Q context

### Knowledge Intent
**Keywords**: how, what, why, when, where, explain, help, documentation, guide, tutorial, example, best practice

**Examples**:
- "What is Amazon EC2?"
- "How do I configure CloudWatch alarms?"
- "Explain AWS IAM roles and policies"

**Behavior**: Routes directly to Amazon Q Developer

## Usage Examples

### Knowledge Queries (Amazon Q)

```bash
# Ask about AWS services
curl -X POST -H "Content-Type: application/json" -H "X-API-Key: your-key" \
  -d '{"userId":"user123","messageText":"What is Amazon ECS?","channel":"web"}' \
  https://your-api.execute-api.region.amazonaws.com/sandbox/chat

# Get best practices
curl -X POST -H "Content-Type: application/json" -H "X-API-Key: your-key" \
  -d '{"userId":"user123","messageText":"Best practices for EC2 security","channel":"web"}' \
  https://your-api.execute-api.region.amazonaws.com/sandbox/chat
```

### Diagnostic Tasks (Hybrid)

```bash
# Get instance information with Q context
curl -X POST -H "Content-Type: application/json" -H "X-API-Key: your-key" \
  -d '{"userId":"user123","messageText":"describe instance i-1234567890abcdef0","channel":"web"}' \
  https://your-api.execute-api.region.amazonaws.com/sandbox/chat

# Check CloudWatch metrics
curl -X POST -H "Content-Type: application/json" -H "X-API-Key: your-key" \
  -d '{"userId":"user123","messageText":"show CPU metrics for i-1234567890abcdef0","channel":"web"}' \
  https://your-api.execute-api.region.amazonaws.com/sandbox/chat
```

### Operational Tasks (OpsAgent)

```bash
# Reboot instance (requires approval)
curl -X POST -H "Content-Type: application/json" -H "X-API-Key: your-key" \
  -d '{"userId":"user123","messageText":"reboot instance i-1234567890abcdef0","channel":"web"}' \
  https://your-api.execute-api.region.amazonaws.com/sandbox/chat
```

## Teams Integration

The Amazon Q integration works seamlessly with Microsoft Teams:

### Knowledge Queries in Teams
```
User: What is Amazon Lambda?
Bot: Amazon Lambda is a serverless compute service that lets you run code without provisioning or managing servers...
```

### Operational Tasks in Teams
```
User: reboot instance i-1234567890abcdef0
Bot: I'll help you with that operational task. This requires approval due to the potential impact on your AWS resources.
     [Approval Card with Approve/Deny buttons]
```

## Deployment

### Using the Deployment Script

```bash
# Deploy with Amazon Q integration
./deploy-amazon-q-integration.sh

# Follow the prompts to configure Amazon Q
```

### Manual SAM Deployment

```bash
# Build the application
sam build

# Deploy with Amazon Q parameters
sam deploy \
  --parameter-overrides \
    "AmazonQAppId=your-app-id" \
    "AmazonQUserId=opsagent-user"
```

### Verify Deployment

```bash
# Check system status
curl -H "X-API-Key: your-key" \
  https://your-api.execute-api.region.amazonaws.com/sandbox/health

# Look for Amazon Q configuration in the response
```

## IAM Permissions

The Lambda execution role needs these additional permissions for Amazon Q:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "qbusiness:ChatSync",
        "qbusiness:Chat",
        "qbusiness:GetApplication",
        "qbusiness:ListConversations"
      ],
      "Resource": [
        "arn:aws:qbusiness:region:account:application/your-app-id",
        "arn:aws:qbusiness:region:account:application/your-app-id/*"
      ]
    }
  ]
}
```

## Monitoring and Troubleshooting

### CloudWatch Logs

Monitor Amazon Q integration in CloudWatch Logs:

```bash
# View Lambda logs
aws logs tail /aws/lambda/opsagent-controller-sandbox --follow

# Look for Amazon Q specific log entries
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-controller-sandbox \
  --filter-pattern "Amazon Q"
```

### Common Issues

#### 1. Amazon Q Access Denied
```
Error: Access denied to Amazon Q Developer. Check permissions.
```
**Solution**: Verify IAM permissions and Amazon Q application configuration

#### 2. Application Not Found
```
Error: Amazon Q application not found. Check application ID.
```
**Solution**: Verify the `AMAZON_Q_APP_ID` environment variable

#### 3. Fallback to Bedrock
```
Warning: Amazon Q failed, falling back to Bedrock
```
**Solution**: Check Amazon Q service availability and permissions

### Health Check Response

When Amazon Q is configured, the health endpoint shows:

```json
{
  "status": "healthy",
  "system": {
    "llm_provider_type": "amazon_q_hybrid",
    "amazon_q_app_id": "your-app-id",
    "amazon_q_user_id": "opsagent-user",
    "hybrid_mode": "enabled"
  }
}
```

## Benefits

### Enhanced Knowledge Base
- Access to comprehensive AWS documentation
- Up-to-date best practices and recommendations
- Contextual help for AWS services

### Intelligent Routing
- Automatic intent classification
- Appropriate provider selection
- Seamless user experience

### Operational Safety
- Approval workflows for write operations
- Audit logging for all actions
- Fallback mechanisms for reliability

### Cost Optimization
- Knowledge queries don't consume Bedrock tokens
- Efficient routing reduces unnecessary API calls
- Hybrid approach optimizes for both cost and capability

## Migration from Bedrock-Only

Existing OpsAgent deployments can be upgraded to use Amazon Q:

1. **Deploy the integration**: Use the deployment script or manual SAM deployment
2. **Configure Amazon Q**: Set the application ID and user ID
3. **Test the integration**: Verify both knowledge and operational queries work
4. **Monitor performance**: Check logs and metrics for any issues

The integration is backward compatible - if Amazon Q is not configured, the system continues to use Bedrock for all queries.

## Security Considerations

### Data Privacy
- User queries to Amazon Q are processed according to AWS data privacy policies
- No sensitive operational data is sent to Amazon Q for knowledge queries
- Operational tasks remain within OpsAgent's secure approval workflows

### Access Control
- Amazon Q access is controlled via IAM permissions
- User authentication remains unchanged (Teams/API key)
- Audit logging captures all interactions

### Network Security
- All communication uses AWS internal networks
- No external API calls required
- Standard AWS encryption in transit and at rest

## Future Enhancements

### Planned Features
- **Session Management**: Persistent conversation context across interactions
- **Custom Knowledge Base**: Integration with organization-specific documentation
- **Advanced Routing**: Machine learning-based intent classification
- **Multi-Modal Support**: Support for images and documents in queries

### Integration Opportunities
- **AWS CodeWhisperer**: Code generation and review capabilities
- **Amazon Bedrock Agents**: Advanced reasoning and tool orchestration
- **AWS Systems Manager**: Enhanced operational automation

## Support

For issues with Amazon Q integration:

1. **Check the logs**: Review CloudWatch logs for error messages
2. **Verify configuration**: Ensure Amazon Q application ID and permissions are correct
3. **Test fallback**: Verify Bedrock fallback works when Amazon Q is unavailable
4. **Contact support**: Reach out to the platform team with specific error messages

## References

- [Amazon Q Developer Documentation](https://docs.aws.amazon.com/amazonq/)
- [Amazon Q Business API Reference](https://docs.aws.amazon.com/qbusiness/latest/APIReference/)
- [OpsAgent Controller Documentation](./README.md)
- [Teams Integration Guide](./teams-integration.md)