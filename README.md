# OpsAgent Controller

A serverless conversational Tier-1 Ops assistant that enables platform engineers to diagnose AWS incidents and perform controlled remediation actions via chat interfaces. Built with security-first design principles and comprehensive audit logging for production environments.

## Overview

The OpsAgent Controller is a **production-ready serverless system** that provides secure AWS operations through natural language interactions. It integrates with Amazon Q Business to provide a chat-based interface for platform engineers to perform diagnostic and remediation tasks with enterprise-grade security and compliance.

### Key Capabilities

**🔍 Diagnostic Operations** (No Approval Required):
- `get_ec2_status` - Get EC2 instance status and CloudWatch metrics
- `get_cloudwatch_metrics` - Retrieve CloudWatch metrics and alarms  
- `describe_alb_target_health` - Check ALB target group health
- `search_cloudtrail_events` - Search CloudTrail for specific events

**⚡ Write Operations** (Approval Required):
- `reboot_ec2` - Reboot EC2 instances (requires `OpsAgentManaged=true` tag)
- `scale_ecs_service` - Scale ECS services up/down

**📋 Workflow Operations** (Fully Audited):
- `create_incident_record` - Create incident records in DynamoDB
- `post_summary_to_channel` - Send notifications to Teams/Slack

### Architecture

**Serverless Design**: Built on AWS Lambda with API Gateway, DynamoDB, and CloudWatch
- **Lambda Function**: Python 3.11 runtime (1024MB memory, 30s timeout)
- **API Gateway**: RESTful API with authentication and rate limiting (500 req/min)
- **DynamoDB**: Audit logs (90 days) and incident records (7 years) 
- **CloudWatch**: Real-time logging and monitoring with alarms
- **Security**: KMS encryption, least-privilege IAM, resource tagging

### Security Features

- **Resource Tagging**: Only resources tagged with `OpsAgentManaged=true` can be modified
- **Approval Workflow**: All write operations require explicit approval with 15-minute token expiry
- **User Authentication**: Allow-list based user validation via SSM Parameter Store
- **Comprehensive Auditing**: Every action logged to CloudWatch and DynamoDB with correlation IDs
- **Least Privilege**: IAM roles with tag-based conditions and minimal permissions
- **Input Validation**: Parameter sanitization and injection prevention

## Quick Start

### Prerequisites

- **AWS Account**: With appropriate permissions (CloudFormation, Lambda, API Gateway, DynamoDB, IAM)
- **Python 3.11+**: Required runtime version
- **AWS CLI v2**: Configured with credentials (`aws configure`)
- **SAM CLI v1.x**: For serverless deployment (`pip install aws-sam-cli`)
- **Docker**: For local testing and container builds

### Development Setup

1. **Clone and setup environment**:
   ```bash
   git clone <repository>
   cd ops-agent-controller
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements-dev.txt
   ```

2. **Run tests**:
   ```bash
   pytest  # Full test suite (416 tests)
   pytest -m unit          # Unit tests only
   pytest -m integration   # Integration tests only
   pytest -m property      # Property-based tests only
   ```

3. **Build and test locally**:
   ```bash
   cd infrastructure
   sam build --use-container
   sam local start-api
   ```

4. **Test health endpoint**:
   ```bash
   curl http://localhost:3000/health
   ```

### Production Deployment

1. **Deploy infrastructure**:
   ```bash
   cd infrastructure
   sam build --use-container
   
   # Deploy to production
   sam deploy \
     --stack-name opsagent-controller-production \
     --parameter-overrides \
       Environment=production \
       ExecutionMode=SANDBOX_LIVE \
       CreateTestResources=false \
       EnableDynamoDBEncryption=true \
     --capabilities CAPABILITY_IAM
   ```

2. **Configure security**:
   ```bash
   # Set secure API key
   SECURE_API_KEY=$(openssl rand -base64 32)
   aws ssm put-parameter \
     --name "/opsagent/api-key" \
     --value "$SECURE_API_KEY" \
     --type "SecureString" \
     --overwrite
   
   # Configure user allow-list (replace with actual emails)
   aws ssm put-parameter \
     --name "/opsagent/allowed-users" \
     --value "senior-engineer@company.com,ops-lead@company.com" \
     --type "StringList" \
     --overwrite
   ```

3. **Tag AWS resources for OpsAgent management**:
   ```bash
   # Tag EC2 instances that OpsAgent can manage
   aws ec2 create-tags \
     --resources i-1234567890abcdef0 \
     --tags \
       Key=OpsAgentManaged,Value=true \
       Key=Environment,Value=production \
       Key=CriticalityLevel,Value=high
   ```

4. **Set up Amazon Q Business plugin**:
   ```bash
   # Get API endpoint and key
   API_ENDPOINT=$(aws cloudformation describe-stacks \
     --stack-name opsagent-controller-production \
     --query 'Stacks[0].Outputs[?OutputKey==`PluginApiEndpointUrl`].OutputValue' \
     --output text)
   
   PLUGIN_API_KEY=$(aws ssm get-parameter \
     --name "/opsagent/plugin-api-key-production" \
     --with-decryption \
     --query 'Parameter.Value' \
     --output text)
   
   echo "Plugin API Endpoint: $API_ENDPOINT"
   echo "Plugin API Key: $PLUGIN_API_KEY"
   ```

5. **Validate deployment**:
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

### Sandbox Deployment (Development/Testing)

```bash
# Quick sandbox deployment
./infrastructure/deploy.sh --environment sandbox

# Or use SAM directly
sam deploy --config-env sandbox
```

## Amazon Q Business Integration

OpsAgent integrates as a custom plugin in Amazon Q Business, providing conversational AWS operations through natural language:

### How It Works

```
User: "Reboot instance i-123 because it's unresponsive"
  ↓
Amazon Q Business Plugin → OpsAgent Controller
  ↓
1. Authenticate user against allow-list
2. Validate resource has OpsAgentManaged=true tag  
3. Create approval token (15-minute expiry)
4. User approves with token
5. Execute reboot operation
6. Log everything to CloudWatch + DynamoDB
7. Return success confirmation
```

### Plugin Configuration

1. **Create Plugin in Amazon Q Business Console**:
   - Navigate to Amazon Q Business Console → Applications → Plugins
   - Create custom plugin with OpenAPI schema (`infrastructure/openapi-schema.yaml`)
   - Configure API key authentication

2. **Plugin Settings**:
   ```yaml
   Name: "OpsAgent Actions - Production"
   Description: "Secure AWS operations for platform engineers"
   API Endpoint: https://your-api-endpoint.com/production
   Authentication: API Key (X-API-Key header)
   ```

### Usage Examples

**Diagnostic Operations** (No approval required):
```
"Show CPU metrics for instance i-1234567890abcdef0"
"Check ALB target health for my-load-balancer"
"Search CloudTrail for EC2 events in the last hour"
```

**Write Operations** (Approval workflow):
```
User: "Reboot instance i-1234567890abcdef0 due to high memory usage"
System: "Approval required. Token: approve-abc123 (expires in 15 minutes)"
User: "Approve with token approve-abc123"
System: "✅ Instance rebooted successfully"
```

**Workflow Operations** (Fully audited):
```
"Create incident record for database connectivity issue"
"Post summary to #ops-channel about the deployment"
```

### Configuration Variables

```bash
# Required for Amazon Q Business integration
AMAZON_Q_APP_ID=your-amazon-q-application-id
AMAZON_Q_USER_ID=opsagent-user
AMAZON_Q_SESSION_ID=optional-session-id

# LLM Configuration
LLM_PROVIDER=bedrock
BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0
```

See [Amazon Q Business Integration Guide](./docs/amazon-q-business-integration-guide.md) for detailed setup instructions.

## Project Structure

```
├── src/                           # Source code
│   ├── main.py                   # Main Lambda handler (1742 lines)
│   ├── models.py                 # Data models and validation
│   ├── tool_execution_engine.py  # AWS operations execution
│   ├── approval_gate.py          # Approval workflow management
│   ├── audit_logger.py           # CloudWatch + DynamoDB logging
│   ├── authentication.py         # User auth and authorization
│   ├── aws_diagnosis_tools.py    # Read-only AWS operations
│   ├── aws_remediation_tools.py  # Write AWS operations
│   ├── workflow_tools.py         # Incident and notification tools
│   ├── tool_guardrails.py        # Security controls and validation
│   ├── llm_provider.py           # Bedrock LLM integration
│   └── channel_adapters.py       # Teams/Slack/Web interfaces
├── tests/                         # Test files (416 tests total)
│   ├── test_main.py              # Main handler tests
│   ├── test_*                    # Component-specific tests
│   ├── test_properties.py        # Property-based tests
│   └── run_smoke_tests.py        # End-to-end validation
├── infrastructure/               # AWS SAM templates and deployment
│   ├── template.yaml             # CloudFormation template (1040 lines)
│   ├── openapi-schema.yaml       # API Gateway OpenAPI spec
│   ├── amazon-q-plugin-schema.yaml # Amazon Q Business plugin schema
│   ├── deploy.sh                 # Deployment automation
│   ├── configure.sh              # Configuration management
│   └── config/                   # Environment-specific configs
│       ├── production.yaml       # Production configuration
│       └── sandbox.yaml          # Development configuration
├── docs/                         # Documentation
│   ├── deployment-guide.md       # Comprehensive deployment guide
│   ├── amazon-q-business-integration-guide.md
│   ├── troubleshooting.md        # Common issues and solutions
│   └── plugin-sample-requests-responses.md
├── PRODUCTION_IMPLEMENTATION_GUIDE.md # Complete production guide
├── requirements.txt              # Production dependencies
├── requirements-dev.txt          # Development dependencies
├── pytest.ini                   # Pytest configuration
├── pyproject.toml               # Project configuration
└── README.md                    # This file
```

## Execution Modes

- **SANDBOX_LIVE**: Full execution on tagged resources (production mode)
  - All operations execute against real AWS resources
  - Resources must be tagged with `OpsAgentManaged=true`
  - Comprehensive audit logging enabled
  - Approval workflow enforced for write operations

Note: LOCAL_MOCK and DRY_RUN modes have been removed for security and simplicity. All development and testing should use SANDBOX_LIVE with properly tagged test resources.

## API Endpoints

### Core Endpoints
- `GET /health` - Health check with system status and component validation
- `POST /chat` - Chat message processing (legacy endpoint)
- `POST /plugin` - Amazon Q Business plugin requests

### Operation Endpoints  
- `POST /operations/diagnostic` - Diagnostic operations (no approval)
- `POST /operations/propose` - Propose write operations (generates approval token)
- `POST /operations/approve` - Approve and execute write operations
- `POST /operations/workflow` - Workflow operations (incident records, notifications)

### Authentication
- All endpoints except `/health` require API key authentication
- API keys managed via AWS API Gateway usage plans
- Rate limiting: 500 requests/minute, 1000 burst capacity

## Configuration

### Environment Variables

**Core Configuration**:
- `EXECUTION_MODE`: SANDBOX_LIVE (only supported mode)
- `ENVIRONMENT`: sandbox | staging | production
- `AWS_REGION`: AWS region for deployment (default: us-east-1)

**LLM Configuration**:
- `LLM_PROVIDER`: bedrock (default)
- `BEDROCK_MODEL_ID`: anthropic.claude-3-sonnet-20240229-v1:0 (default)

**Amazon Q Business Integration** (Optional):
- `AMAZON_Q_APP_ID`: Amazon Q Business application ID
- `AMAZON_Q_USER_ID`: User ID for Amazon Q sessions (default: opsagent-user)
- `AMAZON_Q_SESSION_ID`: Optional session ID for conversation continuity

**Security Configuration**:
- `API_KEY_PARAMETER`: SSM parameter name for API key (default: /opsagent/api-key)
- `USER_ALLOW_LIST_PARAMETER`: SSM parameter for allowed users (default: /opsagent/allowed-users)
- `PLUGIN_API_KEY_PARAMETER`: SSM parameter for plugin API key

**Infrastructure Configuration**:
- `AUDIT_TABLE_NAME`: DynamoDB table for audit logs
- `INCIDENT_TABLE_NAME`: DynamoDB table for incident records
- `CLOUDWATCH_LOG_GROUP`: CloudWatch log group name
- `NOTIFICATION_TOPIC_ARN`: SNS topic for notifications
- `KMS_KEY_ID`: KMS key for encryption

### Resource Tagging Requirements

All AWS resources that can be modified by OpsAgent **must** have these tags:

```yaml
Required Tags:
  - Key: "OpsAgentManaged"
    Value: "true"
  - Key: "Environment" 
    Value: "production" | "staging" | "sandbox"
  - Key: "CriticalityLevel"
    Value: "high" | "critical" | "medium" | "low"
```

**Example: Tag EC2 Instance**:
```bash
aws ec2 create-tags \
  --resources i-1234567890abcdef0 \
  --tags \
    Key=OpsAgentManaged,Value=true \
    Key=Environment,Value=production \
    Key=CriticalityLevel,Value=high \
    Key=Owner,Value=platform-team
```

### User Management

Users are managed via SSM Parameter Store allow-list:

```bash
# View current allowed users
aws ssm get-parameter \
  --name "/opsagent/allowed-users" \
  --query 'Parameter.Value' \
  --output text

# Update allowed users (comma-separated email addresses)
aws ssm put-parameter \
  --name "/opsagent/allowed-users" \
  --value "user1@company.com,user2@company.com,user3@company.com" \
  --type "StringList" \
  --overwrite
```

## Security

### Security Architecture

- **Least Privilege IAM**: Roles with minimal required permissions and tag-based conditions
- **Resource Scoping**: Only resources tagged with `OpsAgentManaged=true` can be modified
- **Approval Workflow**: All write operations require explicit approval with time-limited tokens
- **User Authentication**: Allow-list based validation via SSM Parameter Store
- **API Security**: API Gateway with API keys, usage plans, and rate limiting
- **Encryption**: KMS encryption for DynamoDB tables and CloudWatch Logs
- **Input Validation**: Parameter sanitization and injection prevention
- **Audit Logging**: Complete audit trail with correlation IDs for all operations

### IAM Permissions

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

### Approval Workflow

1. **Propose Action**: User requests write operation → System validates resource tags → Generates approval token
2. **Review**: User reviews action plan and risk assessment
3. **Approve**: User provides approval token → System validates token and executes operation
4. **Audit**: All steps logged with correlation IDs for compliance

### API Security

- **Authentication**: API keys required for all endpoints except health checks
- **Rate Limiting**: 500 requests/minute with 1000 burst capacity
- **CORS**: Configured for specific origins only (not wildcard)
- **TLS**: All communications encrypted with TLS 1.2+
- **Request Validation**: JSON schema validation and parameter sanitization

## Testing

### Test Suite Overview

The project includes comprehensive testing with **416 total tests**:
- **Unit Tests**: Component-level testing with mocked dependencies
- **Integration Tests**: End-to-end testing with real AWS services (requires infrastructure)
- **Property-Based Tests**: Formal verification using Hypothesis for correctness properties
- **Smoke Tests**: Production readiness validation

### Running Tests

**Full Test Suite**:
```bash
pytest  # All 416 tests
```

**Test Categories**:
```bash
pytest -m unit          # Unit tests only (fast, no AWS dependencies)
pytest -m integration   # Integration tests (requires deployed infrastructure)
pytest -m property      # Property-based tests (formal verification)
pytest -m smoke         # Smoke tests (production validation)
```

**Coverage Report**:
```bash
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

### Test Infrastructure Requirements

Integration tests require deployed AWS infrastructure:

```bash
# Deploy test infrastructure
cd infrastructure
sam deploy --config-env sandbox

# Run integration tests
pytest -m integration

# Clean up test resources
sam delete --stack-name opsagent-controller-sandbox
```

### Property-Based Testing

The system includes formal correctness properties validated with Hypothesis:

- **Authentication Properties**: User validation and authorization correctness
- **Approval Workflow Properties**: Token generation, validation, and expiry
- **Resource Tagging Properties**: Tag-based access control validation
- **Audit Logging Properties**: Complete audit trail verification

Example property test:
```python
@given(user_id=st.emails(), operation=st.sampled_from(['reboot_ec2', 'scale_ecs_service']))
def test_approval_workflow_properties(user_id, operation):
    """Property: All write operations require valid approval tokens"""
    # Test implementation validates approval workflow invariants
```

## Monitoring and Observability

### CloudWatch Integration

**Metrics Available**:
- Lambda function performance (duration, errors, invocations)
- API Gateway metrics (requests, latency, 4xx/5xx errors)
- DynamoDB performance (read/write capacity, throttles)
- Custom business metrics (operations by type, approval rates)

**Log Analysis**:
```bash
# View recent logs
aws logs tail /aws/lambda/opsagent-controller-production --follow

# Search for errors
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-controller-production \
  --filter-pattern "ERROR"

# Analyze approval workflow
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-controller-production \
  --filter-pattern "approval_"
```

### Alerting

Critical alerts are configured for:
- High error rates (>5 errors in 10 minutes)
- High latency (>10 seconds average)
- Unauthorized access attempts (>10 in 5 minutes)
- DynamoDB throttling events

### Dashboards

CloudWatch dashboards provide real-time visibility into:
- System health and performance
- User activity and operation patterns
- Security events and compliance metrics
- Cost and resource utilization

## Troubleshooting

### Common Issues

**Authentication Failures**:
```bash
# Check user allow-list
aws ssm get-parameter --name "/opsagent/allowed-users"

# Verify API key
curl -H "X-API-Key: your-key" https://your-endpoint/health
```

**Resource Tag Validation Errors**:
```bash
# Check resource tags
aws ec2 describe-tags --filters "Name=resource-id,Values=i-1234567890abcdef0"

# Add required tags
aws ec2 create-tags \
  --resources i-1234567890abcdef0 \
  --tags Key=OpsAgentManaged,Value=true Key=Environment,Value=production
```

**Performance Issues**:
```bash
# Check Lambda metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=opsagent-controller-production \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average,Maximum
```

See [Troubleshooting Guide](./docs/troubleshooting.md) for detailed solutions.

## Contributing

### Development Workflow

1. **Setup Development Environment**:
   ```bash
   git clone <repository>
   cd ops-agent-controller
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements-dev.txt
   ```

2. **Code Standards**:
   - Follow PEP 8 style guidelines
   - Use Black formatter: `black src/ tests/`
   - Type hints required for all functions
   - Docstrings required for public APIs

3. **Testing Requirements**:
   - Unit tests for all new functionality
   - Integration tests for AWS operations
   - Property-based tests for critical logic
   - All tests must pass before submission

4. **Documentation**:
   - Update README for user-facing changes
   - Add docstrings for new functions/classes
   - Update API documentation for endpoint changes

### Pull Request Process

1. Create feature branch from `main`
2. Implement changes with comprehensive tests
3. Run full test suite: `pytest`
4. Format code: `black src/ tests/`
5. Update documentation as needed
6. Submit pull request with detailed description
7. Address review feedback
8. Merge after approval and CI success

### Code Review Guidelines

- **Security**: All changes reviewed for security implications
- **Performance**: Consider impact on Lambda cold starts and execution time
- **Testing**: Adequate test coverage for new functionality
- **Documentation**: Clear documentation for user-facing changes

## Support and Community

### Getting Help

- **Documentation**: Comprehensive guides in `docs/` directory
- **Issues**: GitHub Issues for bug reports and feature requests
- **Discussions**: GitHub Discussions for questions and community support

### Roadmap

Planned features and improvements:
- Multi-cloud support (Azure, GCP)
- Enhanced approval workflows with multi-step approvals
- Advanced analytics and reporting
- Integration with additional chat platforms
- Expanded AWS service coverage

## License

MIT License

Copyright (c) 2024 Platform Engineering Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## Additional Resources

- **[Production Implementation Guide](./PRODUCTION_IMPLEMENTATION_GUIDE.md)**: Complete production deployment guide
- **[Amazon Q Business Integration Guide](./docs/amazon-q-business-integration-guide.md)**: Detailed plugin setup
- **[Deployment Guide](./docs/deployment-guide.md)**: Step-by-step deployment instructions
- **[Troubleshooting Guide](./docs/troubleshooting.md)**: Common issues and solutions
- **[API Documentation](./infrastructure/openapi-schema.yaml)**: Complete API reference
