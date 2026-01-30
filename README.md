# OpsAgent Controller

A serverless conversational Tier-1 Ops assistant that enables platform engineers to diagnose AWS incidents and perform controlled remediation actions via chat interfaces.

## Features

- **Conversational Interface**: Natural language interaction through Teams, Slack, or Web/CLI
- **Amazon Q Integration**: Hybrid LLM with Amazon Q Developer for knowledge queries and Bedrock for operations
- **AWS Diagnosis Tools**: Read-only access to CloudWatch metrics, EC2, ECS, and ALB resources
- **Controlled Remediation**: Approval-gated write operations with strong security controls
- **Intelligent Routing**: Automatic intent classification for optimal provider selection
- **Multi-Mode Execution**: SANDBOX_LIVE mode for safe production operations
- **Comprehensive Audit Logging**: Complete audit trails with correlation IDs
- **Security-First Design**: Least privilege IAM, tag-based scoping, and input validation

## Quick Start

### Prerequisites

- Python 3.11+
- AWS CLI configured
- AWS SAM CLI installed
- Docker (for local testing)

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
   pytest
   ```

3. **Build and test locally**:
   ```bash
   cd infrastructure
   sam build
   sam local start-api
   ```

4. **Test health endpoint**:
   ```bash
   curl http://localhost:3000/health
   ```

### Deployment

1. **Deploy to sandbox environment**:
   ```bash
   cd infrastructure
   sam build
   sam deploy --config-env sandbox
   ```

2. **Deploy with Amazon Q integration**:
   ```bash
   # Use the deployment script for guided setup
   ./deploy-amazon-q-integration.sh
   
   # Or deploy manually with parameters
   sam deploy --parameter-overrides \
     "AmazonQAppId=your-amazon-q-app-id" \
     "AmazonQUserId=opsagent-user"
   ```

3. **Test deployed health endpoint**:
   ```bash
   curl https://<api-gateway-url>/sandbox/health
   ```

## Amazon Q Integration

OpsAgent supports hybrid LLM capabilities with Amazon Q Developer:

- **Knowledge queries** → Amazon Q Developer (AWS documentation, best practices)
- **Operational tasks** → OpsAgent approval workflows (reboot, scale, deploy)
- **Diagnostic tasks** → Enhanced with Amazon Q context (metrics, status, logs)

### Configuration

Set these environment variables for Amazon Q integration:

```bash
AMAZON_Q_APP_ID=your-amazon-q-application-id
AMAZON_Q_USER_ID=opsagent-user
AMAZON_Q_SESSION_ID=optional-session-id
```

### Usage Examples

```bash
# Knowledge query (routed to Amazon Q)
"What is Amazon ECS and how does it work?"

# Diagnostic task (hybrid: OpsAgent + Q context)
"Show CPU metrics for instance i-1234567890abcdef0"

# Operational task (OpsAgent with approval)
"Reboot instance i-1234567890abcdef0"
```

See [Amazon Q Integration Guide](./docs/amazon-q-integration.md) for detailed configuration and usage.

## Project Structure

```
├── src/                    # Source code
│   ├── main.py            # Main Lambda handler
│   └── __init__.py
├── tests/                 # Test files
│   ├── test_main.py       # Main handler tests
│   └── __init__.py
├── infrastructure/        # AWS SAM templates
│   ├── template.yaml      # CloudFormation template
│   └── samconfig.toml     # SAM configuration
├── requirements.txt       # Production dependencies
├── requirements-dev.txt   # Development dependencies
├── pytest.ini           # Pytest configuration
├── pyproject.toml        # Project configuration
└── README.md             # This file
```

## Execution Modes

- **SANDBOX_LIVE**: Full execution on tagged test resources only (production mode)

Note: LOCAL_MOCK and DRY_RUN modes have been removed for security and simplicity. All development and testing should use SANDBOX_LIVE with properly tagged test resources.

## API Endpoints

- `GET /health` - Health check with system status
- `POST /chat` - Chat message processing (to be implemented)

## Configuration

### Environment Variables

- `EXECUTION_MODE`: SANDBOX_LIVE (only supported mode)
- `LLM_PROVIDER`: bedrock (default)
- `BEDROCK_MODEL_ID`: anthropic.claude-3-sonnet-20240229-v1:0 (default)

### Amazon Q Integration (Optional)

- `AMAZON_Q_APP_ID`: Amazon Q Developer application ID
- `AMAZON_Q_USER_ID`: User ID for Amazon Q sessions (default: opsagent-user)
- `AMAZON_Q_SESSION_ID`: Optional session ID for conversation continuity

### Teams Integration (Optional)

- `TEAMS_BOT_APP_ID`: Microsoft Teams Bot Application ID
- `AZURE_TENANT_ID`: Azure AD Tenant ID for authentication
- `ENVIRONMENT`: sandbox | staging | production

## Security

- IAM roles follow least privilege principles
- Write operations require approval tokens
- Resource access limited by OpsAgentManaged=true tags
- Comprehensive audit logging
- Input validation and sanitization

## Testing

Run the full test suite:
```bash
pytest
```

Run specific test categories:
```bash
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m property      # Property-based tests only
```

## Contributing

1. Follow the existing code style (Black formatter)
2. Add tests for new functionality
3. Update documentation as needed
4. Ensure all tests pass before submitting

## License

MIT License - see LICENSE file for details