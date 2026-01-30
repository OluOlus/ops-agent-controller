# OpsAgent Controller

A serverless conversational Tier-1 Ops assistant that enables platform engineers to diagnose AWS incidents and perform controlled remediation actions via chat interfaces.

## Features

- **Conversational Interface**: Natural language interaction through Teams, Slack, or Web/CLI
- **AWS Diagnosis Tools**: Read-only access to CloudWatch metrics, EC2, ECS, and ALB resources
- **Controlled Remediation**: Approval-gated write operations with strong security controls
- **Multi-Mode Execution**: LOCAL_MOCK, DRY_RUN, and SANDBOX_LIVE modes for safe testing
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

2. **Test deployed health endpoint**:
   ```bash
   curl https://<api-gateway-url>/sandbox/health
   ```

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

- **LOCAL_MOCK**: All AWS and LLM calls are mocked for unit testing
- **DRY_RUN**: Real AWS read calls, write operations simulated
- **SANDBOX_LIVE**: Full execution on tagged test resources only

## API Endpoints

- `GET /health` - Health check with system status
- `POST /chat` - Chat message processing (to be implemented)

## Configuration

Set environment variables:
- `EXECUTION_MODE`: LOCAL_MOCK | DRY_RUN | SANDBOX_LIVE
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