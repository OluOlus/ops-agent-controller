# OpsAgent Controller Testing Suite

This directory contains comprehensive testing for the OpsAgent Controller, including unit tests, integration tests, property-based tests, smoke tests, and readiness validation.

## Test Structure

### Core Test Files
- `test_main.py` - Tests for the main Lambda handler
- `test_models.py` - Tests for data models and validation
- `test_llm_provider.py` - Tests for LLM provider integration
- `test_tool_execution_engine.py` - Tests for tool execution
- `test_tool_guardrails.py` - Tests for security controls
- `test_approval_gate.py` - Tests for approval workflows
- `test_audit_logger.py` - Tests for audit logging
- `test_aws_diagnosis_tools.py` - Tests for AWS diagnosis tools
- `test_aws_remediation_tools.py` - Tests for AWS remediation tools
- `test_channel_adapters.py` - Tests for chat channel adapters
- `test_integration.py` - Integration tests for complete system
- `test_web_channel_integration.py` - Web channel integration tests
- `test_properties.py` - Property-based tests for correctness properties

### Smoke Tests and Readiness Validation
- `test_smoke_tests.py` - Comprehensive smoke tests for all components
- `test_readiness_validation.py` - Readiness validation for deployed infrastructure
- `run_smoke_tests.py` - Test runner script for automated validation

## Running Tests

### Unit Tests
```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run with coverage
make test-cov

# Run specific test file
python3 -m pytest tests/test_main.py -v

# Run specific test
python3 -m pytest tests/test_main.py::TestHealthHandler::test_health_handler_success -v
```

### Property-Based Tests
```bash
# Run property-based tests
python3 -m pytest tests/test_properties.py -v

# Run specific property test
python3 -m pytest tests/test_properties.py::TestProperty8AuthenticationValidation -v
```

### Smoke Tests and Readiness Validation

#### Using Make Targets
```bash
# Run comprehensive smoke tests and readiness validation
make smoke-test

# Run readiness validation against deployed infrastructure
make readiness-test

# Validate deployment with full test suite
make validate-deployment
```

#### Using Test Runner Directly
```bash
# Run all smoke tests and readiness validation
python3 tests/run_smoke_tests.py --suite all --verbose

# Run only smoke tests (no deployed infrastructure tests)
python3 tests/run_smoke_tests.py --suite smoke --verbose

# Run only readiness validation
python3 tests/run_smoke_tests.py --suite readiness --verbose

# Run specific test suites
python3 tests/run_smoke_tests.py --suite infrastructure --verbose
python3 tests/run_smoke_tests.py --suite diagnosis --verbose
python3 tests/run_smoke_tests.py --suite approval --verbose
python3 tests/run_smoke_tests.py --suite audit --verbose
```

#### Using Infrastructure Script
```bash
# Validate deployed infrastructure
./infrastructure/validate-deployment.sh sandbox

# Run smoke tests only
./infrastructure/validate-deployment.sh sandbox --smoke-only

# Run readiness tests only
./infrastructure/validate-deployment.sh sandbox --readiness-only

# Verbose output
./infrastructure/validate-deployment.sh sandbox --verbose
```

## Test Categories

### 1. Infrastructure Smoke Tests
**Requirements: 11.6, 11.8**

Tests basic infrastructure functionality:
- Health endpoint accessibility and response format
- Execution mode reporting
- LLM provider status
- AWS tool access status
- Chat endpoint accessibility
- CORS headers configuration
- Rate limiting functionality
- Component initialization status

### 2. Diagnosis Tools Validation
**Requirements: 11.8, 11.10**

Tests diagnosis tool functionality:
- CloudWatch metrics tool in different execution modes
- EC2 describe tool functionality
- Error handling for AWS API failures
- Integration with chat interface
- Read-only operation guarantee
- Sensitive information sanitization

### 3. Approval Gate and Remediation Testing
**Requirements: 11.10, 11.11**

Tests approval workflows and remediation:
- Approval gate token creation and validation
- Token expiry handling
- Token consumption (one-time use)
- Remediation tools in DRY_RUN mode
- Resource tag validation (OpsAgentManaged=true)
- End-to-end approval workflow
- Approval denial workflow

### 4. Audit Logging Verification
**Requirements: 11.11, 11.14**

Tests audit logging functionality:
- Audit logger initialization
- Request received logging
- Tool execution logging
- Approval workflow logging
- Error logging
- Secret sanitization in logs
- Correlation ID consistency
- Integration with chat interface

### 5. Deployed Infrastructure Readiness
**Requirements: 11.6, 11.8, 11.10, 11.11, 11.14**

Tests against deployed infrastructure:
- Health endpoint accessibility
- Chat endpoint authentication
- CORS headers configuration
- API Gateway rate limiting
- CloudWatch metrics diagnosis through chat
- EC2 instance diagnosis through chat
- Error handling for invalid requests
- Remediation approval requirements
- Approval workflow in dry-run mode
- Approval token expiry handling
- CloudWatch audit logs accessibility
- DynamoDB audit table accessibility
- Audit logging through chat interactions
- Secret sanitization in audit logs

## Configuration

### Environment Variables

The test suite uses the following environment variables:

#### Required for Readiness Validation
- `HEALTH_ENDPOINT` - Health check endpoint URL
- `CHAT_ENDPOINT` - Chat endpoint URL
- `API_KEY` - API key for authentication

#### Optional Configuration
- `EXECUTION_MODE` - Execution mode (LOCAL_MOCK, DRY_RUN, SANDBOX_LIVE)
- `ENVIRONMENT` - Environment name (sandbox, staging, production)
- `AWS_REGION` - AWS region (default: us-east-1)
- `TEST_INSTANCE_ID` - Test EC2 instance ID for remediation testing
- `AUDIT_LOG_GROUP` - CloudWatch log group for audit logs
- `AUDIT_TABLE` - DynamoDB table for audit storage
- `STACK_NAME` - CloudFormation stack name

#### Auto-Discovery
The test runner automatically attempts to discover configuration from:
1. Environment variables
2. CloudFormation stack outputs
3. SSM Parameter Store (for API key)

### Test Modes

#### LOCAL_MOCK Mode
- No AWS credentials required
- All AWS operations are mocked
- LLM responses are mocked
- Fastest execution
- Suitable for unit testing and CI/CD

#### DRY_RUN Mode
- AWS credentials required
- Real AWS API calls for read operations
- Write operations return "WOULD_EXECUTE"
- Real LLM integration
- Suitable for integration testing

#### SANDBOX_LIVE Mode
- AWS credentials required
- Full end-to-end execution
- Write operations execute on tagged resources only
- Complete audit logging
- Suitable for final validation

## Property-Based Testing

The test suite includes property-based tests that validate universal correctness properties:

1. **Authentication Validation** - User identity validation
2. **Allow-List Enforcement** - Tool execution restrictions
3. **Tag Scoping** - Resource access controls
4. **Mode Consistency** - Execution mode behavior
5. **Audit Completeness** - Comprehensive logging
6. **Secret Hygiene** - Sensitive information protection
7. **Error Sanitization** - User-friendly error messages
8. **Health Endpoint Completeness** - System status reporting

## Continuous Integration

### GitHub Actions Integration
```yaml
- name: Run Smoke Tests
  run: |
    cd ops-agent-controller
    make smoke-test

- name: Validate Deployment
  run: |
    cd ops-agent-controller
    ./infrastructure/validate-deployment.sh sandbox --verbose
  env:
    AWS_REGION: us-east-1
    ENVIRONMENT: sandbox
```

### Local Development
```bash
# Quick smoke test during development
make smoke-test

# Full validation before deployment
make validate-deployment

# Test specific functionality
python3 -m pytest tests/test_smoke_tests.py::TestInfrastructureSmokeTests -v
```

## Troubleshooting

### Common Issues

#### AWS Credentials Not Found
```bash
# Configure AWS credentials
aws configure

# Or use environment variables
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
export AWS_REGION=us-east-1
```

#### Missing Dependencies
```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Or install specific packages
pip install pytest boto3 requests hypothesis
```

#### CloudFormation Stack Not Found
```bash
# Check stack exists
aws cloudformation describe-stacks --stack-name opsagent-controller-sandbox

# Deploy stack first
cd infrastructure
sam deploy --config-env sandbox
```

#### API Key Not Found
```bash
# Set API key in SSM Parameter Store
aws ssm put-parameter \
  --name "/opsagent/sandbox/api-key" \
  --value "your-secure-api-key" \
  --type SecureString \
  --overwrite
```

### Debug Mode
```bash
# Run with verbose output
python3 tests/run_smoke_tests.py --suite all --verbose

# Run single test with debug
python3 -m pytest tests/test_smoke_tests.py::TestInfrastructureSmokeTests::test_health_endpoint_accessibility -v -s

# Check test logs
tail -f smoke_test_report.json
```

## Contributing

When adding new tests:

1. **Follow naming conventions**: `test_*.py` for test files, `test_*` for test methods
2. **Add docstrings**: Include requirements references and test descriptions
3. **Use appropriate test categories**: Unit, integration, property-based, or smoke tests
4. **Mock external dependencies**: Use `unittest.mock` for AWS services and external APIs
5. **Test error conditions**: Include negative test cases and error handling
6. **Update documentation**: Add new tests to this README

### Test Template
```python
def test_new_functionality(self):
    """
    Test description
    Requirements: X.Y, Z.A
    """
    # Arrange
    setup_test_data()
    
    # Act
    result = execute_functionality()
    
    # Assert
    assert result.success is True
    assert expected_condition
```