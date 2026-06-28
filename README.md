# OpsAgent Controller

A serverless Tier-1 Ops assistant that lets platform engineers diagnose AWS incidents and perform controlled remediation via chat (Amazon Q Business, Microsoft Teams, Slack, or a plain web interface). Every action is gated by user authentication, resource tagging, an explicit approval workflow, and a complete audit trail.

---

## Table of Contents

1. [Architecture overview](#architecture-overview)
2. [Key capabilities](#key-capabilities)
3. [Security model](#security-model)
4. [Prerequisites](#prerequisites)
5. [Development setup](#development-setup)
6. [Deployment](#deployment)
7. [Post-deployment configuration](#post-deployment-configuration)
8. [Amazon Q Business integration](#amazon-q-business-integration)
9. [Teams integration](#teams-integration)
10. [API reference](#api-reference)
11. [Environment variables](#environment-variables)
12. [Execution modes](#execution-modes)
13. [Monitoring and alerting](#monitoring-and-alerting)
14. [Troubleshooting](#troubleshooting)
15. [Contributing](#contributing)
16. [License](#license)

---

## Architecture overview

```
Chat interface (Amazon Q Business / Teams / Slack / Web)
        │
        ▼
Amazon API Gateway  ──► AWS WAF (recommended for production)
        │
        ▼
AWS Lambda (Python 3.11, 1 GB memory, 60 s timeout)
  │  ├── Authentication & allow-list check (SSM Parameter Store)
  │  ├── LLM intent parsing (AWS Bedrock / Amazon Q Business)
  │  ├── Tool guardrails (schema validation, tag checks)
  │  ├── Approval gate (DynamoDB — staging & production)
  │  └── Tool execution (read-only or approved write ops)
  │
  ├── AWS services operated on (EC2, ECS, CloudWatch, CloudTrail, ALB)
  ├── DynamoDB — audit log, incidents, approval tokens
  ├── CloudWatch Logs — structured audit stream (90-day retention)
  ├── SNS — approval requests, incident notifications, alarm emails
  ├── SQS — dead-letter queue for failed Lambda invocations
  └── KMS — encryption at rest for DynamoDB tables and log groups
```

Infrastructure is defined as AWS SAM (CloudFormation) in `infrastructure/template.yaml`.

---

## Key capabilities

### Diagnostic operations (no approval required)

| Operation | Description |
|---|---|
| `get_ec2_status` | Instance state, status checks, CloudWatch CPU/memory metrics |
| `get_cloudwatch_metrics` | Retrieve any CloudWatch metric with configurable time range |
| `describe_alb_target_health` | ALB/NLB target group health and response codes |
| `search_cloudtrail_events` | Query CloudTrail for API calls by service, user, or time |

### Write operations (approval workflow enforced)

| Operation | Description | Risk level |
|---|---|---|
| `reboot_ec2` | Graceful reboot of a tagged EC2 instance | High |
| `scale_ecs_service` | Change desired task count for an ECS service | Medium / High |

Write operations follow a **propose → approve → execute** workflow:

```
1. User: "Reboot i-0abc123 — it's unresponsive"
2. System validates: user on allow-list ✓, instance has OpsAgentManaged=true tag ✓
3. System creates approval token (15 min TTL, stored in DynamoDB)
4. User reviews the action plan, then: "Approve with token <token>"
5. System executes the action, logs everything, returns result
```

### Workflow operations (no approval, fully audited)

| Operation | Description |
|---|---|
| `create_incident_record` | Write an incident record to DynamoDB + notify via SNS |
| `post_summary_to_channel` | Send a formatted message to Teams or Slack |

---

## Security model

### Defence-in-depth layers

| Layer | Mechanism |
|---|---|
| API authentication | API Gateway API keys (rotated via SSM), checked on every non-health request |
| User authorisation | Allow-list in SSM Parameter Store (`/opsagent/allowed-users`); validated on every request |
| Resource scoping | IAM conditions + code-level tag validation — only resources tagged `OpsAgentManaged=true` can be modified |
| Approval workflow | One-time cryptographic tokens (64 hex chars), 15-minute TTL, single-use enforced |
| Audit trail | Every action logged to CloudWatch Logs AND DynamoDB with correlation IDs |
| Encryption | KMS customer-managed key for DynamoDB SSE and CloudWatch log group encryption |
| Input sanitisation | JSON schema validation on all inputs; sensitive fields redacted from logs |
| CORS | Configurable via `CORS_ALLOWED_ORIGIN` env var; defaults to `null` (restrictive) |
| Rate limiting | Per-IP and per-user limits enforced at API Gateway (usage plan) and in Lambda |

> **Note on Lambda rate limiting:** The in-Lambda rate limiter is per-instance. For hard cross-instance enforcement at scale, rely on the API Gateway usage plan (`ThrottlingRateLimit: 100 req/s`).

### IAM policies

The Lambda role uses four least-privilege policies:

- **AuditLoggingPolicy** — CloudWatch Logs, DynamoDB write, SNS publish, SQS (DLQ), KMS
- **DiagnosisToolsPolicy** — EC2/ECS/ALB/CloudWatch/CloudTrail read-only
- **RemediationToolsPolicy** — EC2 reboot/start/stop, ECS update-service, Auto Scaling — all with `aws:ResourceTag/OpsAgentManaged: 'true'` condition
- **LLMProviderPolicy** — Bedrock InvokeModel, Amazon Q Business Chat, SSM Parameter Store read, Secrets Manager read

### Resource tagging requirement

All AWS resources that OpsAgent may modify **must** carry these tags:

```bash
aws ec2 create-tags --resources i-0abc123 --tags \
  Key=OpsAgentManaged,Value=true \
  Key=Environment,Value=production \
  Key=CriticalityLevel,Value=high
```

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Python | 3.11+ | [python.org](https://python.org) |
| AWS CLI | v2.x | `brew install awscli` |
| AWS SAM CLI | v1.x | `pip install aws-sam-cli` |
| Docker | any | Required for `sam build --use-container` |
| jq | any | `brew install jq` |

**AWS permissions required for deployment:**

CloudFormation, Lambda, API Gateway, DynamoDB, IAM (create roles/policies), CloudWatch, SSM Parameter Store, SNS, SQS, KMS, S3 (SAM deployment bucket).

---

## Development setup

```bash
git clone <repository>
cd ops-agent-controller

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements-dev.txt

# Copy and fill in environment config
cp .env.example .env   # edit .env with your values
```

### Run tests

```bash
# Full suite (~560 tests)
pytest

# By category
pytest -m unit          # No AWS dependencies
pytest -m integration   # Requires deployed infrastructure
pytest -m property      # Hypothesis property-based tests
pytest -m smoke         # Production validation

# With coverage
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

### Local API server

```bash
cd infrastructure
sam build --use-container
sam local start-api --env-vars ../local-env.json
```

```bash
# Test health endpoint
curl http://localhost:3000/health
```

---

## Deployment

### Quick deploy (sandbox)

```bash
./infrastructure/deploy.sh --environment sandbox
```

### Production deploy (SAM)

```bash
cd infrastructure

# Build (use --use-container for reproducible builds)
sam build --use-container

# Deploy to production
sam deploy \
  --stack-name opsagent-controller-production \
  --parameter-overrides \
    Environment=production \
    ExecutionMode=SANDBOX_LIVE \
    CreateTestResources=false \
    EnableDynamoDBEncryption=true \
    BedrockModelId=anthropic.claude-3-5-sonnet-20241022-v2:0 \
    CorsAllowedOrigin=https://your-app.example.com \
    AlarmEmailEndpoint=platform-team@company.com \
  --capabilities CAPABILITY_IAM \
  --region eu-west-2
```

### Deploy parameters

| Parameter | Default | Description |
|---|---|---|
| `Environment` | `sandbox` | `sandbox` \| `staging` \| `production` |
| `ExecutionMode` | `SANDBOX_LIVE` | `SANDBOX_LIVE` \| `DRY_RUN` \| `LOCAL_MOCK` |
| `BedrockModelId` | `anthropic.claude-3-5-sonnet-20241022-v2:0` | Bedrock foundation model ID |
| `LLMProvider` | `bedrock` | `bedrock` \| `openai` \| `azure_openai` |
| `EnableDynamoDBEncryption` | `true` | Enable KMS encryption on DynamoDB tables |
| `CreateTestResources` | `true` | Deploy a tagged test EC2 instance (requires `VpcId`/`SubnetId`) |
| `VpcId` | `` | VPC for test resources |
| `SubnetId` | `` | Subnet for test EC2 instance |
| `CorsAllowedOrigin` | `null` | Allowed CORS origin (e.g. `https://app.company.com`) |
| `AlarmEmailEndpoint` | `` | Email for CloudWatch alarm SNS notifications |
| `AmazonQAppId` | `` | Amazon Q Business application ID (optional) |

---

## Post-deployment configuration

### 1. Set a strong API key

The default API key value (`changeme-...`) must be replaced immediately:

```bash
SECURE_KEY=$(openssl rand -base64 32)
aws ssm put-parameter \
  --name "/opsagent/api-key" \
  --value "$SECURE_KEY" \
  --type "SecureString" \
  --overwrite
```

### 2. Configure the user allow-list

```bash
# Set allowed users (comma-separated email addresses)
aws ssm put-parameter \
  --name "/opsagent/allowed-users" \
  --value "alice@company.com,bob@company.com" \
  --type "StringList" \
  --overwrite

# Optionally allow all users from a domain
aws ssm put-parameter \
  --name "/opsagent/allowed-users" \
  --value "*@company.com" \
  --type "StringList" \
  --overwrite
```

### 3. Retrieve API endpoint and key

```bash
STACK=opsagent-controller-production

API_ENDPOINT=$(aws cloudformation describe-stacks \
  --stack-name $STACK \
  --query 'Stacks[0].Outputs[?OutputKey==`PluginApiEndpointUrl`].OutputValue' \
  --output text)

# Retrieve the actual API key value from API Gateway
KEY_ID=$(aws ssm get-parameter \
  --name "/opsagent/plugin-api-key-production" \
  --query 'Parameter.Value' --output text)

PLUGIN_API_KEY=$(aws apigateway get-api-key \
  --api-key "$KEY_ID" --include-value \
  --query 'value' --output text)

echo "Endpoint: $API_ENDPOINT"
echo "API Key:  $PLUGIN_API_KEY"
```

### 4. Validate deployment

```bash
# Health check
curl -s "$API_ENDPOINT/health" | jq .

# Diagnostic operation
curl -s -X POST "$API_ENDPOINT/operations/diagnostic" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $PLUGIN_API_KEY" \
  -d '{
    "operation": "get_ec2_status",
    "parameters": {"instance_id": "i-0000000000000000"},
    "user_context": {"user_id": "alice@company.com"}
  }' | jq .
```

### 5. API key rotation

```bash
./infrastructure/configure.sh rotate-keys --environment production
```

---

## Amazon Q Business integration

OpsAgent exposes an OpenAPI-compliant plugin endpoint that Amazon Q Business calls when users ask operational questions.

### Setup steps

1. **Deploy OpsAgent** (see above) and note the plugin API endpoint and key.
2. In the [Amazon Q Business console](https://console.aws.amazon.com/amazonq/), open your application → **Plugins** → **Add plugin**.
3. Choose **Custom plugin** and upload `infrastructure/amazon-q-plugin-schema.yaml`.
4. Set **Authentication** → API Key → Header name: `X-API-Key`, value: `$PLUGIN_API_KEY`.
5. Save and enable the plugin.

### Hybrid mode (Amazon Q + Bedrock)

Set `AmazonQAppId` at deploy time to enable hybrid routing: knowledge queries go to Amazon Q Business, operational tool calls go to Bedrock.

```bash
sam deploy ... --parameter-overrides AmazonQAppId=<your-app-id> ...
```

### Usage examples in chat

```
"What is the CPU utilisation of i-0abc123 over the last hour?"
"Check the ALB target health for my-load-balancer"
"Search CloudTrail for EC2 API calls in the last 30 minutes"

"Reboot i-0abc123 — it is not responding to health checks"
→ System: Approval required. Token: a3f8... (expires in 15 minutes)
"Approve with token a3f8..."
→ System: ✅ Instance rebooted successfully. Correlation: corr-xyz
```

---

## Teams integration

See [docs/teams-integration.md](docs/teams-integration.md) and [docs/TEAMS_APP_SETUP.md](docs/TEAMS_APP_SETUP.md) for the full guide.

**Quick summary:**

1. Register a Bot Framework app in Azure Portal — note the App ID and secret.
2. Store the secret: `aws ssm put-parameter --name /opsagent/teams-bot-app-secret --value <secret> --type SecureString`
3. Set `TEAMS_BOT_APP_ID` in your Lambda environment variables.
4. Configure the bot messaging endpoint to `$API_ENDPOINT/chat`.

---

## API reference

All endpoints except `GET /health` require an `X-API-Key` header.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | System health — returns component status (no auth required) |
| `POST` | `/chat` | Chat interface (legacy; Teams/Slack messages arrive here) |
| `POST` | `/plugin` | Amazon Q Business plugin handler |
| `POST` | `/operations/diagnostic` | Execute a read-only diagnostic operation |
| `POST` | `/operations/propose` | Propose a write operation; returns approval token |
| `POST` | `/operations/approve` | Approve and execute a proposed write operation |
| `POST` | `/operations/workflow` | Execute a workflow operation (incident record, notification) |

### POST /operations/diagnostic

```json
{
  "operation": "get_ec2_status",
  "parameters": {
    "instance_id": "i-0abc123"
  },
  "user_context": {
    "user_id": "alice@company.com"
  }
}
```

### POST /operations/propose

```json
{
  "operation": "propose_action",
  "parameters": {
    "action": "reboot_ec2",
    "instance_id": "i-0abc123",
    "reason": "Instance not responding to health checks for 10 minutes"
  },
  "user_context": {
    "user_id": "alice@company.com"
  }
}
```

Response includes `approval_token` and `expires_at`.

### POST /operations/approve

```json
{
  "operation": "approve_action",
  "parameters": {
    "approval_token": "<token from propose>"
  },
  "user_context": {
    "user_id": "alice@company.com"
  }
}
```

Full API schema: [`infrastructure/openapi-schema.yaml`](infrastructure/openapi-schema.yaml)

---

## Environment variables

### Required

| Variable | Description |
|---|---|
| `EXECUTION_MODE` | `SANDBOX_LIVE` \| `DRY_RUN` \| `LOCAL_MOCK` |
| `ENVIRONMENT` | `sandbox` \| `staging` \| `production` |
| `AUDIT_TABLE_NAME` | DynamoDB table for audit logs |
| `INCIDENT_TABLE_NAME` | DynamoDB table for incident records |
| `APPROVAL_GATE_TABLE_NAME` | DynamoDB table for approval tokens |
| `CLOUDWATCH_LOG_GROUP` | CloudWatch log group for audit events |
| `NOTIFICATION_TOPIC_ARN` | SNS topic ARN for notifications |
| `KMS_KEY_ID` | KMS key ID for encryption |
| `PLUGIN_API_KEY_PARAMETER` | SSM parameter name holding the API key ID |

### Optional

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `bedrock` | `bedrock` \| `openai` \| `azure_openai` |
| `BEDROCK_MODEL_ID` | `anthropic.claude-3-5-sonnet-20241022-v2:0` | Bedrock foundation model |
| `AMAZON_Q_APP_ID` | — | Enable Amazon Q Business hybrid mode |
| `AMAZON_Q_USER_ID` | `opsagent-user` | Amazon Q Business user ID |
| `CORS_ALLOWED_ORIGIN` | `null` | Browser CORS allowed origin |
| `TEAMS_BOT_APP_ID` | — | Microsoft Teams bot application ID |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## Execution modes

| Mode | Behaviour | When to use |
|---|---|---|
| `SANDBOX_LIVE` | Full execution against real AWS resources; tag validation enforced | Production, staging, and sandbox environments with tagged test resources |
| `DRY_RUN` | Validates inputs and checks tags but does not mutate resources | Pre-production testing, CI/CD validation |
| `LOCAL_MOCK` | All AWS calls mocked; authentication bypassed | Unit testing and local development only — **never in production** |

Change mode without redeployment:

```bash
aws lambda update-function-configuration \
  --function-name opsagent-controller-production \
  --environment Variables='{
    "EXECUTION_MODE": "DRY_RUN",
    "ENVIRONMENT": "production"
  }'
```

---

## Monitoring and alerting

### CloudWatch dashboard

The stack creates an `OpsAgent-<environment>` dashboard covering:

- Lambda invocations, errors, duration, throttles
- API Gateway request count, 4xx/5xx errors, latency
- DynamoDB consumed capacity
- Recent error log excerpt

```bash
# Open dashboard URL
aws cloudformation describe-stacks \
  --stack-name opsagent-controller-production \
  --query 'Stacks[0].Outputs[?OutputKey==`DashboardUrl`].OutputValue' \
  --output text
```

### CloudWatch alarms

Five alarms are created automatically; all publish to the SNS notification topic:

| Alarm | Trigger |
|---|---|
| `HighErrorRate` | > 5 Lambda errors in 10 minutes |
| `HighLatency` | Average Lambda duration > 10 seconds |
| `Throttles` | Any Lambda throttle event |
| `Api5xxErrors` | > 5 API Gateway 5XX errors in 10 minutes |
| `DLQMessages` | Any message arriving in the dead-letter queue |

To receive email alerts, set `AlarmEmailEndpoint` at deploy time, or subscribe manually:

```bash
aws sns subscribe \
  --topic-arn <NotificationTopicArn> \
  --protocol email \
  --notification-endpoint platform-team@company.com
```

### Log queries

```bash
# Stream live logs
aws logs tail /aws/lambda/opsagent-audit-production --follow

# Find errors
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-audit-production \
  --filter-pattern "ERROR"

# Trace a specific correlation ID
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-audit-production \
  --filter-pattern '"corr-xyz"'
```

---

## Troubleshooting

### Authentication failure (401)

```bash
# Verify the API key in SSM matches what you're sending
KEY_ID=$(aws ssm get-parameter --name /opsagent/plugin-api-key-production --query Parameter.Value --output text)
aws apigateway get-api-key --api-key "$KEY_ID" --include-value --query value --output text
```

### User not authorised (403)

```bash
# Check the allow-list
aws ssm get-parameter --name /opsagent/allowed-users --query Parameter.Value --output text

# Add a user
aws ssm put-parameter \
  --name /opsagent/allowed-users \
  --value "existing@company.com,new@company.com" \
  --type StringList \
  --overwrite
```

### Resource tag validation failed

```bash
# Check current tags
aws ec2 describe-tags --filters "Name=resource-id,Values=i-0abc123"

# Add required tag
aws ec2 create-tags --resources i-0abc123 \
  --tags Key=OpsAgentManaged,Value=true
```

### Lambda timeouts

```bash
# Check recent durations
aws logs filter-log-events \
  --log-group-name /aws/lambda/opsagent-controller-production \
  --filter-pattern "REPORT"

# The function is set to 60 s. If Bedrock calls are timing out,
# check Bedrock model availability in your region.
aws bedrock list-foundation-models --query 'modelSummaries[?contains(modelId, `claude`)]'
```

### Dead-letter queue has messages

```bash
DLQ_URL=$(aws cloudformation describe-stacks \
  --stack-name opsagent-controller-production \
  --query 'Stacks[0].Outputs[?OutputKey==`DeadLetterQueueUrl`].OutputValue' \
  --output text)

# Inspect messages (receive but do not delete)
aws sqs receive-message --queue-url "$DLQ_URL" --max-number-of-messages 1
```

### Enable debug logging

```bash
aws lambda update-function-configuration \
  --function-name opsagent-controller-production \
  --environment Variables='{"LOG_LEVEL": "DEBUG", "EXECUTION_MODE": "SANDBOX_LIVE", "ENVIRONMENT": "production"}'
```

See also: [docs/troubleshooting.md](docs/troubleshooting.md)

---

## Project structure

```
ops-agent-controller/
├── src/                              # Lambda source code
│   ├── main.py                       # Lambda handler & request routing
│   ├── models.py                     # Pydantic-style data models
│   ├── authentication.py             # User auth and allow-list validation
│   ├── approval_gate.py              # Approval token management (memory & DynamoDB)
│   ├── audit_logger.py               # CloudWatch + DynamoDB audit logging
│   ├── tool_execution_engine.py      # Orchestrates tool calls
│   ├── tool_guardrails.py            # Schema validation, tag checks, policy engine
│   ├── llm_provider.py               # Bedrock / Amazon Q Business / OpenAI clients
│   ├── channel_adapters.py           # Teams / Slack / Web response formatting
│   ├── aws_diagnosis_tools.py        # Read-only AWS operations (EC2, CW, ALB, CT)
│   ├── aws_remediation_tools.py      # Write AWS operations (reboot, scale)
│   ├── workflow_tools.py             # Incident records, channel notifications
│   └── requirements.txt             # Lambda package dependencies
├── tests/                            # Test suite
│   ├── test_main.py                  # Lambda handler tests
│   ├── test_approval_gate.py         # Approval workflow unit tests
│   ├── test_audit_logger.py          # Audit logging unit tests
│   ├── test_authentication.py        # Auth unit tests
│   ├── test_tool_guardrails.py       # Guardrail policy unit tests
│   ├── test_properties.py            # Hypothesis property-based tests
│   ├── test_integration.py           # End-to-end integration tests
│   └── test_smoke_tests.py           # Production readiness smoke tests
├── infrastructure/
│   ├── template.yaml                 # AWS SAM / CloudFormation template
│   ├── openapi-schema.yaml           # API Gateway OpenAPI spec
│   ├── amazon-q-plugin-schema.yaml   # Amazon Q Business plugin definition
│   ├── deploy.sh                     # Deployment automation
│   └── configure.sh                  # Post-deploy configuration helper
├── docs/
│   ├── deployment-guide.md           # Step-by-step deployment guide
│   ├── amazon-q-business-integration-guide.md
│   ├── teams-integration.md
│   ├── TEAMS_APP_SETUP.md
│   ├── troubleshooting.md
│   └── credential-setup.md
├── .env                              # Local environment config (gitignored)
├── requirements.txt                  # Development / CI dependencies
├── requirements-dev.txt              # Test and linting dependencies
├── pytest.ini                        # Pytest configuration
└── pyproject.toml                    # Project metadata
```

---

## Contributing

1. Fork and create a feature branch from `main`.
2. Install dev dependencies: `pip install -r requirements-dev.txt`
3. Make changes with tests: `pytest -m unit`
4. Format: `black src/ tests/`
5. Run full suite: `pytest`
6. Submit a pull request with a clear description of what changed and why.

**Coding standards:**
- PEP 8; enforced by Black
- Type hints on all public functions
- No wildcard imports
- Unit tests required for new functionality; integration tests for AWS operations

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Additional resources

- [Deployment guide](docs/deployment-guide.md) — environment-by-environment walkthrough
- [Amazon Q Business integration guide](docs/amazon-q-business-integration-guide.md)
- [Teams integration guide](docs/teams-integration.md)
- [Troubleshooting guide](docs/troubleshooting.md)
- [Credential setup](docs/credential-setup.md)
- [API schema](infrastructure/openapi-schema.yaml)
