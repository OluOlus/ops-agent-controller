# OpsAgent Controller

A serverless Tier-1 Ops assistant that lets platform engineers diagnose AWS incidents and perform controlled remediation via chat (Amazon Q Business, Microsoft Teams, or a plain web interface). Every action is gated by user authentication, resource tagging, an explicit approval workflow, and a complete audit trail.

> **New here?** See [QUICK_START.md](QUICK_START.md) for the fastest path to a running deployment.

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
AWS Lambda (Python 3.13, 1 GB memory, 60 s timeout)
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

Infrastructure is defined as Terraform in `infrastructure-terraform/` (recommended) and alternatively as AWS SAM (CloudFormation) in `infrastructure/template.yaml`.

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
| Python | 3.9+ (local); Lambda runs 3.13 | [python.org](https://python.org) |
| AWS CLI | v2.x | `brew install awscli` |
| Terraform | >= 1.5 | `brew install terraform` |
| pip3 | any | Bundled with Python |
| jq | any | `brew install jq` |
| Azure CLI | 2.x (for Teams integration only) | `brew install azure-cli` |

**AWS permissions required for deployment:**

Lambda, API Gateway, DynamoDB, IAM (create roles/policies), CloudWatch, SSM Parameter Store, SNS, SQS, KMS, S3, Bedrock.

**Bedrock model access:**

The LLM backend defaults to **Amazon Nova Pro** (`amazon.nova-pro-v1:0`), which works immediately with no approval required.

To use **Anthropic Claude** models instead:

1. Go to the Bedrock console → **Model catalog** → find **Claude 3.7 Sonnet**
2. Complete the Anthropic use case form (one-time per account)
3. The Lambda execution role needs `aws-marketplace:ViewSubscriptions` and `aws-marketplace:Subscribe` permissions
4. Invoke the model once from your admin CLI to activate the subscription: `aws bedrock-runtime converse --model-id anthropic.claude-3-7-sonnet-20250219-v1:0 --region eu-west-2 --messages '[{"role":"user","content":[{"text":"hello"}]}]'`
5. Wait 5 minutes for propagation, then set `BEDROCK_MODEL_ID=anthropic.claude-3-7-sonnet-20250219-v1:0` on the Lambda

> **Note:** If you get `AccessDeniedException` with a marketplace error on the Lambda, it means the Anthropic subscription hasn't propagated to the Lambda role yet. Use Amazon Nova Pro in the meantime — it requires no marketplace subscription.

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
```

Create a local environment file for `sam local`:

```bash
cp infrastructure/config/test.yaml local-env.json   # edit with your values
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

### Terraform (recommended)

```bash
cd infrastructure-terraform

# Build the Lambda deployment package
bash build.sh

# Initialize Terraform
terraform init

# Review the plan
terraform plan -var="execution_mode=SANDBOX_LIVE"

# Deploy
terraform apply -var="execution_mode=SANDBOX_LIVE"
```

The `build.sh` script creates `lambda.zip` with cross-compiled dependencies for the Lambda `arm64`/`python3.13` runtime. Re-run it after any code or dependency change.

#### Terraform variables

| Variable | Default | Description |
|---|---|---|
| `aws_region` | `eu-west-2` | AWS region |
| `environment` | `sandbox` | `sandbox` \| `staging` \| `production` |
| `execution_mode` | `DRY_RUN` | `SANDBOX_LIVE` (real AWS calls) \| `DRY_RUN` (simulate) |
| `bedrock_model_id` | `anthropic.claude-3-7-sonnet-20250219-v1:0` | Bedrock model ID |
| `lambda_runtime` | `python3.13` | Lambda Python runtime |
| `lambda_architecture` | `arm64` | Lambda CPU architecture |
| `cors_allowed_origin` | `null` | CORS origin for browser clients |

#### Updating the Lambda code

After code changes in `src/`:

```bash
cd infrastructure-terraform
bash build.sh
aws lambda update-function-code \
  --function-name opsagent-controller-sandbox \
  --zip-file fileb://lambda.zip \
  --region eu-west-2
```

### SAM / CloudFormation (alternative)

SAM templates are in `infrastructure/template.yaml`. Note: AWS accounts with the `EarlyValidation::ResourceExistenceCheck` hook enabled may need to use `aws cloudformation create-stack` directly instead of `sam deploy` (which uses changesets that can trigger the hook).

```bash
cd infrastructure
sam build
sam deploy --config-env sandbox --no-confirm-changeset
```

---

## Post-deployment configuration

### 1. Set a strong API key

```bash
SECURE_KEY=$(openssl rand -base64 32)
aws ssm put-parameter \
  --name "/opsagent/api-key" \
  --value "$SECURE_KEY" \
  --type "SecureString" \
  --overwrite \
  --region eu-west-2
```

### 2. Configure the user allow-list

```bash
aws ssm put-parameter \
  --name "/opsagent/user-allow-list" \
  --value '["alice@company.com","bob@company.com"]' \
  --type "String" \
  --overwrite \
  --region eu-west-2

# Optionally allow all users from a domain
aws ssm put-parameter \
  --name "/opsagent/user-allow-list" \
  --value '["*@company.com"]' \
  --type "String" \
  --overwrite \
  --region eu-west-2
```

### 3. Retrieve API endpoint and key

```bash
# Get the API Gateway ID
API_ID=$(aws apigateway get-rest-apis --region eu-west-2 \
  --query 'items[?contains(name,`opsagent-controller`)].id' --output text)

API_ENDPOINT="https://${API_ID}.execute-api.eu-west-2.amazonaws.com/sandbox"

# Get the API key value
KEY_ID=$(aws apigateway get-api-keys --region eu-west-2 \
  --query 'items[?contains(name,`opsagent`)].id' --output text)

API_KEY=$(aws apigateway get-api-key --api-key "$KEY_ID" \
  --include-value --region eu-west-2 --query 'value' --output text)

echo "Endpoint: $API_ENDPOINT"
echo "API Key:  $API_KEY"
```

### 4. Validate deployment

```bash
# Health check (no auth needed)
curl -s "$API_ENDPOINT/health" | jq .

# Test a diagnostic operation
curl -s -X POST "$API_ENDPOINT/chat" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d '{
    "messageText": "get CloudWatch CPU metrics for instance i-0123456789abcdef0",
    "userId": "alice@company.com",
    "channel": "web"
  }' | jq .
```

### 5. Switch LLM model (optional)

The default is Amazon Nova Pro (no marketplace subscription needed). To switch to Claude:

```bash
aws lambda update-function-configuration \
  --function-name opsagent-controller-sandbox \
  --environment "Variables={...,BEDROCK_MODEL_ID=anthropic.claude-3-7-sonnet-20250219-v1:0}" \
  --region eu-west-2
```

See [Prerequisites → Bedrock model access](#prerequisites) for Anthropic-specific setup steps.

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

1. Register a Bot Framework app in Azure (Single Tenant):
   ```bash
   az login --tenant YOUR_TENANT_ID
   az ad app create --display-name "OpsAgent AWS Bot" --sign-in-audience AzureADMyOrg
   az ad app credential reset --id APP_ID --display-name "Bot Secret" --years 1
   az group create --name opsagent-rg --location uksouth
   az bot create --resource-group opsagent-rg --name opsagent-teams-bot \
     --app-type SingleTenant --appid APP_ID --tenant-id TENANT_ID \
     --endpoint "$API_ENDPOINT/chat"
   az bot msteams create --resource-group opsagent-rg --name opsagent-teams-bot
   ```
2. Store credentials in AWS SSM:
   ```bash
   aws ssm put-parameter --name /opsagent/teams-bot-app-id --value "APP_ID" --type String --overwrite --region eu-west-2
   aws ssm put-parameter --name /opsagent/teams-bot-app-secret --value "APP_SECRET" --type SecureString --overwrite --region eu-west-2
   ```
3. Upload the Teams app manifest (`teams-app/opsagent-teams-app.zip`) via Teams → Apps → Upload a custom app.

**Requirements:** A Microsoft 365 tenant with Teams enabled. Personal Azure accounts without Teams cannot test the bot in Teams — use the Azure Portal "Test in Web Chat" or curl the API directly instead.

**Teardown:**
```bash
az bot delete --resource-group opsagent-rg --name opsagent-teams-bot
az group delete --name opsagent-rg --yes --no-wait
az ad app delete --id APP_ID
```

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
# WARNING: --environment Variables replaces ALL env vars.
# Fetch the current values first to avoid wiping other config.
CURRENT=$(aws lambda get-function-configuration \
  --function-name opsagent-controller-production \
  --query 'Environment.Variables' --output json)

# Then merge in the change using jq before applying
echo "$CURRENT" | jq '. + {"EXECUTION_MODE": "DRY_RUN"}' > /tmp/new-env.json
aws lambda update-function-configuration \
  --function-name opsagent-controller-production \
  --environment "Variables=$(cat /tmp/new-env.json)"
```

For production environments, prefer re-deploying with updated `samconfig.toml` parameters over manual env var patches — it keeps the deployed state reproducible.

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
│   ├── models.py                     # Data models (ExecutionMode, ApprovalRequest, etc.)
│   ├── authentication.py             # User auth and allow-list validation
│   ├── approval_gate.py              # Approval token management (memory & DynamoDB)
│   ├── audit_logger.py               # CloudWatch + DynamoDB audit logging
│   ├── tool_execution_engine.py      # Orchestrates tool calls
│   ├── tool_guardrails.py            # Schema validation, tag checks, policy engine
│   ├── llm_provider.py               # Bedrock / OpenAI client wrappers
│   ├── amazon_q_provider.py          # Amazon Q Business client
│   ├── channel_adapters.py           # Teams / Web response formatting
│   ├── aws_diagnosis_tools.py        # Read-only AWS operations (EC2, CW, ALB, CT)
│   ├── aws_remediation_tools.py      # Write AWS operations (reboot, scale)
│   ├── aws_monitoring_tools.py       # CloudWatch metrics & alarm helpers
│   ├── aws_monitoring_assistant.py   # Higher-level monitoring workflows
│   ├── workflow_tools.py             # Incident records, channel notifications
│   └── requirements.txt             # Lambda package dependencies
├── tests/                            # Test suite (~560 tests)
│   ├── test_main.py                  # Lambda handler tests
│   ├── test_models.py                # Data model unit tests
│   ├── test_approval_gate.py         # Approval workflow unit tests
│   ├── test_audit_logger.py          # Audit logging unit tests
│   ├── test_authentication.py        # Auth unit tests
│   ├── test_tool_guardrails.py       # Guardrail policy unit tests
│   ├── test_tool_execution_engine.py # Tool orchestration tests
│   ├── test_llm_provider.py          # LLM client tests
│   ├── test_channel_adapters.py      # Channel adapter tests
│   ├── test_aws_diagnosis_tools.py   # Diagnosis tool tests
│   ├── test_aws_remediation_tools.py # Remediation tool tests
│   ├── test_amazon_q_integration.py  # Amazon Q Business integration tests
│   ├── test_plugin_integration.py    # Plugin endpoint integration tests
│   ├── test_plugin_operations.py     # Plugin operation tests
│   ├── test_web_channel_integration.py # Web channel integration tests
│   ├── test_infrastructure_provisioning.py # SAM template validation tests
│   ├── test_readiness_validation.py  # Production readiness checks
│   ├── test_properties.py            # Hypothesis property-based tests
│   ├── test_integration.py           # End-to-end integration tests
│   └── test_smoke_tests.py           # Production readiness smoke tests
├── infrastructure/
│   ├── template.yaml                 # AWS SAM / CloudFormation template
│   ├── samconfig.toml                # SAM deploy defaults (region, stack name, S3 bucket)
│   ├── openapi-schema.yaml           # API Gateway OpenAPI spec
│   ├── openapi-q-compatible.yaml     # Amazon Q Business compatible OpenAPI spec
│   ├── amazon-q-plugin-schema.yaml   # Amazon Q Business plugin definition
│   ├── config/
│   │   ├── production.yaml           # Production parameter values
│   │   ├── sandbox.yaml              # Sandbox parameter values
│   │   └── test.yaml                 # Local/test environment config
│   ├── deploy.sh                     # Deployment automation
│   ├── deploy-environment.sh         # Per-environment deploy wrapper
│   ├── configure.sh                  # Post-deploy configuration helper
│   ├── validate-deployment.sh        # Post-deploy validation checks
│   ├── validate.sh                   # Pre-deploy template validation
│   └── cleanup.sh                    # Stack teardown
├── docs/
│   ├── deployment-guide.md           # Step-by-step deployment guide
│   ├── amazon-q-business-integration-guide.md
│   ├── amazon-q-integration.md
│   ├── teams-integration.md
│   ├── TEAMS_APP_SETUP.md
│   ├── TEAMS_AWS_ARCHITECTURE.md
│   ├── troubleshooting.md
│   ├── credential-setup.md
│   └── PRODUCTION_IMPLEMENTATION_GUIDE.md
├── deploy-full-infrastructure.sh     # One-shot full deploy (all environments)
├── deploy-now.sh                     # Fast sandbox deploy shortcut
├── deploy-amazon-q-integration.sh    # Amazon Q Business specific deploy
├── setup-teams-bot.sh                # Teams bot setup helper
├── QUICK_START.md                    # Fastest path to a running deployment
├── CONFIGURATION.md                  # Configuration reference
├── requirements.txt                  # Runtime dependencies
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

- [QUICK_START.md](QUICK_START.md) — fastest path to a running deployment
- [CONFIGURATION.md](CONFIGURATION.md) — full configuration reference
- [docs/deployment-guide.md](docs/deployment-guide.md) — environment-by-environment walkthrough
- [docs/PRODUCTION_IMPLEMENTATION_GUIDE.md](docs/PRODUCTION_IMPLEMENTATION_GUIDE.md) — production hardening checklist
- [docs/amazon-q-business-integration-guide.md](docs/amazon-q-business-integration-guide.md) — Amazon Q Business setup
- [docs/teams-integration.md](docs/teams-integration.md) — Teams bot setup
- [docs/TEAMS_APP_SETUP.md](docs/TEAMS_APP_SETUP.md) — Azure Bot registration walkthrough
- [docs/credential-setup.md](docs/credential-setup.md) — SSM and Secrets Manager credential layout
- [docs/troubleshooting.md](docs/troubleshooting.md) — common errors and fixes
- [infrastructure/openapi-schema.yaml](infrastructure/openapi-schema.yaml) — full API schema
- [docs/plugin-sample-requests-responses.md](docs/plugin-sample-requests-responses.md) — example API payloads
