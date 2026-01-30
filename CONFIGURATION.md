# OpsAgent Controller - Configuration Guide

This guide explains how to configure the OpsAgent Controller for your environment.

## For Open Source Users

This application is designed to be easily configurable for different Azure/AWS environments. You'll need to set up your own credentials.

### Step 1: Create Configuration File

1. Copy the example configuration file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and fill in your values:
   ```bash
   nano .env  # or use your preferred editor
   ```

### Step 2: Get Required Credentials

#### Azure/Microsoft Teams Setup

1. **Create Azure AD App Registration**:
   - Go to [Azure Portal](https://portal.azure.com)
   - Navigate to **Azure Active Directory** > **App Registrations**
   - Click **New registration**
   - Name: `OpsAgent Bot` (or your preferred name)
   - Supported account types: **Single tenant**
   - Click **Register**

2. **Copy Application (client) ID**:
   - This is your `TEAMS_BOT_APP_ID`
   - Format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

3. **Copy Directory (tenant) ID**:
   - This is your `AZURE_TENANT_ID`
   - Format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

4. **Create Bot Service**:
   - In Azure Portal, create a new **Azure Bot**
   - Use the same App ID from above
   - Select your pricing tier (F0 for free tier)
   - Note the Resource Group name

#### AWS Setup

1. **Get AWS Account ID**:
   ```bash
   aws sts get-caller-identity --query Account --output text
   ```

2. **Choose AWS Region**:
   - Recommended: `eu-west-2` (London) or `us-east-1` (N. Virginia)
   - Ensure AWS Bedrock is available in your region

3. **Verify Bedrock Access**:
   ```bash
   aws bedrock list-foundation-models --region eu-west-2
   ```

### Step 3: Configure Your .env File

Edit your `.env` file with the values from above:

```bash
# Azure/Microsoft Teams Configuration
TEAMS_BOT_APP_ID=your-bot-app-id-from-step-2
AZURE_TENANT_ID=your-tenant-id-from-step-3

# AWS Configuration
AWS_ACCOUNT_ID=your-aws-account-id
AWS_REGION=eu-west-2

# Deployment Configuration
ENVIRONMENT=sandbox
EXECUTION_MODE=DRY_RUN
LLM_PROVIDER=bedrock
BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0
```

### Step 4: Update Teams App Manifest

Before packaging the Teams app, you need to update the manifest with your Bot App ID:

1. Edit `teams-app/manifest.json`:
   ```json
   {
     "id": "YOUR_BOT_APP_ID",
     "bots": [
       {
         "botId": "YOUR_BOT_APP_ID"
       }
     ],
     "webApplicationInfo": {
       "id": "YOUR_BOT_APP_ID"
     }
   }
   ```

2. Replace all instances of `YOUR_BOT_APP_ID` with your actual Bot App ID

3. Update the `validDomains` section with your API Gateway URL (after deployment)

### Step 5: Deploy

Once configured, deploy using the deployment script:

```bash
./deploy-now.sh
```

The script will:
1. Load your configuration from `.env`
2. Validate required variables are set
3. Build and deploy the Lambda function
4. Output your API Gateway endpoints

## Environment Variables Reference

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TEAMS_BOT_APP_ID` | Azure AD App Registration ID | `7245659a-25f0-455c-9a75-06451e81fc3e` |
| `AZURE_TENANT_ID` | Azure AD Tenant ID | `78952f68-6959-4fc9-a579-af36c10eee5c` |
| `AWS_ACCOUNT_ID` | AWS Account ID | `612176863084` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS Region for deployment | `eu-west-2` |
| `ENVIRONMENT` | Deployment environment | `sandbox` |
| `EXECUTION_MODE` | OpsAgent execution mode | `DRY_RUN` |
| `LLM_PROVIDER` | LLM provider to use | `bedrock` |
| `BEDROCK_MODEL_ID` | Bedrock model ID | `anthropic.claude-3-sonnet-20240229-v1:0` |
| `ENABLE_DYNAMODB_ENCRYPTION` | Enable DynamoDB encryption | `true` |
| `CREATE_TEST_RESOURCES` | Create test EC2 instance | `true` |

### Advanced Variables

| Variable | Description | Use Case |
|----------|-------------|----------|
| `AZURE_TENANT_IDS` | Multiple tenant IDs (comma-separated) | Multi-tenant deployments |
| `AWS_ACCOUNT_IDS` | Multiple AWS account IDs (comma-separated) | Cross-account operations |
| `AWS_ROLE_NAME` | IAM role name for Teams users | Custom role setup |
| `AWS_ROLE_ARN` | Specific IAM role ARN | Override default role |

## Execution Modes

### LOCAL_MOCK
- **Purpose**: Unit testing and local development
- **Behavior**: All AWS and LLM calls are mocked
- **Use When**: Running tests or developing without AWS access

### DRY_RUN
- **Purpose**: Safe testing in AWS environment
- **Behavior**: Read operations are real, write operations are simulated
- **Use When**: Testing diagnosis tools without making changes

### SANDBOX_LIVE
- **Purpose**: Full execution on test resources
- **Behavior**: All operations execute on tagged resources only
- **Use When**: Testing remediation actions on resources tagged with `OpsAgentManaged=true`

## Security Best Practices

### 1. Never Commit Credentials
- The `.env` file is in `.gitignore` and should never be committed
- Always use the `.env.example` template for documentation

### 2. Use AWS IAM Roles
- For production, use IAM roles instead of access keys
- Configure cross-account access using IAM role assumption

### 3. Enable Encryption
- Keep `ENABLE_DYNAMODB_ENCRYPTION=true` for production
- All data at rest is encrypted with KMS

### 4. Rotate Credentials Regularly
- Rotate Bot App secrets every 90 days
- Update credentials in AWS Secrets Manager or SSM Parameter Store

### 5. Limit Resource Access
- Only tag test resources with `OpsAgentManaged=true`
- Use separate AWS accounts for different environments

## Troubleshooting

### Configuration Not Loading
```bash
# Verify .env file exists
ls -la .env

# Test configuration loading
source ./config.sh
```

### Missing Required Variables
```bash
# Check which variables are set
env | grep -E 'TEAMS_|AZURE_|AWS_'
```

### Deployment Fails
```bash
# Validate CloudFormation template
cd infrastructure
sam validate

# Check AWS credentials
aws sts get-caller-identity
```

## Multi-Environment Setup

For managing multiple environments (sandbox, staging, production):

1. Create separate `.env` files:
   - `.env.sandbox`
   - `.env.staging`
   - `.env.production`

2. Load the appropriate file before deployment:
   ```bash
   cp .env.sandbox .env
   ./deploy-now.sh
   ```

3. Or use environment-specific deployment:
   ```bash
   ENV_FILE=.env.production ./deploy-now.sh
   ```

## See Also

- [Quick Start Guide](QUICK_START.md) - Getting started quickly
- [Deployment Guide](docs/deployment-guide.md) - Detailed deployment instructions
- [Teams Integration](TEAMS_APP_SETUP.md) - Teams app setup and configuration
