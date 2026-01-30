# OpsAgent Controller - Quick Start Guide

## Current Configuration

### AWS Settings
- **AWS Account ID**: 612176863084
- **AWS Region**: eu-west-2
- **Chat Endpoint**: https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/chat

### Azure/Teams Settings
- **Azure Tenant ID**: 78952f68-6959-4fc9-a579-af36c10eee5c
- **Bot App ID**: 7245659a-25f0-455c-9a75-06451e81fc3e
- **Bot Name**: opsagent-live
- **Resource Group**: opsagent-rg
- **Admin Email**: ops@ooluwafemilimesoftsystem.onmicrosoft.com

## Prerequisites

1. **AWS CLI** configured with your credentials
2. **AWS SAM CLI** installed
3. **Python 3.11+**
4. **Docker** (for local testing)

## Quick Deployment Steps

### 1. Install Dependencies

```bash
# Activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements-dev.txt
```

### 2. Build the Application

```bash
cd infrastructure
sam build
```

### 3. Deploy to AWS

```bash
# Deploy to sandbox environment (eu-west-2)
sam deploy --config-env sandbox --region eu-west-2

# Or use the guided deployment
sam deploy --guided
```

### 4. Configure Azure Bot Service

After deployment, you'll get the API Gateway URL. Configure your Azure Bot Service:

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Resource Groups** > **opsagent-rg**
3. Select your bot registration: **opsagent-live**
4. Go to **Configuration** > **Messaging endpoint**
5. Set to: `https://<your-api-gateway-id>.execute-api.eu-west-2.amazonaws.com/sandbox/chat`

### 5. Install Teams App

```bash
# Package is ready at:
cd ../teams-app
# Upload opsagent-teams-app.zip to Microsoft Teams
```

**In Microsoft Teams:**
1. Go to **Apps** > **Upload a custom app**
2. Select `opsagent-teams-app.zip`
3. Click **Add** to install

### 6. Test the Bot

In Microsoft Teams, start a chat with **OpsAgent AWS** and try:

```
login
health
help
```

## Verification Commands

### Test Health Endpoint
```bash
curl https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/health
```

### Test Chat Endpoint
```bash
curl -X POST https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/chat \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "test-user",
    "messageText": "health",
    "channel": "web"
  }'
```

### Check Lambda Logs
```bash
aws logs tail /aws/lambda/opsagent-controller-sandbox --follow --region eu-west-2
```

## Troubleshooting

### Issue: Bot not responding in Teams
1. Check Azure Bot Service messaging endpoint is correct
2. Verify Lambda function is deployed and accessible
3. Check CloudWatch logs for errors

### Issue: Authentication errors
1. Verify TEAMS_BOT_APP_ID and AZURE_TENANT_ID in Lambda environment variables
2. Check Azure AD app registration has correct permissions
3. Verify OIDC federation with AWS is configured

### Issue: AWS operations failing
1. Check Lambda execution role has required permissions
2. Verify resources are tagged with `OpsAgentManaged=true`
3. Ensure Bedrock access is enabled in eu-west-2

## Key Files Fixed

1. ✅ [src/requirements.txt](src/requirements.txt) - Fixed duplicate PyJWT, added jsonschema
2. ✅ [requirements.txt](requirements.txt) - Updated with all dependencies
3. ✅ [infrastructure/samconfig.toml](infrastructure/samconfig.toml) - Changed region to eu-west-2
4. ✅ [teams-app/manifest.json](teams-app/manifest.json) - Already configured with correct credentials
5. ✅ [infrastructure/template.yaml](infrastructure/template.yaml) - Already configured with correct credentials

## Next Steps

1. **Deploy the Lambda function** to AWS using SAM CLI
2. **Update Azure Bot Service** messaging endpoint with the deployed API Gateway URL
3. **Install the Teams app** from the packaged zip file
4. **Test the bot** in Microsoft Teams

## Environment Variables

The Lambda function is configured with these environment variables (already in template.yaml):

- `TEAMS_BOT_APP_ID`: 7245659a-25f0-455c-9a75-06451e81fc3e
- `AZURE_TENANT_ID`: 78952f68-6959-4fc9-a579-af36c10eee5c
- `AWS_ACCOUNT_ID`: 612176863084
- `EXECUTION_MODE`: DRY_RUN (sandbox)
- `ENVIRONMENT`: sandbox

## Support

For detailed documentation:
- [README.md](README.md) - General overview
- [TEAMS_APP_SETUP.md](TEAMS_APP_SETUP.md) - Teams integration details
- [infrastructure/README.md](infrastructure/README.md) - Infrastructure details
