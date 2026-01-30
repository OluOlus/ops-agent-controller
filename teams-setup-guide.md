# OpsAgent Teams Integration - Quick Setup Guide

## Prerequisites
- Azure subscription with admin access
- Microsoft 365 tenant with Teams
- OpsAgent Controller deployed (✅ Done)

## Step 1: Create Azure Bot Registration

### Option A: Using Azure Portal (Recommended)

1. **Go to Azure Portal**: https://portal.azure.com
2. **Create Bot Service**:
   - Click "Create a resource"
   - Search for "Azure Bot"
   - Click "Create"

3. **Configure Bot**:
   ```
   Bot handle: opsagent-live (must be globally unique)
   Subscription: Your Azure subscription
   Resource group: Create new "opsagent-rg"
   Pricing tier: F0 (Free)
   Microsoft App ID: Create new
   Microsoft App Type: Multi Tenant
   ```

4. **Set Messaging Endpoint**:
   ```
   Messaging endpoint: https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/chat
   ```

### Option B: Using Azure CLI

```bash
# Login to Azure
az login

# Create resource group
az group create --name opsagent-rg --location eastus

# Create bot registration
az bot create \
    --resource-group opsagent-rg \
    --name opsagent-live \
    --kind registration \
    --app-type MultiTenant \
    --description "OpsAgent Controller Teams Bot" \
    --endpoint "https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/chat"
```

## Step 2: Get Bot Credentials

1. **Get App ID**:
   - Go to your bot resource in Azure Portal
   - Navigate to "Configuration"
   - Copy the "Microsoft App ID"

2. **Create Client Secret**:
   - Click "Manage" next to the App ID
   - Go to "Certificates & secrets"
   - Click "New client secret"
   - Description: "OpsAgent Teams Bot Secret"
   - Expiration: 24 months
   - **Copy the secret value immediately!**

## Step 3: Store Credentials in AWS

```bash
# Store Bot App ID
aws ssm put-parameter \
    --name "/opsagent/teams-bot-app-id" \
    --value "YOUR_APP_ID_HERE" \
    --type String \
    --region eu-west-2 \
    --overwrite

# Store Bot App Secret
aws ssm put-parameter \
    --name "/opsagent/teams-bot-app-secret" \
    --value "YOUR_SECRET_HERE" \
    --type SecureString \
    --region eu-west-2 \
    --overwrite
```

## Step 4: Enable Teams Channel

1. **In Azure Portal**:
   - Go to your bot resource
   - Navigate to "Channels"
   - Click "Microsoft Teams"
   - Click "Apply"

## Step 5: Create Teams App Package

We'll create a simple Teams app manifest and package it for installation.

## Current Status
- ✅ OpsAgent Controller deployed and working
- ✅ Chat endpoint: https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/chat
- ✅ Health endpoint: https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/health
- ✅ AWS operations enabled (SANDBOX_LIVE mode)
- ✅ Bedrock LLM integration working

## Next Steps
1. Create Azure Bot Registration
2. Get credentials and store in AWS
3. Create Teams app package
4. Install in Teams and test!