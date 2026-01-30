# Manual Teams Integration Setup

Since we're encountering permission issues with the automated script, let's set up Teams integration manually through the Azure Portal.

## Step 1: Create App Registration

1. **Go to Azure Portal**: https://portal.azure.com
2. **Navigate to Azure Active Directory** → **App registrations**
3. **Click "New registration"**
4. **Configure the app**:
   - Name: `OpsAgent Controller`
   - Supported account types: `Accounts in any organizational directory (Any Azure AD directory - Multitenant)`
   - Redirect URI: Leave blank for now
5. **Click "Register"**

## Step 2: Get App ID and Create Secret

1. **Copy the Application (client) ID** - this is your Bot App ID
2. **Go to "Certificates & secrets"**
3. **Click "New client secret"**
4. **Add description**: `OpsAgent Teams Bot Secret`
5. **Set expiration**: 24 months
6. **Click "Add" and copy the secret value immediately**

## Step 3: Create Bot Service

1. **Go to Azure Portal** → **Create a resource**
2. **Search for "Azure Bot"** and select it
3. **Click "Create"**
4. **Configure the bot**:
   - Bot handle: `opsagent-live` (must be globally unique)
   - Subscription: Your Azure subscription
   - Resource group: Create new `opsagent-rg` or use existing
   - Pricing tier: F0 (Free)
   - Microsoft App ID: Use the App ID from Step 2
   - Microsoft App Type: Multi Tenant
   - Creation type: Use existing app registration
5. **Set Messaging endpoint**: `https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/chat`
6. **Click "Review + create"** then **"Create"**

## Step 4: Store Credentials in AWS

Run these commands with your actual values:

```bash
# Replace YOUR_APP_ID_HERE with the actual App ID from Step 2
aws ssm put-parameter \
    --name "/opsagent/teams-bot-app-id" \
    --value "YOUR_APP_ID_HERE" \
    --type String \
    --region eu-west-2 \
    --overwrite

# Replace YOUR_SECRET_HERE with the actual secret from Step 2
aws ssm put-parameter \
    --name "/opsagent/teams-bot-app-secret" \
    --value "YOUR_SECRET_HERE" \
    --type SecureString \
    --region eu-west-2 \
    --overwrite
```

## Step 5: Enable Teams Channel

1. **Go to your bot resource in Azure Portal**
2. **Navigate to "Channels"**
3. **Click "Microsoft Teams"**
4. **Click "Apply"**

## Step 6: Create Teams App Package

I'll create the Teams app package for you once you provide the App ID from Step 2.

## What You Need to Provide

Please provide:
1. **Bot App ID** (from Step 2)
2. **Bot App Secret** (from Step 2)

Then I can:
1. Store the credentials in AWS
2. Create the Teams app package
3. Guide you through installing it in Teams

**Ready to proceed with the manual setup?**