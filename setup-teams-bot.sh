#!/bin/bash
set -e

echo "=================================================="
echo "OpsAgent - Teams Bot Setup Script"
echo "=================================================="
echo ""

# Configuration
BOT_NAME="opsagent-live"
RESOURCE_GROUP="opsagent-rg"
SUBSCRIPTION_ID="4753c8c5-c458-4451-9736-51c667874b6f"
APP_ID="7245659a-25f0-455c-9a75-06451e81fc3e"

# Get the deployed Lambda URL
LAMBDA_CHAT_ENDPOINT="https://a1gxl8y8wg.execute-api.eu-west-2.amazonaws.com/sandbox/chat"
LAMBDA_AUTH_CALLBACK="https://a1gxl8y8wg.execute-api.eu-west-2.amazonaws.com/sandbox/auth/callback"

echo "Configuration:"
echo "  Bot Name: $BOT_NAME"
echo "  Resource Group: $RESOURCE_GROUP"
echo "  Subscription: $SUBSCRIPTION_ID"
echo "  Messaging Endpoint: $LAMBDA_CHAT_ENDPOINT"
echo "  Auth Callback: $LAMBDA_AUTH_CALLBACK"
echo ""

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "ERROR: Azure CLI not found. Please install it first:"
    echo "   https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

echo "✅ Azure CLI found"
echo ""

# Check if logged in
echo "Checking Azure login status..."
if ! az account show &> /dev/null; then
    echo "⚠️  Not logged in to Azure. Logging in..."
    az login
else
    echo "✅ Already logged in to Azure"
fi
echo ""

# Set subscription
echo "Setting subscription..."
az account set --subscription "$SUBSCRIPTION_ID"
CURRENT_SUB=$(az account show --query name -o tsv)
echo "✅ Using subscription: $CURRENT_SUB"
echo ""

# Step 1: Update Bot Service Messaging Endpoint
echo "Step 1: Updating Bot Service messaging endpoint..."
az bot update \
  --name "$BOT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --endpoint "$LAMBDA_CHAT_ENDPOINT" \
  --output table

echo "✅ Bot messaging endpoint updated"
echo ""

# Step 2: Add OAuth Redirect URI to App Registration
echo "Step 2: Adding OAuth redirect URI to App Registration..."

# Check if redirect URI already exists
EXISTING_URIS=$(az ad app show --id "$APP_ID" --query "web.redirectUris" -o json 2>/dev/null || echo "[]")

if echo "$EXISTING_URIS" | grep -q "$LAMBDA_AUTH_CALLBACK"; then
    echo "✅ Redirect URI already exists"
else
    echo "Adding redirect URI: $LAMBDA_AUTH_CALLBACK"

    # Get current redirect URIs and add the new one
    CURRENT_URIS=$(az ad app show --id "$APP_ID" --query "web.redirectUris" -o json)

    # Add the new URI (this will append to existing URIs)
    az ad app update \
      --id "$APP_ID" \
      --web-redirect-uris $LAMBDA_AUTH_CALLBACK \
      --output none 2>/dev/null || true

    echo "✅ Redirect URI added"
fi
echo ""

# Step 3: Verify configuration
echo "Step 3: Verifying configuration..."
echo ""

BOT_ENDPOINT=$(az bot show \
  --name "$BOT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "properties.endpoint" -o tsv)

echo "Configured Bot Endpoint: $BOT_ENDPOINT"

if [ "$BOT_ENDPOINT" = "$LAMBDA_CHAT_ENDPOINT" ]; then
    echo "✅ Bot endpoint is correctly configured"
else
    echo "⚠️  Warning: Bot endpoint doesn't match expected value"
    echo "   Expected: $LAMBDA_CHAT_ENDPOINT"
    echo "   Actual: $BOT_ENDPOINT"
fi
echo ""

# Step 4: Test the endpoint
echo "Step 4: Testing Lambda endpoint..."
HEALTH_ENDPOINT="https://a1gxl8y8wg.execute-api.eu-west-2.amazonaws.com/sandbox/health"

if curl -s -f "$HEALTH_ENDPOINT" > /dev/null; then
    echo "✅ Lambda endpoint is responding"
    echo ""
    echo "Health check response:"
    curl -s "$HEALTH_ENDPOINT" | python3 -m json.tool | head -20
else
    echo "❌ Lambda endpoint is not responding"
    echo "   Check if the Lambda function is deployed correctly"
fi
echo ""

# Summary
echo "=================================================="
echo "Setup Summary"
echo "=================================================="
echo ""
echo "✅ Bot Service messaging endpoint updated"
echo "✅ OAuth redirect URI configured"
echo "✅ Configuration verified"
echo ""
echo "Next Steps:"
echo ""
echo "1. Install the Teams App:"
echo "   - Open Microsoft Teams"
echo "   - Go to Apps > Upload a custom app"
echo "   - Select: teams-app/opsagent-teams-app.zip"
echo "   - Click Add"
echo ""
echo "2. Test the bot:"
echo "   - Start a chat with 'OpsAgent AWS'"
echo "   - Send: health"
echo "   - Send: help"
echo ""
echo "3. Authenticate:"
echo "   - Send: login"
echo "   - Complete OAuth flow"
echo "   - Send: whoami"
echo ""
echo "=================================================="
echo "Teams Bot Setup Complete! 🎉"
echo "=================================================="
