#!/bin/bash

# Teams Integration Setup Script
# This script creates Azure Bot Registration and configures Teams integration

set -e

# Configuration
AZURE_SUBSCRIPTION_ID="4753c8c5-c458-4451-9736-51c667874b6f"
TENANT_ID="78952f68-6959-4fc9-a579-af36c10eee5c"
BOT_NAME="opsagent-live"
RESOURCE_GROUP="opsagent-rg"
LOCATION="eastus"
CHAT_ENDPOINT="https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/chat"
AWS_REGION="eu-west-2"

echo "🚀 Setting up Teams Integration for OpsAgent Controller"
echo "=================================================="

# Step 1: Login to Azure
echo "📝 Step 1: Logging into Azure..."
echo "Please complete the interactive login in your browser..."
az login --tenant "$TENANT_ID"

# Set subscription
az account set --subscription "$AZURE_SUBSCRIPTION_ID"

echo "✅ Logged into Azure successfully"

# Step 2: Create Resource Group
echo "📝 Step 2: Creating resource group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" || echo "Resource group may already exist"

echo "✅ Resource group ready"

# Step 3: Create App Registration
echo "📝 Step 3: Creating App Registration..."
APP_RESULT=$(az ad app create \
    --display-name "$BOT_NAME" \
    --sign-in-audience AzureADMultipleOrgs \
    --output json)

BOT_APP_ID=$(echo "$APP_RESULT" | jq -r '.appId')
echo "App ID: $BOT_APP_ID"

# Step 4: Create Client Secret
echo "📝 Step 4: Creating client secret..."
SECRET_RESULT=$(az ad app credential reset --id "$BOT_APP_ID" --append --display-name "OpsAgent Teams Bot Secret" --output json)
BOT_APP_SECRET=$(echo "$SECRET_RESULT" | jq -r '.password')

echo "✅ App registration and secret created"

# Step 5: Create Bot Registration
echo "📝 Step 5: Creating Azure Bot Registration..."
BOT_RESULT=$(az bot create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$BOT_NAME" \
    --appid "$BOT_APP_ID" \
    --app-type SingleTenant \
    --tenant-id "$TENANT_ID" \
    --description "OpsAgent Controller Teams Bot" \
    --endpoint "$CHAT_ENDPOINT" \
    --sku F0 \
    --output json)

echo "✅ Bot registration created"

# Step 6: Store credentials in AWS SSM
echo "📝 Step 6: Storing credentials in AWS SSM Parameter Store..."

# Store Bot App ID
aws ssm put-parameter \
    --name "/opsagent/teams-bot-app-id" \
    --value "$BOT_APP_ID" \
    --type String \
    --region "$AWS_REGION" \
    --overwrite

# Store Bot App Secret
aws ssm put-parameter \
    --name "/opsagent/teams-bot-app-secret" \
    --value "$BOT_APP_SECRET" \
    --type SecureString \
    --region "$AWS_REGION" \
    --overwrite

echo "✅ Credentials stored in AWS SSM"

# Step 7: Enable Teams Channel
echo "📝 Step 7: Enabling Teams channel..."
az bot msteams create --name "$BOT_NAME" --resource-group "$RESOURCE_GROUP"

echo "✅ Teams channel enabled"

# Step 8: Create Teams App Manifest
echo "📝 Step 8: Creating Teams app manifest..."
cat > teams-app-manifest.json << EOF
{
  "\$schema": "https://developer.microsoft.com/en-us/json-schemas/teams/v1.16/MicrosoftTeams.schema.json",
  "manifestVersion": "1.16",
  "version": "1.0.0",
  "id": "$BOT_APP_ID",
  "packageName": "com.opsagent.controller",
  "developer": {
    "name": "OpsAgent Team",
    "websiteUrl": "https://github.com/opsagent/controller",
    "privacyUrl": "https://github.com/opsagent/controller/privacy",
    "termsOfUseUrl": "https://github.com/opsagent/controller/terms"
  },
  "name": {
    "short": "OpsAgent",
    "full": "OpsAgent Controller - AWS Operations Assistant"
  },
  "description": {
    "short": "Conversational AWS operations assistant for incident response",
    "full": "OpsAgent Controller helps platform teams diagnose AWS incidents and perform controlled remediation actions through chat interfaces with approval gates and comprehensive audit logging. Features include CloudWatch metrics analysis, EC2 instance management, and secure approval workflows."
  },
  "icons": {
    "outline": "outline.png",
    "color": "color.png"
  },
  "accentColor": "#FF6B35",
  "bots": [
    {
      "botId": "$BOT_APP_ID",
      "scopes": ["personal", "team", "groupchat"],
      "commandLists": [
        {
          "scopes": ["personal", "team", "groupchat"],
          "commands": [
            {
              "title": "health",
              "description": "Check OpsAgent system health and status"
            },
            {
              "title": "describe instance i-1234567890abcdef0",
              "description": "Get detailed information about an EC2 instance"
            },
            {
              "title": "cpu metrics for i-1234567890abcdef0",
              "description": "Get CPU utilization metrics for an EC2 instance"
            },
            {
              "title": "cloudwatch metrics AWS/EC2 CPUUtilization",
              "description": "Get CloudWatch metrics for a specific namespace and metric"
            },
            {
              "title": "reboot instance i-1234567890abcdef0",
              "description": "Request to reboot an EC2 instance (requires approval)"
            },
            {
              "title": "help",
              "description": "Show available commands and usage examples"
            }
          ]
        }
      ],
      "isNotificationOnly": false
    }
  ],
  "permissions": ["identity", "messageTeamMembers"],
  "validDomains": [
    "xt3qtho8l6.execute-api.eu-west-2.amazonaws.com",
    "login.microsoftonline.com"
  ],
  "webApplicationInfo": {
    "id": "$BOT_APP_ID",
    "resource": "https://RscBasedStoreApp"
  }
}
EOF

echo "✅ Teams app manifest created"

# Step 9: Create app icons (simple placeholders)
echo "📝 Step 9: Creating app icons..."
python3 << 'EOF'
from PIL import Image, ImageDraw
import os

# Create color icon (192x192)
color_img = Image.new('RGB', (192, 192), color='#FF6B35')
draw = ImageDraw.Draw(color_img)
draw.ellipse([48, 48, 144, 144], fill='white')
draw.text((96, 96), 'OA', fill='#FF6B35', anchor='mm')
color_img.save('color.png')

# Create outline icon (32x32)
outline_img = Image.new('RGBA', (32, 32), color=(0, 0, 0, 0))
draw = ImageDraw.Draw(outline_img)
draw.ellipse([4, 4, 28, 28], outline='white', width=2)
draw.text((16, 16), 'O', fill='white', anchor='mm')
outline_img.save('outline.png')

print("Icons created successfully")
EOF

echo "✅ App icons created"

# Step 10: Package Teams app
echo "📝 Step 10: Creating Teams app package..."
zip -r opsagent-teams-app.zip teams-app-manifest.json color.png outline.png

echo "✅ Teams app package created: opsagent-teams-app.zip"

# Step 11: Display summary
echo ""
echo "🎉 Teams Integration Setup Complete!"
echo "===================================="
echo ""
echo "📋 Summary:"
echo "- Bot Name: $BOT_NAME"
echo "- Bot App ID: $BOT_APP_ID"
echo "- Resource Group: $RESOURCE_GROUP"
echo "- Chat Endpoint: $CHAT_ENDPOINT"
echo "- Teams App Package: opsagent-teams-app.zip"
echo ""
echo "📝 Next Steps:"
echo "1. Install the Teams app package in your tenant"
echo "2. Test the bot by sending 'health' message"
echo "3. Try AWS operations like 'describe instance i-xxx'"
echo ""
echo "🔧 Installation Instructions:"
echo "1. Go to Teams Admin Center: https://admin.teams.microsoft.com"
echo "2. Navigate to Teams apps > Manage apps"
echo "3. Click 'Upload new app' and select opsagent-teams-app.zip"
echo "4. Approve and assign to users/groups"
echo ""
echo "Or install directly in Teams:"
echo "1. Open Microsoft Teams"
echo "2. Go to Apps"
echo "3. Click 'Upload a custom app'"
echo "4. Select opsagent-teams-app.zip"
echo "5. Click 'Add' to install"
echo ""
echo "✅ Ready to test in Teams!"
