#!/bin/bash

# Enhanced Teams Integration Setup with AWS Authentication
# This script creates Azure Bot Registration with proper AWS integration

set -e

# Configuration
AZURE_SUBSCRIPTION_ID="4753c8c5-c458-4451-9736-51c667874b6f"
TENANT_ID="78952f68-6959-4fc9-a579-af36c10eee5c"
BOT_NAME="opsagent-aws-live"
RESOURCE_GROUP="opsagent-rg"
LOCATION="eastus"
CHAT_ENDPOINT="https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/chat"
AWS_REGION="eu-west-2"
AWS_ACCOUNT_ID="612176863084"

echo "🚀 Setting up Enhanced Teams Integration with AWS Authentication"
echo "=============================================================="

# Step 1: Login to Azure
echo "📝 Step 1: Logging into Azure..."
az login --tenant "$TENANT_ID"
az account set --subscription "$AZURE_SUBSCRIPTION_ID"

echo "✅ Logged into Azure successfully"

# Step 2: Create Resource Group
echo "📝 Step 2: Creating resource group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" || echo "Resource group may already exist"

# Step 3: Create App Registration with enhanced permissions
echo "📝 Step 3: Creating App Registration with AWS integration permissions..."
APP_RESULT=$(az ad app create \
    --display-name "$BOT_NAME" \
    --sign-in-audience AzureADMultipleOrgs \
    --required-resource-accesses '[
        {
            "resourceAppId": "00000003-0000-0000-c000-000000000000",
            "resourceAccess": [
                {
                    "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
                    "type": "Scope"
                },
                {
                    "id": "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0",
                    "type": "Scope"
                }
            ]
        }
    ]' \
    --output json)

BOT_APP_ID=$(echo "$APP_RESULT" | jq -r '.appId')
echo "App ID: $BOT_APP_ID"

# Step 4: Create Client Secret
echo "📝 Step 4: Creating client secret..."
SECRET_RESULT=$(az ad app credential reset --id "$BOT_APP_ID" --append --display-name "OpsAgent AWS Teams Bot Secret" --output json)
BOT_APP_SECRET=$(echo "$SECRET_RESULT" | jq -r '.password')

# Step 5: Add redirect URIs for OAuth flow
echo "📝 Step 5: Configuring OAuth redirect URIs..."
az ad app update --id "$BOT_APP_ID" \
    --web-redirect-uris "https://token.botframework.com/.auth/web/redirect" \
    --web-home-page-url "https://github.com/opsagent/controller"

# Step 6: Create Bot Registration with OAuth settings
echo "📝 Step 6: Creating Azure Bot Registration with OAuth..."
BOT_RESULT=$(az bot create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$BOT_NAME" \
    --appid "$BOT_APP_ID" \
    --app-type SingleTenant \
    --tenant-id "$TENANT_ID" \
    --description "OpsAgent Controller Teams Bot with AWS Integration" \
    --endpoint "$CHAT_ENDPOINT" \
    --sku F0 \
    --output json)

echo "✅ Bot registration created"

# Step 7: Configure OAuth Connection for AWS
echo "📝 Step 7: Setting up OAuth connection for AWS authentication..."

# Create OAuth connection settings
cat > oauth-connection.json << EOF
{
    "properties": {
        "serviceProviderDisplayName": "AWS IAM",
        "serviceProviderId": "oauth2generic",
        "clientId": "$BOT_APP_ID",
        "clientSecret": "$BOT_APP_SECRET",
        "scopes": "openid profile",
        "parameters": [
            {
                "key": "AuthorizationUrl",
                "value": "https://signin.aws.amazon.com/oauth"
            },
            {
                "key": "TokenUrl", 
                "value": "https://signin.aws.amazon.com/oauth/token"
            },
            {
                "key": "RefreshUrl",
                "value": "https://signin.aws.amazon.com/oauth/token"
            }
        ]
    }
}
EOF

# Note: OAuth connection creation via CLI is complex, we'll configure this manually
echo "⚠️  OAuth connection needs manual configuration in Azure Portal"

# Step 8: Store credentials in AWS SSM
echo "📝 Step 8: Storing credentials in AWS SSM Parameter Store..."

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

# Store AWS Account ID for validation
aws ssm put-parameter \
    --name "/opsagent/aws-account-id" \
    --value "$AWS_ACCOUNT_ID" \
    --type String \
    --region "$AWS_REGION" \
    --overwrite

# Store Tenant ID for validation
aws ssm put-parameter \
    --name "/opsagent/azure-tenant-id" \
    --value "$TENANT_ID" \
    --type String \
    --region "$AWS_REGION" \
    --overwrite

echo "✅ Credentials stored in AWS SSM"

# Step 9: Enable Teams Channel
echo "📝 Step 9: Enabling Teams channel..."
az bot msteams create --name "$BOT_NAME" --resource-group "$RESOURCE_GROUP"

# Step 10: Create Enhanced Teams App Manifest with AWS permissions
echo "📝 Step 10: Creating enhanced Teams app manifest..."
cat > teams-app-manifest-aws.json << EOF
{
  "\$schema": "https://developer.microsoft.com/en-us/json-schemas/teams/v1.16/MicrosoftTeams.schema.json",
  "manifestVersion": "1.16",
  "version": "1.0.1",
  "id": "$BOT_APP_ID",
  "packageName": "com.opsagent.aws.controller",
  "developer": {
    "name": "OpsAgent Team",
    "websiteUrl": "https://github.com/opsagent/controller",
    "privacyUrl": "https://github.com/opsagent/controller/privacy",
    "termsOfUseUrl": "https://github.com/opsagent/controller/terms"
  },
  "name": {
    "short": "OpsAgent AWS",
    "full": "OpsAgent Controller - AWS Operations Assistant with Authentication"
  },
  "description": {
    "short": "Secure AWS operations assistant with organizational authentication",
    "full": "OpsAgent Controller provides secure AWS operations management through Teams with proper authentication, authorization, and audit logging. Features include CloudWatch monitoring, EC2 management, and approval workflows with organizational controls."
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
              "title": "login",
              "description": "Authenticate with AWS and verify organization access"
            },
            {
              "title": "health",
              "description": "Check OpsAgent system health and AWS connectivity"
            },
            {
              "title": "whoami",
              "description": "Show current AWS identity and permissions"
            },
            {
              "title": "describe instance",
              "description": "Get detailed information about an EC2 instance"
            },
            {
              "title": "cpu metrics",
              "description": "Get CPU utilization metrics for an EC2 instance"
            },
            {
              "title": "cloudwatch metrics",
              "description": "Get CloudWatch metrics for a specific namespace"
            },
            {
              "title": "reboot instance",
              "description": "Request to reboot an EC2 instance (requires approval)"
            },
            {
              "title": "logout",
              "description": "Sign out and clear authentication tokens"
            },
            {
              "title": "help",
              "description": "Show available commands and usage examples"
            }
          ]
        }
      ],
      "isNotificationOnly": false,
      "supportsFiles": false
    }
  ],
  "permissions": [
    "identity",
    "messageTeamMembers"
  ],
  "validDomains": [
    "xt3qtho8l6.execute-api.eu-west-2.amazonaws.com",
    "signin.aws.amazon.com",
    "token.botframework.com",
    "login.microsoftonline.com"
  ],
  "webApplicationInfo": {
    "id": "$BOT_APP_ID",
    "resource": "https://RscBasedStoreApp"
  },
  "authorization": {
    "permissions": {
      "resourceSpecific": [
        {
          "name": "TeamMember.Read.Group",
          "type": "Application"
        },
        {
          "name": "ChannelMessage.Read.Group", 
          "type": "Application"
        }
      ]
    }
  }
}
EOF

echo "✅ Enhanced Teams app manifest created"

# Step 11: Create enhanced app icons
echo "📝 Step 11: Creating enhanced app icons with AWS branding..."
python3 << 'EOF'
from PIL import Image, ImageDraw, ImageFont
import os

# Create color icon (192x192) with AWS styling
color_img = Image.new('RGB', (192, 192), color='#232F3E')  # AWS Dark Blue
draw = ImageDraw.Draw(color_img)

# Draw AWS-style background
draw.rectangle([16, 16, 176, 176], fill='#FF9900', outline='#232F3E', width=4)  # AWS Orange

# Draw OpsAgent logo
draw.ellipse([48, 48, 144, 144], fill='#232F3E')
try:
    # Try to use a better font if available
    font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 36)
except:
    font = ImageFont.load_default()

draw.text((96, 96), 'OA', fill='#FF9900', anchor='mm', font=font)
draw.text((96, 130), 'AWS', fill='#FF9900', anchor='mm', font=ImageFont.load_default())

color_img.save('color.png')

# Create outline icon (32x32) with AWS styling
outline_img = Image.new('RGBA', (32, 32), color=(0, 0, 0, 0))
draw = ImageDraw.Draw(outline_img)

# AWS-style outline
draw.rectangle([2, 2, 30, 30], outline='#FF9900', width=2)
draw.ellipse([6, 6, 26, 26], outline='white', width=2)
draw.text((16, 16), 'O', fill='white', anchor='mm')

outline_img.save('outline.png')

print("Enhanced AWS-branded icons created successfully")
EOF

echo "✅ Enhanced app icons created"

# Step 12: Package Enhanced Teams app
echo "📝 Step 12: Creating enhanced Teams app package..."
zip -r opsagent-aws-teams-app.zip teams-app-manifest-aws.json color.png outline.png

echo "✅ Enhanced Teams app package created: opsagent-aws-teams-app.zip"

# Step 13: Create AWS IAM role for Teams integration
echo "📝 Step 13: Creating AWS IAM role for Teams integration..."

cat > teams-trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::$AWS_ACCOUNT_ID:oidc-provider/login.microsoftonline.com/$TENANT_ID"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "login.microsoftonline.com/$TENANT_ID:aud": "$BOT_APP_ID"
                }
            }
        }
    ]
}
EOF

# Create the role (this might fail if OIDC provider doesn't exist)
aws iam create-role \
    --role-name OpsAgent-Teams-Integration-Role \
    --assume-role-policy-document file://teams-trust-policy.json \
    --description "Role for OpsAgent Teams integration with AWS" \
    --region "$AWS_REGION" || echo "⚠️  Role creation failed - OIDC provider may need manual setup"

# Step 14: Display comprehensive setup summary
echo ""
echo "🎉 Enhanced Teams Integration Setup Complete!"
echo "=============================================="
echo ""
echo "📋 Summary:"
echo "- Bot Name: $BOT_NAME"
echo "- Bot App ID: $BOT_APP_ID"
echo "- Resource Group: $RESOURCE_GROUP"
echo "- Chat Endpoint: $CHAT_ENDPOINT"
echo "- AWS Account: $AWS_ACCOUNT_ID"
echo "- Azure Tenant: $TENANT_ID"
echo "- Enhanced Teams App Package: opsagent-aws-teams-app.zip"
echo ""
echo "🔐 Authentication Flow:"
echo "1. User sends message to bot in Teams"
echo "2. Bot requests AWS authentication if not logged in"
echo "3. User completes OAuth flow with organizational credentials"
echo "4. Bot validates user belongs to authorized organization"
echo "5. AWS operations are performed with user's identity"
echo ""
echo "📝 Manual Configuration Required:"
echo ""
echo "1. 🔗 Set up OIDC Identity Provider in AWS:"
echo "   - Go to AWS IAM Console > Identity Providers"
echo "   - Create OpenID Connect provider"
echo "   - Provider URL: https://login.microsoftonline.com/$TENANT_ID"
echo "   - Audience: $BOT_APP_ID"
echo ""
echo "2. 🤖 Configure OAuth Connection in Azure:"
echo "   - Go to Azure Portal > Bot Services > $BOT_NAME"
echo "   - Navigate to Configuration > OAuth Connection Settings"
echo "   - Add new OAuth connection for AWS authentication"
echo ""
echo "3. 📱 Install Enhanced Teams App:"
echo "   - Upload opsagent-aws-teams-app.zip to Teams"
echo "   - Grant required permissions for your organization"
echo "   - Test with 'login' command"
echo ""
echo "4. 🔧 Update Lambda Function:"
echo "   - Deploy updated authentication logic"
echo "   - Configure organization validation"
echo "   - Test end-to-end flow"
echo ""
echo "✅ Ready for enhanced AWS-authenticated Teams integration!"

# Cleanup temporary files
rm -f oauth-connection.json teams-trust-policy.json

echo ""
echo "🔍 Next Steps:"
echo "1. Complete manual configuration steps above"
echo "2. Test authentication flow with 'login' command"
echo "3. Verify organizational access controls"
echo "4. Deploy updated Lambda function with enhanced auth"
