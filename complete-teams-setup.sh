#!/bin/bash

# Complete Teams Integration Setup
# Uses the existing app registration and creates the Teams app package

set -e

# Configuration
BOT_APP_ID="7245659a-25f0-455c-9a75-06451e81fc3e"  # From previous run
BOT_APP_SECRET="q048Q~RnmyC6Fw_qMhZ6SLGIgEkV08yyU_GsBbp~"  # From previous run
CHAT_ENDPOINT="https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox/chat"
AWS_REGION="eu-west-2"

echo "🚀 Completing Teams Integration Setup"
echo "===================================="

# Step 1: Store credentials in AWS SSM
echo "📝 Step 1: Storing credentials in AWS SSM Parameter Store..."

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

# Step 2: Create Teams App Manifest
echo "📝 Step 2: Creating Teams app manifest..."
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
    "xt3qtho8l6.execute-api.eu-west-2.amazonaws.com"
  ],
  "webApplicationInfo": {
    "id": "$BOT_APP_ID",
    "resource": "https://RscBasedStoreApp"
  }
}
EOF

echo "✅ Teams app manifest created"

# Step 3: Create app icons
echo "📝 Step 3: Creating app icons..."
python3 << 'EOF'
from PIL import Image, ImageDraw, ImageFont
import os

# Create color icon (192x192)
color_img = Image.new('RGB', (192, 192), color='#FF6B35')
draw = ImageDraw.Draw(color_img)

# Draw a circle background
draw.ellipse([20, 20, 172, 172], fill='white')

# Draw "OA" text
try:
    # Try to use a system font
    font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 60)
except:
    # Fallback to default font
    font = ImageFont.load_default()

# Get text size and center it
text = "OA"
bbox = draw.textbbox((0, 0), text, font=font)
text_width = bbox[2] - bbox[0]
text_height = bbox[3] - bbox[1]
x = (192 - text_width) // 2
y = (192 - text_height) // 2

draw.text((x, y), text, fill='#FF6B35', font=font)
color_img.save('color.png')

# Create outline icon (32x32)
outline_img = Image.new('RGBA', (32, 32), color=(0, 0, 0, 0))
draw = ImageDraw.Draw(outline_img)

# Draw circle outline
draw.ellipse([2, 2, 30, 30], outline='white', width=2)

# Draw "O" text
try:
    font_small = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 16)
except:
    font_small = ImageFont.load_default()

text = "O"
bbox = draw.textbbox((0, 0), text, font=font_small)
text_width = bbox[2] - bbox[0]
text_height = bbox[3] - bbox[1]
x = (32 - text_width) // 2
y = (32 - text_height) // 2

draw.text((x, y), text, fill='white', font=font_small)
outline_img.save('outline.png')

print("Icons created successfully")
EOF

echo "✅ App icons created"

# Step 4: Package Teams app
echo "📝 Step 4: Creating Teams app package..."
zip -r opsagent-teams-app.zip teams-app-manifest.json color.png outline.png

echo "✅ Teams app package created: opsagent-teams-app.zip"

# Step 5: Test AWS connection
echo "📝 Step 5: Testing OpsAgent endpoint..."
curl -X POST \
    -H "Content-Type: application/json" \
    -d '{
        "userId": "test-user",
        "messageText": "health",
        "channel": "teams"
    }' \
    "$CHAT_ENDPOINT" | jq '.'

echo ""
echo "🎉 Teams Integration Setup Complete!"
echo "===================================="
echo ""
echo "📋 Summary:"
echo "- Bot App ID: $BOT_APP_ID"
echo "- Chat Endpoint: $CHAT_ENDPOINT"
echo "- Teams App Package: opsagent-teams-app.zip"
echo "- AWS SSM Parameters: /opsagent/teams-bot-app-id, /opsagent/teams-bot-app-secret"
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