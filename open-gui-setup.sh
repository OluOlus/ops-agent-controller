#!/bin/bash

# Interactive GUI Setup Script for Teams AWS Integration
# This script opens the necessary web interfaces for configuration

set -e

# Configuration
BOT_APP_ID="7245659a-25f0-455c-9a75-06451e81fc3e"
TENANT_ID="78952f68-6959-4fc9-a579-af36c10eee5c"
RESOURCE_GROUP="opsagent-rg"
BOT_NAME="opsagent-live"

echo "🚀 Opening GUI Interfaces for Teams AWS Integration Setup"
echo "======================================================="
echo ""
echo "Bot App ID: $BOT_APP_ID"
echo "Tenant ID: $TENANT_ID"
echo ""

# Function to open URL based on OS
open_url() {
    local url=$1
    local description=$2
    
    echo "📱 Opening: $description"
    echo "🔗 URL: $url"
    echo ""
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        open "$url"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        xdg-open "$url"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        # Windows
        start "$url"
    else
        echo "Please manually open: $url"
    fi
    
    read -p "Press Enter when you've completed this step..."
    echo ""
}

echo "We'll now open each interface you need to configure. Complete each step before moving to the next."
echo ""
read -p "Press Enter to start..."
echo ""

# Step 1: Azure App Registration
echo "🔧 Step 1: Configure Azure App Registration"
echo "============================================"
echo "Tasks to complete:"
echo "- Add redirect URIs for OAuth"
echo "- Configure API permissions"
echo "- Create client secret"
echo ""

open_url "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Authentication/appId/$BOT_APP_ID" "Azure App Registration - Authentication"

# Step 2: AWS IAM OIDC Provider
echo "🔧 Step 2: Set up AWS OIDC Identity Provider"
echo "============================================="
echo "Tasks to complete:"
echo "- Create OIDC identity provider"
echo "- Configure provider URL and audience"
echo "- Create IAM role for Teams users"
echo ""

open_url "https://console.aws.amazon.com/iam/home?region=eu-west-2#/providers" "AWS IAM - Identity Providers"

# Step 3: Azure Bot Service OAuth
echo "🔧 Step 3: Configure Bot Service OAuth Connection"
echo "================================================="
echo "Tasks to complete:"
echo "- Add OAuth connection settings"
echo "- Configure Azure AD v2 connection"
echo "- Test the connection"
echo ""

open_url "https://portal.azure.com/#@$TENANT_ID/resource/subscriptions/4753c8c5-c458-4451-9736-51c667874b6f/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.BotService/botServices/$BOT_NAME/oAuthConnection" "Azure Bot Service - OAuth Settings"

# Step 4: Teams Admin Center
echo "🔧 Step 4: Configure Teams App Permissions"
echo "==========================================="
echo "Tasks to complete:"
echo "- Upload updated Teams app package"
echo "- Configure app permissions"
echo "- Set up permission policies"
echo ""

open_url "https://admin.teams.microsoft.com/policies/manage-apps" "Teams Admin Center - Manage Apps"

# Step 5: AWS IAM Roles
echo "🔧 Step 5: Create AWS IAM Role for Teams Users"
echo "=============================================="
echo "Tasks to complete:"
echo "- Create role with web identity trust"
echo "- Attach appropriate policies"
echo "- Configure conditions for security"
echo ""

open_url "https://console.aws.amazon.com/iam/home?region=eu-west-2#/roles" "AWS IAM - Roles"

# Step 6: Test in Teams
echo "🔧 Step 6: Test Integration in Microsoft Teams"
echo "=============================================="
echo "Tasks to complete:"
echo "- Install the updated app"
echo "- Test authentication flow"
echo "- Verify AWS operations work"
echo ""

open_url "https://teams.microsoft.com" "Microsoft Teams"

echo "✅ All GUI interfaces have been opened!"
echo ""
echo "📋 Configuration Checklist:"
echo "□ Azure App Registration configured with OAuth settings"
echo "□ AWS OIDC Identity Provider created"
echo "□ AWS IAM Role created for Teams users"
echo "□ Bot Service OAuth connection configured"
echo "□ Teams app updated and permissions set"
echo "□ Integration tested end-to-end"
echo ""
echo "📖 For detailed instructions, see: teams-aws-gui-setup-guide.md"
echo ""
echo "🔍 Next Steps:"
echo "1. Complete all configuration steps in the opened interfaces"
echo "2. Update the Lambda function to handle OAuth tokens"
echo "3. Test the complete authentication flow"
echo "4. Deploy to production environment"