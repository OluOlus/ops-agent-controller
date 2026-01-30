#!/bin/bash

# Package Teams App with Integrated AWS Authentication
# This creates a clean Teams app package with seamless AWS authentication

set -e

echo "📦 Packaging OpsAgent Teams App"
echo "================================"

# Change to teams-app directory
cd "$(dirname "$0")"

# Create icons if they don't exist
if [ ! -f "color.png" ] || [ ! -f "outline.png" ]; then
    echo "🎨 Creating Teams app icons..."
    python3 create-icons.py
fi

# Validate manifest
echo "📝 Validating manifest.json..."
if ! python3 -m json.tool manifest.json > /dev/null; then
    echo "❌ Invalid JSON in manifest.json"
    exit 1
fi

# Create the Teams app package
echo "📦 Creating Teams app package..."
zip -r ../opsagent-teams-app.zip manifest.json color.png outline.png

echo "✅ Teams app package created: opsagent-teams-app.zip"

# Display package contents
echo ""
echo "📋 Package Contents:"
unzip -l ../opsagent-teams-app.zip

echo ""
echo "🚀 Installation Instructions:"
echo "=============================="
echo ""
echo "1. 📱 Install in Teams:"
echo "   - Open Microsoft Teams"
echo "   - Go to Apps > Upload a custom app"
echo "   - Select: opsagent-teams-app.zip"
echo "   - Click 'Add' to install"
echo ""
echo "2. 🔑 First Time Usage:"
echo "   - Start a chat with OpsAgent AWS"
echo "   - Send: login"
echo "   - Complete authentication in the popup"
echo "   - Return to Teams and start using AWS commands"
echo ""
echo "3. 🎯 Available Commands:"
echo "   - login    - Authenticate with AWS"
echo "   - health   - Check system status"
echo "   - whoami   - Show your AWS identity"
echo "   - help     - See all commands"
echo "   - logout   - Sign out"
echo ""
echo "4. 🔧 AWS Operations:"
echo "   - describe instance i-1234567890abcdef0"
echo "   - cpu metrics i-1234567890abcdef0"
echo "   - reboot instance i-1234567890abcdef0"
echo ""
echo "✨ Features:"
echo "- 🔐 Seamless authentication within Teams"
echo "- 🏢 Organization-based access control"
echo "- ✅ Approval workflows for sensitive operations"
echo "- 📊 Comprehensive audit logging"
echo "- 🔄 Automatic session management"
echo ""
echo "🎉 Ready to deploy!"