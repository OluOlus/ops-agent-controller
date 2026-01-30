#!/bin/bash

# Package Teams App with Integrated Authentication
# This creates a Teams app package with seamless AWS authentication

set -e

echo "📦 Packaging Teams App with Integrated AWS Authentication"
echo "======================================================="

# Create enhanced icons if they don't exist
if [ ! -f "color.png" ] || [ ! -f "outline.png" ]; then
    echo "🎨 Creating enhanced app icons..."
    python3 << 'EOF'
from PIL import Image, ImageDraw, ImageFont
import os

# Create color icon (192x192) with AWS styling
color_img = Image.new('RGB', (192, 192), color='#232F3E')  # AWS Dark Blue
draw = ImageDraw.Draw(color_img)

# Draw AWS-style background with gradient effect
draw.rectangle([16, 16, 176, 176], fill='#FF9900', outline='#232F3E', width=4)  # AWS Orange

# Draw OpsAgent logo
draw.ellipse([48, 48, 144, 144], fill='#232F3E')
draw.ellipse([56, 56, 136, 136], fill='#FF9900')

# Add text
try:
    font_large = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 32)
    font_small = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 16)
except:
    font_large = ImageFont.load_default()
    font_small = ImageFont.load_default()

draw.text((96, 88), 'OA', fill='#232F3E', anchor='mm', font=font_large)
draw.text((96, 118), 'AWS', fill='#232F3E', anchor='mm', font=font_small)

# Add authentication indicator
draw.ellipse([140, 40, 160, 60], fill='#28a745')  # Green dot for auth
draw.text((150, 50), '🔐', fill='white', anchor='mm')

color_img.save('color.png')

# Create outline icon (32x32) with AWS styling
outline_img = Image.new('RGBA', (32, 32), color=(0, 0, 0, 0))
draw = ImageDraw.Draw(outline_img)

# AWS-style outline
draw.rectangle([2, 2, 30, 30], outline='#FF9900', width=2)
draw.ellipse([6, 6, 26, 26], outline='white', width=2)
draw.text((16, 16), 'O', fill='white', anchor='mm')

# Add small auth indicator
draw.ellipse([22, 6, 28, 12], fill='#28a745')

outline_img.save('outline.png')

print("✅ Enhanced AWS-branded icons with auth indicators created")
EOF
fi

# Copy manifest with correct filename for Teams
echo "📝 Preparing manifest file..."
cp teams-app-integrated-auth.json manifest.json

# Package the app with only the required files
echo "📦 Creating Teams app package..."
zip opsagent-integrated-auth.zip manifest.json color.png outline.png

# Clean up temporary manifest file
rm manifest.json

echo "✅ Teams app package created: opsagent-integrated-auth.zip"

# Display package contents
echo ""
echo "📋 Package Contents:"
unzip -l opsagent-integrated-auth.zip

echo ""
echo "🚀 Installation Instructions:"
echo "=============================="
echo ""
echo "1. 📱 Install in Teams:"
echo "   - Open Microsoft Teams"
echo "   - Go to Apps > Upload a custom app"
echo "   - Select: opsagent-integrated-auth.zip"
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