# OpsAgent Teams App

This directory contains the Microsoft Teams app package for OpsAgent Controller with integrated AWS authentication.

## 📁 Directory Structure

```
teams-app/
├── README.md              # This file
├── manifest.json          # Teams app manifest
├── create-icons.py        # Script to generate app icons
├── package-teams-app.sh   # Script to package the app
├── color.png             # Generated color icon (192x192)
├── outline.png           # Generated outline icon (32x32)
└── opsagent-teams-app.zip # Generated Teams app package
```

## 🚀 Quick Start

### 1. Package the Teams App

```bash
cd teams-app
./package-teams-app.sh
```

This will:
- Generate the required icons (color.png and outline.png)
- Validate the manifest.json
- Create the opsagent-teams-app.zip package

### 2. Install in Microsoft Teams

1. Open Microsoft Teams
2. Go to **Apps** > **Upload a custom app**
3. Select `opsagent-teams-app.zip`
4. Click **Add** to install

### 3. Start Using OpsAgent

1. Start a chat with **OpsAgent AWS**
2. Send: `login`
3. Complete authentication in the popup
4. Return to Teams and start using AWS commands

## 🔑 Authentication Flow

The Teams app includes seamless AWS authentication:

1. **OAuth Integration**: Uses Azure AD for organization authentication
2. **AWS OIDC Federation**: Automatically assumes AWS roles
3. **Session Management**: 1-hour sessions with automatic expiry
4. **Organization Validation**: Only users from your tenant can access

## 🎯 Available Commands

### Authentication Commands
- `login` - Authenticate with AWS using your organization credentials
- `logout` - Sign out and clear your authentication session
- `whoami` - Show your current AWS identity and session info

### System Commands
- `health` - Check OpsAgent system health and AWS connectivity
- `help` - Show all available commands and usage examples

### AWS Operations
- `describe instance i-xxx` - Get detailed information about an EC2 instance
- `cpu metrics i-xxx` - Get CPU utilization metrics for an EC2 instance
- `cloudwatch metrics` - Get CloudWatch metrics for AWS services
- `reboot instance i-xxx` - Request to reboot an EC2 instance (requires approval)

## 🔧 Configuration

The Teams app is pre-configured with:

- **Bot App ID**: `7245659a-25f0-455c-9a75-06451e81fc3e`
- **Azure Tenant**: `78952f68-6959-4fc9-a579-af36c10eee5c`
- **AWS Endpoint**: `https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox`
- **Valid Domains**: API Gateway and Azure AD login domains

## 🛡️ Security Features

- ✅ **Single Sign-On**: Integrated with your organization's Azure AD
- ✅ **Least Privilege**: AWS access through specific IAM roles
- ✅ **Session Timeout**: Automatic logout after 1 hour
- ✅ **Audit Logging**: All actions logged and audited
- ✅ **Approval Workflows**: Sensitive operations require approval

## 📦 Package Contents

The Teams app package includes:

1. **manifest.json** - Teams app configuration
2. **color.png** - 192x192 color icon with AWS branding
3. **outline.png** - 32x32 outline icon

## 🔄 Updating the App

To update the Teams app:

1. Modify `manifest.json` as needed
2. Update version number in manifest
3. Run `./package-teams-app.sh`
4. Upload the new package to Teams

## 🐛 Troubleshooting

### App Installation Issues
- Ensure the ZIP file contains exactly 3 files: manifest.json, color.png, outline.png
- Check that manifest.json is valid JSON
- Verify all required fields are present in the manifest

### Authentication Issues
- Check that the bot is properly registered in Azure
- Verify the bot app ID matches in both Azure and the manifest
- Ensure the OAuth redirect URI is configured correctly

### Command Issues
- Verify the Lambda function is deployed and accessible
- Check CloudWatch logs for any errors
- Ensure the user is authenticated before running AWS commands

## 📚 Additional Resources

- [Teams App Development Guide](../docs/teams-integration.md)
- [AWS Lambda Deployment Guide](../docs/deployment-guide.md)
- [OpsAgent Controller Documentation](../README.md)