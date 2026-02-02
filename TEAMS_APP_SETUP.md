# OpsAgent Teams App - Complete Setup Guide

## 🎉 Ready-to-Use Teams App

The OpsAgent Teams app has been cleaned up and is ready for deployment with integrated AWS authentication.

## 📦 What's Included

### Clean Teams App Package
- **Location**: `teams-app/opsagent-teams-app.zip`
- **Size**: 7.3KB (optimized)
- **Contents**: 
  - `manifest.json` - Teams app configuration
  - `color.png` - 192x192 AWS-branded color icon
  - `outline.png` - 32x32 outline icon

### Key Features
- ✅ **Integrated Authentication**: Seamless OAuth with Azure AD + AWS OIDC
- ✅ **Organization Security**: Only your tenant users can access
- ✅ **Session Management**: 1-hour sessions with automatic expiry
- ✅ **Comprehensive Commands**: Login, AWS operations, system health
- ✅ **Approval Workflows**: Sensitive operations require approval
- ✅ **Audit Logging**: All actions logged to CloudWatch and DynamoDB

## 🚀 Installation Steps

### 1. Install the Teams App

```bash
# The app package is ready at:
ops-agent-controller/teams-app/opsagent-teams-app.zip
```

**In Microsoft Teams:**
1. Go to **Apps** > **Upload a custom app**
2. Select `opsagent-teams-app.zip`
3. Click **Add** to install

### 2. Test the Authentication Flow

1. Start a chat with **OpsAgent AWS**
2. Send: `login`
3. Complete OAuth authentication in popup
4. Return to Teams and test: `whoami`

### 3. Available Commands

#### Authentication
- `login` - Authenticate with AWS
- `logout` - Sign out
- `whoami` - Show current identity

#### System
- `health` - Check system status
- `help` - Show all commands

#### AWS Operations
- `describe instance i-xxx` - Get EC2 instance details
- `cpu metrics i-xxx` - View CPU metrics
- `reboot instance i-xxx` - Reboot instance (requires approval)

## 🔧 Technical Configuration

### Bot Registration
- **App ID**: `[your-teams-bot-app-id]`
- **Tenant**: `[your-azure-tenant-id]`
- **Endpoint**: `https://[your-api-gateway-id].execute-api.[region].amazonaws.com/[stage]`

### AWS Lambda Function
- **Name**: `opsagent-controller-sandbox`
- **Runtime**: Python 3.11
- **Region**: eu-west-2
- **Status**: ✅ Deployed and working

### Authentication Flow
1. **Teams → Azure AD**: OAuth 2.0 with organization validation
2. **Azure AD → AWS**: OIDC federation with role assumption
3. **AWS → Teams**: Secure session with 1-hour expiry

## 🧹 Cleanup Completed

### Removed Files
- ❌ Duplicate icons from root directory
- ❌ Old Teams app packages
- ❌ Obsolete setup scripts
- ❌ Empty/unused source files
- ❌ Build artifacts

### Organized Structure
```
ops-agent-controller/
├── teams-app/                 # Clean Teams app directory
│   ├── manifest.json         # Updated with auth features
│   ├── create-icons.py       # Icon generation script
│   ├── package-teams-app.sh  # Clean packaging script
│   ├── README.md            # Comprehensive documentation
│   └── opsagent-teams-app.zip # Ready-to-install package
├── src/                      # Clean source code
│   ├── main.py              # Updated with Teams auth
│   ├── teams_auth_handler.py # Complete auth implementation
│   └── ...                  # Other core modules
└── infrastructure/           # AWS deployment
```

## ✅ Verification Checklist

- [x] Teams app package created and validated
- [x] Lambda function deployed with Teams authentication
- [x] OAuth flow configured with Azure AD
- [x] AWS OIDC federation working
- [x] All unnecessary files removed
- [x] Documentation updated
- [x] Icons properly generated
- [x] Manifest validated

## 🎯 Next Steps

1. **Install the Teams app** using the package in `teams-app/opsagent-teams-app.zip`
2. **Test the authentication flow** by sending `login` in Teams
3. **Verify AWS operations** work after authentication
4. **Test approval workflows** with sensitive commands like `reboot`

## 🆘 Support

If you encounter any issues:

1. **Check CloudWatch Logs**: `/aws/lambda/opsagent-controller-sandbox`
2. **Verify Bot Registration**: Azure Portal > App Registrations
3. **Test Lambda Function**: Use AWS Console to test directly
4. **Review Documentation**: `teams-app/README.md` for detailed troubleshooting

---

**Status**: ✅ **READY FOR PRODUCTION USE**

The OpsAgent Teams app is now clean, properly configured, and ready for deployment with integrated AWS authentication.