# Teams App AWS Authentication - GUI Setup Guide

This guide walks you through setting up the Teams app with proper AWS authentication using the Azure Portal and Teams Admin Center GUIs.

## Prerequisites
- Azure Portal access with App Registration permissions
- Teams Admin Center access
- AWS Console access with IAM permissions
- Bot App ID: `7245659a-25f0-455c-9a75-06451e81fc3e`

## Step 1: Configure Azure App Registration for AWS Authentication

### 1.1 Open Azure Portal
1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** > **App registrations**
3. Find your app: `opsagent-live` (App ID: `7245659a-25f0-455c-9a75-06451e81fc3e`)

### 1.2 Configure Authentication
1. Click on your app registration
2. Go to **Authentication** in the left menu
3. Click **+ Add a platform**
4. Select **Web**
5. Add these Redirect URIs:
   ```
   https://token.botframework.com/.auth/web/redirect
   https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/auth/callback
   ```
6. Check **Access tokens** and **ID tokens**
7. Click **Configure**

### 1.3 Add API Permissions
1. Go to **API permissions** in the left menu
2. Click **+ Add a permission**
3. Select **Microsoft Graph**
4. Choose **Delegated permissions**
5. Add these permissions:
   - `User.Read` (to read user profile)
   - `Organization.Read.All` (to verify organization membership)
   - `Directory.Read.All` (to read directory information)
6. Click **Add permissions**
7. Click **Grant admin consent** for your organization

### 1.4 Configure Certificates & Secrets
1. Go to **Certificates & secrets**
2. Under **Client secrets**, click **+ New client secret**
3. Description: `OpsAgent Teams AWS Integration`
4. Expires: `24 months`
5. Click **Add**
6. **Copy the secret value** - you'll need this later

## Step 2: Set up AWS OIDC Identity Provider

### 2.1 Open AWS IAM Console
1. Go to [AWS IAM Console](https://console.aws.amazon.com/iam/)
2. Navigate to **Identity providers** in the left menu
3. Click **Add provider**

### 2.2 Configure OIDC Provider
1. Provider type: **OpenID Connect**
2. Provider URL: `https://login.microsoftonline.com/78952f68-6959-4fc9-a579-af36c10eee5c`
3. Audience: `7245659a-25f0-455c-9a75-06451e81fc3e`
4. Click **Get thumbprint**
5. Click **Add provider**

### 2.3 Create IAM Role for Teams Users
1. Go to **Roles** in IAM
2. Click **Create role**
3. Select **Web identity**
4. Identity provider: Select the OIDC provider you just created
5. Audience: `7245659a-25f0-455c-9a75-06451e81fc3e`
6. Click **Next**
7. Attach these policies:
   - `CloudWatchReadOnlyAccess`
   - `EC2ReadOnlyAccess`
   - Create custom policy for limited EC2 actions (see below)
8. Role name: `OpsAgent-Teams-User-Role`
9. Click **Create role**

### 2.4 Custom Policy for EC2 Actions
Create a custom policy with these permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceStatus",
                "ec2:RebootInstances"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": "eu-west-2"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:GetMetricStatistics",
                "cloudwatch:ListMetrics"
            ],
            "Resource": "*"
        }
    ]
}
```

## Step 3: Configure Bot Framework OAuth Connection

### 3.1 Open Azure Bot Service
1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Resource groups** > `opsagent-rg`
3. Click on your bot service: `opsagent-live`

### 3.2 Add OAuth Connection
1. In the bot service, go to **Configuration** > **OAuth Connection Settings**
2. Click **+ Add Setting**
3. Fill in the details:
   - **Name**: `AWSConnection`
   - **Service Provider**: `Azure Active Directory v2`
   - **Client ID**: `7245659a-25f0-455c-9a75-06451e81fc3e`
   - **Client Secret**: (the secret you copied earlier)
   - **Tenant ID**: `78952f68-6959-4fc9-a579-af36c10eee5c`
   - **Scopes**: `openid profile User.Read Organization.Read.All`
4. Click **Save**

### 3.3 Test OAuth Connection
1. Click **Test Connection** next to your OAuth setting
2. Complete the sign-in flow
3. Verify you get a success message

## Step 4: Update Teams App Manifest

### 4.1 Create Enhanced Manifest
Create a new manifest file with OAuth support:

```json
{
  "$schema": "https://developer.microsoft.com/en-us/json-schemas/teams/v1.16/MicrosoftTeams.schema.json",
  "manifestVersion": "1.16",
  "version": "1.0.2",
  "id": "7245659a-25f0-455c-9a75-06451e81fc3e",
  "packageName": "com.opsagent.aws.controller",
  "developer": {
    "name": "OpsAgent Team",
    "websiteUrl": "https://github.com/opsagent/controller",
    "privacyUrl": "https://github.com/opsagent/controller/privacy",
    "termsOfUseUrl": "https://github.com/opsagent/controller/terms"
  },
  "name": {
    "short": "OpsAgent AWS",
    "full": "OpsAgent Controller - Secure AWS Operations"
  },
  "description": {
    "short": "Secure AWS operations with organizational authentication",
    "full": "OpsAgent Controller provides secure AWS operations management through Teams with proper authentication, authorization, and audit logging for your organization."
  },
  "icons": {
    "outline": "outline.png",
    "color": "color.png"
  },
  "accentColor": "#FF6B35",
  "bots": [
    {
      "botId": "7245659a-25f0-455c-9a75-06451e81fc3e",
      "scopes": ["personal", "team", "groupchat"],
      "commandLists": [
        {
          "scopes": ["personal", "team", "groupchat"],
          "commands": [
            {
              "title": "login",
              "description": "Authenticate with AWS using your organization credentials"
            },
            {
              "title": "health",
              "description": "Check system health and AWS connectivity"
            },
            {
              "title": "whoami",
              "description": "Show your current AWS identity and permissions"
            },
            {
              "title": "describe instance i-xxx",
              "description": "Get EC2 instance details"
            },
            {
              "title": "cpu metrics i-xxx",
              "description": "Get CPU metrics for an instance"
            },
            {
              "title": "reboot instance i-xxx",
              "description": "Request instance reboot (requires approval)"
            },
            {
              "title": "logout",
              "description": "Sign out and clear authentication"
            }
          ]
        }
      ],
      "isNotificationOnly": false
    }
  ],
  "permissions": [
    "identity",
    "messageTeamMembers"
  ],
  "validDomains": [
    "xt3qtho8l6.execute-api.eu-west-2.amazonaws.com",
    "login.microsoftonline.com",
    "token.botframework.com"
  ],
  "webApplicationInfo": {
    "id": "7245659a-25f0-455c-9a75-06451e81fc3e",
    "resource": "https://RscBasedStoreApp"
  }
}
```

### 4.2 Package and Upload to Teams
1. Create a new ZIP file with:
   - Updated manifest.json
   - color.png (192x192)
   - outline.png (32x32)
2. Go to [Teams Admin Center](https://admin.teams.microsoft.com)
3. Navigate to **Teams apps** > **Manage apps**
4. Click **Upload new app**
5. Select your ZIP file
6. Review and approve the app

## Step 5: Configure Organizational Permissions

### 5.1 Set App Permissions
1. In Teams Admin Center, find your uploaded app
2. Click on the app name
3. Go to **Permissions** tab
4. Configure these settings:
   - **Availability**: Specific users/groups
   - **Users**: Add authorized AWS operators
   - **Groups**: Add your operations team group

### 5.2 Configure App Policies
1. Go to **Teams apps** > **Permission policies**
2. Create a new policy: `OpsAgent-AWS-Policy`
3. Allow your custom app
4. Assign this policy to authorized users

## Step 6: Test the Integration

### 6.1 Install App in Teams
1. Open Microsoft Teams
2. Go to **Apps**
3. Search for "OpsAgent AWS"
4. Click **Add**
5. Start a conversation with the bot

### 6.2 Test Authentication Flow
1. Send message: `login`
2. Bot should respond with authentication link
3. Complete OAuth flow
4. Verify you're authenticated: `whoami`
5. Test AWS operation: `health`

## Step 7: Monitor and Troubleshoot

### 7.1 Check Bot Analytics
1. Azure Portal > Bot Service > Analytics
2. Monitor conversation flow
3. Check for authentication errors

### 7.2 AWS CloudTrail
1. Monitor AWS API calls from Teams users
2. Verify proper role assumption
3. Check for permission issues

### 7.3 Teams Admin Center
1. Monitor app usage
2. Check user feedback
3. Review permission grants

## Security Considerations

1. **Principle of Least Privilege**: Only grant minimum required AWS permissions
2. **Conditional Access**: Use Azure AD conditional access policies
3. **Session Management**: Configure appropriate token lifetimes
4. **Audit Logging**: Enable comprehensive logging in both Azure and AWS
5. **Regular Reviews**: Periodically review user access and permissions

## Troubleshooting Common Issues

### Authentication Fails
- Check OAuth connection configuration
- Verify redirect URIs are correct
- Ensure admin consent is granted

### AWS Access Denied
- Verify OIDC provider configuration
- Check IAM role trust policy
- Confirm user has required Azure AD permissions

### Bot Not Responding
- Check bot endpoint configuration
- Verify Lambda function is running
- Review CloudWatch logs for errors

## Next Steps

After completing this setup:
1. Update Lambda function to handle OAuth tokens
2. Implement user session management
3. Add organizational validation logic
4. Deploy to production environment
5. Train users on the authentication flow