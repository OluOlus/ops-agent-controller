# Teams Bot Troubleshooting Guide

## Current Status

✅ **Lambda deployed and working**: https://a1gxl8y8wg.execute-api.eu-west-2.amazonaws.com/sandbox/chat
✅ **Azure Bot Service configured**: Endpoint set correctly
✅ **Teams app installed**: Version 1.3.0
❌ **Messages not being received**: When you click "login", nothing happens

## Possible Issues & Solutions

### Issue 1: Teams Channels Not Enabled

**Check**:
1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to: Resource Groups > opsagent-rg > opsagent-live
3. Click **Channels** in the left menu
4. Verify **Microsoft Teams** channel is **enabled**

**Fix if needed**:
- Click **Microsoft Teams** icon
- Click **Save** to enable it

### Issue 2: Bot Service Authentication

Teams uses Bot Framework authentication. The Lambda needs to validate Teams tokens.

**Quick Test**:
Send a test message from Teams Test Web Chat:
1. In Azure Portal, go to your bot (opsagent-live)
2. Click **Test in Web Chat**
3. Type: `login`
4. See if you get a response

If this works, the bot is fine and the issue is with the Teams app configuration.

### Issue 3: Teams App Manifest Issues

The manifest might need updating:

**Check these settings**:
1. Bot ID in manifest matches: `7245659a-25f0-455c-9a75-06451e81fc3e`
2. Valid domains include: `xt3qtho8l6.execute-api.eu-west-2.amazonaws.com`
3. Bot scopes are set correctly

### Issue 4: Missing Bot Permissions

**Required Azure AD permissions**:
- Go to: Azure Portal > App Registrations > OpsAgent
- Click **API permissions**
- Verify you have:
  - Microsoft Graph: `User.Read`
  - Bot Framework: Basic permissions

## Debugging Steps

### Step 1: Enable Diagnostic Logging

```bash
# Enable logging in Azure Bot Service
az bot update \
  --name opsagent-live \
  --resource-group opsagent-rg \
  --set properties.developerAppInsightKey="YOUR_APP_INSIGHTS_KEY"
```

### Step 2: Watch Lambda Logs

```bash
# In one terminal, watch logs
aws logs tail /aws/lambda/opsagent-debug-v2-sandbox \
  --region eu-west-2 \
  --follow \
  --format short
```

Then send a message in Teams and see if ANY logs appear.

### Step 3: Test Direct API Call

```bash
# Test if Lambda receives Teams-format messages
curl -X POST https://a1gxl8y8wg.execute-api.eu-west-2.amazonaws.com/sandbox/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-token" \
  -d '{
    "type": "message",
    "text": "login",
    "from": {
      "id": "test-user-id",
      "name": "Test User"
    },
    "conversation": {
      "id": "test-conversation-id",
      "conversationType": "personal"
    },
    "channelId": "msteams",
    "serviceUrl": "https://smba.trafficmanager.net/emea/"
  }'
```

Expected response: JSON with authentication message

### Step 4: Check Bot Service Activity

In Azure Portal:
1. Go to opsagent-live bot
2. Click **Analytics** (if available)
3. Check if there are any incoming messages

## Common Solutions

### Solution 1: Reinstall Teams App

Sometimes Teams caches the old bot configuration:

1. In Teams, remove the OpsAgent app completely
2. Wait 2 minutes
3. Re-upload `opsagent-teams-app.zip` (version 1.3.0)
4. Try again

### Solution 2: Use Teams Developer Portal

For better debugging:

1. Go to https://dev.teams.microsoft.com
2. Sign in with your account
3. Click **Apps**
4. Import your app zip file
5. Use the built-in testing tools

### Solution 3: Check Service URL Configuration

The Lambda might need to know the Teams service URL. Add this environment variable:

```bash
# Add to Lambda configuration
TEAMS_SERVICE_URL=https://smba.trafficmanager.net/emea/
```

## Still Not Working?

### Quick Workaround: Use Web Interface

While we debug Teams, you can test the bot via curl:

```bash
# Test login command
curl -X POST https://a1gxl8y8wg.execute-api.eu-west-2.amazonaws.com/sandbox/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test" \
  -d '{
    "type": "message",
    "text": "login",
    "from": {"id": "your-email@example.com", "name": "Your Name"},
    "conversation": {"id": "test"}
  }'
```

### Enable Detailed Logging

Let me create a version with more detailed logging to see exactly what Teams is sending:

Would you like me to:
1. ✅ **Enable verbose logging** in the Lambda to see ALL incoming requests?
2. ✅ **Create a simple web interface** to test the bot without Teams?
3. ✅ **Add Bot Framework validation** to properly handle Teams auth?

Let me know and I'll implement the fix!

## Contact Microsoft Teams Support

If none of the above works, the issue might be:
- Teams admin policies blocking custom apps
- Tenant restrictions
- Bot approval required

Check with your Teams admin or Microsoft support.
