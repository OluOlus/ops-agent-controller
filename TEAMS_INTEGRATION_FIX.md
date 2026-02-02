# Teams Integration Fix Guide

## Current Status
- ✅ AWS Lambda function deployed and working
- ✅ API Gateway responding: `https://[your-api-gateway-id].execute-api.[region].amazonaws.com/[stage]`
- ✅ Bot Framework authentication fixed (Status 200)
- ❌ **Teams not sending requests to endpoint**

## Root Cause
The issue is **Azure Bot Service configuration** - Teams doesn't know where to send messages because the messaging endpoint is not properly configured in Azure Bot Service.

## Step-by-Step Fix

### 1. Configure Azure Bot Service Messaging Endpoint

**CRITICAL**: This is the main issue that needs to be fixed.

1. **Go to Azure Portal**: https://portal.azure.com
2. **Find your bot**: 
   - Search for "Bot Services" 
   - Look for bot with App ID: `[your-teams-bot-app-id]`
3. **Go to Configuration**:
   - Click on your bot service
   - Navigate to "Configuration" or "Settings"
4. **Set Messaging Endpoint**:
   ```
   https://[your-api-gateway-id].execute-api.[region].amazonaws.com/[stage]/chat
   ```
5. **IMPORTANT**: Click "Save" and wait for confirmation

### 2. Verify Bot Registration Settings

Ensure these exact settings:
- **Bot ID**: `[your-teams-bot-app-id]`
- **Messaging Endpoint**: `https://[your-api-gateway-id].execute-api.[region].amazonaws.com/[stage]/chat`
- **Microsoft App ID**: `[your-teams-bot-app-id]`

### 3. Test Azure Bot Service First

Before testing in Teams, verify the bot service itself:

1. **Go to Azure Portal → Bot Service → Test in Web Chat**
2. **Send a test message**: "health"
3. **Expected result**: Bot should respond
4. **If Web Chat doesn't work**: The bot service itself has issues
5. **If Web Chat works but Teams doesn't**: Teams channel configuration issue

### 4. Verify Teams Channel Configuration

1. **Go to Azure Portal → Bot Service → Channels**
2. **Check Microsoft Teams channel**:
   - Should be **enabled**
   - Click on it to verify configuration
3. **If needed**: Disable and re-enable the Teams channel
4. **Save changes**

### 5. Test Teams Integration

After configuration changes:
1. **Wait 2-3 minutes** for changes to propagate
2. **In Teams, send**: "login"
3. **Expected result**: Bot responds with authentication card
4. **Also test**: "health", "whoami"

## Verification Commands

Test these commands in Teams after fixing:

```
login          # Should show authentication card
health         # Should show system status
whoami         # Should show authentication status
help           # Should show available commands
```

## Troubleshooting

### If Web Chat Test Fails
The bot service itself has issues:
- Check that the messaging endpoint is saved correctly
- Verify the bot app secret is configured
- Check Azure Bot Service logs for errors

### If Web Chat Works but Teams Doesn't
Teams channel configuration issue:
- Disable and re-enable Teams channel
- Check Teams app manifest matches bot ID
- Verify Teams app is properly installed

### If Still Not Working
1. **Check Azure Bot Service Status**:
   - Look for error messages in Azure Portal
   - Check if bot shows as "Running" or "Healthy"

2. **Verify Bot App Registration**:
   - Go to Azure AD → App Registrations
   - Find app ID: `[your-teams-bot-app-id]`
   - Verify it's active and has proper permissions

3. **Check CloudWatch Logs**:
   - Look for incoming requests from Teams
   - If no requests: Azure Bot Service routing issue
   - If requests with errors: Authentication/processing issue

## Current Bot Configuration

Based on the provided information:

```json
{
  "appId": "[your-teams-bot-app-id]",
  "messagingEndpoint": "https://[your-api-gateway-id].execute-api.[region].amazonaws.com/[stage]/chat",
  "replyUrls": [
    "https://[your-api-gateway-id].execute-api.[region].amazonaws.com/[stage]/auth/callback"
  ]
}
```

## Expected Behavior After Fix

Once properly configured:
- Send "login" → Bot responds with authentication card
- Send "health" → Bot shows system status
- Send "whoami" → Bot shows authentication status
- Send AWS commands → Bot processes and responds
- Write operations → Bot requests approval first

## Alternative Testing Method

If you want to test the API directly while fixing Teams:

```bash
curl -X POST "https://[your-api-gateway-id].execute-api.[region].amazonaws.com/[stage]/chat" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-token" \
  -d '{
    "type": "message",
    "id": "test123",
    "from": {"id": "test-user", "name": "Test User"},
    "conversation": {"id": "test-conv"},
    "text": "health",
    "serviceUrl": "https://smba.trafficmanager.net/amer/",
    "channelId": "msteams"
  }'
```

This should return a Bot Framework Activity response.

## Key Points

1. **The AWS side is working correctly** - authentication is fixed
2. **The issue is Azure Bot Service configuration** - messaging endpoint
3. **Teams needs to know where to send messages** - this is configured in Azure Portal
4. **Test Web Chat first** - this isolates bot service vs Teams channel issues
5. **Wait for propagation** - changes take 2-3 minutes to take effect

The fix is straightforward but critical: **configure the messaging endpoint in Azure Bot Service**.