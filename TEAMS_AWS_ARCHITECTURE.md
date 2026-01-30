# Teams to AWS Integration Architecture

## 🏗️ Complete Architecture Overview

```
┌─────────────┐
│   Teams     │
│   User      │
└──────┬──────┘
       │ 1. Send message ("login")
       ▼
┌─────────────────────────────┐
│   Microsoft Teams           │
│   (Client App)              │
└──────┬──────────────────────┘
       │ 2. Teams Bot Framework Protocol
       ▼
┌─────────────────────────────┐
│   Azure Bot Service         │
│   (opsagent-live)           │
│   Bot ID: 7245659a-...      │
│   Endpoint: API Gateway     │
└──────┬──────────────────────┘
       │ 3. HTTPS POST with Bot Framework Activity
       ▼
┌─────────────────────────────┐
│   AWS API Gateway           │
│   (eu-west-2)               │
│   /sandbox/chat             │
└──────┬──────────────────────┘
       │ 4. Invoke Lambda
       ▼
┌─────────────────────────────┐
│   AWS Lambda                │
│   (opsagent-debug-v2)       │
│   - Parse Teams message     │
│   - Process command         │
│   - Call AWS services       │
└──────┬──────────────────────┘
       │ 5. Response back through chain
       ▼
    Teams User sees response
```

## 🔐 Authentication Flow

### Phase 1: Azure AD Authentication

When user clicks "login" in Teams:

```
1. Teams App sends "login" command
   ↓
2. Lambda detects login request
   ↓
3. Lambda creates OAuth URL:
   https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize
   ↓
4. Teams shows authentication popup
   ↓
5. User logs in with Azure AD credentials
   (ops@ooluwafemilimesoftsystem.onmicrosoft.com)
   ↓
6. Azure AD validates user
   ↓
7. Azure AD redirects to:
   https://API_GATEWAY/sandbox/auth/callback?code=xxx
   ↓
8. Lambda exchanges code for Azure AD token
```

### Phase 2: AWS Authentication (OIDC Federation)

```
9. Lambda has Azure AD token
   ↓
10. Use Azure AD token to assume AWS IAM role:
    Role: OpsAgent-Teams-User-Role
    Trust: Azure AD OIDC Provider
   ↓
11. AWS STS validates Azure token
    - Checks tenant ID matches
    - Verifies user is authorized
   ↓
12. AWS STS issues temporary credentials:
    - Access Key
    - Secret Key
    - Session Token
    - Valid for 1 hour
   ↓
13. Lambda stores session for user:
    {
      "teamsUserId": "xxx",
      "awsAccessKey": "ASIA...",
      "awsSecretKey": "...",
      "awsSessionToken": "...",
      "expiresAt": "2026-01-30T13:00:00Z"
    }
```

### Phase 3: Authenticated AWS Operations

```
User sends: "describe instance i-12345"
   ↓
1. Lambda checks if user has valid session
   ↓
2. If yes, use stored AWS credentials
   ↓
3. Make AWS API call:
   ec2.describe_instances(InstanceIds=['i-12345'])
   ↓
4. Return results to user in Teams
```

## 📡 Message Flow Details

### Step 1: Teams Sends Message

When you type a message in Teams, it sends this to Azure:

```json
{
  "type": "message",
  "id": "unique-message-id",
  "timestamp": "2026-01-30T12:00:00Z",
  "channelId": "msteams",
  "from": {
    "id": "29:user-id-in-teams",
    "name": "Your Name",
    "aadObjectId": "azure-ad-user-id"
  },
  "conversation": {
    "id": "conversation-id",
    "conversationType": "personal"
  },
  "recipient": {
    "id": "28:bot-id",
    "name": "OpsAgent AWS"
  },
  "text": "login",
  "serviceUrl": "https://smba.trafficmanager.net/emea/"
}
```

### Step 2: Azure Bot Service Processes

Azure Bot Service:
1. Validates the message is from authentic Teams
2. Adds Bot Framework authentication header
3. Forwards to your configured endpoint

### Step 3: API Gateway Receives Request

```http
POST /sandbox/chat HTTP/1.1
Host: a1gxl8y8wg.execute-api.eu-west-2.amazonaws.com
Content-Type: application/json
Authorization: Bearer <teams-bot-framework-token>

{
  "type": "message",
  "text": "login",
  ...
}
```

### Step 4: Lambda Processes

```python
# Lambda handler flow
1. Detect it's a Teams message (channelId: "msteams")
2. Skip API key auth for Teams
3. Parse the Bot Framework Activity
4. Extract user ID and message text
5. Process command ("login")
6. Generate response
7. Format for Teams (with markdown, buttons, etc.)
8. Return JSON response
```

### Step 5: Response Returns to Teams

```json
{
  "type": "message",
  "text": "🔑 **Authenticate with AWS**\n\nClick the button below to log in...",
  "attachments": [
    {
      "contentType": "application/vnd.microsoft.card.adaptive",
      "content": {
        "type": "AdaptiveCard",
        "actions": [
          {
            "type": "Action.OpenUrl",
            "title": "Login",
            "url": "https://login.microsoftonline.com/..."
          }
        ]
      }
    }
  ]
}
```

## 🔑 Current Configuration

### Azure Components

| Component | Value |
|-----------|-------|
| **Tenant ID** | 78952f68-6959-4fc9-a579-af36c10eee5c |
| **Bot App ID** | 7245659a-25f0-455c-9a75-06451e81fc3e |
| **Bot Name** | opsagent-live |
| **Resource Group** | opsagent-rg |
| **Subscription** | 4753c8c5-c458-4451-9736-51c667874b6f |

### AWS Components

| Component | Value |
|-----------|-------|
| **Account ID** | 612176863084 |
| **Region** | eu-west-2 |
| **Lambda** | opsagent-debug-v2-sandbox |
| **API Gateway** | a1gxl8y8wg |
| **Chat Endpoint** | /sandbox/chat |

### Connection Configuration

```yaml
Azure Bot Service:
  Messaging Endpoint: https://a1gxl8y8wg.execute-api.eu-west-2.amazonaws.com/sandbox/chat

Teams App Manifest:
  Bot ID: 7245659a-25f0-455c-9a75-06451e81fc3e
  Valid Domains:
    - xt3qtho8l6.execute-api.eu-west-2.amazonaws.com
    - login.microsoftonline.com

Lambda Environment:
  TEAMS_BOT_APP_ID: 7245659a-25f0-455c-9a75-06451e81fc3e
  AZURE_TENANT_ID: 78952f68-6959-4fc9-a579-af36c10eee5c
  AWS_ACCOUNT_ID: 612176863084
```

## 🔒 Security Layers

### Layer 1: Teams to Azure
- Teams validates user is authenticated
- Only users in your tenant can access the bot
- Messages encrypted with TLS 1.3

### Layer 2: Azure to AWS
- Bot Framework adds authentication token
- API Gateway validates HTTPS
- Lambda validates request format

### Layer 3: AWS API Calls
- User must authenticate with Azure AD
- Azure AD token exchanged for AWS credentials
- AWS credentials are temporary (1 hour)
- All operations tagged with user identity

### Layer 4: AWS Resource Access
- IAM policies enforce least privilege
- Only resources tagged `OpsAgentManaged=true` can be modified
- All operations logged to CloudWatch & DynamoDB
- Approval required for write operations

## 🚫 What's NOT Working (Current Issue)

The connection chain has a problem:

```
✅ Teams App installed
❌ Teams → Azure Bot Service (No messages being sent)
✅ Azure Bot Service → AWS Lambda (Endpoint configured)
✅ AWS Lambda processing (Tested with curl)
✅ AWS operations (IAM permissions OK)
```

**The break is at step 2**: Teams isn't sending messages to Azure Bot Service

### Possible Causes:

1. **Teams App Configuration**
   - App manifest might have wrong bot ID
   - Bot might not be properly linked

2. **Azure Bot Service**
   - Might need additional configuration
   - Channel might not be fully activated

3. **Bot Framework Authentication**
   - Teams might be rejecting responses from Lambda
   - Lambda might need to sign responses with bot secret

## 🔧 How It SHOULD Work

### Example: User sends "describe instance i-12345"

```
Step 1: Message Sent
─────────────────────
User types in Teams: "describe instance i-12345"
Teams client → Azure Bot Service

Step 2: Azure Processing
─────────────────────
Azure Bot Service validates message
Azure adds authentication headers
Azure → AWS API Gateway (POST /sandbox/chat)

Step 3: Lambda Processing
─────────────────────
API Gateway → Lambda
Lambda receives:
{
  "type": "message",
  "text": "describe instance i-12345",
  "from": {"id": "user-123", "name": "User"},
  ...
}

Lambda checks:
1. Is user authenticated? (Check session store)
2. Does user have valid AWS credentials?
3. Parse command: "describe instance i-12345"
4. Call AWS API: ec2.describe_instances()

Step 4: AWS API Call
─────────────────────
Using user's temporary AWS credentials:
ec2 = boto3.client('ec2',
    aws_access_key_id=user_session.access_key,
    aws_secret_access_key=user_session.secret_key,
    aws_session_token=user_session.session_token
)

result = ec2.describe_instances(InstanceIds=['i-12345'])

Step 5: Format Response
─────────────────────
Lambda formats result for Teams:
{
  "type": "message",
  "text": "**Instance: i-12345**\n" +
          "State: running\n" +
          "Type: t3.medium\n" +
          "IP: 10.0.1.50",
  "attachments": [...]
}

Step 6: Return to User
─────────────────────
Lambda → API Gateway → Azure Bot Service → Teams → User
```

## 🎯 Required Setup (Already Done ✅)

1. ✅ Azure AD App Registration created
2. ✅ Azure Bot Service created and configured
3. ✅ AWS Lambda deployed
4. ✅ API Gateway endpoint configured
5. ✅ Bot Service messaging endpoint set
6. ✅ Teams app manifest created
7. ✅ OAuth redirect URI configured

## ❓ Missing Piece

The missing piece is likely **Bot Framework token validation**.

When Azure Bot Service sends messages to your Lambda, it includes a JWT token in the Authorization header. Your Lambda needs to:

1. Extract the token
2. Validate it's signed by Microsoft
3. Verify it's for your bot ID
4. Accept the message

Currently, the Lambda skips this validation for Teams requests, which is OK for receiving messages, but Teams might reject responses if the Lambda doesn't sign them properly.

## 🔍 Next Steps to Debug

1. **Test in Azure Web Chat**
   - If this works: Issue is Teams-specific
   - If this doesn't work: Issue is Lambda/Bot Framework

2. **Enable detailed logging**
   - See if ANY requests arrive from Teams

3. **Implement proper Bot Framework auth**
   - Add Microsoft Bot Framework SDK
   - Validate incoming tokens
   - Sign outgoing messages

Would you like me to implement proper Bot Framework authentication in the Lambda?
