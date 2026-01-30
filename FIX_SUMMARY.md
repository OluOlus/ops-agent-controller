# Fix Summary - Bot Framework Response Format

## Problem Identified ✅

**Issue**: Lambda returns responses in custom JSON format, not Bot Framework Activity format

**Result**: Azure Bot Service receives the response but can't display it in Teams/Web Chat

## Current Response Format (Wrong ❌)

```json
{
  "success": true,
  "data": {
    "message": "🔐 Authentication Required...",
    "channel_data": {...}
  },
  "timestamp": "..."
}
```

## Required Format for Bot Framework (Correct ✅)

```json
{
  "type": "message",
  "from": {
    "id": "28:bot-app-id",
    "name": "OpsAgent AWS"
  },
  "conversation": {
    "id": "conversation-id"
  },
  "recipient": {
    "id": "29:user-id",
    "name": "User Name"
  },
  "text": "🔐 **Authentication Required**\n\nSend `login` to get started.",
  "replyToId": "original-message-id"
}
```

## The Fix

Update `/Users/Olu/vsc/ops-agent-controller/src/main.py` to:

1. Detect Bot Framework requests (Teams/Web Chat)
2. Extract conversation context from incoming Activity
3. Return response in Activity format with proper fields

## Implementation

### Option 1: Quick Fix (Modify main.py)

Add Bot Framework response formatting in `chat_handler`:

```python
def create_bot_framework_response(
    text: str,
    incoming_activity: Dict[str, Any],
    bot_id: str
) -> Dict[str, Any]:
    """Create Bot Framework Activity response"""
    return {
        "type": "message",
        "from": {
            "id": bot_id,
            "name": "OpsAgent AWS"
        },
        "conversation": incoming_activity.get("conversation", {}),
        "recipient": incoming_activity.get("from", {}),
        "text": text,
        "replyToId": incoming_activity.get("id"),
        "serviceUrl": incoming_activity.get("serviceUrl"),
        "channelId": incoming_activity.get("channelId", "msteams")
    }
```

### Option 2: Full Bot Framework SDK

Install Microsoft Bot Framework SDK:
```bash
pip install botbuilder-core botbuilder-schema
```

## Files That Need Changes

1. **src/main.py** - Update `chat_handler` to return Activity format
2. **src/channel_adapters.py** - Update `TeamsChannelAdapter` response formatting
3. **src/requirements.txt** - Add `botbuilder-schema>=4.14.0`

## Testing After Fix

```bash
# Test with Bot Framework format
curl -X POST https://...amazonaws.com/sandbox/chat \
  -H "Content-Type: application/json" \
  -d '{
    "type": "message",
    "text": "health",
    "from": {"id": "user-123", "name": "Test"},
    "conversation": {"id": "conv-123"},
    "channelId": "msteams"
  }'

# Expected response (Bot Framework Activity):
{
  "type": "message",
  "text": "System Status: Healthy",
  "from": {"id": "bot-id", "name": "OpsAgent AWS"},
  "conversation": {"id": "conv-123"},
  "recipient": {"id": "user-123", "name": "Test"}
}
```

## Status

- ✅ Problem identified
- ✅ Solution designed
- ⏳ Implementation needed
- ⏳ Testing needed
- ⏳ Deployment needed

Would you like me to implement this fix now?
