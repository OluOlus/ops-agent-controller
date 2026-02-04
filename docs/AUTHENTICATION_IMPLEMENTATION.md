# Authentication and Authorization Implementation

## Overview

This document describes the comprehensive user authentication and authorization system implemented for the OpsAgent Controller, fulfilling the requirements specified in task 2.1.

## Requirements Fulfilled

- **8.1**: User authentication and authorization with least-privilege execution
- **8.2**: User allow-list validation using SSM Parameter Store  
- **9.1**: Correlation ID tracking for audit purposes
- **Plugin Security**: Request signature validation for Amazon Q Business plugin security

## Components Implemented

### 1. Core Authentication Module (`src/authentication.py`)

#### UserAuthenticator Class
- **Purpose**: Handles user authentication from multiple sources (Amazon Q Business, Teams, Web)
- **Key Features**:
  - User identity extraction from Amazon Q Business context
  - Teams Bot Framework user validation
  - Web/CLI request user extraction
  - User allow-list validation with SSM Parameter Store integration
  - Caching for performance (5-minute TTL)
  - Wildcard domain support (`*@company.com`)

#### RequestSignatureValidator Class
- **Purpose**: Validates request signatures for plugin security
- **Key Features**:
  - Amazon Q Business plugin signature validation using HMAC-SHA256
  - API key validation for direct API calls
  - Teams Bot Framework Bearer token validation
  - Secure signature comparison using constant-time operations

#### Data Models
- **AuthenticationResult**: Encapsulates authentication outcomes
- **AuthorizationResult**: Tracks authorization decisions
- **UserContext**: Enhanced user context with Teams tenant and session tracking

### 2. Integration Points

#### Main Handler Integration (`src/main.py`)
- Updated `chat_handler` to use comprehensive authentication
- Added `plugin_handler` for Amazon Q Business plugin requests
- Enhanced `validate_request_signature` to use new authentication system
- Added missing `auth_callback_handler` for future OAuth flows

#### Enhanced Models (`src/models.py`)
- Added `user_context` field to `InternalMessage` for authentication tracking
- Enhanced serialization/deserialization with user context support

#### Audit Logging (`src/audit_logger.py`)
- Added `log_plugin_request` method for Amazon Q Business plugin audit trails
- Enhanced audit events with user context information

### 3. Authentication Flow

#### Amazon Q Business Plugin Requests
1. **Signature Validation**: Validates HMAC signature using plugin secret from SSM
2. **User Extraction**: Extracts user identity from `user_context` field
3. **Authorization Check**: Validates user against allow-list in SSM Parameter Store
4. **Correlation Tracking**: Generates and tracks correlation IDs for audit

#### Teams Bot Framework Requests
1. **Bearer Token Validation**: Validates JWT token structure and required fields
2. **User Extraction**: Extracts user ID from Teams activity (removes `29:` prefix)
3. **Authorization Check**: Validates user against allow-list
4. **Bot Request Filtering**: Rejects requests from bot applications (`28:` prefix)

#### Web/CLI Requests
1. **API Key Validation**: Validates API key from headers or SSM Parameter Store
2. **User Extraction**: Extracts user ID from request body
3. **Authorization Check**: Validates user against allow-list
4. **Format Validation**: Validates user ID format (email or alphanumeric)

### 4. Security Features

#### User Allow-List Management
- **Storage**: SSM Parameter Store (`/opsagent/user-allow-list`)
- **Format Support**: JSON array or comma-separated values
- **Wildcard Support**: Domain wildcards (`*@company.com`)
- **Caching**: 5-minute TTL to reduce SSM calls
- **Normalization**: Case-insensitive user ID comparison

#### Request Signature Security
- **HMAC-SHA256**: Cryptographically secure signature validation
- **Constant-Time Comparison**: Prevents timing attacks
- **Secret Management**: Plugin secrets stored in SSM Parameter Store
- **Fallback Modes**: Sandbox mode allows requests without signatures for testing

#### Correlation ID Tracking
- **Generation**: UUID4-based correlation IDs for all requests
- **Propagation**: Correlation IDs passed through entire request lifecycle
- **Audit Integration**: All audit events include correlation IDs
- **Error Tracking**: Failed authentication attempts logged with correlation IDs

### 5. Configuration

#### Environment Variables
- `EXECUTION_MODE`: Controls authentication strictness (SANDBOX_LIVE allows fallbacks)
- `API_KEY`: Direct API key (alternative to SSM)
- `API_KEY_PARAMETER`: SSM parameter path for API key
- `USER_ALLOW_LIST_PARAMETER`: SSM parameter path for user allow-list (default: `/opsagent/user-allow-list`)
- `PLUGIN_SECRET_PARAMETER`: SSM parameter path for plugin secret (default: `/opsagent/plugin-secret`)

#### SSM Parameters
- `/opsagent/user-allow-list`: JSON array or comma-separated list of authorized users
- `/opsagent/plugin-secret`: Secret key for Amazon Q Business plugin signature validation
- `/opsagent/api-key`: API key for direct API access (optional)

### 6. Error Handling

#### Authentication Failures
- **Invalid Signatures**: Returns 401 with descriptive error message
- **Unauthorized Users**: Returns 403 with user not authorized message
- **Missing Context**: Returns 400 with missing required fields message
- **System Errors**: Returns 500 with generic error message (details in logs)

#### Fallback Behavior
- **Sandbox Mode**: Allows requests without authentication when `EXECUTION_MODE=SANDBOX_LIVE`
- **Missing Configuration**: Graceful degradation with appropriate error messages
- **SSM Failures**: Cached values used when SSM is temporarily unavailable

### 7. Testing

#### Unit Tests (`tests/test_authentication.py`)
- **UserAuthenticator Tests**: 15+ test cases covering all authentication scenarios
- **RequestSignatureValidator Tests**: 8+ test cases for signature validation
- **Integration Tests**: End-to-end authentication flow validation
- **Model Tests**: UserContext and AuthenticationResult serialization
- **Mock Integration**: Comprehensive mocking of AWS services

#### Test Coverage
- User identity extraction from all sources (Amazon Q, Teams, Web)
- Authorization validation with various allow-list configurations
- Signature validation for all request types
- Error handling and edge cases
- Singleton pattern validation for global instances

### 8. Performance Considerations

#### Caching Strategy
- **User Allow-List**: 5-minute TTL cache to reduce SSM calls
- **Singleton Pattern**: Reuse authenticator and validator instances
- **Lazy Loading**: SSM clients created only when needed

#### Optimization Features
- **Batch Validation**: Single SSM call for user allow-list
- **Early Termination**: Fast failure for obviously invalid requests
- **Minimal Logging**: Structured logging without sensitive data exposure

### 9. Security Best Practices

#### Data Protection
- **Sensitive Data Sanitization**: Passwords, tokens, and secrets never logged
- **Constant-Time Comparison**: Prevents timing attacks on signatures
- **Secure Random Generation**: Cryptographically secure correlation IDs

#### Access Control
- **Least Privilege**: Users only authorized for specific operations
- **Explicit Allow-List**: No default access, all users must be explicitly authorized
- **Audit Trail**: Complete audit log of all authentication attempts

### 10. Future Enhancements

#### Planned Improvements
- **JWT Token Validation**: Full JWT validation for Teams Bot Framework tokens
- **OAuth Integration**: Support for OAuth callback flows
- **Role-Based Access**: Granular permissions beyond simple allow-list
- **Multi-Factor Authentication**: Additional authentication factors for high-risk operations

#### Extensibility Points
- **Custom Authenticators**: Plugin architecture for additional authentication methods
- **External Identity Providers**: Integration with SAML, OIDC providers
- **Dynamic Authorization**: Real-time authorization policy evaluation

## Usage Examples

### Amazon Q Business Plugin Request
```json
{
  "operation": "get_ec2_status",
  "parameters": {
    "instance_id": "i-1234567890abcdef0"
  },
  "user_context": {
    "user_id": "engineer@company.com",
    "teams_tenant": "company.onmicrosoft.com",
    "session_id": "session-123"
  }
}
```

### Teams Bot Framework Activity
```json
{
  "type": "message",
  "text": "get status of i-1234567890abcdef0",
  "from": {
    "id": "29:1234567890abcdef",
    "name": "Platform Engineer"
  },
  "conversation": {
    "id": "19:conversation-id",
    "tenantId": "company.onmicrosoft.com"
  }
}
```

### Web/CLI Request
```json
{
  "userId": "engineer@company.com",
  "messageText": "get status of i-1234567890abcdef0",
  "sessionId": "web-session-123"
}
```

## Conclusion

The authentication and authorization system provides comprehensive security for the OpsAgent Controller while maintaining usability and performance. It supports multiple authentication sources, implements industry-standard security practices, and provides complete audit trails for compliance requirements.

The implementation fulfills all requirements specified in task 2.1 and provides a solid foundation for secure AWS operations through Amazon Q Business integration.