"""
User Authentication and Authorization System for OpsAgent Controller
Requirements: 8.1, 8.2, 9.1
"""
import json
import logging
import os
import hashlib
import hmac
import base64
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import boto3
from botocore.exceptions import ClientError

from models import UserContext, generate_correlation_id

logger = logging.getLogger(__name__)


@dataclass
class AuthenticationResult:
    """
    Result of authentication validation
    Requirements: 8.2, 9.1
    """
    authenticated: bool
    user_context: Optional[UserContext] = None
    error_message: Optional[str] = None
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            "authenticated": self.authenticated,
            "correlation_id": self.correlation_id
        }
        
        if self.user_context:
            result["user_context"] = self.user_context.to_dict()
        
        if self.error_message:
            result["error_message"] = self.error_message
            
        return result


@dataclass
class AuthorizationResult:
    """
    Result of authorization validation
    Requirements: 8.1, 8.2
    """
    authorized: bool
    user_id: str
    permissions: List[str]
    error_message: Optional[str] = None
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "authorized": self.authorized,
            "user_id": self.user_id,
            "permissions": self.permissions,
            "error_message": self.error_message,
            "correlation_id": self.correlation_id
        }


class UserAuthenticator:
    """
    Handles user authentication from Amazon Q Business context and other sources
    Requirements: 8.1, 8.2, 9.1
    """
    
    def __init__(self):
        """Initialize the user authenticator"""
        self.ssm_client = None
        self._user_allow_list_cache = None
        self._cache_expiry = None
        self._cache_ttl_seconds = 300  # 5 minutes cache TTL
        
        logger.info("Initialized UserAuthenticator")
    
    def _get_ssm_client(self) -> boto3.client:
        """Get or create SSM client"""
        if self.ssm_client is None:
            self.ssm_client = boto3.client('ssm')
        return self.ssm_client
    
    def extract_user_identity_from_amazon_q(self, request_data: Dict[str, Any]) -> Tuple[Optional[UserContext], Optional[str]]:
        """
        Extract user identity from Amazon Q Business context
        Requirements: 8.2, 9.1
        
        Args:
            request_data: Raw request data from Amazon Q Business plugin
            
        Returns:
            Tuple of (UserContext, error_message)
        """
        try:
            # Amazon Q Business plugin requests include user context
            user_context_data = request_data.get("user_context", {})
            
            if not user_context_data:
                return None, "Missing user context in Amazon Q Business request"
            
            # Extract user ID (required)
            user_id = user_context_data.get("user_id")
            if not user_id or not isinstance(user_id, str):
                return None, "Missing or invalid user_id in user context"
            
            # Validate user ID format (basic email validation for Amazon Q Business users)
            if not self._is_valid_user_id(user_id):
                return None, f"Invalid user ID format: {user_id}"
            
            # Extract optional fields
            teams_tenant = user_context_data.get("teams_tenant")
            session_id = user_context_data.get("session_id")
            
            # Create user context
            user_context = UserContext(
                user_id=user_id.strip().lower(),  # Normalize to lowercase
                teams_tenant=teams_tenant,
                session_id=session_id
            )
            
            logger.info(f"Extracted user identity from Amazon Q Business: {user_context.user_id}")
            return user_context, None
            
        except Exception as e:
            error_msg = f"Failed to extract user identity from Amazon Q Business context: {str(e)}"
            logger.error(error_msg)
            return None, error_msg
    
    def extract_user_identity_from_teams(self, activity: Dict[str, Any]) -> Tuple[Optional[UserContext], Optional[str]]:
        """
        Extract user identity from Teams Bot Framework Activity
        Requirements: 8.2, 9.1
        
        Args:
            activity: Teams Bot Framework Activity object
            
        Returns:
            Tuple of (UserContext, error_message)
        """
        try:
            # Extract user information from 'from' field
            from_user = activity.get("from", {})
            if not from_user:
                return None, "Missing 'from' field in Teams activity"
            
            # Get user ID from Teams
            user_id = from_user.get("id")
            if not user_id:
                return None, "Missing user ID in Teams activity"
            
            # Teams user IDs are in format "29:user-guid" or "28:app-guid"
            # We want the actual user, not the app
            if user_id.startswith("28:"):
                return None, "Request from bot application, not user"
            
            # Extract the actual user identifier
            if user_id.startswith("29:"):
                # Remove the Teams prefix for cleaner user ID
                clean_user_id = user_id[3:]  # Remove "29:"
            else:
                clean_user_id = user_id
            
            # Extract Teams tenant information from conversation
            conversation = activity.get("conversation", {})
            tenant_id = conversation.get("tenantId")
            
            # Create user context
            user_context = UserContext(
                user_id=clean_user_id.lower(),  # Normalize to lowercase
                teams_tenant=tenant_id,
                session_id=conversation.get("id")  # Use conversation ID as session
            )
            
            logger.info(f"Extracted user identity from Teams: {user_context.user_id}")
            return user_context, None
            
        except Exception as e:
            error_msg = f"Failed to extract user identity from Teams activity: {str(e)}"
            logger.error(error_msg)
            return None, error_msg
    
    def extract_user_identity_from_web(self, request_data: Dict[str, Any]) -> Tuple[Optional[UserContext], Optional[str]]:
        """
        Extract user identity from Web/CLI request
        Requirements: 8.2, 9.1
        
        Args:
            request_data: Raw HTTP request data
            
        Returns:
            Tuple of (UserContext, error_message)
        """
        try:
            # Extract body from HTTP request
            if isinstance(request_data.get("body"), str):
                body = json.loads(request_data["body"])
            else:
                body = request_data.get("body", {})
            
            # Get user ID from request body
            user_id = body.get("userId")
            if not user_id or not isinstance(user_id, str):
                return None, "Missing or invalid userId in request body"
            
            # Validate user ID format
            if not self._is_valid_user_id(user_id):
                return None, f"Invalid user ID format: {user_id}"
            
            # Create user context
            user_context = UserContext(
                user_id=user_id.strip().lower(),  # Normalize to lowercase
                teams_tenant=None,
                session_id=body.get("sessionId")
            )
            
            logger.info(f"Extracted user identity from Web request: {user_context.user_id}")
            return user_context, None
            
        except json.JSONDecodeError as e:
            return None, f"Invalid JSON in request body: {str(e)}"
        except Exception as e:
            error_msg = f"Failed to extract user identity from Web request: {str(e)}"
            logger.error(error_msg)
            return None, error_msg
    
    def authenticate_request(self, request_data: Dict[str, Any], correlation_id: Optional[str] = None) -> AuthenticationResult:
        """
        Authenticate incoming request and extract user context
        Requirements: 8.1, 8.2, 9.1
        
        Args:
            request_data: Raw request data
            correlation_id: Optional correlation ID for tracking
            
        Returns:
            AuthenticationResult with user context if successful
        """
        if not correlation_id:
            correlation_id = generate_correlation_id()
        
        logger.info(f"Authenticating request: {correlation_id}")
        
        try:
            # Determine request type and extract user identity
            user_context = None
            error_message = None
            
            # Check if this is an Amazon Q Business plugin request
            if "user_context" in request_data:
                user_context, error_message = self.extract_user_identity_from_amazon_q(request_data)
            
            # Check if this is a Teams Bot Framework request
            elif self._is_teams_activity(request_data):
                if isinstance(request_data.get("body"), str):
                    activity = json.loads(request_data["body"])
                else:
                    activity = request_data.get("body", request_data)
                
                user_context, error_message = self.extract_user_identity_from_teams(activity)
            
            # Check if this is a Web/CLI request
            elif "body" in request_data:
                user_context, error_message = self.extract_user_identity_from_web(request_data)
            
            else:
                error_message = "Unable to determine request type for authentication"
            
            if not user_context:
                logger.warning(f"Authentication failed: {error_message}")
                return AuthenticationResult(
                    authenticated=False,
                    error_message=error_message or "Failed to extract user identity",
                    correlation_id=correlation_id
                )
            
            # Validate user against allow-list
            is_authorized, auth_error = self.validate_user_authorization(user_context.user_id, correlation_id)
            
            if not is_authorized:
                logger.warning(f"User not authorized: {user_context.user_id} - {auth_error}")
                return AuthenticationResult(
                    authenticated=False,
                    user_context=user_context,
                    error_message=f"User not authorized: {auth_error}",
                    correlation_id=correlation_id
                )
            
            logger.info(f"Authentication successful: {user_context.user_id}")
            return AuthenticationResult(
                authenticated=True,
                user_context=user_context,
                correlation_id=correlation_id
            )
            
        except Exception as e:
            error_msg = f"Authentication error: {str(e)}"
            logger.error(error_msg)
            return AuthenticationResult(
                authenticated=False,
                error_message=error_msg,
                correlation_id=correlation_id
            )
    
    def validate_user_authorization(self, user_id: str, correlation_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate user against allow-list stored in SSM Parameter Store
        Requirements: 8.1, 8.2
        
        Args:
            user_id: User ID to validate
            correlation_id: Optional correlation ID for tracking
            
        Returns:
            Tuple of (is_authorized, error_message)
        """
        try:
            # Get user allow-list from SSM Parameter Store (with caching)
            allow_list = self._get_user_allow_list()
            
            if allow_list is None:
                # If allow-list is not configured, check execution mode
                execution_mode = os.environ.get("EXECUTION_MODE", "SANDBOX_LIVE")
                if execution_mode == "SANDBOX_LIVE":
                    # In sandbox mode, allow all users if no allow-list is configured
                    logger.warning(f"No user allow-list configured, allowing user in sandbox mode: {user_id}")
                    return True, None
                else:
                    return False, "User allow-list not configured and not in sandbox mode"
            
            # Normalize user ID for comparison
            normalized_user_id = user_id.lower().strip()
            
            # Check if user is in allow-list
            if normalized_user_id in allow_list:
                logger.info(f"User authorized via allow-list: {user_id}")
                return True, None
            
            # Check for wildcard domain matches (e.g., "*@company.com")
            if "@" in normalized_user_id:
                user_domain = "@" + normalized_user_id.split("@")[1]
                wildcard_domain = "*" + user_domain
                
                if wildcard_domain in allow_list:
                    logger.info(f"User authorized via domain wildcard: {user_id}")
                    return True, None
            
            logger.warning(f"User not found in allow-list: {user_id}")
            return False, "User not found in authorized user list"
            
        except Exception as e:
            error_msg = f"Failed to validate user authorization: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def _get_user_allow_list(self) -> Optional[List[str]]:
        """
        Get user allow-list from SSM Parameter Store with caching
        Requirements: 8.1, 8.2
        
        Returns:
            List of authorized user IDs, or None if not configured
        """
        try:
            # Check cache first
            current_time = datetime.utcnow()
            if (self._user_allow_list_cache is not None and 
                self._cache_expiry is not None and 
                current_time < self._cache_expiry):
                return self._user_allow_list_cache
            
            # Get parameter name from environment
            allow_list_parameter = os.environ.get("USER_ALLOW_LIST_PARAMETER", "/opsagent/user-allow-list")
            
            # Retrieve from SSM Parameter Store
            ssm_client = self._get_ssm_client()
            response = ssm_client.get_parameter(
                Name=allow_list_parameter,
                WithDecryption=False  # User list doesn't need encryption
            )
            
            # Parse the parameter value (JSON array or comma-separated)
            parameter_value = response['Parameter']['Value'].strip()
            
            if parameter_value.startswith('['):
                # JSON array format
                allow_list = json.loads(parameter_value)
            else:
                # Comma-separated format
                allow_list = [user.strip().lower() for user in parameter_value.split(',') if user.strip()]
            
            # Validate and normalize the allow-list
            normalized_allow_list = []
            for user in allow_list:
                if isinstance(user, str) and user.strip():
                    normalized_user = user.strip().lower()
                    if self._is_valid_user_id(normalized_user) or normalized_user.startswith("*@"):
                        normalized_allow_list.append(normalized_user)
                    else:
                        logger.warning(f"Invalid user ID in allow-list: {user}")
            
            # Update cache
            self._user_allow_list_cache = normalized_allow_list
            self._cache_expiry = current_time + timedelta(seconds=self._cache_ttl_seconds)
            
            logger.info(f"Loaded user allow-list from SSM: {len(normalized_allow_list)} entries")
            return normalized_allow_list
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == 'ParameterNotFound':
                logger.warning(f"User allow-list parameter not found: {allow_list_parameter}")
                return None
            else:
                logger.error(f"Failed to retrieve user allow-list from SSM: {e}")
                return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in user allow-list parameter: {e}")
            return None
        except Exception as e:
            logger.error(f"Error retrieving user allow-list: {e}")
            return None
    
    def _is_teams_activity(self, request_data: Dict[str, Any]) -> bool:
        """
        Check if request is a Teams Bot Framework Activity
        Requirements: 8.2
        
        Args:
            request_data: Raw request data
            
        Returns:
            True if this appears to be a Teams activity
        """
        try:
            # Check for Teams-specific headers
            headers = request_data.get("headers", {})
            auth_header = headers.get("authorization") or headers.get("Authorization", "")
            
            if not auth_header.startswith("Bearer "):
                return False
            
            # Check request body structure
            if isinstance(request_data.get("body"), str):
                body = json.loads(request_data["body"])
            else:
                body = request_data.get("body", {})
            
            # Teams Bot Framework Activity has specific structure
            return (
                body.get("type") == "message" and
                "from" in body and
                "conversation" in body
            )
            
        except (json.JSONDecodeError, TypeError):
            return False
    
    def _is_valid_user_id(self, user_id: str) -> bool:
        """
        Validate user ID format
        Requirements: 8.2
        
        Args:
            user_id: User ID to validate
            
        Returns:
            True if user ID format is valid
        """
        if not user_id or not isinstance(user_id, str):
            return False
        
        user_id = user_id.strip()
        
        # Must not be empty
        if not user_id:
            return False
        
        # Length limits
        if len(user_id) > 256:
            return False
        
        # If it contains @, validate as email format
        if "@" in user_id:
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return re.match(email_pattern, user_id) is not None
        
        # Otherwise, allow alphanumeric with common separators
        import re
        user_pattern = r'^[a-zA-Z0-9._-]+$'
        return re.match(user_pattern, user_id) is not None


class RequestSignatureValidator:
    """
    Validates request signatures for plugin security
    Requirements: 8.1, 9.1
    """
    
    def __init__(self):
        """Initialize the request signature validator"""
        self.ssm_client = None
        logger.info("Initialized RequestSignatureValidator")
    
    def _get_ssm_client(self) -> boto3.client:
        """Get or create SSM client"""
        if self.ssm_client is None:
            self.ssm_client = boto3.client('ssm')
        return self.ssm_client
    
    def validate_plugin_signature(self, request_data: Dict[str, Any], correlation_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate request signature for Amazon Q Business plugin security
        Requirements: 8.1, 9.1
        
        Args:
            request_data: Raw request data
            correlation_id: Optional correlation ID for tracking
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # For Amazon Q Business plugin requests, validate the signature
            headers = request_data.get("headers", {})
            
            # Check for plugin signature header
            plugin_signature = headers.get("x-amazon-q-signature") or headers.get("X-Amazon-Q-Signature")
            
            if not plugin_signature:
                # If no plugin signature, this might be a direct API call
                # Check for API key authentication instead
                return self._validate_api_key(request_data, correlation_id)
            
            # Validate Amazon Q Business plugin signature
            return self._validate_amazon_q_signature(request_data, plugin_signature, correlation_id)
            
        except Exception as e:
            error_msg = f"Signature validation error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def _validate_amazon_q_signature(self, request_data: Dict[str, Any], signature: str, correlation_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate Amazon Q Business plugin signature
        Requirements: 8.1, 9.1
        
        Args:
            request_data: Raw request data
            signature: Plugin signature from header
            correlation_id: Optional correlation ID for tracking
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Get plugin secret from SSM Parameter Store
            plugin_secret = self._get_plugin_secret()
            
            if not plugin_secret:
                # In sandbox mode, allow requests without signature validation
                execution_mode = os.environ.get("EXECUTION_MODE", "SANDBOX_LIVE")
                if execution_mode == "SANDBOX_LIVE":
                    logger.warning("Plugin secret not configured, allowing request in sandbox mode")
                    return True, None
                else:
                    return False, "Plugin secret not configured"
            
            # Extract request body for signature calculation
            body = request_data.get("body", "")
            if isinstance(body, dict):
                body = json.dumps(body, sort_keys=True)
            elif not isinstance(body, str):
                body = str(body)
            
            # Calculate expected signature
            expected_signature = self._calculate_hmac_signature(body, plugin_secret)
            
            # Compare signatures using constant-time comparison
            if hmac.compare_digest(signature, expected_signature):
                logger.info(f"Plugin signature validation successful: {correlation_id}")
                return True, None
            else:
                logger.warning(f"Plugin signature validation failed: {correlation_id}")
                return False, "Invalid plugin signature"
                
        except Exception as e:
            error_msg = f"Plugin signature validation error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def _validate_api_key(self, request_data: Dict[str, Any], correlation_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate API key for direct API calls
        Requirements: 8.1, 9.1
        
        Args:
            request_data: Raw request data
            correlation_id: Optional correlation ID for tracking
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            headers = request_data.get("headers", {})
            api_key = headers.get("x-api-key") or headers.get("X-API-Key")
            
            if not api_key:
                # Check for Teams Bot Framework requests (they use Bearer tokens)
                auth_header = headers.get("authorization") or headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    # This is a Teams Bot Framework request, validate differently
                    return self._validate_teams_bearer_token(request_data, correlation_id)
                
                # In sandbox mode, allow requests without API key
                execution_mode = os.environ.get("EXECUTION_MODE", "SANDBOX_LIVE")
                if execution_mode == "SANDBOX_LIVE":
                    logger.warning("No API key provided, allowing request in sandbox mode")
                    return True, None
                else:
                    return False, "API key required"
            
            # Get expected API key from environment or SSM
            expected_api_key = self._get_api_key()
            
            if not expected_api_key:
                return False, "API key not configured"
            
            # Compare API keys using constant-time comparison
            if hmac.compare_digest(api_key, expected_api_key):
                logger.info(f"API key validation successful: {correlation_id}")
                return True, None
            else:
                logger.warning(f"API key validation failed: {correlation_id}")
                return False, "Invalid API key"
                
        except Exception as e:
            error_msg = f"API key validation error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def _validate_teams_bearer_token(self, request_data: Dict[str, Any], correlation_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Validate Teams Bot Framework Bearer token
        Requirements: 8.1, 9.1
        
        Args:
            request_data: Raw request data
            correlation_id: Optional correlation ID for tracking
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # For MVP, we'll do basic validation of Teams Bot Framework structure
            # In production, we should validate the JWT token properly
            
            # Check if request body looks like Teams Bot Framework Activity
            if isinstance(request_data.get("body"), str):
                body = json.loads(request_data["body"])
            else:
                body = request_data.get("body", {})
            
            # Teams Bot Framework Activity has these required fields
            required_fields = ["type", "id", "from", "conversation"]
            for field in required_fields:
                if field not in body:
                    return False, f"Missing required Teams activity field: {field}"
            
            # Validate it's a message activity
            if body.get("type") != "message":
                return False, f"Unsupported Teams activity type: {body.get('type')}"
            
            logger.info(f"Teams Bearer token validation successful: {correlation_id}")
            return True, None
            
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in Teams activity: {str(e)}"
        except Exception as e:
            error_msg = f"Teams Bearer token validation error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def _get_plugin_secret(self) -> Optional[str]:
        """
        Get plugin secret from SSM Parameter Store
        Requirements: 8.1
        
        Returns:
            Plugin secret string, or None if not configured
        """
        try:
            secret_parameter = os.environ.get("PLUGIN_SECRET_PARAMETER", "/opsagent/plugin-secret")
            
            ssm_client = self._get_ssm_client()
            response = ssm_client.get_parameter(
                Name=secret_parameter,
                WithDecryption=True
            )
            
            return response['Parameter']['Value']
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == 'ParameterNotFound':
                logger.warning(f"Plugin secret parameter not found: {secret_parameter}")
            else:
                logger.error(f"Failed to retrieve plugin secret from SSM: {e}")
            return None
        except Exception as e:
            logger.error(f"Error retrieving plugin secret: {e}")
            return None
    
    def _get_api_key(self) -> Optional[str]:
        """
        Get API key from environment or SSM Parameter Store
        Requirements: 8.1
        
        Returns:
            API key string, or None if not configured
        """
        try:
            # Try environment variable first
            api_key = os.environ.get("API_KEY")
            if api_key:
                return api_key
            
            # Try SSM Parameter Store
            api_key_parameter = os.environ.get("API_KEY_PARAMETER", "/opsagent/api-key")
            
            ssm_client = self._get_ssm_client()
            response = ssm_client.get_parameter(
                Name=api_key_parameter,
                WithDecryption=True
            )
            
            return response['Parameter']['Value']
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == 'ParameterNotFound':
                logger.warning(f"API key parameter not found: {api_key_parameter}")
            else:
                logger.error(f"Failed to retrieve API key from SSM: {e}")
            return None
        except Exception as e:
            logger.error(f"Error retrieving API key: {e}")
            return None
    
    def _calculate_hmac_signature(self, message: str, secret: str) -> str:
        """
        Calculate HMAC-SHA256 signature for message
        Requirements: 8.1, 9.1
        
        Args:
            message: Message to sign
            secret: Secret key for signing
            
        Returns:
            Base64-encoded HMAC signature
        """
        signature = hmac.new(
            secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        return base64.b64encode(signature).decode('utf-8')


# Global instances for reuse
_user_authenticator = None
_signature_validator = None


def get_user_authenticator() -> UserAuthenticator:
    """
    Get or create global UserAuthenticator instance
    Requirements: 8.1, 8.2
    
    Returns:
        UserAuthenticator instance
    """
    global _user_authenticator
    if _user_authenticator is None:
        _user_authenticator = UserAuthenticator()
    return _user_authenticator


def get_signature_validator() -> RequestSignatureValidator:
    """
    Get or create global RequestSignatureValidator instance
    Requirements: 8.1, 9.1
    
    Returns:
        RequestSignatureValidator instance
    """
    global _signature_validator
    if _signature_validator is None:
        _signature_validator = RequestSignatureValidator()
    return _signature_validator


def authenticate_and_authorize_request(request_data: Dict[str, Any], correlation_id: Optional[str] = None) -> AuthenticationResult:
    """
    Convenience function to authenticate and authorize a request
    Requirements: 8.1, 8.2, 9.1
    
    Args:
        request_data: Raw request data
        correlation_id: Optional correlation ID for tracking
        
    Returns:
        AuthenticationResult with user context if successful
    """
    if not correlation_id:
        correlation_id = generate_correlation_id()
    
    # First validate request signature
    signature_validator = get_signature_validator()
    is_valid_signature, signature_error = signature_validator.validate_plugin_signature(request_data, correlation_id)
    
    if not is_valid_signature:
        logger.warning(f"Request signature validation failed: {signature_error}")
        return AuthenticationResult(
            authenticated=False,
            error_message=f"Request signature validation failed: {signature_error}",
            correlation_id=correlation_id
        )
    
    # Then authenticate and authorize user
    authenticator = get_user_authenticator()
    auth_result = authenticator.authenticate_request(request_data, correlation_id)
    
    return auth_result