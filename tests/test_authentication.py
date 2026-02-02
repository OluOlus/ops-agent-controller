"""
Unit tests for authentication and authorization system
Requirements: 8.1, 8.2, 9.1
"""
import json
import os
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from authentication import (
    UserAuthenticator, 
    RequestSignatureValidator, 
    AuthenticationResult,
    authenticate_and_authorize_request,
    get_user_authenticator,
    get_signature_validator
)
from src.models import UserContext, PluginRequest, generate_correlation_id


class TestUserAuthenticator:
    """Test cases for UserAuthenticator class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.authenticator = UserAuthenticator()
        self.correlation_id = generate_correlation_id()
    
    def test_extract_user_identity_from_amazon_q_success(self):
        """Test successful user identity extraction from Amazon Q Business context"""
        request_data = {
            "user_context": {
                "user_id": "test.user@company.com",
                "teams_tenant": "company.onmicrosoft.com",
                "session_id": "session-123"
            }
        }
        
        user_context, error = self.authenticator.extract_user_identity_from_amazon_q(request_data)
        
        assert user_context is not None
        assert error is None
        assert user_context.user_id == "test.user@company.com"
        assert user_context.teams_tenant == "company.onmicrosoft.com"
        assert user_context.session_id == "session-123"
    
    def test_extract_user_identity_from_amazon_q_missing_context(self):
        """Test user identity extraction with missing user context"""
        request_data = {}
        
        user_context, error = self.authenticator.extract_user_identity_from_amazon_q(request_data)
        
        assert user_context is None
        assert "Missing user context" in error
    
    def test_extract_user_identity_from_amazon_q_invalid_user_id(self):
        """Test user identity extraction with invalid user ID"""
        request_data = {
            "user_context": {
                "user_id": "",  # Empty user ID
                "teams_tenant": "company.onmicrosoft.com"
            }
        }
        
        user_context, error = self.authenticator.extract_user_identity_from_amazon_q(request_data)
        
        assert user_context is None
        assert "Missing or invalid user_id" in error
    
    def test_extract_user_identity_from_teams_success(self):
        """Test successful user identity extraction from Teams activity"""
        activity = {
            "type": "message",
            "from": {
                "id": "29:1234567890abcdef",
                "name": "Test User"
            },
            "conversation": {
                "id": "19:conversation-id",
                "tenantId": "company.onmicrosoft.com"
            }
        }
        
        user_context, error = self.authenticator.extract_user_identity_from_teams(activity)
        
        assert user_context is not None
        assert error is None
        assert user_context.user_id == "1234567890abcdef"  # Teams prefix removed
        assert user_context.teams_tenant == "company.onmicrosoft.com"
        assert user_context.session_id == "19:conversation-id"
    
    def test_extract_user_identity_from_teams_bot_request(self):
        """Test Teams identity extraction rejects bot requests"""
        activity = {
            "type": "message",
            "from": {
                "id": "28:bot-app-id",  # Bot application ID
                "name": "Bot App"
            },
            "conversation": {
                "id": "19:conversation-id"
            }
        }
        
        user_context, error = self.authenticator.extract_user_identity_from_teams(activity)
        
        assert user_context is None
        assert "Request from bot application" in error
    
    def test_extract_user_identity_from_web_success(self):
        """Test successful user identity extraction from web request"""
        request_data = {
            "body": json.dumps({
                "userId": "test.user@company.com",
                "sessionId": "web-session-123"
            })
        }
        
        user_context, error = self.authenticator.extract_user_identity_from_web(request_data)
        
        assert user_context is not None
        assert error is None
        assert user_context.user_id == "test.user@company.com"
        assert user_context.session_id == "web-session-123"
    
    def test_extract_user_identity_from_web_missing_user_id(self):
        """Test web identity extraction with missing user ID"""
        request_data = {
            "body": json.dumps({
                "sessionId": "web-session-123"
            })
        }
        
        user_context, error = self.authenticator.extract_user_identity_from_web(request_data)
        
        assert user_context is None
        assert "Missing or invalid userId" in error
    
    @patch('src.authentication.boto3.client')
    def test_validate_user_authorization_success(self, mock_boto3_client):
        """Test successful user authorization validation"""
        # Mock SSM client
        mock_ssm = Mock()
        mock_boto3_client.return_value = mock_ssm
        mock_ssm.get_parameter.return_value = {
            'Parameter': {
                'Value': '["test.user@company.com", "admin@company.com"]'
            }
        }
        
        is_authorized, error = self.authenticator.validate_user_authorization("test.user@company.com", self.correlation_id)
        
        assert is_authorized is True
        assert error is None
    
    @patch('src.authentication.boto3.client')
    def test_validate_user_authorization_not_in_list(self, mock_boto3_client):
        """Test user authorization validation for user not in allow-list"""
        # Mock SSM client
        mock_ssm = Mock()
        mock_boto3_client.return_value = mock_ssm
        mock_ssm.get_parameter.return_value = {
            'Parameter': {
                'Value': '["admin@company.com", "manager@company.com"]'
            }
        }
        
        is_authorized, error = self.authenticator.validate_user_authorization("test.user@company.com", self.correlation_id)
        
        assert is_authorized is False
        assert "User not found in authorized user list" in error
    
    @patch('src.authentication.boto3.client')
    def test_validate_user_authorization_wildcard_domain(self, mock_boto3_client):
        """Test user authorization validation with wildcard domain"""
        # Mock SSM client
        mock_ssm = Mock()
        mock_boto3_client.return_value = mock_ssm
        mock_ssm.get_parameter.return_value = {
            'Parameter': {
                'Value': '["*@company.com", "admin@external.com"]'
            }
        }
        
        is_authorized, error = self.authenticator.validate_user_authorization("test.user@company.com", self.correlation_id)
        
        assert is_authorized is True
        assert error is None
    
    @patch.dict(os.environ, {'EXECUTION_MODE': 'SANDBOX_LIVE'})
    @patch('src.authentication.boto3.client')
    def test_validate_user_authorization_sandbox_mode_no_config(self, mock_boto3_client):
        """Test user authorization in sandbox mode with no allow-list configured"""
        # Mock SSM client to raise ParameterNotFound
        mock_ssm = Mock()
        mock_boto3_client.return_value = mock_ssm
        from botocore.exceptions import ClientError
        mock_ssm.get_parameter.side_effect = ClientError(
            {'Error': {'Code': 'ParameterNotFound'}}, 'GetParameter'
        )
        
        is_authorized, error = self.authenticator.validate_user_authorization("test.user@company.com", self.correlation_id)
        
        assert is_authorized is True  # Should allow in sandbox mode
        assert error is None
    
    def test_is_valid_user_id_email_format(self):
        """Test user ID validation for email format"""
        assert self.authenticator._is_valid_user_id("test.user@company.com") is True
        assert self.authenticator._is_valid_user_id("user123@example.org") is True
        assert self.authenticator._is_valid_user_id("invalid-email") is False
        assert self.authenticator._is_valid_user_id("@company.com") is False
        assert self.authenticator._is_valid_user_id("user@") is False
    
    def test_is_valid_user_id_alphanumeric_format(self):
        """Test user ID validation for alphanumeric format"""
        assert self.authenticator._is_valid_user_id("user123") is True
        assert self.authenticator._is_valid_user_id("test_user") is True
        assert self.authenticator._is_valid_user_id("user-name") is True
        assert self.authenticator._is_valid_user_id("user.name") is True
        assert self.authenticator._is_valid_user_id("user@name!") is False  # Invalid characters
        assert self.authenticator._is_valid_user_id("") is False  # Empty
    
    def test_is_teams_activity_valid(self):
        """Test Teams activity detection"""
        request_data = {
            "headers": {
                "Authorization": "Bearer jwt-token"
            },
            "body": json.dumps({
                "type": "message",
                "from": {"id": "29:user-id"},
                "conversation": {"id": "19:conv-id"}
            })
        }
        
        assert self.authenticator._is_teams_activity(request_data) is True
    
    def test_is_teams_activity_invalid(self):
        """Test Teams activity detection with invalid structure"""
        request_data = {
            "headers": {
                "Authorization": "Bearer jwt-token"
            },
            "body": json.dumps({
                "type": "message",
                # Missing required fields
            })
        }
        
        assert self.authenticator._is_teams_activity(request_data) is False
    
    @patch('src.authentication.boto3.client')
    def test_authenticate_request_amazon_q_success(self, mock_boto3_client):
        """Test successful authentication of Amazon Q Business request"""
        # Mock SSM client for user authorization
        mock_ssm = Mock()
        mock_boto3_client.return_value = mock_ssm
        mock_ssm.get_parameter.return_value = {
            'Parameter': {
                'Value': '["test.user@company.com"]'
            }
        }
        
        request_data = {
            "user_context": {
                "user_id": "test.user@company.com",
                "teams_tenant": "company.onmicrosoft.com"
            }
        }
        
        result = self.authenticator.authenticate_request(request_data, self.correlation_id)
        
        assert result.authenticated is True
        assert result.user_context is not None
        assert result.user_context.user_id == "test.user@company.com"
        assert result.error_message is None
    
    @patch('src.authentication.boto3.client')
    def test_authenticate_request_unauthorized_user(self, mock_boto3_client):
        """Test authentication failure for unauthorized user"""
        # Mock SSM client for user authorization
        mock_ssm = Mock()
        mock_boto3_client.return_value = mock_ssm
        mock_ssm.get_parameter.return_value = {
            'Parameter': {
                'Value': '["admin@company.com"]'  # Different user
            }
        }
        
        request_data = {
            "user_context": {
                "user_id": "test.user@company.com",
                "teams_tenant": "company.onmicrosoft.com"
            }
        }
        
        result = self.authenticator.authenticate_request(request_data, self.correlation_id)
        
        assert result.authenticated is False
        assert result.user_context is not None  # User context extracted but not authorized
        assert "User not authorized" in result.error_message


class TestRequestSignatureValidator:
    """Test cases for RequestSignatureValidator class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.validator = RequestSignatureValidator()
        self.correlation_id = generate_correlation_id()
    
    def test_validate_teams_bearer_token_success(self):
        """Test successful Teams Bearer token validation"""
        request_data = {
            "headers": {
                "Authorization": "Bearer jwt-token"
            },
            "body": json.dumps({
                "type": "message",
                "id": "activity-id",
                "from": {"id": "29:user-id"},
                "conversation": {"id": "19:conv-id"}
            })
        }
        
        is_valid, error = self.validator._validate_teams_bearer_token(request_data, self.correlation_id)
        
        assert is_valid is True
        assert error is None
    
    def test_validate_teams_bearer_token_invalid_activity(self):
        """Test Teams Bearer token validation with invalid activity"""
        request_data = {
            "headers": {
                "Authorization": "Bearer jwt-token"
            },
            "body": json.dumps({
                "type": "message",
                # Missing required fields
            })
        }
        
        is_valid, error = self.validator._validate_teams_bearer_token(request_data, self.correlation_id)
        
        assert is_valid is False
        assert "Missing required Teams activity field" in error
    
    @patch.dict(os.environ, {'API_KEY': 'test-api-key'})
    def test_validate_api_key_success(self):
        """Test successful API key validation"""
        request_data = {
            "headers": {
                "X-API-Key": "test-api-key"
            }
        }
        
        is_valid, error = self.validator._validate_api_key(request_data, self.correlation_id)
        
        assert is_valid is True
        assert error is None
    
    @patch.dict(os.environ, {'API_KEY': 'test-api-key'})
    def test_validate_api_key_invalid(self):
        """Test API key validation with invalid key"""
        request_data = {
            "headers": {
                "X-API-Key": "wrong-api-key"
            }
        }
        
        is_valid, error = self.validator._validate_api_key(request_data, self.correlation_id)
        
        assert is_valid is False
        assert "Invalid API key" in error
    
    @patch.dict(os.environ, {'EXECUTION_MODE': 'SANDBOX_LIVE'})
    def test_validate_api_key_sandbox_mode_no_key(self):
        """Test API key validation in sandbox mode without key"""
        request_data = {
            "headers": {}
        }
        
        is_valid, error = self.validator._validate_api_key(request_data, self.correlation_id)
        
        assert is_valid is True  # Should allow in sandbox mode
        assert error is None
    
    def test_calculate_hmac_signature(self):
        """Test HMAC signature calculation"""
        message = "test message"
        secret = "test-secret"
        
        signature = self.validator._calculate_hmac_signature(message, secret)
        
        assert isinstance(signature, str)
        assert len(signature) > 0
        
        # Test that same inputs produce same signature
        signature2 = self.validator._calculate_hmac_signature(message, secret)
        assert signature == signature2
        
        # Test that different inputs produce different signatures
        signature3 = self.validator._calculate_hmac_signature("different message", secret)
        assert signature != signature3


class TestAuthenticationIntegration:
    """Integration tests for authentication system"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.correlation_id = generate_correlation_id()
    
    @patch('src.authentication.get_signature_validator')
    @patch('src.authentication.get_user_authenticator')
    def test_authenticate_and_authorize_request_success(self, mock_get_authenticator, mock_get_validator):
        """Test successful end-to-end authentication and authorization"""
        # Mock signature validator
        mock_validator = Mock()
        mock_get_validator.return_value = mock_validator
        mock_validator.validate_plugin_signature.return_value = (True, None)
        
        # Mock user authenticator
        mock_authenticator = Mock()
        mock_get_authenticator.return_value = mock_authenticator
        mock_auth_result = AuthenticationResult(
            authenticated=True,
            user_context=UserContext(user_id="test.user@company.com"),
            correlation_id=self.correlation_id
        )
        mock_authenticator.authenticate_request.return_value = mock_auth_result
        
        request_data = {
            "user_context": {
                "user_id": "test.user@company.com"
            }
        }
        
        result = authenticate_and_authorize_request(request_data, self.correlation_id)
        
        assert result.authenticated is True
        assert result.user_context is not None
        assert result.user_context.user_id == "test.user@company.com"
    
    @patch('src.authentication.get_signature_validator')
    def test_authenticate_and_authorize_request_signature_failure(self, mock_get_validator):
        """Test authentication failure due to invalid signature"""
        # Mock signature validator to fail
        mock_validator = Mock()
        mock_get_validator.return_value = mock_validator
        mock_validator.validate_plugin_signature.return_value = (False, "Invalid signature")
        
        request_data = {
            "user_context": {
                "user_id": "test.user@company.com"
            }
        }
        
        result = authenticate_and_authorize_request(request_data, self.correlation_id)
        
        assert result.authenticated is False
        assert "Request signature validation failed" in result.error_message
    
    def test_get_user_authenticator_singleton(self):
        """Test that get_user_authenticator returns singleton instance"""
        authenticator1 = get_user_authenticator()
        authenticator2 = get_user_authenticator()
        
        assert authenticator1 is authenticator2
        assert isinstance(authenticator1, UserAuthenticator)
    
    def test_get_signature_validator_singleton(self):
        """Test that get_signature_validator returns singleton instance"""
        validator1 = get_signature_validator()
        validator2 = get_signature_validator()
        
        assert validator1 is validator2
        assert isinstance(validator1, RequestSignatureValidator)


class TestUserContextModel:
    """Test cases for UserContext model"""
    
    def test_user_context_creation(self):
        """Test UserContext creation and serialization"""
        user_context = UserContext(
            user_id="test.user@company.com",
            teams_tenant="company.onmicrosoft.com",
            session_id="session-123"
        )
        
        assert user_context.user_id == "test.user@company.com"
        assert user_context.teams_tenant == "company.onmicrosoft.com"
        assert user_context.session_id == "session-123"
        
        # Test serialization
        data = user_context.to_dict()
        assert data["user_id"] == "test.user@company.com"
        assert data["teams_tenant"] == "company.onmicrosoft.com"
        assert data["session_id"] == "session-123"
        
        # Test deserialization
        user_context2 = UserContext.from_dict(data)
        assert user_context2.user_id == user_context.user_id
        assert user_context2.teams_tenant == user_context.teams_tenant
        assert user_context2.session_id == user_context.session_id


class TestAuthenticationResult:
    """Test cases for AuthenticationResult model"""
    
    def test_authentication_result_success(self):
        """Test successful AuthenticationResult"""
        user_context = UserContext(user_id="test.user@company.com")
        correlation_id = generate_correlation_id()
        
        result = AuthenticationResult(
            authenticated=True,
            user_context=user_context,
            correlation_id=correlation_id
        )
        
        assert result.authenticated is True
        assert result.user_context == user_context
        assert result.error_message is None
        assert result.correlation_id == correlation_id
        
        # Test serialization
        data = result.to_dict()
        assert data["authenticated"] is True
        assert data["user_context"]["user_id"] == "test.user@company.com"
        assert data["correlation_id"] == correlation_id
    
    def test_authentication_result_failure(self):
        """Test failed AuthenticationResult"""
        correlation_id = generate_correlation_id()
        
        result = AuthenticationResult(
            authenticated=False,
            error_message="Authentication failed",
            correlation_id=correlation_id
        )
        
        assert result.authenticated is False
        assert result.user_context is None
        assert result.error_message == "Authentication failed"
        assert result.correlation_id == correlation_id
        
        # Test serialization
        data = result.to_dict()
        assert data["authenticated"] is False
        assert data["error_message"] == "Authentication failed"
        assert data["correlation_id"] == correlation_id


if __name__ == "__main__":
    pytest.main([__file__])