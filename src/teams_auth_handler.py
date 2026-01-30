"""
Teams Authentication Handler - Integrated AWS Authentication
Handles OAuth flow directly within Teams chat interface
"""
import json
import logging
import os
import boto3
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class TeamsUser:
    """Teams user with AWS authentication status"""
    teams_id: str
    name: str
    email: str
    tenant_id: str
    aws_role_arn: Optional[str] = None
    aws_session_token: Optional[str] = None
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    session_expires: Optional[datetime] = None
    is_authenticated: bool = False

class TeamsAuthHandler:
    """
    Handles Teams-integrated AWS authentication
    """
    
    def __init__(self):
        """Initialize the Teams auth handler"""
        self.bot_app_id = os.environ.get("TEAMS_BOT_APP_ID", "7245659a-25f0-455c-9a75-06451e81fc3e")
        self.tenant_id = os.environ.get("AZURE_TENANT_ID", "78952f68-6959-4fc9-a579-af36c10eee5c")
        self.tenant_ids = [
            tenant.strip()
            for tenant in os.environ.get("AZURE_TENANT_IDS", self.tenant_id).split(",")
            if tenant.strip()
        ]
        self.aws_account_id = os.environ.get("AWS_ACCOUNT_ID", "612176863084")
        self.aws_account_ids = [
            account.strip()
            for account in os.environ.get("AWS_ACCOUNT_IDS", self.aws_account_id).split(",")
            if account.strip()
        ]
        self.aws_role_name = os.environ.get("AWS_ROLE_NAME", "OpsAgent-Teams-User-Role")
        self.aws_role_arn = os.environ.get("AWS_ROLE_ARN")
        self.aws_role_arn_by_tenant = self._load_role_arn_map()
        self.aws_region = os.environ.get("AWS_REGION", "eu-west-2")
        
        # In-memory session store (use Redis/DynamoDB in production)
        self.user_sessions = {}
        
        logger.info("Teams auth handler initialized")
    
    def is_user_authenticated(self, teams_user_id: str) -> bool:
        """Check if user has valid AWS authentication"""
        user = self.user_sessions.get(teams_user_id)
        if not user or not user.is_authenticated:
            return False
        
        # Check if session is expired
        if user.session_expires and datetime.utcnow() > user.session_expires:
            logger.info(f"Session expired for user {teams_user_id}")
            self.clear_user_session(teams_user_id)
            return False
        
        return True
    
    def get_user_session(self, teams_user_id: str) -> Optional[TeamsUser]:
        """Get user session if authenticated"""
        if self.is_user_authenticated(teams_user_id):
            return self.user_sessions.get(teams_user_id)
        return None
    
    def clear_user_session(self, teams_user_id: str):
        """Clear user authentication session"""
        if teams_user_id in self.user_sessions:
            del self.user_sessions[teams_user_id]
            logger.info(f"Cleared session for user {teams_user_id}")
    
    def create_auth_card(self, teams_user_id: str, conversation_id: str) -> Dict[str, Any]:
        """
        Create Teams Adaptive Card for AWS authentication
        """
        # Generate state parameter for OAuth security
        state = f"{teams_user_id}:{conversation_id}:{datetime.utcnow().timestamp()}"
        
        # OAuth URL for Azure AD authentication
        # Get API Gateway URL from environment or use default
        api_gateway_url = os.environ.get("API_GATEWAY_URL", "https://xt3qtho8l6.execute-api.eu-west-2.amazonaws.com/sandbox")
        redirect_uri = f"{api_gateway_url}/auth/callback"

        auth_url = (
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize?"
            f"client_id={self.bot_app_id}&"
            f"response_type=code&"
            f"redirect_uri={redirect_uri}&"
            f"scope=openid profile User.Read&"
            f"state={state}&"
            f"response_mode=query"
        )
        
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.signin",
                    "content": {
                        "text": (
                            "🔐 AWS Authentication Required\n\n"
                            "Sign in with your organization to access AWS resources."
                        ),
                        "buttons": [
                            {
                                "type": "signin",
                                "title": "🔑 Sign in with your organization",
                                "value": auth_url
                            }
                        ]
                    }
                }
            ]
        }
    
    def handle_auth_callback(self, auth_code: str, state: str) -> Dict[str, Any]:
        """
        Handle OAuth callback and establish AWS session
        """
        try:
            # Parse state parameter
            parts = state.split(':')
            if len(parts) != 3:
                raise ValueError("Invalid state parameter")
            
            teams_user_id, conversation_id, timestamp = parts
            
            # Exchange auth code for tokens
            token_response = self._exchange_auth_code(auth_code)
            if not token_response:
                return {"success": False, "error": "Failed to exchange auth code"}
            
            # Get user info from Microsoft Graph
            user_info = self._get_user_info(token_response['access_token'])
            if not user_info:
                return {"success": False, "error": "Failed to get user info"}
            
            # Validate user belongs to organization
            if not self._validate_user_organization(user_info):
                return {"success": False, "error": "User not authorized for this organization"}
            
            # Get AWS credentials using OIDC
            aws_credentials = self._get_aws_credentials(token_response['id_token'], user_info)
            if not aws_credentials:
                return {"success": False, "error": "Failed to get AWS credentials"}
            
            # Create user session
            user = TeamsUser(
                teams_id=teams_user_id,
                name=user_info.get('displayName', 'Unknown'),
                email=user_info.get('mail', user_info.get('userPrincipalName', '')),
                tenant_id=self.tenant_id,
                aws_role_arn=aws_credentials['role_arn'],
                aws_session_token=aws_credentials['session_token'],
                aws_access_key=aws_credentials['access_key'],
                aws_secret_key=aws_credentials['secret_key'],
                session_expires=datetime.utcnow() + timedelta(hours=1),
                is_authenticated=True
            )
            
            self.user_sessions[teams_user_id] = user
            
            logger.info(f"Successfully authenticated user {teams_user_id} ({user.email})")
            
            return {
                "success": True,
                "user": {
                    "name": user.name,
                    "email": user.email,
                    "aws_role": user.aws_role_arn,
                    "expires": user.session_expires.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Auth callback error: {e}")
            return {"success": False, "error": str(e)}
    
    def _exchange_auth_code(self, auth_code: str) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for tokens"""
        # TODO: Implement OAuth token exchange
        # This requires the requests library which needs to be properly packaged
        logger.warning("OAuth token exchange not implemented yet")
        return None
    
    def _get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user information from Microsoft Graph"""
        # TODO: Implement Microsoft Graph API call
        # This requires the requests library which needs to be properly packaged
        logger.warning("Microsoft Graph API call not implemented yet")
        return None
    
    def _validate_user_organization(self, user_info: Dict[str, Any]) -> bool:
        """Validate user belongs to authorized organization"""
        # Check if user's tenant matches expected tenant
        user_tenant = user_info.get('tenantId', '')
        if user_tenant not in self.tenant_ids:
            logger.warning(f"User from unauthorized tenant: {user_tenant}")
            return False
        
        # Additional organization validation can be added here
        # e.g., check group membership, domain, etc.
        
        return True
    
    def _get_aws_credentials(self, id_token: str, user_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get AWS credentials using OIDC federation"""
        try:
            # Assume role using OIDC token
            sts = boto3.client('sts', region_name=self.aws_region)
            
            role_arn = self._resolve_role_arn(user_info)
            session_name = f"teams-{user_info.get('userPrincipalName', 'unknown')}"
            
            response = sts.assume_role_with_web_identity(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                WebIdentityToken=id_token,
                DurationSeconds=3600  # 1 hour
            )
            
            credentials = response['Credentials']
            
            return {
                'role_arn': role_arn,
                'access_key': credentials['AccessKeyId'],
                'secret_key': credentials['SecretAccessKey'],
                'session_token': credentials['SessionToken']
            }
            
        except Exception as e:
            logger.error(f"AWS credentials error: {e}")
            return None

    def _load_role_arn_map(self) -> Dict[str, str]:
        """Load tenant-to-role ARN mapping from environment."""
        raw_map = os.environ.get("AWS_ROLE_ARN_BY_TENANT")
        if not raw_map:
            return {}
        try:
            return json.loads(raw_map)
        except json.JSONDecodeError as exc:
            logger.warning(f"Invalid AWS_ROLE_ARN_BY_TENANT JSON: {exc}")
            return {}

    def _resolve_role_arn(self, user_info: Dict[str, Any]) -> str:
        """Resolve the role ARN for the authenticated user."""
        user_tenant = user_info.get('tenantId', '')

        if user_tenant in self.aws_role_arn_by_tenant:
            return self.aws_role_arn_by_tenant[user_tenant]

        if self.aws_role_arn:
            return self.aws_role_arn

        account_id = self.aws_account_ids[0] if self.aws_account_ids else self.aws_account_id
        return f"arn:aws:iam::{account_id}:role/{self.aws_role_name}"
    
    def create_success_card(self, user: TeamsUser) -> Dict[str, Any]:
        """Create success card after authentication"""
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.3",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": "✅ Successfully Authenticated!",
                                "weight": "Bolder",
                                "size": "Large",
                                "color": "Good"
                            },
                            {
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "auto",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": "**Name:**\n**Email:**\n**AWS Role:**\n**Session Expires:**",
                                                "weight": "Bolder"
                                            }
                                        ]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": f"{user.name}\n{user.email}\n{user.aws_role_arn.split('/')[-1]}\n{user.session_expires.strftime('%H:%M UTC')}",
                                                "wrap": True
                                            }
                                        ]
                                    }
                                ]
                            },
                            {
                                "type": "TextBlock",
                                "text": "🚀 You can now use AWS commands like:\n• `health` - Check system status\n• `describe instance i-xxx` - Get instance details\n• `cpu metrics i-xxx` - View CPU metrics\n• `help` - See all available commands",
                                "wrap": True,
                                "spacing": "Medium"
                            }
                        ],
                        "actions": [
                            {
                                "type": "Action.Submit",
                                "title": "🔍 Check System Health",
                                "data": {
                                    "action": "health_check"
                                },
                                "style": "positive"
                            },
                            {
                                "type": "Action.Submit",
                                "title": "🚪 Sign Out",
                                "data": {
                                    "action": "logout",
                                    "user_id": user.teams_id
                                }
                            }
                        ]
                    }
                }
            ]
        }
    
    def get_aws_client(self, teams_user_id: str, service: str):
        """Get AWS client with user's credentials"""
        user = self.get_user_session(teams_user_id)
        if not user:
            raise ValueError("User not authenticated")
        
        return boto3.client(
            service,
            region_name=self.aws_region,
            aws_access_key_id=user.aws_access_key,
            aws_secret_access_key=user.aws_secret_key,
            aws_session_token=user.aws_session_token
        )
