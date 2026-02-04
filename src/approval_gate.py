"""
Approval gate system for controlling write operations
Requirements: 3.1, 3.4
"""
import secrets
import time
import os
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field
import json
import logging

import boto3
from botocore.exceptions import ClientError

from src.models import ToolCall, ApprovalRequest, ExecutionMode, generate_correlation_id

logger = logging.getLogger(__name__)


@dataclass
class ApprovalDecision:
    """
    Represents a user's approval decision
    """
    token: str
    approved: bool
    decided_by: str
    decided_at: datetime = field(default_factory=datetime.utcnow)
    correlation_id: str = field(default_factory=generate_correlation_id)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "token": self.token,
            "approved": self.approved,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat() + "Z",
            "correlation_id": self.correlation_id
        }


class ApprovalGate:
    """
    Manages approval tokens and validation for write operations
    Requirements: 3.1, 3.4
    """
    
    def __init__(self, storage_backend: str = "memory", default_expiry_minutes: int = 15,
                 dynamodb_table_name: Optional[str] = None):
        """
        Initialize the approval gate

        Args:
            storage_backend: "memory" or "dynamodb" for MVP
            default_expiry_minutes: Default token expiry time in minutes
            dynamodb_table_name: DynamoDB table name (required for dynamodb backend)
        """
        self.storage_backend = storage_backend
        self.default_expiry_minutes = default_expiry_minutes

        # In-memory storage for MVP (not production-ready)
        self._pending_approvals: Dict[str, ApprovalRequest] = {}
        self._used_tokens: set = set()
        self._approval_decisions: Dict[str, ApprovalDecision] = {}

        # DynamoDB client and table (for production)
        self._dynamodb_client = None
        self._dynamodb_table_name = dynamodb_table_name

        if self.storage_backend == "dynamodb":
            if not dynamodb_table_name:
                raise ValueError("dynamodb_table_name is required when using dynamodb backend")
            self._dynamodb_client = boto3.resource('dynamodb')
            logger.info(f"ApprovalGate initialized with DynamoDB backend (table: {dynamodb_table_name})")
        else:
            logger.info(f"ApprovalGate initialized with {storage_backend} backend")
    
    def generate_approval_token(self) -> str:
        """
        Generate a cryptographically secure approval token
        
        Returns:
            Secure random token string
        """
        # Generate 32 bytes of random data, encode as hex
        return secrets.token_hex(32)
    
    def create_approval_request(
        self,
        tool_call: ToolCall,
        requested_by: str,
        risk_level: str = "medium",
        expiry_minutes: Optional[int] = None
    ) -> ApprovalRequest:
        """
        Create a new approval request for a write operation
        
        Args:
            tool_call: The tool call requiring approval
            requested_by: User ID requesting the operation
            risk_level: Risk level assessment ("low", "medium", "high")
            expiry_minutes: Custom expiry time, defaults to default_expiry_minutes
            
        Returns:
            ApprovalRequest object with generated token
            
        Requirements: 3.1, 3.4
        """
        if not tool_call.requires_approval:
            raise ValueError("Tool call does not require approval")
        
        if risk_level not in ["low", "medium", "high"]:
            raise ValueError("Risk level must be 'low', 'medium', or 'high'")
        
        expiry_time = expiry_minutes or self.default_expiry_minutes
        expires_at = datetime.utcnow() + timedelta(minutes=expiry_time)
        
        approval_request = ApprovalRequest(
            token=self.generate_approval_token(),
            expires_at=expires_at,
            user_id=requested_by,
            tool_call=tool_call,
            risk_level=risk_level,
            correlation_id=tool_call.correlation_id
        )
        
        # Store the approval request
        self._store_approval_request(approval_request)
        
        logger.info(
            f"Created approval request for {tool_call.tool_name} "
            f"by {requested_by}, token expires at {expires_at.isoformat()}"
        )
        
        return approval_request
    
    def validate_approval_token(
        self,
        token: str,
        user_id: str,
        tool_call: ToolCall
    ) -> tuple[bool, str]:
        """
        Validate an approval token for execution
        
        Args:
            token: The approval token to validate
            user_id: User attempting to use the token
            tool_call: The tool call being executed
            
        Returns:
            Tuple of (is_valid, reason)
            
        Requirements: 3.1, 3.4
        """
        # Check if token was already used (one-time use enforcement)
        if self._is_token_used(token):
            return False, "Token has already been used"
        
        # Retrieve the approval request
        approval_request = self._get_approval_request(token)
        if not approval_request:
            return False, "Invalid or unknown token"
        
        # Check expiration
        if datetime.utcnow() > approval_request.expires_at:
            return False, "Token has expired"
        
        # Check if the tool call matches the approved request
        if not self._tool_calls_match(approval_request.tool_call, tool_call):
            return False, "Tool call does not match approved request"
        
        # Check if user is authorized (for MVP, same user who requested)
        if approval_request.user_id != user_id:
            return False, "User not authorized to use this token"
        
        return True, "Token is valid"
    
    def approve_request(
        self,
        token: str,
        user_id: str,
        approved: bool = True
    ) -> ApprovalDecision:
        """
        Record an approval decision for a pending request
        
        Args:
            token: The approval token
            user_id: User making the decision
            approved: Whether the request is approved or denied
            
        Returns:
            ApprovalDecision object
            
        Requirements: 3.1, 3.4
        """
        approval_request = self._get_approval_request(token)
        if not approval_request:
            raise ValueError("Invalid or unknown token")
        
        if datetime.utcnow() > approval_request.expires_at:
            raise ValueError("Token has expired")
        
        # For MVP, only the requester can approve their own request
        if approval_request.user_id != user_id:
            raise ValueError("User not authorized to approve this request")
        
        decision = ApprovalDecision(
            token=token,
            approved=approved,
            decided_by=user_id,
            correlation_id=approval_request.correlation_id
        )

        self._store_approval_decision(decision)

        logger.info(
            f"Approval decision recorded: {token} "
            f"{'approved' if approved else 'denied'} by {user_id}"
        )

        return decision
    
    def consume_approval_token(self, token: str) -> bool:
        """
        Mark a token as used (one-time use enforcement)

        Args:
            token: The approval token to consume

        Returns:
            True if token was successfully consumed

        Requirements: 3.4
        """
        if self._is_token_used(token):
            return False

        approval_request = self._get_approval_request(token)
        if not approval_request:
            return False

        # Check if there's an approval decision
        decision = self._get_approval_decision(token)
        if not decision or not decision.approved:
            return False

        self._mark_token_used(token)
        logger.info(f"Approval token consumed: {token}")
        return True
    
    def format_approval_request_for_chat(
        self,
        approval_request: ApprovalRequest,
        execution_mode: ExecutionMode = ExecutionMode.SANDBOX_LIVE
    ) -> Dict[str, Any]:
        """
        Format an approval request for display in chat interfaces
        
        Args:
            approval_request: The approval request to format
            execution_mode: Current execution mode
            
        Returns:
            Dictionary with formatted approval request for chat display
            
        Requirements: 3.1
        """
        tool_call = approval_request.tool_call
        if not tool_call:
            raise ValueError("Approval request missing tool call")
        
        # Format tool arguments for display
        args_display = []
        for key, value in tool_call.args.items():
            args_display.append(f"  • {key}: {value}")
        
        args_text = "\n".join(args_display) if args_display else "  • No parameters"
        
        # Determine action description based on execution mode
        mode_description = {
            ExecutionMode.SANDBOX_LIVE: "EXECUTE"
        }.get(execution_mode, "EXECUTE")
        
        # Risk level emoji
        risk_emoji = {
            "low": "🟢",
            "medium": "🟡", 
            "high": "🔴"
        }.get(approval_request.risk_level, "🟡")
        
        expires_in_minutes = int((approval_request.expires_at - datetime.utcnow()).total_seconds() / 60)
        
        return {
            "type": "approval_request",
            "token": approval_request.token,
            "title": f"Approval Required: {tool_call.tool_name}",
            "description": f"**Action:** {mode_description} {tool_call.tool_name}\n\n"
                          f"**Parameters:**\n{args_text}\n\n"
                          f"**Risk Level:** {risk_emoji} {approval_request.risk_level.upper()}\n"
                          f"**Expires:** {expires_in_minutes} minutes\n"
                          f"**Correlation ID:** {approval_request.correlation_id}",
            "risk_level": approval_request.risk_level,
            "expires_at": approval_request.expires_at.isoformat() + "Z",
            "expires_in_minutes": expires_in_minutes,
            "correlation_id": approval_request.correlation_id,
            "execution_mode": execution_mode.value,
            "actions": [
                {
                    "type": "approve",
                    "label": f"Approve {mode_description}",
                    "token": approval_request.token
                },
                {
                    "type": "deny", 
                    "label": "Deny",
                    "token": approval_request.token
                }
            ]
        }
    
    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired approval requests and tokens
        
        Returns:
            Number of expired tokens cleaned up
        """
        current_time = datetime.utcnow()
        expired_tokens = []
        
        for token, request in self._pending_approvals.items():
            if current_time > request.expires_at:
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del self._pending_approvals[token]
            # Also clean up any decisions for expired tokens
            if token in self._approval_decisions:
                del self._approval_decisions[token]
        
        logger.info(f"Cleaned up {len(expired_tokens)} expired approval tokens")
        return len(expired_tokens)
    
    def get_pending_approvals(self, user_id: str) -> List[ApprovalRequest]:
        """
        Get all pending approval requests for a user
        
        Args:
            user_id: User ID to filter by
            
        Returns:
            List of pending approval requests
        """
        current_time = datetime.utcnow()
        pending = []
        
        for request in self._pending_approvals.values():
            if (request.user_id == user_id and 
                current_time <= request.expires_at and
                request.token not in self._used_tokens):
                pending.append(request)
        
        return pending
    
    def _store_approval_request(self, approval_request: ApprovalRequest) -> None:
        """Store approval request in the configured backend"""
        if self.storage_backend == "memory":
            self._pending_approvals[approval_request.token] = approval_request
        elif self.storage_backend == "dynamodb":
            try:
                table = self._dynamodb_client.Table(self._dynamodb_table_name)

                # Serialize the approval request
                item = {
                    'token': approval_request.token,
                    'record_type': 'approval_request',
                    'user_id': approval_request.user_id,
                    'tool_name': approval_request.tool_call.tool_name,
                    'tool_args': json.dumps(approval_request.tool_call.args),
                    'tool_correlation_id': approval_request.tool_call.correlation_id,
                    'tool_requires_approval': approval_request.tool_call.requires_approval,
                    'risk_level': approval_request.risk_level,
                    'correlation_id': approval_request.correlation_id,
                    'expires_at': approval_request.expires_at.isoformat() + 'Z',
                    'created_at': datetime.utcnow().isoformat() + 'Z',
                    'ttl': int(approval_request.expires_at.timestamp())  # DynamoDB TTL
                }

                table.put_item(Item=item)
                logger.info(f"Stored approval request in DynamoDB: {approval_request.token}")
            except ClientError as e:
                logger.error(f"Failed to store approval request in DynamoDB: {e}")
                raise
        else:
            raise ValueError(f"Unknown storage backend: {self.storage_backend}")
    
    def _get_approval_request(self, token: str) -> Optional[ApprovalRequest]:
        """Retrieve approval request from the configured backend"""
        if self.storage_backend == "memory":
            return self._pending_approvals.get(token)
        elif self.storage_backend == "dynamodb":
            try:
                table = self._dynamodb_client.Table(self._dynamodb_table_name)

                response = table.get_item(
                    Key={
                        'token': token,
                        'record_type': 'approval_request'
                    }
                )

                if 'Item' not in response:
                    return None

                item = response['Item']

                # Reconstruct the ToolCall object
                tool_call = ToolCall(
                    tool_name=item['tool_name'],
                    args=json.loads(item['tool_args']),
                    correlation_id=item['tool_correlation_id'],
                    requires_approval=item['tool_requires_approval']
                )

                # Reconstruct the ApprovalRequest object
                approval_request = ApprovalRequest(
                    token=item['token'],
                    expires_at=datetime.fromisoformat(item['expires_at'].replace('Z', '')),
                    user_id=item['user_id'],
                    tool_call=tool_call,
                    risk_level=item['risk_level'],
                    correlation_id=item['correlation_id']
                )

                return approval_request
            except ClientError as e:
                logger.error(f"Failed to retrieve approval request from DynamoDB: {e}")
                return None
        else:
            raise ValueError(f"Unknown storage backend: {self.storage_backend}")
    
    def _tool_calls_match(self, approved_call: ToolCall, execution_call: ToolCall) -> bool:
        """
        Check if two tool calls match for approval validation

        Args:
            approved_call: The originally approved tool call
            execution_call: The tool call being executed

        Returns:
            True if the calls match sufficiently for approval
        """
        # Tool names must match exactly
        if approved_call.tool_name != execution_call.tool_name:
            return False

        # Arguments must match exactly (prevent parameter tampering)
        if approved_call.args != execution_call.args:
            return False

        # Correlation IDs should match
        if approved_call.correlation_id != execution_call.correlation_id:
            return False

        return True

    def _is_token_used(self, token: str) -> bool:
        """Check if a token has been used"""
        if self.storage_backend == "memory":
            return token in self._used_tokens
        elif self.storage_backend == "dynamodb":
            try:
                table = self._dynamodb_client.Table(self._dynamodb_table_name)
                response = table.get_item(
                    Key={
                        'token': token,
                        'record_type': 'used_token'
                    }
                )
                return 'Item' in response
            except ClientError as e:
                logger.error(f"Failed to check token usage in DynamoDB: {e}")
                return False
        return False

    def _mark_token_used(self, token: str) -> None:
        """Mark a token as used"""
        if self.storage_backend == "memory":
            self._used_tokens.add(token)
        elif self.storage_backend == "dynamodb":
            try:
                table = self._dynamodb_client.Table(self._dynamodb_table_name)
                table.put_item(
                    Item={
                        'token': token,
                        'record_type': 'used_token',
                        'used_at': datetime.utcnow().isoformat() + 'Z',
                        'ttl': int((datetime.utcnow() + timedelta(days=7)).timestamp())
                    }
                )
            except ClientError as e:
                logger.error(f"Failed to mark token as used in DynamoDB: {e}")

    def _get_approval_decision(self, token: str) -> Optional[ApprovalDecision]:
        """Get approval decision for a token"""
        if self.storage_backend == "memory":
            return self._approval_decisions.get(token)
        elif self.storage_backend == "dynamodb":
            try:
                table = self._dynamodb_client.Table(self._dynamodb_table_name)
                response = table.get_item(
                    Key={
                        'token': token,
                        'record_type': 'approval_decision'
                    }
                )

                if 'Item' not in response:
                    return None

                item = response['Item']
                return ApprovalDecision(
                    token=item['token'],
                    approved=item['approved'],
                    decided_by=item['decided_by'],
                    decided_at=datetime.fromisoformat(item['decided_at'].replace('Z', '')),
                    correlation_id=item['correlation_id']
                )
            except ClientError as e:
                logger.error(f"Failed to get approval decision from DynamoDB: {e}")
                return None
        return None

    def _store_approval_decision(self, decision: ApprovalDecision) -> None:
        """Store approval decision"""
        if self.storage_backend == "memory":
            self._approval_decisions[decision.token] = decision
        elif self.storage_backend == "dynamodb":
            try:
                table = self._dynamodb_client.Table(self._dynamodb_table_name)
                table.put_item(
                    Item={
                        'token': decision.token,
                        'record_type': 'approval_decision',
                        'approved': decision.approved,
                        'decided_by': decision.decided_by,
                        'decided_at': decision.decided_at.isoformat() + 'Z',
                        'correlation_id': decision.correlation_id,
                        'ttl': int((datetime.utcnow() + timedelta(days=7)).timestamp())
                    }
                )
            except ClientError as e:
                logger.error(f"Failed to store approval decision in DynamoDB: {e}")
